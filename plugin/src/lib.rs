//! deathwatch: tells the Discord watcher when a player dies on an Enshrouded dedicated server.
//!
//! Ships as `dbghelp.dll` next to `enshrouded_server.exe`. On load it forwards the real dbghelp
//! exports, then (server only) hooks places found by byte signature:
//!
//! 1. the server's loop over its 16 player slots, to learn where the slot table is;
//! 2. every place an `EntityDiedEvent` gets its `deadEntityId` (type hash 0xD8EC982A), to queue
//!    the id of anything that dies; the PlayerDeath record (cause, position) and the freezing
//!    drain (freeze.rs) to give those deaths a cause.
//!
//! A thread of ours drains the queue, matches ids against the player slots and appends
//! `[I <unix time>] [deathwatch] death '<name>' died` to `logs/deathwatch_events.log`, which the
//! watcher follows (line formats: `chat_line`, `death_line`, `sleep_line`, `notice_line`).
//! Diagnostics go to `logs/deathwatch.log` (the previous run's is kept as `deathwatch.log.1`).
//! Each feature checks its own signatures: one that does not fit is left out (logged) and the
//! others still install. On a server build not in KNOWN_BUILDS the features that read game
//! structures through pointers or call game functions stay off (safe mode).
//!
//! Second feature, `sleep.rs`: one sleeping player skips the night. Third, `drops.rs`: consumables
//! follow resourceDropStackAmountFactor. Fourth, `harvest.rs`: plant and bush harvests follow it
//! too (its own page and log thread). Fifth, `chest.rs`: the player who opens a world chest that
//! rolls new loot gets a private chat line saying when it refills. All are switched in
//! `servermods.ini` next to the exe (created with defaults on first start).

mod cave;
mod chat;
mod chest;
mod deaths;
mod drops;
mod freeze;
mod harvest;
mod memory;
mod proxy;
mod sleep;
#[cfg(all(test, windows))]
mod mapped;

use std::{
    borrow::Cow,
    collections::{HashMap, HashSet},
    ffi::c_void,
    fs::{self, File, OpenOptions},
    io::{self, Write},
    os::windows::ffi::OsStringExt,
    panic,
    path::{Path, PathBuf},
    ptr,
    sync::{Mutex, OnceLock},
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use windows_sys::Win32::{
    Foundation::{BOOL, HMODULE, TRUE},
    System::{
        LibraryLoader::{DisableThreadLibraryCalls, GetModuleFileNameW, GetModuleHandleW},
        SystemServices::DLL_PROCESS_ATTACH,
        Threading::CreateThread,
    },
};

use crate::memory::{Image, matches, parse_signature, read, safe_read};

// Server 1.0, SVN 1267041 (re-targeted 2026-10-16 from SVN 1024233). Re-check every signature
// after a game update: plugin/tools/check_signatures.py <enshrouded_server.exe>.

/// PE link timestamps (`image.timestamp`) of the server builds every signature, offset and
/// structure layout here was checked against: 1.0, SVN 1267041. The servers update themselves; on
/// any other build the features that read game structures through pointers or call game functions
/// with arguments we build (chat both ways, the PlayerDeath record copy, the freezing hook, the
/// harvest hook) stay off unless `allow_unknown_build = true`. The rest only store a register or
/// patch bytes after checking the original bytes, and stay on.
const KNOWN_BUILDS: &[u32] = &[0x6ad1_0810, 0x6ad2_025e];

/// `imul r14, r15, <stride>; mov [rsp+..], eax; add r14, <table offset>; add r14, rsi; mov ecx,[r14]`
/// (1.0: the server object is rsi and the slot r14; 0.9 had them the other way round)
const SIG_SLOTS: &str = "4D 69 F7 ?? ?? ?? ?? 89 44 24 ?? 49 81 C6 ?? ?? ?? ?? 4C 03 F6 41 8B 0E";
const SLOTS_HOOK_OFFSET: usize = 11; // the `add r14, imm32`
/// `mov edx, EntityDiedEvent; mov r8d, 16` (event type and size before allocating the event).
const SIG_DIED_EVENT: &str = "BA 2A 98 EC D8 41 B8 10 00 00 00";
/// `mov ecx,[rax]; mov [rbx+8],ecx`: deadEntityId (offset 8 in the event) is stored.
const SIG_DIED_STORE: &str = "8B 08 89 4B 08";
const DIED_STORE_REACH: usize = 0x40;
/// `mov dl, 11 (Sleeping); inc r14b (players); call has_state; test al,al; je +3; inc bpl
/// (sleepers); add rsi, <player step>; cmp rsi, <bound>; jb` in `server_nighttime_skip` (1.0:
/// exe+0x103a10); the hook covers the 7 bytes before `add rsi`. 1.0 steps 0xA0 per player up to
/// 0xA00 (16 players); 0.9 stepped 0x60.
const SIG_SLEEPER: &str =
    "B2 0B 41 FE C6 E8 ?? ?? ?? ?? 84 C0 74 03 40 FE C5 48 81 C6 ?? ?? ?? ?? 48 81 FE ?? ?? ?? ?? 72";
const SLEEPER_HOOK_OFFSET: usize = 10;
const SLEEPER_STEP_IMM: usize = 20;
const SLEEPER_BOUND_IMM: usize = 27;
/// Entry of the function the fall, fog, oxygen and damage deaths call with `r8 = &keen::PlayerDeath`
/// (1.0: exe+0x4df70; freezing, admin and debug kills never do). Its first 5 bytes (`mov [rsp+20h],rbx`)
/// go to the cave.
const SIG_DEATH_RECORD: &str =
    "48 89 5C 24 20 55 56 57 41 54 41 55 48 8D AC 24 ?? ?? ?? ?? 48 81 EC ?? ?? ?? ?? 48 8D 5A 18 48 8B F1 48 8B CB 4D 8B E8 4C 8B E2 E8";

// keen::PlayerDeath (reflection data, 48 bytes)
const PD_ACCOUNT: usize = 0x00; // u64 accountIdHash
const PD_USER: usize = 0x08; // u32 userId
const PD_CAUSE: usize = 0x0C; // u8 DeathCause: Impact, FallDamage, Fog, Suffocated
const PD_POSITION: usize = 0x10; // float3, metres (WorldPosition 32.32 fixed point * 2^-32)
const PD_CAUSE_GUID: usize = 0x1C; // Guid, 16 bytes; set for Impact (what dealt the blow)
const PD_DEADLY_FOG: usize = 0x2C; // bool
const PD_DROWNED: usize = 0x2D; // bool
/// How long a player death waits for its PlayerDeath record (they come from different systems).
const PAIR_WINDOW: Duration = Duration::from_millis(1500);
/// Bytes of a player slot searched for a chat sender's accountIdHash (capped at the stride).
const ACCOUNT_SCAN: usize = 0x400;

const PLAYER_SLOTS: usize = 16;
const SLOT_HANDLE: usize = 0x00; // u32, 0 = free slot; low 6 bits slot index, the rest counts sessions
/// u32: the player's network connection (full handle, as in the connection table at server+0x16A0
/// and the session's channel table, indexed by handle & 0x7f). The server passes it to the
/// session's per-connection functions (exe+0x79c051: `mov edx,[slot+4]; call exe+0x9f6210`).
const SLOT_CONNECTION: usize = 0x04;
/// u8 login state: 1 login pending, 2 accepted, 3 logged in (set by the "Ready" handler exe+0x7a3e90
/// with "[server] Machine '%u': Player '%k' logged in"), 4 leaving at shutdown, 5 disconnecting,
/// 6 rejected. The slot loop exe+0x7b33e0 switches on it; the entity is assigned in state 3.
const SLOT_STATE: usize = 0x0A;
const SLOT_LOGGED_IN: u8 = 3;
const SLOT_ENTITY: usize = 0x18; // u32 entity id ("Remove Entity for Player" passes it; 0.9: 0x38)
/// What "[server] Player '%k'" prints: {char* ptr, u64 len, u64 capacity, grow fn, allocator},
/// no NUL terminator (0.9: inline text at 0x40).
const SLOT_NAME: usize = 0x20;
const SLOT_NAME_END: usize = SLOT_NAME + 0x28;
/// Longest player name (GameMessageLoginRequest.username holds 256 bytes).
const NAME_BYTES: usize = 256;

const POLL: Duration = Duration::from_millis(250);
const DUPLICATE_WINDOW: Duration = Duration::from_secs(5);
/// Log the slot table for the first player deaths, to confirm the layout on a new build. Deaths
/// of other entities (creatures) have a budget of their own, so they cannot use these up.
const VERBOSE_DEATHS: u32 = 10;
/// Log this many loot rolls of containers not placed in the world (corpses) after a start.
const VERBOSE_NOT_WORLD: u32 = 20;
/// What the chest notice says when servermods.ini does not say otherwise. The 30 minutes are the
/// game's (chest.rs): an unloaded area resets 30 minutes after the last player left it.
const CHEST_TEXT: &str = "This chest refills about 30 minutes after everyone has left the area.";

struct Hooks {
    page: usize,
    slot_base: usize,
    slot_stride: usize,
    /// The EntityDiedEvent id stores are hooked: deaths are queued in the ring.
    deaths: bool,
    /// The PlayerDeath hook is in: deaths can carry cause and position.
    records: bool,
    /// The night-skip sleeper hook is in.
    sleepers: bool,
    /// Bytes between sleeper cells: (player step >> 5) * 4.
    sleeper_cell: usize,
    /// The chat relay hook is in: lines in chat_outbox.txt are broadcast in game.
    chat: bool,
    /// Player chat is copied to the events file for Discord.
    chat_seen: bool,
    /// The freezing-kill page (cave::FZ_*), 0 when that hook is not in.
    freeze_page: usize,
    /// The chest-roll page (chest.rs), 0 when the chest notice is not in.
    chest_page: usize,
    /// Chest notice: text, chat type, and the least time between two notices to one player.
    chest_text: String,
    chest_type: u8,
    chest_every: Duration,
}

impl Hooks {
    /// What is hooked, for the log.
    fn describe(&self) -> String {
        let parts = [
            (true, "player slots"),
            (self.deaths, "deaths"),
            (self.records, "PlayerDeath record"),
            (self.freeze_page != 0, "freezing kills"),
            (self.sleepers, "sleepers"),
            (self.chat_seen, "chat-to-Discord"),
            (self.chat, "chat broadcast"),
            (self.chest_page != 0, "chest notice"),
        ];
        parts.iter().filter(|(on, _)| *on).map(|(_, name)| *name).collect::<Vec<_>>().join(", ")
    }
}

/// A copied keen::PlayerDeath.
#[derive(Clone, Debug, PartialEq)]
struct Record {
    account: u64,
    user: u32,
    cause: u8,
    position: [f32; 3],
    cause_guid: [u8; 16],
    deadly_fog: bool,
    drowned: bool,
}

impl Record {
    fn parse(b: &[u8]) -> Option<Record> {
        if b.len() < cave::RECORD_BYTES {
            return None;
        }
        let f = |o: usize| f32::from_le_bytes(b[o..o + 4].try_into().unwrap());
        Some(Record {
            account: u64::from_le_bytes(b[PD_ACCOUNT..PD_ACCOUNT + 8].try_into().unwrap()),
            user: u32::from_le_bytes(b[PD_USER..PD_USER + 4].try_into().unwrap()),
            cause: b[PD_CAUSE],
            position: [f(PD_POSITION), f(PD_POSITION + 4), f(PD_POSITION + 8)],
            cause_guid: b[PD_CAUSE_GUID..PD_CAUSE_GUID + 16].try_into().unwrap(),
            deadly_fog: b[PD_DEADLY_FOG] != 0,
            drowned: b[PD_DROWNED] != 0,
        })
    }

    fn cause_name(&self) -> &'static str {
        match self.cause {
            0 => "Impact",
            1 => "FallDamage",
            2 => "Fog",
            3 if self.drowned => "Drowned",
            3 => "Suffocated",
            _ => "Unknown",
        }
    }

    /// ` cause=Impact pos=1.0,2.0,3.0 killer=<guid>` for the events file.
    fn suffix(&self) -> String {
        let mut s = format!(" cause={}", self.cause_name());
        if self.position.iter().all(|v| v.is_finite()) {
            let [x, y, z] = self.position;
            s += &format!(" pos={x:.1},{y:.1},{z:.1}");
        }
        if self.cause_guid.iter().any(|&b| b != 0) {
            s += &format!(" killer={}", guid_text(&self.cause_guid));
        }
        if self.deadly_fog {
            s += " deadlyfog=1";
        }
        s
    }
}

/// Guid as the game's data files print it: 8-4-4-4-12 hex of the 16 bytes in memory order.
fn guid_text(g: &[u8; 16]) -> String {
    let h = hex(g).replace(' ', "");
    format!("{}-{}-{}-{}-{}", &h[0..8], &h[8..12], &h[12..16], &h[16..20], &h[20..32])
}

/// A player death from the EntityDiedEvent hook, waiting for its record.
struct Pending {
    name: String,
    slot: usize,
    entity: u32,
    /// accountIdHash in the slot when the death was seen (None: unreadable or 0).
    account: Option<u64>,
    /// Time from the player's arrival in the slot to the death (None: unknown).
    since_arrival: Option<Duration>,
    at: Instant,
}

static LOG: OnceLock<Mutex<File>> = OnceLock::new();
static START: OnceLock<Instant> = OnceLock::new();
/// Whether the real dbghelp exports are forwarded (false: not found, or Wine returned us).
static PROXY_OK: OnceLock<bool> = OnceLock::new();

fn log(text: &str) {
    if let Some(file) = LOG.get() {
        let secs = START.get().map_or(0.0, |s| s.elapsed().as_secs_f64());
        if let Ok(mut f) = file.lock() {
            let _ = writeln!(f, "[{secs:10.3}] {text}");
            let _ = f.flush();
        }
    }
}

#[unsafe(no_mangle)]
extern "system" fn DllMain(module: HMODULE, reason: u32, _reserved: *mut c_void) -> BOOL {
    if reason == DLL_PROCESS_ATTACH {
        unsafe { DisableThreadLibraryCalls(module) };
        let forwarding = proxy::init(module);
        let _ = PROXY_OK.set(forwarding);
        // Hooks go in here, before any server code runs, so no game thread can be inside
        // the bytes being replaced. A panic must never take the server down.
        if let Ok(Some(hooks)) = panic::catch_unwind(start) {
            let hooks = Box::into_raw(Box::new(hooks));
            // Created, not waited for: it starts once the loader lock is released.
            unsafe { CreateThread(ptr::null(), 0, Some(poll_thread), hooks.cast(), 0, ptr::null_mut()) };
        }
    }
    TRUE
}

fn exe_path() -> PathBuf {
    let mut buffer = [0u16; 1024];
    let len = unsafe { GetModuleFileNameW(ptr::null_mut(), buffer.as_mut_ptr(), buffer.len() as u32) } as usize;
    PathBuf::from(std::ffi::OsString::from_wide(&buffer[..len]))
}

const LOG_FILE: &str = "deathwatch.log";
const EVENTS_FILE: &str = "deathwatch_events.log";

/// The previous run's log becomes `<log>.1`, replacing an older one.
fn keep_previous_log(path: &Path) -> io::Result<()> {
    if !path.exists() {
        return Ok(());
    }
    let mut kept = path.as_os_str().to_owned();
    kept.push(".1");
    let kept = PathBuf::from(kept);
    fs::rename(path, &kept).or_else(|_| {
        fs::remove_file(&kept)?;
        fs::rename(path, &kept)
    })
}

fn start() -> Option<Hooks> {
    let exe = exe_path();
    let name = exe.file_name()?.to_string_lossy().to_lowercase();
    if !name.starts_with("enshrouded_server") {
        return None; // the game client also imports dbghelp; leave it alone
    }
    let dir = exe.parent()?;
    let logs = dir.join("logs");
    let _ = fs::create_dir_all(&logs);
    let _ = START.set(Instant::now());
    let log_path = logs.join(LOG_FILE);
    let kept = keep_previous_log(&log_path);
    let _ = LOG.set(Mutex::new(File::create(&log_path).ok()?));

    // The version stays line 1: the Discord watcher reads it to know which outbox format we take.
    let image = unsafe { Image::from_base(GetModuleHandleW(ptr::null()) as usize) };
    log(&format!("deathwatch {} in {} (image timestamp {:#x})", env!("CARGO_PKG_VERSION"), exe.display(), image.timestamp));
    if let Err(e) = kept {
        log(&format!("could not keep the previous log as {LOG_FILE}.1: {e}"));
    }
    if PROXY_OK.get() != Some(&true) {
        log("WARNING: real dbghelp not loaded (or the loader returned this DLL); dbghelp calls from the server will fail");
    }

    let config = Config::load(&dir.join(CONFIG_FILE));
    log(&format!("{CONFIG_FILE}: {}", config.describe()));

    // Build gate: an unknown build runs only what checks the bytes it changes.
    let known_build = KNOWN_BUILDS.contains(&image.timestamp);
    let trusted = known_build || config.allow_unknown_build;
    if !known_build {
        if config.allow_unknown_build {
            log(&format!(
                "WARNING: unknown server build {:#010x}; allow_unknown_build = true, so every feature is on",
                image.timestamp
            ));
        } else {
            log(&format!(
                "WARNING: unknown server build {:#010x}; safe mode: chat_broadcast, chat_to_discord, harvest_drops, the PlayerDeath record hook and the freezing hook are off (deaths post without a cause). Check the signatures, then add the build to KNOWN_BUILDS or set allow_unknown_build = true",
                image.timestamp
            ));
            // Posted in Discord by the watcher.
            write_line(
                &logs.join(EVENTS_FILE),
                &notice_line(&format!("mod running in safe mode, unknown server build {:#010x}", image.timestamp)),
            );
        }
    }

    if config.one_sleeper {
        match sleep::install(&image) {
            Ok(rva) => log(&format!("one sleeper skips the night: patched exe+{rva:#x}")),
            Err(why) => log(&format!("one sleeper NOT installed: {why}")),
        }
    }
    if config.consumable_drops {
        match drops::install(&image) {
            Ok(rva) => log(&format!("consumables follow the resource drop factor: patched exe+{rva:#x}")),
            Err(why) => log(&format!("consumable drops NOT installed: {why}")),
        }
    }
    // Independent of the death hooks (and of install() below): its own page and its own thread.
    if config.harvest_drops {
        if !trusted {
            log(&format!("harvest drops NOT installed: unknown server build {:#x}", image.timestamp));
        } else {
            match harvest::install(&image) {
                Ok(h) => {
                    log(&format!(
                        "plant harvests follow the resource drop factor ({} crops): hooked exe+{:#x}, cave at {:#x}",
                        h.items, h.rva, h.page
                    ));
                    // Its own thread: it reads only the harvest page, never the death hooks' page.
                    unsafe { CreateThread(ptr::null(), 0, Some(harvest_thread), ptr::null(), 0, ptr::null_mut()) };
                }
                Err(why) => log(&format!("harvest drops NOT installed: {why}")),
            }
        }
    }
    if !config.death_messages && !config.sleep_messages && !config.chat_broadcast && !config.chat_to_discord {
        return None;
    }
    match install(&image, &config, trusted) {
        Ok(hooks) => {
            log(&format!("hooks in place: {}", hooks.describe()));
            Some(hooks)
        }
        Err(why) => {
            log(&format!("death, sleep and chat messages NOT installed: {why}"));
            None
        }
    }
}

const CONFIG_FILE: &str = "servermods.ini";
/// Next to the exe. A folder of its own so the Discord watcher can be given write access to just it.
const CHAT_OUTBOX: &str = "servermods/chat_outbox.txt";

/// Lines waiting in the outbox. The file is renamed before it is read, so a writer appending at
/// the same moment starts a new file instead of losing its line to a truncate.
struct Outbox {
    /// Each line and how long ago it was written.
    lines: Vec<(String, Duration)>,
    /// The bytes were not UTF-8 (nor UTF-16 with a BOM) and were decoded with replacement characters.
    lossy: bool,
}

fn take_outbox(path: &std::path::Path) -> Outbox {
    let mut out = Outbox { lines: Vec::new(), lossy: false };
    if !path.exists() {
        return out;
    }
    let taken = path.with_extension("taking");
    if fs::rename(path, &taken).is_err() {
        return out;
    }
    let file_age = fs::metadata(&taken)
        .and_then(|m| m.modified())
        .ok()
        .and_then(|t| SystemTime::now().duration_since(t).ok())
        .unwrap_or_default();
    match fs::read(&taken) {
        Ok(bytes) => {
            let _ = fs::remove_file(&taken);
            let (text, lossy) = decode_outbox(&bytes);
            out.lossy = lossy;
            let now = SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs());
            out.lines = text.lines().filter_map(|l| outbox_line(l, now, file_age)).collect();
        }
        Err(e) => {
            let keep = path.with_extension("unreadable");
            let _ = fs::rename(&taken, &keep);
            log(&format!("cannot read {}: {e}; kept as {}", taken.display(), keep.display()));
        }
    }
    out
}

/// `@<unix> text` (the watcher stamps each line with the time it wrote it) or plain `text`, which
/// is as old as the file.
fn outbox_line(line: &str, now: u64, file_age: Duration) -> Option<(String, Duration)> {
    let line = line.trim();
    if let Some(rest) = line.strip_prefix('@') {
        let (stamp, text) = rest.split_once(' ').unwrap_or((rest, ""));
        if let Ok(written) = stamp.parse::<u64>() {
            let text = text.trim();
            return (!text.is_empty()).then(|| (text.to_string(), Duration::from_secs(now.saturating_sub(written))));
        }
    }
    (!line.is_empty()).then(|| (line.to_string(), file_age))
}

/// Outbox bytes as text: UTF-8 (a BOM is dropped), UTF-16 with a BOM (what Windows PowerShell 5.1
/// redirection writes), anything else UTF-8 with replacement characters (true = replaced).
fn decode_outbox(bytes: &[u8]) -> (String, bool) {
    let utf16 = |units: Vec<u16>| String::from_utf16_lossy(&units);
    match bytes {
        [0xEF, 0xBB, 0xBF, rest @ ..] => decode_outbox(rest),
        [0xFF, 0xFE, rest @ ..] => (utf16(rest.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect()), false),
        [0xFE, 0xFF, rest @ ..] => (utf16(rest.chunks_exact(2).map(|c| u16::from_be_bytes([c[0], c[1]])).collect()), false),
        _ => match String::from_utf8_lossy(bytes) {
            std::borrow::Cow::Borrowed(text) => (text.to_string(), false),
            std::borrow::Cow::Owned(text) => (text, true),
        },
    }
}
const CONFIG_DEFAULT: &str = "\
; Tartaros server mods (dbghelp.dll next to enshrouded_server.exe). Read once at server start.
; Remove dbghelp.dll to turn everything off. Keys missing from this file are added at the next
; start, with the value in effect (anything that changes gameplay is off when its key is missing).

; Write player deaths (cause, position) to logs/deathwatch_events.log for the Discord watcher.
death_messages = true
; Freezing deaths (the game keeps no cause for them) are written as cause=Freezing. Hooks the
; body-heat drain (bodyheat_depletion); false leaves that code untouched.
freezing_cause = true

; One sleeping player is enough to skip the night at full speed (the game: 60x * sleepers / players).
one_sleeper_skips_night = true

; Write who went to sleep while the night is being skipped to the same events file.
sleep_messages = true

; resourceDropStackAmountFactor also scales consumables (berries, mushrooms, food, potions), not just
; materials, build blocks and ammunition. Wild pickups and loot rolls alike. Changes gameplay.
consumable_drops = false

; Plant and bush harvests give their crop times resourceDropStackAmountFactor (at least 1, at most a
; stack): berries, vegetables, grain, herbs, mushrooms, flowers, night plants, plant fibre, twigs, reeds,
; straw and wheat, planted or wild (52 items). Seedlings, flame essence, shroud cores and spores, fog nest
; resources, bones, fur, weapons and fishing bait keep their normal count.
harvest_drops = false

; Lines written to servermods/chat_outbox.txt (next to the exe) are shown in the in-game chat of every
; player online, as \u{5b}Server\u{5d} ... ; a line waits at most 5 minutes for a player. EXPERIMENTAL.
chat_broadcast = false
; Copy what players type in chat to the events file, for the Discord watcher.
chat_to_discord = true
; ChatMessageServerMessage.type for those lines: 4 = shown like the game's join/leave notices (the
; text alone); 0 = shown as chat with the receiving player's own name in front.
chat_type = 4
; playerHandle for those lines; one no player has, so the client shows them without a name.
chat_sender = 4294967295

; When a player opens a chest placed in the world and it rolls new loot (the first opening since its
; area last reset), tell that player alone in chat when it refills. Needs chat_broadcast.
chest_notice = false
; What it says (one line, no semicolons), after \u{5b}Server\u{5d}.
chest_notice_text = This chest refills about 30 minutes after everyone has left the area.
; Its type, like chat_type: 4 = shown like a join/leave notice, 0 = as chat.
chest_notice_type = 4
; At most one chest notice per player in this many minutes (0: one for every chest).
chest_notice_minutes = 10

; On a server build this mod was not checked against (the server updates itself), only the parts
; that check the bytes they change run: death messages without a cause, sleep messages and the two
; patches. true runs everything anyway; only after plugin/tools/check_signatures.py passes on it.
allow_unknown_build = false
";

/// Every key in file order, with the one-line comment written above it when it is added to an
/// existing file.
const CONFIG_KEYS: [(&str, &str); 15] = [
    ("death_messages", "Write player deaths (cause, position) to logs/deathwatch_events.log for the Discord watcher."),
    ("freezing_cause", "Freezing deaths are written as cause=Freezing (hooks the body-heat drain)."),
    ("one_sleeper_skips_night", "One sleeping player is enough to skip the night at full speed."),
    ("sleep_messages", "Write who went to sleep while the night is being skipped to the events file."),
    ("consumable_drops", "resourceDropStackAmountFactor also scales consumables. Changes gameplay; off unless true."),
    ("harvest_drops", "Plant and bush harvests (52 crops) are multiplied by resourceDropStackAmountFactor. Changes gameplay; off unless true."),
    ("chat_broadcast", "Lines in servermods/chat_outbox.txt are shown in the in-game chat. EXPERIMENTAL."),
    ("chat_to_discord", "Copy what players type in chat to the events file, for the Discord watcher."),
    ("chat_type", "ChatMessageServerMessage.type for broadcast lines: 4 = shown like a join/leave notice, 0 = as chat with the player's own name."),
    ("chat_sender", "playerHandle for broadcast lines; must be one no player can have (bit 5 set: slot index handle & 63 >= 32)."),
    ("chest_notice", "A player who opens a world chest that rolls new loot is told alone in chat when it refills. Needs chat_broadcast."),
    ("chest_notice_text", "What the chest notice says (one line, no semicolons)."),
    ("chest_notice_type", "Type of the chest notice, like chat_type: 4 = shown like a join/leave notice, 0 = as chat."),
    ("chest_notice_minutes", "At most one chest notice per player in this many minutes (0: one for every chest)."),
    ("allow_unknown_build", "true: chat, death causes and harvest drops run even on a server build this mod was not checked against."),
];

#[derive(Debug, PartialEq)]
struct Config {
    death_messages: bool,
    freezing_cause: bool,
    one_sleeper: bool,
    sleep_messages: bool,
    consumable_drops: bool,
    harvest_drops: bool,
    chat_broadcast: bool,
    chat_to_discord: bool,
    chat_type: u8,
    chat_sender: u32,
    chest_notice: bool,
    chest_notice_text: String,
    chest_notice_type: u8,
    chest_notice_minutes: u32,
    allow_unknown_build: bool,
}

/// The values of missing keys. Gameplay changes are off unless the file turns them on.
impl Default for Config {
    fn default() -> Config {
        Config {
            death_messages: true,
            freezing_cause: true,
            one_sleeper: true,
            sleep_messages: true,
            consumable_drops: false,
            harvest_drops: false,
            chat_broadcast: false,
            chat_to_discord: true,
            chat_type: 4,
            chat_sender: u32::MAX,
            chest_notice: false,
            chest_notice_text: CHEST_TEXT.to_string(),
            chest_notice_type: 4,
            chest_notice_minutes: 10,
            allow_unknown_build: false,
        }
    }
}

/// What a servermods.ini says.
struct Parsed {
    config: Config,
    /// Keys the text does not set (they keep their default).
    missing: Vec<&'static str>,
    /// Keys we do not know (typos), ignored.
    unknown: Vec<String>,
}

impl Config {
    /// Reads `key = value` lines. A missing file is created with the defaults; keys missing from
    /// an existing file are appended with the value in effect. Any other read error: defaults,
    /// and the file is not touched. Not UTF-8: decoded with replacement characters.
    fn load(path: &Path) -> Config {
        let bytes = match fs::read(path) {
            Ok(bytes) => bytes,
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                match OpenOptions::new().write(true).create_new(true).open(path).and_then(|mut f| f.write_all(CONFIG_DEFAULT.as_bytes())) {
                    Ok(()) => log(&format!("{CONFIG_FILE} created with the defaults")),
                    Err(e) => log(&format!("{CONFIG_FILE} not found and could not be created: {e}")),
                }
                return Config::parse(CONFIG_DEFAULT).config;
            }
            Err(e) => {
                log(&format!("{CONFIG_FILE} could not be read ({e}): using the defaults, the file is left as it is"));
                return Config::default();
            }
        };
        let text = String::from_utf8_lossy(&bytes);
        if matches!(text, Cow::Owned(_)) {
            log(&format!("{CONFIG_FILE} is not UTF-8: read with replacement characters"));
        }
        let parsed = Config::parse(&text);
        for key in &parsed.unknown {
            log(&format!("{CONFIG_FILE}: unknown key '{key}' ignored"));
        }
        if !parsed.missing.is_empty() {
            let keys = parsed.missing.join(", ");
            if bytes.contains(&0) {
                // UTF-16 or binary: appending UTF-8 lines would only make it worse.
                log(&format!("{CONFIG_FILE} has NUL bytes (saved as UTF-16?): {keys} not added; they use their defaults"));
            } else {
                let block = parsed.config.missing_block(&parsed.missing, &text);
                match OpenOptions::new().append(true).open(path).and_then(|mut f| f.write_all(block.as_bytes())) {
                    Ok(()) => log(&format!("{CONFIG_FILE}: added the missing key(s) {keys}")),
                    Err(e) => log(&format!("{CONFIG_FILE}: could not add the missing key(s) {keys}: {e}")),
                }
            }
        }
        parsed.config
    }

    fn parse(text: &str) -> Parsed {
        let mut config = Config::default();
        let mut seen = HashSet::new();
        let mut unknown = Vec::new();
        for line in text.trim_start_matches('\u{feff}').lines() {
            let line = line.split(';').next().unwrap_or("").trim();
            let Some((key, value)) = line.split_once('=') else { continue };
            let key = key.trim();
            match CONFIG_KEYS.iter().find(|(known, _)| *known == key) {
                Some(&(known, _)) => {
                    config.set(known, value.trim());
                    seen.insert(known);
                }
                None => unknown.push(key.to_string()),
            }
        }
        let missing = CONFIG_KEYS.iter().map(|&(key, _)| key).filter(|key| !seen.contains(key)).collect();
        Parsed { config, missing, unknown }
    }

    /// Later lines win; a bad number keeps the default.
    fn set(&mut self, key: &str, value: &str) {
        let on = matches!(value.to_ascii_lowercase().as_str(), "true" | "1" | "yes" | "on");
        match key {
            "death_messages" => self.death_messages = on,
            "freezing_cause" => self.freezing_cause = on,
            "one_sleeper_skips_night" => self.one_sleeper = on,
            "sleep_messages" => self.sleep_messages = on,
            "consumable_drops" => self.consumable_drops = on,
            "harvest_drops" => self.harvest_drops = on,
            "chat_broadcast" => self.chat_broadcast = on,
            "chat_to_discord" => self.chat_to_discord = on,
            "chat_type" => self.chat_type = value.parse().unwrap_or(Config::default().chat_type),
            "chat_sender" => self.chat_sender = value.parse().unwrap_or(Config::default().chat_sender),
            "chest_notice" => self.chest_notice = on,
            "chest_notice_text" => {
                let text = one_line(value);
                self.chest_notice_text = if text.is_empty() { CHEST_TEXT.to_string() } else { text };
            }
            "chest_notice_type" => self.chest_notice_type = value.parse().unwrap_or(Config::default().chest_notice_type),
            "chest_notice_minutes" => self.chest_notice_minutes = value.parse().unwrap_or(Config::default().chest_notice_minutes),
            "allow_unknown_build" => self.allow_unknown_build = on,
            _ => {}
        }
    }

    /// The value in effect, written the way the file takes it.
    fn get(&self, key: &str) -> String {
        match key {
            "death_messages" => self.death_messages.to_string(),
            "freezing_cause" => self.freezing_cause.to_string(),
            "one_sleeper_skips_night" => self.one_sleeper.to_string(),
            "sleep_messages" => self.sleep_messages.to_string(),
            "consumable_drops" => self.consumable_drops.to_string(),
            "harvest_drops" => self.harvest_drops.to_string(),
            "chat_broadcast" => self.chat_broadcast.to_string(),
            "chat_to_discord" => self.chat_to_discord.to_string(),
            "chat_type" => self.chat_type.to_string(),
            "chat_sender" => self.chat_sender.to_string(),
            "chest_notice" => self.chest_notice.to_string(),
            "chest_notice_text" => self.chest_notice_text.clone(),
            "chest_notice_type" => self.chest_notice_type.to_string(),
            "chest_notice_minutes" => self.chest_notice_minutes.to_string(),
            "allow_unknown_build" => self.allow_unknown_build.to_string(),
            _ => String::new(),
        }
    }

    /// Every key and its value in effect, for the start of the log (a value with spaces in quotes).
    fn describe(&self) -> String {
        let shown = |v: String| if v.contains(' ') { format!("\"{v}\"") } else { v };
        CONFIG_KEYS.iter().map(|(key, _)| format!("{key}={}", shown(self.get(key)))).collect::<Vec<_>>().join(" ")
    }

    /// Text appended to a file (`existing`) that lacks `missing`: for each key a comment line and
    /// `key = <value in effect>`, in the file's own line ending.
    fn missing_block(&self, missing: &[&str], existing: &str) -> String {
        let nl = if existing.contains("\r\n") { "\r\n" } else { "\n" };
        let mut block = String::new();
        if !existing.is_empty() && !existing.ends_with('\n') {
            block += nl;
        }
        for key in missing {
            let comment = CONFIG_KEYS.iter().find(|(known, _)| known == key).map_or("", |(_, c)| c);
            block += &format!("{nl}; {comment} (added by deathwatch {}){nl}", env!("CARGO_PKG_VERSION"));
            block += &format!("{key} = {}{nl}", self.get(key));
        }
        block
    }
}

/// One feature's hooks on the shared page: cave code (copied in first; nothing runs it until a
/// jump to it is written) and the jumps written over the game's code.
struct Feature {
    name: &'static str,
    code: Vec<(usize, Vec<u8>)>,
    jumps: Vec<(usize, Vec<u8>)>,
}

/// A feature whose caves could be built; None (logged) otherwise.
fn built(what: &str, feature: Result<Feature, &str>) -> Option<Feature> {
    feature.map_err(|why| log(&format!("{what} NOT installed: {why}"))).ok()
}

fn slots_feature(page: usize, hook: usize) -> Result<Feature, &'static str> {
    let original: [u8; 7] = unsafe { read(hook) };
    let code = cave::slots_cave(page, hook, &original).ok_or("slots cave out of range")?;
    let jump = cave::jump_patch(hook, page + cave::SLOTS_CAVE, 7).ok_or("slots jump out of range")?;
    Ok(Feature { name: "player slots", code: vec![(page + cave::SLOTS_CAVE, code)], jumps: vec![(hook, jump)] })
}

fn deaths_feature(page: usize, died: &[usize]) -> Result<Feature, &'static str> {
    let mut feature = Feature { name: "death site", code: Vec::new(), jumps: Vec::new() };
    for (index, &hook) in died.iter().enumerate() {
        let (at, body) = cave::death_cave(page, index).ok_or("death cave out of range")?;
        feature.code.push((at, cave::finish_death_cave(at, body, hook).ok_or("death cave too big or out of range")?));
        feature.jumps.push((hook, cave::jump_patch(hook, at, 5).ok_or("death jump out of range")?));
    }
    Ok(feature)
}

fn record_feature(page: usize, hook: usize) -> Result<Feature, &'static str> {
    let original: [u8; 5] = unsafe { read(hook) };
    let code = cave::record_cave(page, hook, &original).ok_or("record cave too big or out of range")?;
    let jump = cave::jump_patch(hook, page + cave::RECORD_CAVE, 5).ok_or("record jump out of range")?;
    Ok(Feature { name: "PlayerDeath record", code: vec![(page + cave::RECORD_CAVE, code)], jumps: vec![(hook, jump)] })
}

fn sleeper_feature(page: usize, hook: usize) -> Result<Feature, &'static str> {
    let code = cave::sleep_cave(page, hook).ok_or("sleep cave too big or out of range")?;
    let jump = cave::jump_patch(hook, page + cave::SLEEP_CAVE, 7).ok_or("sleep jump out of range")?;
    Ok(Feature { name: "sleeper check", code: vec![(page + cave::SLEEP_CAVE, code)], jumps: vec![(hook, jump)] })
}

fn chat_in_feature(page: usize, hook: usize) -> Result<Feature, &'static str> {
    let original: [u8; 8] = unsafe { read(hook) };
    let code = cave::chat_in_cave(page, hook, &original).ok_or("chat-in cave out of range")?;
    let jump = cave::jump_patch(hook, page + cave::CHAT_IN_CAVE, 8).ok_or("chat-in jump out of range")?;
    Ok(Feature { name: "chat receive", code: vec![(page + cave::CHAT_IN_CAVE, code)], jumps: vec![(hook, jump)] })
}

fn chat_feature(page: usize, api: &chat::ChatApi) -> Result<Feature, &'static str> {
    let original: [u8; 5] = unsafe { read(api.relay) };
    let callback = chat::chat_tick as usize;
    let code = cave::chat_cave(page, api.relay, &original, callback).ok_or("chat cave out of range")?;
    let jump = cave::jump_patch(api.relay, page + cave::CHAT_CAVE, 5).ok_or("chat jump out of range")?;
    Ok(Feature { name: "chat relay entry", code: vec![(page + cave::CHAT_CAVE, code)], jumps: vec![(api.relay, jump)] })
}

/// Every EntityDiedEvent id store.
fn died_stores(image: &Image) -> Result<Vec<usize>, String> {
    let store = parse_signature(SIG_DIED_STORE).unwrap();
    let mut died = Vec::new();
    for event in image.find_all(SIG_DIED_EVENT) {
        let window = unsafe { std::slice::from_raw_parts(event as *const u8, DIED_STORE_REACH + store.len()) };
        match (0..DIED_STORE_REACH).find(|&i| matches(&store, &window[i..])) {
            Some(i) => {
                log(&format!("EntityDiedEvent at exe+{:#x}: id store at +{i:#x}", image.rva(event)));
                died.push(event + i);
            }
            None => log(&format!("EntityDiedEvent at exe+{:#x}: no id store nearby, skipped", image.rva(event))),
        }
    }
    if died.is_empty() {
        return Err("no EntityDiedEvent id store found".into());
    }
    if died.len() > cave::MAX_DEATH_CAVES {
        return Err(format!("{} death sites, more than the page holds", died.len()));
    }
    Ok(died)
}

/// The night-skip loop's sleeper check: (hook, bytes between sleeper cells).
fn find_sleeper(image: &Image) -> Result<(usize, usize), String> {
    let found = image.find_all(SIG_SLEEPER);
    let [at] = found[..] else { return Err(format!("sleeper signature matched {} times", found.len())) };
    let step = unsafe { read::<u32>(at + SLEEPER_STEP_IMM) } as usize;
    let bound = unsafe { read::<u32>(at + SLEEPER_BOUND_IMM) } as usize;
    let cell = sleeper_cells(step, bound)?;
    log(&format!(
        "night-skip sleeper check at exe+{:#x}, player step {step:#x}, loop bound {bound:#x}",
        image.rva(at + SLEEPER_HOOK_OFFSET)
    ));
    Ok((at + SLEEPER_HOOK_OFFSET, cell))
}

/// The sleep cave stores each sleeper at SLEEPERS + (rsi >> 5) * 4 for the loop `rsi = 0; rsi <
/// bound; rsi += step`, without bounds of its own, and the poll thread reads PLAYER_SLOTS cells.
/// Both stay inside SLEEPERS..SLEEPERS_END only if the step is a multiple of 32, the loop runs at
/// most PLAYER_SLOTS times and PLAYER_SLOTS cells fit. Returns the bytes between cells.
fn sleeper_cells(step: usize, bound: usize) -> Result<usize, String> {
    if step == 0 || step % 32 != 0 {
        return Err(format!("night-skip player step {step:#x} is not a multiple of 32"));
    }
    let players = bound.div_ceil(step);
    if players == 0 || players > PLAYER_SLOTS {
        return Err(format!("night-skip loop runs {players} times (bound {bound:#x}, step {step:#x}), not 1 to {PLAYER_SLOTS}"));
    }
    let cell = (step >> 5) * 4;
    if cave::SLEEPERS + (PLAYER_SLOTS - 1) * cell + 4 > cave::SLEEPERS_END {
        return Err(format!("night-skip player step {step:#x} does not fit the sleeper cells"));
    }
    Ok(cell)
}

fn install(image: &Image, config: &Config, trusted: bool) -> Result<Hooks, String> {
    // 1. Player slot loop: death, sleep and chat messages all need the slot table.
    let found = image.find_all(SIG_SLOTS);
    let [slot_loop] = found[..] else { return Err(format!("player-slot signature matched {} times", found.len())) };
    let slot_stride = unsafe { read::<u32>(slot_loop + 3) } as usize;
    let slot_base = unsafe { read::<u32>(slot_loop + 14) } as usize;
    chat::set_slots(slot_base, slot_stride);
    let slots_hook = slot_loop + SLOTS_HOOK_OFFSET;
    log(&format!("player slots: loop at exe+{:#x}, table at server+{slot_base:#x}, stride {slot_stride:#x}", image.rva(slot_loop)));
    if slot_stride < deaths::SLOT_SCAN.max(SLOT_NAME_END) {
        return Err(format!("player slot stride {slot_stride:#x} is smaller than the fields read"));
    }

    // 2. Deaths: every EntityDiedEvent id store, only looked for when death_messages is on.
    let died = if config.death_messages {
        died_stores(image).unwrap_or_else(|why| {
            log(&format!("death messages NOT installed: {why}"));
            Vec::new()
        })
    } else {
        Vec::new()
    };

    // 3. With deaths: the PlayerDeath record (cause, position, killer). Without it deaths still post.
    let record_hook = if died.is_empty() {
        None
    } else if !trusted {
        log("PlayerDeath record NOT hooked: unknown server build, deaths will have no cause");
        None
    } else {
        let records = image.find_all(SIG_DEATH_RECORD);
        match records[..] {
            [at] => {
                log(&format!("PlayerDeath record function at exe+{:#x}", image.rva(at)));
                Some(at)
            }
            _ => {
                log(&format!("PlayerDeath record signature matched {} times: deaths will have no cause", records.len()));
                None
            }
        }
    };

    // 3b. With deaths: freezing deaths get a cause (freeze.rs). Without it they post without one.
    let freeze_site = if died.is_empty() || !config.freezing_cause {
        None
    } else if !trusted {
        log("freezing cause NOT installed: unknown server build");
        None
    } else {
        match freeze::resolve(image) {
            Ok(site) => {
                log(&format!("bodyheat_depletion health drain at exe+{:#x}", image.rva(site.hook)));
                Some(site)
            }
            Err(why) => {
                log(&format!("freezing cause NOT installed: {why}"));
                None
            }
        }
    };

    // 4. Who is asleep while the night is skipped.
    let sleeper_hook = if config.sleep_messages {
        find_sleeper(image).map_err(|why| log(&format!("sleep messages NOT installed: {why}"))).ok()
    } else {
        None
    };

    // 5. Chat (chat.rs): to Discord from the receive handler, and the broadcast through the
    // relay. Resolved separately: either can be in without the other.
    let chat_in_hook = if !config.chat_to_discord {
        None
    } else if !trusted {
        log("chat-to-Discord NOT installed: unknown server build");
        None
    } else {
        match chat::resolve_chat_in(image) {
            Ok(hook) => {
                log(&format!("chat-to-Discord: receive hook at exe+{:#x}", image.rva(hook)));
                Some(hook)
            }
            Err(why) => {
                log(&format!("chat-to-Discord NOT installed: {why}"));
                None
            }
        }
    };
    let chat_api = if !config.chat_broadcast {
        None
    } else if !trusted {
        log("chat broadcast NOT installed: unknown server build");
        None
    } else {
        match chat::resolve(image, config.chat_type, config.chat_sender) {
            Ok(api) => {
                log(&chat::describe(api, image));
                Some(api)
            }
            Err(why) => {
                log(&format!("chat broadcast NOT installed: {why}"));
                None
            }
        }
    };
    if died.is_empty() && sleeper_hook.is_none() && chat_api.is_none() && chat_in_hook.is_none() {
        return Err("nothing to hook".into());
    }

    // 6. Build every cave first and write the game's code last. A cave that cannot be built
    // leaves out only its own feature; without the slot hook nothing is written.
    let page = memory::alloc_near(image.base, cave::PAGE);
    if page == 0 {
        return Err("no memory within jump range of the image".into());
    }
    let slots = slots_feature(page, slots_hook)?;
    let death_sites = if died.is_empty() { None } else { built("death messages", deaths_feature(page, &died)) };
    let record = match (record_hook, &death_sites) {
        (Some(hook), Some(_)) => built("PlayerDeath record", record_feature(page, hook)),
        _ => None,
    };
    let sleepers = sleeper_hook.and_then(|(hook, _)| built("sleep messages", sleeper_feature(page, hook)));
    let chat_seen = chat_in_hook.and_then(|hook| built("chat-to-Discord", chat_in_feature(page, hook)));
    let chat = chat_api.and_then(|api| built("chat broadcast", chat_feature(page, api)));

    // 7. Copy every cave in (nothing jumps there yet), then write the jumps: the slot hook first,
    // then feature by feature. memory::write fails before changing anything, so a failure leaves
    // that feature off; the log names every hook in place at that moment.
    let all = [Some(&slots), death_sites.as_ref(), record.as_ref(), sleepers.as_ref(), chat_seen.as_ref(), chat.as_ref()];
    for feature in all.into_iter().flatten() {
        for (at, bytes) in &feature.code {
            unsafe { ptr::copy_nonoverlapping(bytes.as_ptr(), *at as *mut u8, bytes.len()) };
        }
    }
    let mut in_place: Vec<String> = Vec::new();
    let mut write = |feature: &Feature| -> bool {
        for (at, bytes) in &feature.jumps {
            if !memory::write(*at, bytes) {
                let list = if in_place.is_empty() { "none".to_string() } else { in_place.join(", ") };
                log(&format!("{} NOT installed: could not write exe+{:#x}; hooks in place: {list}", feature.name, image.rva(*at)));
                return false;
            }
            in_place.push(format!("{} exe+{:#x}", feature.name, image.rva(*at)));
        }
        true
    };
    if !write(&slots) {
        return Err("the player-slot hook could not be written".into());
    }
    let deaths_in = death_sites.as_ref().is_some_and(&mut write);
    let records_in = deaths_in && record.as_ref().is_some_and(&mut write);
    let sleepers_in = sleepers.as_ref().is_some_and(&mut write);
    let chat_seen_in = chat_seen.as_ref().is_some_and(&mut write);
    let chat_in = chat.as_ref().is_some_and(&mut write);
    if deaths_in {
        log(&format!(
            "{} death site(s) hooked{}, cave page at {page:#x}",
            died.len(),
            if records_in { " plus the PlayerDeath record" } else { "" }
        ));
    }
    if sleepers_in {
        log("sleeper hook installed");
    }
    if chat_seen_in {
        log("chat-to-Discord hook installed");
    }
    if chat_in {
        log("chat broadcast hook installed (write lines to chat_outbox.txt)");
    }
    if !deaths_in && !sleepers_in && !chat_seen_in && !chat_in {
        return Err("no feature could be written (the player-slot hook stays, it only stores a pointer)".into());
    }

    // 8. Last, and on its own page: only with the death hooks in. A failure here leaves the
    // game's code untouched (memory::write fails before copying anything).
    let freeze_page = match freeze_site.filter(|_| deaths_in).map(|site| install_freeze(image, &site)) {
        Some(Ok(at)) => {
            log(&format!("freezing-kill hook installed, page at {at:#x}"));
            at
        }
        Some(Err(why)) => {
            log(&format!("freezing cause NOT installed: {why}"));
            0
        }
        None => 0,
    };
    if deaths_in {
        log("death hooks installed");
    }

    // 9. The chest notice (chest.rs), on its own page: only with the broadcast in (it sends
    // through it) and on a known build (the cave reads the event through r13).
    let chest_page = if !config.chest_notice {
        0
    } else if !trusted {
        log("chest notice NOT installed: unknown server build");
        0
    } else if !chat_in {
        log("chest notice NOT installed: it needs chat_broadcast");
        0
    } else if !chat::chat_type_allowed(config.chest_notice_type) {
        log(&format!("chest notice NOT installed: chest_notice_type {} is not allowed; 0 or 4", config.chest_notice_type));
        0
    } else {
        match chest::install(image) {
            Ok(c) => {
                log(&format!(
                    "chest notice: hooked exe+{:#x}, page at {:#x}; type {}, at most one per player per {} min: {}",
                    c.rva, c.page, config.chest_notice_type, config.chest_notice_minutes, config.chest_notice_text
                ));
                c.page
            }
            Err(why) => {
                log(&format!("chest notice NOT installed: {why}"));
                0
            }
        }
    };
    Ok(Hooks {
        page,
        slot_base,
        slot_stride,
        deaths: deaths_in,
        records: records_in,
        sleepers: sleepers_in,
        sleeper_cell: sleeper_hook.map_or(0, |(_, cell)| cell),
        chat: chat_in,
        chat_seen: chat_seen_in,
        freeze_page,
        chest_page,
        chest_text: config.chest_notice_text.clone(),
        chest_type: config.chest_notice_type,
        chest_every: Duration::from_secs(60 * config.chest_notice_minutes as u64),
    })
}

/// The freezing cave on a page of its own, then the 7-byte jump over the drain.
fn install_freeze(image: &Image, site: &freeze::Site) -> Result<usize, String> {
    let page = memory::alloc_near(image.base, cave::FZ_PAGE);
    if page == 0 {
        return Err("no memory within jump range of the image".into());
    }
    let code = cave::freeze_cave(page, site.hook, &site.original, freeze::ENTITY_IDS, freeze::ENTITY_COUNT)
        .ok_or("freezing cave out of range")?;
    let patch = cave::jump_patch(site.hook, page + cave::FZ_CAVE, 7).ok_or("freezing jump out of range")?;
    unsafe { ptr::copy_nonoverlapping(code.as_ptr(), (page + cave::FZ_CAVE) as *mut u8, code.len()) };
    if !memory::write(site.hook, &patch) {
        return Err(format!("could not write exe+{:#x}", image.rva(site.hook)));
    }
    Ok(page)
}

/// Logs the stacks plant harvests gave (harvest.rs), every POLL.
unsafe extern "system" fn harvest_thread(_: *mut c_void) -> u32 {
    let _ = panic::catch_unwind(|| {
        let mut state = harvest::LogState::default();
        loop {
            thread::sleep(POLL);
            for line in harvest::poll(&mut state) {
                log(&line);
            }
        }
    });
    log("harvest log thread ended");
    0
}

unsafe extern "system" fn poll_thread(hooks: *mut c_void) -> u32 {
    let hooks = unsafe { Box::from_raw(hooks.cast::<Hooks>()) };
    let _ = panic::catch_unwind(panic::AssertUnwindSafe(|| poll_loop(&hooks)));
    log("poll thread ended");
    0
}

fn poll_loop(hooks: &Hooks) {
    let events_path = exe_path().parent().map(|p| p.join("logs").join(EVENTS_FILE));
    let head_ptr = (hooks.page + cave::HEAD) as *const u32;
    let ring = (hooks.page + cave::RING) as *mut u32;
    let mut tail = unsafe { ptr::read_volatile(head_ptr) };
    let record_head = (hooks.page + cave::RECORD_HEAD) as *const u32;
    let mut record_tail = unsafe { ptr::read_volatile(record_head) };
    let mut recent: HashMap<u32, Instant> = HashMap::new();
    let mut pending: Vec<Pending> = Vec::new();
    let mut records: Vec<(Record, Instant)> = Vec::new();
    // Deaths logged in detail so far: players, and other entities (creatures) separately.
    let mut player_deaths = 0u32;
    let mut other_deaths = 0u32;
    let mut server_logged = false;
    let outbox = exe_path().parent().map(|p| p.join(CHAT_OUTBOX));
    if let Some(dir) = outbox.as_ref().and_then(|p| p.parent()) {
        if hooks.chat {
            let _ = fs::create_dir_all(dir);
        }
    }
    let mut chat_ticks_logged = false;
    let mut chat_in_tail = if hooks.chat_seen { unsafe { ptr::read_volatile((hooks.page + cave::CHAT_IN_HEAD) as *const u32) } } else { 0 };
    let mut sleepers = sleep::Sleepers::default();
    let mut slots = deaths::SlotTracker::default();
    let freeze_head = (hooks.freeze_page + cave::FZ_HEAD) as *const u32;
    let freeze_ring = (hooks.freeze_page + cave::FZ_RING) as *mut u32;
    let mut freeze_tail = if hooks.freeze_page != 0 { unsafe { ptr::read_volatile(freeze_head) } } else { 0 };
    let mut freezes: Vec<(u32, Instant)> = Vec::new(); // freezing kills: entity id, when seen
    let mut dead_accounts: HashSet<u64> = HashSet::new(); // accounts with a death posted by this process
    let mut chest_tail = if hooks.chest_page != 0 { chest::head(hooks.chest_page) } else { 0 };
    let mut chest_told: HashMap<u64, Instant> = HashMap::new(); // player (account, else slot handle) -> last notice
    let mut not_world_logged = 0u32;

    loop {
        thread::sleep(POLL);
        if !server_logged {
            let server = unsafe { ptr::read_volatile((hooks.page + cave::SERVER_SLOT) as *const usize) };
            if server != 0 {
                log(&format!("server object captured at {server:#x}"));
                server_logged = true;
            }
        }

        // Who is in which slot, and since when: a cause-less death right after arriving is a
        // character restored dead, and sleepers are told apart by their slot handle. Scanned
        // before the queues are drained.
        if let Some(table) = slot_table(hooks) {
            let now = Instant::now();
            for i in 0..PLAYER_SLOTS {
                let Some(in_slot) = deaths::SlotSeen::parse(&table[i * hooks.slot_stride..]) else { continue };
                let before = slots.seen(i);
                if slots.scan(i, in_slot, now) {
                    log(&format!("slot {i}: handle {:#x} entity {:#x} arrived", in_slot.handle, in_slot.entity));
                    freezes.retain(|&(id, _)| id != in_slot.entity); // ids are reused by the next player
                }
                if before.handle != 0 && before.handle != in_slot.handle {
                    sleepers.left(before.handle);
                }
            }
            slots.scanned(now);
        }

        // Player deaths (EntityDiedEvent ids).
        if hooks.deaths {
            let head = unsafe { ptr::read_volatile(head_ptr) };
            if head.wrapping_sub(tail) as usize > cave::RING_LEN {
                log(&format!("{} deaths dropped (queue overflow)", head.wrapping_sub(tail) as usize - cave::RING_LEN));
                tail = head.wrapping_sub(cave::RING_LEN as u32);
            }
            while tail != head {
                let slot = unsafe { ring.add(tail as usize % cave::RING_LEN) };
                let value = unsafe { ptr::read_volatile(slot) };
                if value == 0 {
                    break; // counted but not stored yet; next poll
                }
                unsafe { ptr::write_volatile(slot, 0) };
                tail = tail.wrapping_add(1);

                let id = value - 1;
                recent.retain(|_, t| t.elapsed() < DUPLICATE_WINDOW);
                if recent.insert(id, Instant::now()).is_some() {
                    continue;
                }
                let verbose = player_deaths < VERBOSE_DEATHS;
                let verbose_other = other_deaths < VERBOSE_DEATHS;
                if let Some((slot, name)) = player_name(hooks, id, verbose, verbose_other) {
                    player_deaths = player_deaths.saturating_add(1);
                    let now = Instant::now();
                    let in_slot = slot_seen(hooks, slot);
                    let account = in_slot.and_then(|s| s.account());
                    let since_arrival = in_slot.and_then(|s| slots.since_arrival(slot, s, now));
                    let arrived = since_arrival.map_or(String::new(), |d| format!(", {:.1} s after arriving", d.as_secs_f64()));
                    log(&format!("player died: '{name}' (entity {id:#x}, slot {slot}{arrived})"));
                    pending.push(Pending { name, slot, entity: id, account, since_arrival, at: now });
                } else {
                    if verbose_other {
                        log(&format!("entity {id:#x} died (not a player)"));
                    }
                    other_deaths = other_deaths.saturating_add(1);
                }
            }
        }

        // PlayerDeath records (cause, position, killer).
        if hooks.records {
            let head = unsafe { ptr::read_volatile(record_head) };
            if head.wrapping_sub(record_tail) as usize > cave::RECORDS_LEN {
                record_tail = head.wrapping_sub(cave::RECORDS_LEN as u32);
            }
            while record_tail != head {
                let at = hooks.page + cave::RECORDS + (record_tail as usize % cave::RECORDS_LEN) * cave::RECORD_SIZE;
                let ready = (at + cave::RECORD_BYTES) as *mut u32;
                if unsafe { ptr::read_volatile(ready) } == 0 {
                    break;
                }
                let bytes = unsafe { std::slice::from_raw_parts(at as *const u8, cave::RECORD_BYTES) }.to_vec();
                unsafe { ptr::write_volatile(ready, 0) };
                record_tail = record_tail.wrapping_add(1);
                if let Some(record) = Record::parse(&bytes) {
                    log(&format!("death record: {record:?} raw {}", hex(&bytes)));
                    records.push((record, Instant::now()));
                }
            }
        }

        // Freezing kills (bodyheat_depletion took Health to 0): entity ids.
        if hooks.freeze_page != 0 {
            let head = unsafe { ptr::read_volatile(freeze_head) };
            if head.wrapping_sub(freeze_tail) as usize > cave::FZ_RING_LEN {
                log(&format!("{} freezing kills dropped (queue overflow)", head.wrapping_sub(freeze_tail) as usize - cave::FZ_RING_LEN));
                freeze_tail = head.wrapping_sub(cave::FZ_RING_LEN as u32);
            }
            while freeze_tail != head {
                let cell = unsafe { freeze_ring.add(freeze_tail as usize % cave::FZ_RING_LEN) };
                let value = unsafe { ptr::read_volatile(cell) };
                if value == 0 {
                    break; // counted but not stored yet; next poll
                }
                unsafe { ptr::write_volatile(cell, 0) };
                freeze_tail = freeze_tail.wrapping_add(1);
                log(&format!("freezing kill: entity {:#x}", value - 1));
                freezes.push((value - 1, Instant::now()));
            }
        }

        // Player chat -> events file ("chat '<name>' says: <text>"), once per message.
        if hooks.chat_seen {
            let (messages, lost) = chat::take_chat_in(hooks.page, &mut chat_in_tail);
            if lost > 0 {
                log(&format!("{lost} chat message(s) lost (more than {} between two polls)", cave::CHAT_IN_LEN));
            }
            for seen in messages {
                if seen.rejected {
                    log(&format!(
                        "chat (type {}) from handle {:#x} longer than {} bytes: the game drops it, not posted",
                        seen.chat_type,
                        seen.handle,
                        cave::CHAT_IN_TEXT_MAX
                    ));
                    continue;
                }
                let text = one_line(&String::from_utf8_lossy(&seen.text));
                if text.is_empty() {
                    log(&format!("chat (type {}) without text from handle {:#x}: skipped", seen.chat_type, seen.handle));
                    continue;
                }
                let name = chat_sender_name(hooks, seen.handle, seen.account).unwrap_or_else(|| "A player".into());
                if let Some(path) = &events_path {
                    write_line(path, &chat_line(&name, &text));
                }
            }
        }

        // In-game chat: move outbox lines into the queue the server thread sends from.
        if hooks.chat {
            if !chat_ticks_logged && chat::TICKS.load(std::sync::atomic::Ordering::Relaxed) > 0 {
                log("chat relay is running (hook called)");
                chat_ticks_logged = true;
            }
            if let Some(path) = &outbox {
                let taken = take_outbox(path);
                if taken.lossy {
                    log("chat_outbox.txt was not valid UTF-8: decoded with replacement characters");
                }
                for (line, age) in taken.lines {
                    if age >= chat::EXPIRE {
                        log(&format!("chat line not sent, written {} s ago: {line}", age.as_secs()));
                        continue;
                    }
                    match chat::say("[Server] ", &line, age) {
                        chat::Said::Queued { parts, waiting } => {
                            let split = if parts > 1 { format!(" in {parts} parts") } else { String::new() };
                            log(&format!("chat queued{split} ({waiting} waiting): {line}"));
                        }
                        chat::Said::Full { dropped } => {
                            log(&format!("chat queue full ({} lines): {dropped} part(s) dropped: {line}", chat::QUEUE_MAX))
                        }
                        chat::Said::Empty => {}
                    }
                }
            }
            for line in chat::expire() {
                log(&format!(
                    "chat line expired after {} s with nobody to send it to ({} player(s) in game now): {line}",
                    chat::EXPIRE.as_secs(),
                    players_online(hooks)
                ));
            }
            for note in chat::take_notes() {
                log(&note);
            }
        }

        // Chest notices (chest.rs): whoever just rolled a world chest's loot is told, alone, when
        // it refills. At most one per player per `chest_every`.
        if hooks.chest_page != 0 {
            let taken = chest::take(hooks.chest_page, &mut chest_tail);
            if taken.dropped > 0 {
                log(&format!("chest notice: {} roll(s) not seen (more than {} between two polls)", taken.dropped, chest::RING_LEN));
            }
            let now = Instant::now();
            chest_told.retain(|_, t| now.duration_since(*t) < hooks.chest_every);
            for roll in taken.rolls {
                let what = chest::entity_text(roll.host);
                if !chest::in_world(roll.host) {
                    if not_world_logged < VERBOSE_NOT_WORLD {
                        log(&format!("chest notice: entity {what} rolled loot for entity {:#x} but is not placed in the world (a corpse?): no notice", roll.guest));
                        not_world_logged += 1;
                    }
                    continue;
                }
                let Some(player) = player_in_game(hooks, roll.guest) else {
                    log(&format!("chest notice: chest {what} rolled for entity {:#x}, which is no player in game: no notice", roll.guest));
                    continue;
                };
                let key = if player.account != 0 { player.account } else { player.handle as u64 };
                if let Some(t) = chest_told.get(&key) {
                    log(&format!(
                        "chest notice: '{}' rolled chest {what}; told {} s ago, not repeated",
                        player.name,
                        now.duration_since(*t).as_secs()
                    ));
                    continue;
                }
                match chat::say_to(player.connection, hooks.chest_type, "[Server] ", &hooks.chest_text) {
                    chat::Said::Queued { .. } => {
                        if !hooks.chest_every.is_zero() {
                            chest_told.insert(key, now);
                        }
                        log(&format!(
                            "chest notice for '{}' (slot {}, connection {:#x}): rolled chest {what}",
                            player.name, player.slot, player.connection
                        ));
                    }
                    chat::Said::Full { .. } => log(&format!("chest notice for '{}' dropped: chat queue full", player.name)),
                    chat::Said::Empty => {}
                }
            }
        }

        // Sleepers while the night is being skipped (cells are only written at night). Keyed by
        // entity and slot handle: the next player in a slot gets the same entity id.
        if hooks.sleepers {
            let now = Instant::now();
            let mut now_asleep = Vec::new();
            for i in 0..PLAYER_SLOTS {
                let cell = (hooks.page + cave::SLEEPERS + i * hooks.sleeper_cell) as *mut u32;
                let id = unsafe { ptr::read_volatile(cell) };
                if id != 0 {
                    unsafe { ptr::write_volatile(cell, 0) };
                    now_asleep.push(id);
                }
            }
            for &id in &now_asleep {
                let handle = slots.find_entity(id).map_or(0, |(_, s)| s.handle);
                if sleepers.seen((id, handle), now) {
                    let sleeping = sleepers.sleeping(now);
                    match player_name(hooks, id, true, true) {
                        Some((_, name)) => {
                            let players = players_online(hooks);
                            log(&format!("'{name}' is sleeping ({sleeping} of {players})"));
                            if let Some(path) = &events_path {
                                write_line(path, &sleep_line(&name, sleeping, players));
                            }
                        }
                        None => log(&format!("sleeper entity {id:#x} not in any player slot")),
                    }
                }
            }
            sleepers.prune(now);
        }

        // Pair each player death with a record or a freezing kill; post when paired or when the
        // wait is over, unless it is a character restored dead (deaths.rs).
        records.retain(|(_, t)| t.elapsed() < deaths::KEEP);
        freezes.retain(|(_, t)| t.elapsed() < deaths::FREEZE_LEAD + PAIR_WINDOW);
        let mut still = Vec::new();
        for death in pending.drain(..) {
            let record = deaths::pick_record(death.account, &records, death.at);
            let freeze = if record.is_none() { deaths::pick_freeze(death.entity, &freezes, death.at) } else { None };
            let verdict = deaths::decide(&deaths::Facts {
                paired: record.is_some() || freeze.is_some(),
                waited: death.at.elapsed(),
                since_arrival: death.since_arrival,
                records_hook: hooks.records,
                freeze_hook: hooks.freeze_page != 0,
                died_before: death.account.is_some_and(|a| dead_accounts.contains(&a)),
            });
            let arrived = death.since_arrival.map_or("unknown".into(), |d| format!("{:.1} s", d.as_secs_f64()));
            let suffix = match verdict {
                deaths::Verdict::Wait => {
                    still.push(death);
                    continue;
                }
                deaths::Verdict::Suppress => {
                    log(&format!(
                        "'{}' (slot {}, entity {:#x}) died {arrived} after arriving with no record and no freezing kill: a character saved dead, not posted",
                        death.name, death.slot, death.entity
                    ));
                    freezes.retain(|&(id, _)| id != death.entity);
                    continue;
                }
                deaths::Verdict::Post => match (record, freeze) {
                    (Some((i, by)), _) => {
                        log(&format!("record paired by {}", if by == deaths::PairedBy::Account { "account id (slot +0x48)" } else { "time" }));
                        records.remove(i).0.suffix()
                    }
                    (None, Some(i)) => {
                        freezes.remove(i);
                        log(&format!("freezing kill paired by entity id {:#x}", death.entity));
                        " cause=Freezing".to_string()
                    }
                    (None, None) => {
                        log(&format!("'{}' died with no record and no freezing kill ({arrived} after arriving): posted without a cause", death.name));
                        String::new()
                    }
                },
            };
            freezes.retain(|&(id, _)| id != death.entity);
            if let Some(a) = death.account {
                dead_accounts.insert(a);
            }
            if let Some(path) = &events_path {
                write_event(path, &death.name, &suffix);
            }
        }
        pending = still;
    }
}

/// The whole player-slot table in one read (None before the server object is known, or unreadable).
fn slot_table(hooks: &Hooks) -> Option<Vec<u8>> {
    let server = unsafe { ptr::read_volatile((hooks.page + cave::SERVER_SLOT) as *const usize) };
    if server == 0 || hooks.slot_stride < deaths::SLOT_SCAN {
        return None;
    }
    safe_read(server + hooks.slot_base, PLAYER_SLOTS * hooks.slot_stride)
}

/// Handle, entity and account of slot `i` now.
fn slot_seen(hooks: &Hooks, i: usize) -> Option<deaths::SlotSeen> {
    let server = unsafe { ptr::read_volatile((hooks.page + cave::SERVER_SLOT) as *const usize) };
    if server == 0 || hooks.slot_stride < deaths::SLOT_SCAN {
        return None;
    }
    deaths::SlotSeen::parse(&safe_read(server + hooks.slot_base + i * hooks.slot_stride, deaths::SLOT_SCAN)?)
}

fn write_event(path: &PathBuf, name: &str, suffix: &str) {
    write_line(path, &death_line(name, suffix));
}

/// Appends `[I <unix time>] [deathwatch] <text>` to the events file. `text` is one of the lines
/// below (`chat_line`, `death_line`, `sleep_line`, `notice_line`).
fn write_line(path: &PathBuf, text: &str) {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs());
    let line = format!("[I {now}] [deathwatch] {text}\n");
    match OpenOptions::new().create(true).append(true).open(path) {
        Ok(mut f) => {
            let _ = f.write_all(line.as_bytes());
        }
        Err(e) => log(&format!("cannot write {}: {e}", path.display())),
    }
}

/// A player name for the events file: on one line, in single quotes, with `\` and `'` escaped, so
/// the watcher can tell where it ends whatever the player called their character.
fn quoted(name: &str) -> String {
    let flat: String = name.chars().map(|c| if is_line_break(c) { ' ' } else { c }).collect();
    format!("'{}'", flat.replace('\\', "\\\\").replace('\'', "\\'"))
}

/// Control characters (CR, LF, tab, NEL, ...) and the Unicode line and paragraph separators.
fn is_line_break(c: char) -> bool {
    c.is_control() || c == '\u{2028}' || c == '\u{2029}'
}

/// Text on one line: control characters and line/paragraph separators become spaces; the ends
/// are trimmed.
fn one_line(text: &str) -> String {
    let spaced: String = text.chars().map(|c| if is_line_break(c) { ' ' } else { c }).collect();
    spaced.trim().to_string()
}

// Lines of the events file, after "[I <unix>] [deathwatch] ". The kind comes first, so no
// character name or chat text can make one kind of line read as another. The watcher
// (watcher/enshrouded_watch.py, PATTERNS) parses these and still reads the older
// "Player '<name>' died|sleeps|says: ..." lines of builds before 0.2.0.
fn chat_line(name: &str, text: &str) -> String {
    format!("chat {} says: {}", quoted(name), one_line(text))
}

fn death_line(name: &str, suffix: &str) -> String {
    format!("death {} died{suffix}", quoted(name))
}

fn sleep_line(name: &str, sleepers: usize, players: usize) -> String {
    format!("sleep {} sleeps sleepers={sleepers} players={players}", quoted(name))
}

/// A message from the mod itself for the Discord channel (the watcher posts it as a warning).
fn notice_line(text: &str) -> String {
    format!("notice: {}", one_line(text))
}

/// A slot whose player is in the game: a handle, an entity and login state 3 (SLOT_STATE).
/// Connecting, accepted-but-not-ready and leaving players are not counted.
fn in_game(slot: &[u8]) -> bool {
    let u32_at = |o: usize| slot.get(o..o + 4).map(|b| u32::from_le_bytes(b.try_into().unwrap()));
    u32_at(SLOT_HANDLE).is_some_and(|h| h != 0)
        && u32_at(SLOT_ENTITY).is_some_and(|e| e != 0)
        && slot.get(SLOT_STATE) == Some(&SLOT_LOGGED_IN)
}

/// Players in the game.
fn players_online(hooks: &Hooks) -> usize {
    let Some(table) = slot_table(hooks) else { return 0 };
    (0..PLAYER_SLOTS).filter(|i| in_game(&table[i * hooks.slot_stride..(i + 1) * hooks.slot_stride])).count()
}

/// A player in the game, found by entity id.
#[derive(Debug, PartialEq)]
struct InGame {
    slot: usize,
    handle: u32,
    connection: u32,
    account: u64,
    name: String,
}

/// The player in the game (`in_game`) whose slot holds entity `id`.
fn player_in_game(hooks: &Hooks, id: u32) -> Option<InGame> {
    let table = slot_table(hooks)?;
    find_in_game(&table, hooks.slot_stride, id)
}

fn find_in_game(table: &[u8], stride: usize, id: u32) -> Option<InGame> {
    if id == 0 || stride < SLOT_NAME_END.max(deaths::SLOT_SCAN) {
        return None;
    }
    let u32_at = |s: &[u8], o: usize| u32::from_le_bytes(s[o..o + 4].try_into().unwrap());
    (0..PLAYER_SLOTS).find_map(|i| {
        let slot = table.get(i * stride..(i + 1) * stride)?;
        if !in_game(slot) || u32_at(slot, SLOT_ENTITY) != id {
            return None;
        }
        let seen = deaths::SlotSeen::parse(slot)?;
        Some(InGame {
            slot: i,
            handle: seen.handle,
            connection: u32_at(slot, SLOT_CONNECTION),
            account: seen.account,
            name: slot_name(&slot[SLOT_NAME..SLOT_NAME_END]).unwrap_or_else(|| "A player".into()),
        })
    })
}

/// Name of the player who sent a chat message: the slot whose handle (+0) is the message's
/// playerHandle, else the slot that contains its accountIdHash.
fn chat_sender_name(hooks: &Hooks, handle: u32, account: u64) -> Option<String> {
    let server = unsafe { ptr::read_volatile((hooks.page + cave::SERVER_SLOT) as *const usize) };
    if server == 0 {
        return None;
    }
    let slots: Vec<Vec<u8>> = (0..PLAYER_SLOTS)
        .filter_map(|i| safe_read(server + hooks.slot_base + i * hooks.slot_stride, hooks.slot_stride.min(ACCOUNT_SCAN)))
        .collect();
    let name_of = |b: &Vec<u8>| {
        let name = slot_name(&b[SLOT_NAME..SLOT_NAME + 16]);
        if name.is_none() {
            log(&format!("chat sender slot found but name unreadable: {}", hex(&b[SLOT_NAME..SLOT_NAME + 32])));
        }
        name
    };
    for b in &slots {
        let h = u32::from_le_bytes(b[SLOT_HANDLE..SLOT_HANDLE + 4].try_into().unwrap());
        if h != 0 && h == handle {
            return name_of(b);
        }
    }
    if account != 0 {
        let needle = account.to_le_bytes();
        for b in &slots {
            if b.windows(8).any(|w| w == needle) {
                return name_of(b);
            }
        }
    }
    log(&format!("chat sender not matched (handle {handle:#x}, account {account:#x})"));
    None
}

/// (slot index, name) of the player whose slot holds entity `id`. `log_name`: log the name field
/// of the slot found; `log_miss`: log the slots in use when none holds it.
fn player_name(hooks: &Hooks, id: u32, log_name: bool, log_miss: bool) -> Option<(usize, String)> {
    let server = unsafe { ptr::read_volatile((hooks.page + cave::SERVER_SLOT) as *const usize) };
    if server == 0 {
        if log_miss {
            log("server object not seen yet");
        }
        return None;
    }
    let mut table = Vec::new();
    for i in 0..PLAYER_SLOTS {
        let slot = server + hooks.slot_base + i * hooks.slot_stride;
        let Some(bytes) = safe_read(slot, SLOT_NAME_END) else { continue };
        let handle = u32::from_le_bytes(bytes[SLOT_HANDLE..SLOT_HANDLE + 4].try_into().unwrap());
        let entity = u32::from_le_bytes(bytes[SLOT_ENTITY..SLOT_ENTITY + 4].try_into().unwrap());
        if handle == 0 {
            continue;
        }
        table.push(format!("{i}:{handle:#x}/{entity:#x}"));
        if entity != 0 && entity == id {
            let name = slot_name(&bytes[SLOT_NAME..]);
            if log_name || name.is_none() {
                log(&format!("slot {i} name field: {}", hex(&bytes[SLOT_NAME..SLOT_NAME_END])));
            }
            return Some((i, name.unwrap_or_else(|| "A player".into())));
        }
    }
    if log_miss {
        log(&format!("entity {id:#x}: no slot matches; slots in use (index:handle/entity) [{}]", table.join(" ")));
    }
    None
}

/// The player name from the slot's string field (SLOT_NAME): `len` bytes at `ptr`, 1 to
/// NAME_BYTES of them, with no terminator (what follows is stale heap memory). Decoded as UTF-8
/// with replacement characters, control characters dropped.
fn slot_name(field: &[u8]) -> Option<String> {
    let ptr = u64::from_le_bytes(field.get(0..8)?.try_into().ok()?) as usize;
    let len = u64::from_le_bytes(field.get(8..16)?.try_into().ok()?) as usize;
    if !(1..=NAME_BYTES).contains(&len) {
        return None;
    }
    let bytes = safe_read(ptr, len)?;
    let name: String = String::from_utf8_lossy(&bytes).chars().filter(|c| !c.is_control()).collect();
    (!name.is_empty()).then_some(name)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A 1.0 name field {ptr, len, capacity, grow fn, allocator} pointing at `text`.
    fn name_field(text: &[u8], len: usize) -> [u8; 0x28] {
        let mut field = [0u8; 0x28];
        field[0..8].copy_from_slice(&(text.as_ptr() as u64).to_le_bytes());
        field[8..16].copy_from_slice(&(len as u64).to_le_bytes());
        field[16..24].copy_from_slice(&(len.next_power_of_two() as u64).to_le_bytes());
        field[24..32].copy_from_slice(&0x1_4012_3450u64.to_le_bytes());
        field[32..40].copy_from_slice(&0x1_5000_0000u64.to_le_bytes());
        field
    }

    #[test]
    fn slot_name_1_0_layout() {
        // Live (server 1, 2026-10-16): 10 2b 67 fc 00 00 00 00 | 0c 00.. | 10 00.. | grow | allocator,
        // 'Hrothgar1066'. The pointer is replaced by one into this process.
        let text = b"Hrothgar1066";
        let field = name_field(text, 12);
        assert_eq!(&field[8..24], &[0x0c, 0, 0, 0, 0, 0, 0, 0, 0x10, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(slot_name(&field).as_deref(), Some("Hrothgar1066"));
    }

    #[test]
    fn slot_name_reads_exactly_len_bytes() {
        // 'larb' with heap bytes after it ('w...'): the old NUL-terminated reading gave 'larbw'.
        let heap = b"larbwiz\0\0";
        assert_eq!(slot_name(&name_field(heap, 4)).as_deref(), Some("larb"));
        // The longest name the game accepts, and one byte more.
        let long = [b'x'; NAME_BYTES + 1];
        assert_eq!(slot_name(&name_field(&long, NAME_BYTES)).map(|n| n.len()), Some(NAME_BYTES));
        assert_eq!(slot_name(&name_field(&long, NAME_BYTES + 1)), None);
        assert_eq!(slot_name(&name_field(heap, 0)), None);
        // Unreadable pointer, short field.
        let mut field = name_field(heap, 4);
        field[0..8].copy_from_slice(&0x10u64.to_le_bytes());
        assert_eq!(slot_name(&field), None);
        assert_eq!(slot_name(&name_field(heap, 4)[..15]), None);
    }

    #[test]
    fn slot_name_decoding() {
        let text = "Bjørn the Bold".as_bytes();
        assert_eq!(slot_name(&name_field(text, text.len())).as_deref(), Some("Bjørn the Bold"));
        // Not UTF-8: replacement character; control characters are dropped.
        assert_eq!(slot_name(&name_field(b"A\xffB", 3)).as_deref(), Some("A\u{fffd}B"));
        assert_eq!(slot_name(&name_field(b"Bo\x07b\n", 5)).as_deref(), Some("Bob"));
        assert_eq!(slot_name(&name_field(b"\x01\x02", 2)), None);
    }

    #[test]
    fn players_in_game() {
        let mut slot = vec![0u8; 0x148];
        assert!(!in_game(&slot)); // free
        slot[SLOT_HANDLE..SLOT_HANDLE + 4].copy_from_slice(&0x40u32.to_le_bytes());
        slot[SLOT_STATE] = 1;
        assert!(!in_game(&slot)); // connecting
        slot[SLOT_STATE] = SLOT_LOGGED_IN;
        assert!(!in_game(&slot)); // logged in, no entity yet
        slot[SLOT_ENTITY..SLOT_ENTITY + 4].copy_from_slice(&1u32.to_le_bytes());
        assert!(in_game(&slot));
        slot[SLOT_STATE] = 5;
        assert!(!in_game(&slot)); // disconnecting
        assert!(!in_game(&slot[..SLOT_STATE])); // short read
    }

    #[test]
    fn chest_notice_finds_the_player_by_entity() {
        const STRIDE: usize = 0x148;
        let name = b"theodore47";
        let mut table = vec![0u8; PLAYER_SLOTS * STRIDE];
        let mut put = |i: usize, handle: u32, connection: u32, entity: u32, state: u8, account: u64| {
            let s = &mut table[i * STRIDE..(i + 1) * STRIDE];
            s[SLOT_HANDLE..SLOT_HANDLE + 4].copy_from_slice(&handle.to_le_bytes());
            s[SLOT_CONNECTION..SLOT_CONNECTION + 4].copy_from_slice(&connection.to_le_bytes());
            s[SLOT_STATE] = state;
            s[SLOT_ENTITY..SLOT_ENTITY + 4].copy_from_slice(&entity.to_le_bytes());
            s[SLOT_NAME..SLOT_NAME + 0x28].copy_from_slice(&name_field(name, name.len()));
            s[deaths::SLOT_ACCOUNT..deaths::SLOT_ACCOUNT + 8].copy_from_slice(&account.to_le_bytes());
        };
        put(0, 0x40, 0x81, 1, SLOT_LOGGED_IN, 0xAB);
        put(3, 0x83, 0x102, 2, 5, 0xCD); // disconnecting
        put(5, 0x45, 0x183, 3, SLOT_LOGGED_IN, 0);
        let p = find_in_game(&table, STRIDE, 1).unwrap();
        assert_eq!(p, InGame { slot: 0, handle: 0x40, connection: 0x81, account: 0xAB, name: "theodore47".into() });
        assert_eq!(find_in_game(&table, STRIDE, 3).map(|p| (p.slot, p.connection, p.account)), Some((5, 0x183, 0)));
        assert_eq!(find_in_game(&table, STRIDE, 2), None); // not in game any more
        assert_eq!(find_in_game(&table, STRIDE, 9), None);
        assert_eq!(find_in_game(&table, STRIDE, 0), None);
        assert_eq!(find_in_game(&table[..STRIDE * 2], STRIDE, 3), None); // short table
        assert_eq!(find_in_game(&table, 0x40, 1), None); // a stride too small for the fields
    }

    #[test]
    fn chest_notice_settings() {
        let c = Config::default();
        assert_eq!((c.chest_notice, c.chest_notice_type, c.chest_notice_minutes), (false, 4, 10));
        assert_eq!(c.chest_notice_text, CHEST_TEXT);
        // the template says the same as a missing key
        let t = Config::parse(CONFIG_DEFAULT).config;
        assert_eq!(t, c);
        let c = Config::parse("chest_notice = true\nchest_notice_text =  Refills  = soon \nchest_notice_type = 4\nchest_notice_minutes = 0\n").config;
        assert!(c.chest_notice);
        assert_eq!((c.chest_notice_text.as_str(), c.chest_notice_type, c.chest_notice_minutes), ("Refills  = soon", 4, 0));
        // an empty text keeps the default; text after a semicolon is a comment
        let c = Config::parse("chest_notice_text =\nchest_notice_minutes = lots").config;
        assert_eq!((c.chest_notice_text.as_str(), c.chest_notice_minutes), (CHEST_TEXT, 10));
        assert_eq!(Config::parse("chest_notice_text = Soon; very soon").config.chest_notice_text, "Soon");
        // values survive get -> set
        let mut c = Config::default();
        for (key, value) in [("chest_notice", "true"), ("chest_notice_text", "Back in 30 minutes."), ("chest_notice_type", "4"), ("chest_notice_minutes", "5")] {
            c.set(key, value);
            assert_eq!(c.get(key), value);
        }
        assert!(CHEST_TEXT.len() + "[Server] ".len() <= chat::LINE_MAX && !CHEST_TEXT.contains(';'));
    }

    #[test]
    fn sleeper_loop_bound() {
        // 1.0 exe+0x103ad5: add rsi, 0xa0; cmp rsi, 0xa00; jb
        assert_eq!(sleeper_cells(0xA0, 0xA00), Ok(20));
        assert_eq!(sleeper_cells(0x60, 0x600), Ok(12)); // 0.9's step
        assert_eq!(sleeper_cells(0x100, 0x1000), Ok(32)); // the largest step the cells hold
        assert!(sleeper_cells(0xA0, 0xA01).is_err()); // 17 players
        assert!(sleeper_cells(0xA0, 0x1400).is_err()); // 32 players
        assert!(sleeper_cells(0xA0, 0).is_err());
        assert!(sleeper_cells(0x120, 0x1200).is_err()); // cells past SLEEPERS_END
        assert!(sleeper_cells(0x50, 0x500).is_err()); // not a multiple of 32
        assert!(sleeper_cells(0, 0xA00).is_err());
    }

    #[test]
    fn outbox_is_taken_whole() {
        let dir = std::env::temp_dir().join(format!("dw-outbox-{}", std::process::id()));
        let _ = fs::create_dir_all(&dir);
        let path = dir.join("chat_outbox.txt");
        fs::write(&path, "first line

  second line  
").unwrap();
        let taken = take_outbox(&path);
        let lines: Vec<&str> = taken.lines.iter().map(|(l, _)| l.as_str()).collect();
        assert_eq!(lines, vec!["first line", "second line"]);
        assert!(taken.lines.iter().all(|(_, age)| *age < Duration::from_secs(60)) && !taken.lossy);
        assert!(!path.exists() && !path.with_extension("taking").exists());
        assert!(take_outbox(&path).lines.is_empty());
        fs::write(&path, b"Caf\xe9 open\r\n").unwrap();
        let taken = take_outbox(&path);
        assert!(taken.lossy);
        assert_eq!(taken.lines[0].0, "Caf\u{fffd} open");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn outbox_lines_and_encodings() {
        let file_age = Duration::from_secs(7);
        assert_eq!(outbox_line("@1000 hello there", 1060, file_age), Some(("hello there".into(), Duration::from_secs(60))));
        assert_eq!(outbox_line("@1000 ", 1060, file_age), None);
        assert_eq!(outbox_line("@2000 from the future", 1060, file_age), Some(("from the future".into(), Duration::ZERO)));
        assert_eq!(outbox_line("  plain  ", 1060, file_age), Some(("plain".into(), file_age)));
        assert_eq!(outbox_line("@soon not a stamp", 1060, file_age), Some(("@soon not a stamp".into(), file_age)));
        assert_eq!(outbox_line("   ", 1060, file_age), None);
        assert_eq!(decode_outbox(b"\xEF\xBB\xBFhi"), ("hi".into(), false));
        let utf16: Vec<u8> = [0xFF, 0xFE].into_iter().chain("h\u{e9}".encode_utf16().flat_map(u16::to_le_bytes)).collect();
        assert_eq!(decode_outbox(&utf16), ("h\u{e9}".into(), false));
        assert_eq!(decode_outbox(b"a\xffb"), ("a\u{fffd}b".into(), true));
    }

    #[test]
    fn config() {
        let p = Config::parse(CONFIG_DEFAULT);
        assert!(p.missing.is_empty() && p.unknown.is_empty(), "{:?} {:?}", p.missing, p.unknown);
        let c = p.config;
        assert!(c.death_messages && c.one_sleeper && c.sleep_messages && !c.chat_broadcast && c.freezing_cause);
        assert!(!c.consumable_drops && !c.harvest_drops && !c.allow_unknown_build && c.chat_to_discord);
        assert_eq!((c.chat_type, c.chat_sender), (4, u32::MAX));
        assert_eq!(c, Config::default()); // the new file says what a missing key means
        assert!(!Config::parse("freezing_cause = false").config.freezing_cause);
        assert!(Config::parse("death_messages = true").config.freezing_cause); // missing key: on
        let c = Config::parse("chat_broadcast = true\nchat_type = 3\nchat_sender = 7\nchat_to_discord = false\n").config;
        assert!(c.chat_broadcast && !c.chat_to_discord);
        assert_eq!((c.chat_type, c.chat_sender), (3, 7));
        let c = Config::parse("death_messages = false ; off\none_sleeper_skips_night=0\nsleep_messages=no\n").config;
        assert!(!c.death_messages && !c.one_sleeper && !c.sleep_messages);
        let c = Config::parse("one_sleeper_skips_night = TRUE").config;
        assert!(c.death_messages && c.one_sleeper); // missing keys keep their defaults
        assert!(!c.harvest_drops); // off unless the ini says so
        // Gameplay changes are off when their key is missing, on only when set.
        assert!(!Config::parse("").config.consumable_drops);
        assert!(Config::parse("consumable_drops = true").config.consumable_drops);
        assert!(!Config::parse("").config.harvest_drops);
        assert!(!Config::parse(CONFIG_DEFAULT).config.harvest_drops);
        assert!(Config::parse("harvest_drops = true").config.harvest_drops);
        assert!(!Config::parse("harvest_drops = true\nharvest_drops = off").config.harvest_drops);
        assert!(!Config::parse("consumable_drops = true").config.harvest_drops); // independent keys
        assert!(Config::parse("allow_unknown_build = yes").config.allow_unknown_build);
        // The last line wins; a bad number keeps the default.
        assert!(!Config::parse("consumable_drops = true\nconsumable_drops = off").config.consumable_drops);
        assert_eq!(Config::parse("chat_type = lots\nchat_sender = -1").config.chat_type, 4);
        assert_eq!(Config::parse("chat_sender = -1").config.chat_sender, u32::MAX);
        // A UTF-8 byte order mark does not hide the first key.
        assert!(!Config::parse("\u{feff}death_messages = false").config.death_messages);
    }

    #[test]
    fn config_missing_and_unknown_keys() {
        let p = Config::parse("death_mesages = false\nsleep_messages = false\n");
        assert_eq!(p.unknown, vec!["death_mesages"]);
        assert!(p.config.death_messages && !p.config.sleep_messages);
        assert_eq!(p.missing.len(), CONFIG_KEYS.len() - 1);
        assert!(!p.missing.contains(&"sleep_messages") && p.missing.contains(&"allow_unknown_build"));
    }

    #[test]
    fn config_keys_round_trip() {
        // Every key is in the template, and set/get agree on every key.
        for (key, comment) in CONFIG_KEYS {
            assert!(CONFIG_DEFAULT.lines().any(|l| l.starts_with(&format!("{key} = "))), "{key} not in CONFIG_DEFAULT");
            assert!(!comment.contains('\n'));
        }
        let mut c = Config::default();
        for (key, value) in [("chat_type", "9"), ("chat_sender", "12"), ("death_messages", "false"), ("allow_unknown_build", "true"), ("harvest_drops", "true")] {
            c.set(key, value);
            assert_eq!(c.get(key), value);
        }
        let all = Config::default().describe();
        assert!(CONFIG_KEYS.iter().all(|(key, _)| all.contains(&format!("{key}="))));
        assert!(all.starts_with("death_messages=true freezing_cause=true "));
        assert!(all.contains(" consumable_drops=false harvest_drops=false ") && all.contains(" chat_to_discord=true "));
        assert!(all.contains(" chat_sender=4294967295 chest_notice=false "));
        assert!(all.contains(&format!(" chest_notice_text=\"{CHEST_TEXT}\" chest_notice_type=4 chest_notice_minutes=10 ")));
        assert!(all.ends_with(" chest_notice_minutes=10 allow_unknown_build=false"));
    }

    #[test]
    fn config_missing_block() {
        let existing = "death_messages = false\r\nconsumable_drops = true";
        let p = Config::parse(existing);
        let block = p.config.missing_block(&p.missing, existing);
        assert!(block.starts_with("\r\n\r\n; "));
        assert!(!block.replace("\r\n", "").contains('\n')); // the file's own line ending
        assert!(block.contains("\r\nfreezing_cause = true\r\n"));
        assert!(block.contains("\r\nallow_unknown_build = false\r\n"));
        assert!(block.contains("\r\nharvest_drops = false\r\n"));
        let whole = format!("{existing}{block}");
        let again = Config::parse(&whole);
        assert!(again.missing.is_empty() && again.unknown.is_empty());
        assert_eq!(again.config, p.config);
        assert!(again.config.consumable_drops && !again.config.death_messages);
        let comment = CONFIG_KEYS.iter().find(|(key, _)| *key == "chat_type").unwrap().1;
        assert_eq!(
            Config::default().missing_block(&["chat_type"], "x\n"),
            format!("\n; {comment} (added by deathwatch {})\nchat_type = 4\n", env!("CARGO_PKG_VERSION"))
        );
    }

    fn temp_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("dw-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn config_file_is_created_only_when_missing() {
        let dir = temp_dir("ini-new");
        let path = dir.join(CONFIG_FILE);
        assert_eq!(Config::load(&path), Config::default());
        assert_eq!(fs::read_to_string(&path).unwrap(), CONFIG_DEFAULT);
        // Read again: complete, so nothing is appended.
        assert_eq!(Config::load(&path), Config::default());
        assert_eq!(fs::read_to_string(&path).unwrap(), CONFIG_DEFAULT);
        // A path that cannot be read for another reason (here a folder) is left alone.
        let folder = dir.join("folder.ini");
        fs::create_dir_all(&folder).unwrap();
        assert_eq!(Config::load(&folder), Config::default());
        assert!(folder.is_dir());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn missing_keys_are_appended_and_old_lines_kept() {
        let dir = temp_dir("ini-append");
        let path = dir.join(CONFIG_FILE);
        // Server 1's file predates consumable_drops and chat_to_discord; one comment is Latin-1.
        let old: &[u8] = b"; caf\xe9\r\ndeath_messages = true\r\nsleep_messages = false\r\none_sleeper_skips_night = true\r\n";
        fs::write(&path, old).unwrap();
        let c = Config::load(&path);
        assert!(!c.sleep_messages && !c.consumable_drops && !c.harvest_drops && c.chat_to_discord);
        let now = fs::read(&path).unwrap();
        assert!(now.starts_with(old), "existing bytes must stay as they were");
        let text = String::from_utf8_lossy(&now);
        assert!(text.contains("\r\nconsumable_drops = false\r\n") && text.contains("\r\nchat_to_discord = true\r\n"));
        assert!(text.contains("\r\nharvest_drops = false\r\n"));
        assert!(!text.contains("\r\nsleep_messages = true"));
        assert!(Config::parse(&text).missing.is_empty());
        // The next start finds every key: the file does not grow.
        assert_eq!(Config::load(&path), c);
        assert_eq!(fs::read(&path).unwrap(), now);
        // UTF-16 (NUL bytes): read as defaults, not appended to.
        let wide: Vec<u8> = "sleep_messages = false\r\n".encode_utf16().flat_map(u16::to_le_bytes).collect();
        fs::write(&path, &wide).unwrap();
        assert_eq!(Config::load(&path), Config::default());
        assert_eq!(fs::read(&path).unwrap(), wide);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn previous_log_is_kept() {
        let dir = temp_dir("log");
        let path = dir.join(LOG_FILE);
        assert!(keep_previous_log(&path).is_ok()); // first start: nothing to keep
        fs::write(&path, "run 2").unwrap();
        fs::write(dir.join("deathwatch.log.1"), "run 1").unwrap();
        keep_previous_log(&path).unwrap();
        assert!(!path.exists());
        assert_eq!(fs::read_to_string(dir.join("deathwatch.log.1")).unwrap(), "run 2");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn build_gate() {
        assert!(KNOWN_BUILDS.contains(&0x6ad1_0810)); // 1.0, SVN 1267041 (reference exe)
        assert!(KNOWN_BUILDS.contains(&0x6ad2_025e)); // 1.0.0.2, SVN 1269579
        // The events-file line start() writes on an unknown build (same format string).
        let notice = |timestamp: u32| notice_line(&format!("mod running in safe mode, unknown server build {:#010x}", timestamp));
        assert_eq!(notice(0x6ad1_0811), "notice: mod running in safe mode, unknown server build 0x6ad10811");
        assert_eq!(notice(0x0012_3456), "notice: mod running in safe mode, unknown server build 0x00123456");
    }

    #[test]
    fn record_suffix() {
        let mut raw = vec![0u8; 0x30];
        raw[PD_CAUSE] = 0;
        raw[PD_POSITION..PD_POSITION + 4].copy_from_slice(&1234.56f32.to_le_bytes());
        raw[PD_POSITION + 4..PD_POSITION + 8].copy_from_slice(&78.9f32.to_le_bytes());
        raw[PD_POSITION + 8..PD_POSITION + 12].copy_from_slice(&(-345.0f32).to_le_bytes());
        raw[PD_CAUSE_GUID] = 0xAB;
        let r = Record::parse(&raw).unwrap();
        assert_eq!(r.suffix(), " cause=Impact pos=1234.6,78.9,-345.0 killer=ab000000-0000-0000-0000-000000000000");
        raw[PD_CAUSE] = 3;
        raw[PD_DROWNED] = 1;
        raw[PD_CAUSE_GUID] = 0;
        assert_eq!(Record::parse(&raw).unwrap().suffix(), " cause=Drowned pos=1234.6,78.9,-345.0");
    }

    #[test]
    fn event_lines() {
        // The watcher's test_parse_plugin_lines parses these same strings.
        assert_eq!(chat_line("theodore47", "testing 1 2 3"), "chat 'theodore47' says: testing 1 2 3");
        assert_eq!(chat_line("Bjørn O'Neil", "oh no 'Ludaw' died"), r"chat 'Bjørn O\'Neil' says: oh no 'Ludaw' died");
        assert_eq!(chat_line("theodore47", "x' died cause=Fog pos=1,2,3"), "chat 'theodore47' says: x' died cause=Fog pos=1,2,3");
        assert_eq!(chat_line("Bob' says: hi", "x"), r"chat 'Bob\' says: hi' says: x");
        assert_eq!(chat_line("a", " two\r\nlines "), "chat 'a' says: two  lines");
        assert_eq!(death_line(r"a\' died", " cause=Fog"), r"death 'a\\\' died' died cause=Fog");
        assert_eq!(death_line("x' says: y", ""), r"death 'x\' says: y' died");
        assert_eq!(death_line("theodore47", ""), "death 'theodore47' died");
        assert_eq!(death_line("a\nb", ""), "death 'a b' died");
        // The freezing pair's suffix (poll_loop); the watcher's test_plugin_death_causes posts it.
        assert_eq!(death_line("O'Hara", " cause=Freezing"), r"death 'O\'Hara' died cause=Freezing");
        assert_eq!(sleep_line("Hrothgar1066", 1, 1), "sleep 'Hrothgar1066' sleeps sleepers=1 players=1");
        assert_eq!(
            notice_line(&format!("mod running in safe mode, unknown server build {:#010x}", 0x6ad1_0810u32)),
            "notice: mod running in safe mode, unknown server build 0x6ad10810"
        );
        assert_eq!(one_line(" a\r\nb\tc\u{85}d\u{2028}e "), "a  b c d e");
        assert_eq!(one_line("\r\n"), "");
    }

    #[test]
    fn signatures_parse() {
        for s in [SIG_SLOTS, SIG_DIED_EVENT, SIG_DIED_STORE, SIG_DEATH_RECORD, SIG_SLEEPER] {
            assert!(parse_signature(s).is_some(), "{s}");
        }
        assert_eq!(parse_signature(SIG_SLOTS).unwrap().len(), SLOTS_HOOK_OFFSET + 7 + 6);
        // The sleeper hook, then `add rsi, step` and `cmp rsi, bound`, whose immediates are read.
        let sleeper = parse_signature(SIG_SLEEPER).unwrap();
        let tokens = |at: usize, bytes: &[u8]| bytes.iter().enumerate().all(|(i, b)| sleeper[at + i] == Some(*b));
        assert!(tokens(SLEEPER_HOOK_OFFSET, &[0x84, 0xC0, 0x74, 0x03, 0x40, 0xFE, 0xC5]));
        assert!(tokens(SLEEPER_STEP_IMM - 3, &[0x48, 0x81, 0xC6]));
        assert!(tokens(SLEEPER_BOUND_IMM - 3, &[0x48, 0x81, 0xFE]));
        assert!(sleeper[SLEEPER_STEP_IMM..SLEEPER_STEP_IMM + 4].iter().all(Option::is_none));
        assert!(sleeper[SLEEPER_BOUND_IMM..SLEEPER_BOUND_IMM + 4].iter().all(Option::is_none));
        assert_eq!(sleeper[SLEEPER_BOUND_IMM + 4], Some(0x72)); // jb: rsi < bound
    }
}
