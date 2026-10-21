//! Chat (server 1.0, SVN 1267041): player chat to the events file, and lines from
//! `servermods/chat_outbox.txt` into every player's chat.
//!
//! **Chat to Discord** (`chat_to_discord`). The server's receive handler (exe+0x7b2190) takes each
//! `ChatMessageClientMessage` a client sends, looks up the sender's account and appends the message
//! once to the server's chat list with `call enqueue` (exe+0x9085d0) at exe+0x7b2cb9. A store-only
//! cave on the two instructions right before that call (exe+0x7b2cb1, `cave::chat_in_cave`) copies
//! type, sender handle, account and text into a ring in our page; the poll thread drains it
//! (`take_chat_in`). Once per message, whatever the number of players, and never our own broadcast
//! lines (they do not pass through the receive handler). The hook must stay on that call site: a
//! hook at enqueue's entry would also see join/leave notices and the game's own lines.
//!
//! **Broadcast** (`chat_broadcast`). The chat relay (exe+0x7aeed0) runs every tick on the server
//! thread and sends every chat message once per connection: for each of the 17 connection entries
//! at `server+0x16A0` (handle u32, bit 0 of +4 = active) it allocates a buffer on that connection's
//! channel, serialises a `ChatMessageServerMessage` into it and commits it. A cave at the relay's
//! first instruction calls `chat_tick`, which does the same for our line on every connection that
//! has been active for `GRACE`, one connection at a time. A refused buffer (status 2, congestion)
//! is retried on later ticks for that connection only; any other failure loses the line for that
//! connection only. `playerHandle` is a value no player has, so no line is shown as the player's
//! own. A line can also go to one connection only (the chest notice, chest.rs) and carry its own
//! `type`.
//!
//! **What the client shows (game client 1.0.0.2, found 2026-10-18).** The client stores every
//! ChatMessageServerMessage (enshrouded.exe+0x840a90), but its chat window (+0x8717c0) makes a line
//! only when the message's accountIdHash is a player in its session list (all 16 slots, self
//! included) who is not blocked and whose communication is allowed (record +0x250 == 0, +0x252 != 0;
//! the same check again at +0xd77970). Account 0 matches nobody: such a line is dropped without a
//! trace. So every line carries its recipient's own accountIdHash (player slot +0x48 of the slot
//! whose connection +0x4 is the recipient), found on the server thread right before sending.
//! Up to 0.3.0 the account was 0, which is why no broadcast line has been seen since the hotfix.
//!
//! `type` (`chat_type`): the server itself sends 0 for player chat, 1 from
//! `player_control_not_predicted` (exe+0xcabe0) and 4 for the join and leave notices (exe+0x7b458d,
//! exe+0x7a23b3: empty text, a loca tag, the player's handle). The client draws type 0 as
//! `<name>: text` with the name of the account's player (here: the recipient's own name), and type
//! 4 with locaTag1 = 0 as the text alone in the notice style (+0xb62287). With the client's text
//! chat off it keeps type 4 only (+0x8730ca). Hence 4 by default; 0 stays allowed.
//!
//! `ChatMessageServerMessage` (0x420 bytes): type @0, string length @4 + text @8 (max 0x400),
//! locaTag1 @0x408, locaTag2 @0x40C, playerHandle @0x410, accountIdHash @0x418.

use std::{
    collections::{HashMap, VecDeque},
    sync::{
        Mutex, MutexGuard, OnceLock, TryLockError,
        atomic::{AtomicU32, AtomicU64, Ordering, fence},
    },
    time::{Duration, Instant},
};

use crate::cave;
use crate::memory::{Image, matches, parse_signature, read, safe_read};

// --- chat to Discord ----------------------------------------------------------------------------

/// The receive handler's chat path up to `call enqueue` (1.0 exe+0x7b2c75..0x7b2cb9):
/// `movzx r8d,byte [rbp+type]; lea rax,[rbp+18h]; mov rdx,[r13+60h]; lea r9,[rbp-8] (&{text,len});
/// mov [rsp+40h],rax; lea rcx,[rbp+8]; mov eax,[rbp+handle]; mov [rsp+38h],rbx (account);
/// mov [rsp+30h],eax (handle); mov eax,[rbp+tag2]; mov [rsp+28h],eax; mov eax,[rbp+tag1];
/// mov [rsp+20h],eax; mov byte [rbp+20h],0; call enqueue`. It pins every register the cave reads.
const SIG_CHAT_IN: &str = "44 0F B6 85 ?? ?? ?? ?? 48 8D 45 18 49 8B 55 60 4C 8D 4D F8 48 89 44 24 40 48 8D 4D 08 8B 85 ?? ?? ?? ?? 48 89 5C 24 38 89 44 24 30 8B 85 ?? ?? ?? ?? 89 44 24 28 8B 85 ?? ?? ?? ?? 89 44 24 20 C6 45 20 00 E8";
/// The hook: `mov [rsp+20h],eax; mov byte [rbp+20h],0`, 8 bytes, right before the call.
pub const CHAT_IN_HOOK: usize = 60;
const CHAT_IN_CALL: usize = 68;
/// enqueue(&status, list, type r8b, &{text, len} r9, tag1, tag2, handle, account, &{u64, bool})
/// (1.0 exe+0x9085d0): `mov rax,[r9+8]; ...; movzx r12d,r8b; ...; cmp rax,400h`.
const SIG_ENQUEUE: &str = "40 55 56 41 54 41 55 41 57 48 83 EC 30 49 8B 41 08 33 ED 4D 8B F9 45 0F B6 E0 48 8B F2 4C 8B E9 48 3D 00 04 00 00";

/// The chat-in hook site (the 8 bytes before `call enqueue`), or why there is none.
pub fn resolve_chat_in(image: &Image) -> Result<usize, String> {
    let found = image.find_all(SIG_CHAT_IN);
    let [at] = found[..] else { return Err(format!("chat-in signature matched {} times", found.len())) };
    let target = call_target(at + CHAT_IN_CALL);
    let pattern = parse_signature(SIG_ENQUEUE).unwrap();
    if !image.is_code(target, pattern.len()) {
        return Err("chat-in call target is outside the exe's code".into());
    }
    let bytes = unsafe { std::slice::from_raw_parts(target as *const u8, pattern.len()) };
    if !matches(&pattern, bytes) {
        return Err(format!("chat-in call goes to exe+{:#x}, not the chat enqueue", image.rva(target)));
    }
    Ok(at + CHAT_IN_HOOK)
}

/// A chat message a player sent, as the receive handler queued it.
#[derive(Debug, PartialEq)]
pub struct ChatIn {
    pub chat_type: u8,
    pub handle: u32,
    pub account: u64,
    pub text: Vec<u8>,
    /// Longer than 0x400 bytes: the game drops it and the cave copied nothing.
    pub rejected: bool,
}

fn seq(slot: usize) -> &'static AtomicU32 {
    unsafe { AtomicU32::from_ptr(slot as *mut u32) }
}

/// Messages the cave published since `tail` (a counter the caller keeps), and how many were
/// lost to the ring wrapping around. Never blocks; a slot still being written is left for later.
pub fn take_chat_in(page: usize, tail: &mut u32) -> (Vec<ChatIn>, u32) {
    let head = seq(page + cave::CHAT_IN_HEAD).load(Ordering::Acquire);
    let mut lost = 0u32;
    let behind = head.wrapping_sub(*tail);
    if behind as usize > cave::CHAT_IN_LEN {
        lost += behind - cave::CHAT_IN_LEN as u32;
        *tail = head.wrapping_sub(cave::CHAT_IN_LEN as u32);
    }
    let mut out = Vec::new();
    while *tail != head {
        let slot = page + cave::CHAT_IN_RING + (*tail as usize % cave::CHAT_IN_LEN) * cave::CHAT_IN_SLOT;
        let want = tail.wrapping_add(1);
        let s = seq(slot + cave::CI_SEQ).load(Ordering::Acquire);
        if s != want {
            if (s.wrapping_sub(want) as i32) > 0 {
                // a newer message already took this slot
                lost += 1;
                *tail = want;
                continue;
            }
            break; // claimed but not published yet: next poll
        }
        let v8 = |o: usize| unsafe { std::ptr::read_volatile((slot + o) as *const u8) };
        let v32 = |o: usize| unsafe { std::ptr::read_volatile((slot + o) as *const u32) };
        let v64 = |o: usize| unsafe { std::ptr::read_volatile((slot + o) as *const u64) };
        let len = (v32(cave::CI_LEN) as usize).min(cave::CHAT_IN_TEXT_MAX);
        let message = ChatIn {
            chat_type: v8(cave::CI_TYPE),
            handle: v32(cave::CI_HANDLE),
            account: v64(cave::CI_ACCOUNT),
            text: (0..len).map(|i| v8(cave::CI_TEXT + i)).collect(),
            rejected: v8(cave::CI_REJECTED) != 0,
        };
        fence(Ordering::Acquire);
        *tail = want;
        if seq(slot + cave::CI_SEQ).load(Ordering::Relaxed) != want {
            lost += 1; // overwritten while we copied it
            continue;
        }
        out.push(message);
    }
    (out, lost)
}

// --- broadcast ----------------------------------------------------------------------------------

/// Relay entry: `mov [rsp+20h],rbx; push ...; lea rbp,..; sub rsp,..; mov rsi,rcx; xor edi,edi;
/// mov ecx,edi; mov r13d,<entries>; lea r14,[rsi+<table>]`
const SIG_RELAY: &str = "48 89 5C 24 20 55 56 57 41 54 41 55 41 56 41 57 48 8D AC 24 ?? ?? ?? ?? 48 81 EC ?? ?? ?? ?? 48 8B F1 33 FF 8B CF 41 BD ?? 00 00 00 4C 8D B6 ?? ?? ?? ??";
const RELAY_ENTRIES_IMM: usize = 40;
const RELAY_TABLE_IMM: usize = 47;
const RELAY_LEN: usize = 0x400; // the pieces below are searched only inside the relay

/// `mov r8,[r8+<send>]; movups [rbp-48h],xmm0; movsd [rbp-38h],xmm1; call alloc` (1.0)
const SIG_ALLOC: &str = "4D 8B 80 ?? ?? ?? ?? 0F 11 45 B8 F2 0F 11 4D C8 E8";
const ALLOC_SEND_IMM: usize = 3;
const ALLOC_CALL: usize = 16;
/// `mov eax,[r14]; mov edx,eax; mov r10,[rsi+<holder>]`: the session holder offset.
const SIG_HOLDER: &str = "41 8B 06 8B D0 4C 8B 56 ??";
const HOLDER_IMM: usize = 8;
/// `add r8,[r10+28h]; cmp [r8],eax; jne; test r8,r8; je; mov r8,[r8+10h]`
const SIG_CHANNEL: &str = "4D 03 42 28 41 39 00 75 ?? 4D 85 C0 74 ?? 4D 8B 40 10";
/// `lea r8,[rip+descriptor]; mov eax,[rbx+0Ch]; lea rdx,[rbp-30h]`
const SIG_DESCRIPTOR: &str = "4C 8D 05 ?? ?? ?? ?? 8B 43 0C 48 8D 55 D0";
/// `mov [rsp+30h],rax; call serialize; movzx edx,byte [rsp+48h]`
const SIG_SERIALIZE: &str = "48 89 44 24 30 E8 ?? ?? ?? ?? 0F B6 54 24 48";
/// `mov rcx,[rcx]; call commit; mov r9d,[rsp+70h]` (1.0)
const SIG_COMMIT: &str = "48 8B 09 E8 ?? ?? ?? ?? 44 8B 4C 24 70";
/// commit(session, result+8) reads the used byte count as `mov r8d,[rdx+18h]`: result+0x20.
const COMMIT_READS_USED: &str = "44 8B 42 18";
const RESULT_USED: usize = 0x20;
/// `mov rcx,[rcx]; call discard; mov rcx,[rsp+20h]; test rcx,rcx; je`
const SIG_DISCARD: &str = "48 8B 09 E8 ?? ?? ?? ?? 48 8B 4C 24 20 48 85 C9 74";
const CHANNEL_TABLE: usize = 0x28;
const CHANNEL_ENTRY_SIZE: usize = 32;
const CHANNEL_OBJECT: usize = 0x10;

const MSG_SIZE: usize = 0x420;
const MSG_TEXT_MAX: usize = 0x400;
const MSG_LEN: usize = 0x04;
const MSG_TEXT: usize = 0x08;
const MSG_HANDLE: usize = 0x410;
const MSG_ACCOUNT: usize = 0x418;

/// Longest line we send, in bytes. The chat channel's own size limit is negotiated at run time
/// and unknown; 0x1C0 keeps the request (text + 0x40) far below any plausible limit. Longer
/// outbox lines are split.
pub const LINE_MAX: usize = 0x1C0;
/// A connection must have been active this long before it gets a line (its chat may not be up yet).
const GRACE: Duration = Duration::from_secs(10);
/// A line waits at most this long for a player to send it to.
pub const EXPIRE: Duration = Duration::from_secs(300);
/// How long a congested connection (alloc status 2) is retried before the line is given up for it.
/// The game itself retries its own chat on later ticks without a limit.
const BUSY_FOR: Duration = Duration::from_secs(10);
/// While nobody can receive the front line, look again this often.
const NOBODY_RECHECK: Duration = Duration::from_millis(500);
pub const QUEUE_MAX: usize = 32;

pub struct ChatApi {
    pub relay: usize,
    table: usize,
    entries: usize,
    holder: usize,
    send: usize,
    alloc: usize,
    serialize: usize,
    commit: usize,
    discard: usize,
    descriptor: usize,
    pub chat_type: u8,
    pub sender: u32,
}

static API: OnceLock<ChatApi> = OnceLock::new();
pub static TICKS: AtomicU64 = AtomicU64::new(0);

fn find_in(start: usize, len: usize, sig: &str) -> Option<usize> {
    let pattern = parse_signature(sig)?;
    let bytes = unsafe { std::slice::from_raw_parts(start as *const u8, len + pattern.len()) };
    (0..len).find(|&i| matches(&pattern, &bytes[i..])).map(|i| start + i)
}

fn call_target(at: usize) -> usize {
    let rel = unsafe { read::<i32>(at + 1) } as isize;
    (at as isize + 5 + rel) as usize
}

/// The `type` values a line may carry: 0 (plain chat, shown as `<recipient's name>: text`) and 4
/// (the kind the game's join/leave notices use, shown as the text alone).
pub fn chat_type_allowed(chat_type: u8) -> bool {
    matches!(chat_type, 0 | 4)
}

/// Where the player slots are (server object + base, stride), set once the slot loop is known.
static SLOTS: OnceLock<(usize, usize)> = OnceLock::new();

pub fn set_slots(base: usize, stride: usize) {
    let _ = SLOTS.set((base, stride));
}

/// The accountIdHash of the player whose slot holds connection `connection` (slot +0x4), 0 when
/// no slot does. `table` is the whole slot table (PLAYER_SLOTS slots of `stride` bytes).
fn account_for(table: &[u8], stride: usize, connection: u32) -> u64 {
    if connection == 0 || stride < crate::deaths::SLOT_SCAN {
        return 0;
    }
    let u32_at = |s: &[u8], o: usize| u32::from_le_bytes(s[o..o + 4].try_into().unwrap());
    (0..crate::PLAYER_SLOTS)
        .filter_map(|i| table.get(i * stride..i * stride + crate::deaths::SLOT_SCAN))
        .find(|s| u32_at(s, crate::SLOT_HANDLE) != 0 && u32_at(s, crate::SLOT_CONNECTION) == connection)
        .map_or(0, |s| u64::from_le_bytes(s[crate::deaths::SLOT_ACCOUNT..crate::deaths::SLOT_ACCOUNT + 8].try_into().unwrap()))
}

/// A playerHandle no player can have. It is a slot handle: the low 6 bits are the slot index
/// (16 slots), the generation is above them. Bit 5 set puts the index at 32..63, past every slot,
/// so the line is attributed to nobody (4294967295 by default).
pub fn sender_is_safe(sender: u32) -> bool {
    sender & 0x20 != 0
}

/// The broadcast pieces inside the relay, or why it cannot be used.
pub fn resolve(image: &Image, chat_type: u8, sender: u32) -> Result<&'static ChatApi, String> {
    if !chat_type_allowed(chat_type) {
        return Err(format!("chat_type {chat_type} is not allowed; 0 (plain chat) or 4 (EXPERIMENTAL)"));
    }
    if !sender_is_safe(sender) {
        return Err(format!("chat_sender {sender} could be a real player's handle"));
    }
    let found = image.find_all(SIG_RELAY);
    let [relay] = found[..] else { return Err(format!("chat relay signature matched {} times", found.len())) };
    let inside = |sig: &str, what: &str| find_in(relay, RELAY_LEN, sig).ok_or(format!("{what} not found in the relay"));
    find_in(relay, RELAY_LEN, SIG_CHANNEL).ok_or("channel lookup not found in the relay")?;

    let alloc_site = inside(SIG_ALLOC, "alloc call")?;
    let holder_site = inside(SIG_HOLDER, "session holder")?;
    let descriptor_at = inside(SIG_DESCRIPTOR, "descriptor")?;
    let serialize_at = inside(SIG_SERIALIZE, "serialize call")? + 5;
    let commit_at = inside(SIG_COMMIT, "commit call")? + 3;
    let discard_at = inside(SIG_DISCARD, "discard call")? + 3;

    let disp = unsafe { read::<i32>(descriptor_at + 3) } as isize;
    let api = ChatApi {
        relay,
        table: unsafe { read::<u32>(relay + RELAY_TABLE_IMM) } as usize,
        entries: unsafe { read::<u32>(relay + RELAY_ENTRIES_IMM) } as usize,
        holder: unsafe { read::<u8>(holder_site + HOLDER_IMM) } as usize,
        send: unsafe { read::<u32>(alloc_site + ALLOC_SEND_IMM) } as usize,
        alloc: call_target(alloc_site + ALLOC_CALL),
        serialize: call_target(serialize_at),
        commit: call_target(commit_at),
        discard: call_target(discard_at),
        descriptor: (descriptor_at as isize + 7 + disp) as usize,
        chat_type,
        sender,
    };
    if api.entries == 0 || api.entries > 64 {
        return Err(format!("odd channel entry count {}", api.entries));
    }
    for (what, at) in [("alloc", api.alloc), ("serialize", api.serialize), ("commit", api.commit), ("discard", api.discard)] {
        if !image.is_code(at, 0x20) {
            return Err(format!("{what} call target is outside the exe's code"));
        }
    }
    // The descriptor's first field points at the name "ChatMessageServerMessage".
    let name_ptr = safe_read(api.descriptor, 16).map(|b| usize::from_le_bytes(b[0..8].try_into().unwrap())).unwrap_or(0);
    let name = safe_read(name_ptr, 24).unwrap_or_default();
    if name != b"ChatMessageServerMessage" {
        return Err("descriptor does not name ChatMessageServerMessage".into());
    }
    if unsafe { read::<usize>(api.descriptor + 8) } != MSG_SIZE {
        return Err(format!("ChatMessageServerMessage size is not {MSG_SIZE:#x}"));
    }
    if find_in(api.commit, 0x20, COMMIT_READS_USED).is_none() {
        return Err("commit does not read the used size where expected".into());
    }
    let _ = API.set(api);
    Ok(API.get().unwrap())
}

pub fn describe(api: &ChatApi, image: &Image) -> String {
    format!(
        "chat relay exe+{:#x}: {} entries at server+{:#x}, session holder +{:#x}, channel send +{:#x}; alloc exe+{:#x}, serialize exe+{:#x}, commit exe+{:#x}, discard exe+{:#x}, descriptor exe+{:#x}; type {}, sender {:#x}",
        image.rva(api.relay),
        api.entries,
        api.table,
        api.holder,
        api.send,
        image.rva(api.alloc),
        image.rva(api.serialize),
        image.rva(api.commit),
        image.rva(api.discard),
        image.rva(api.descriptor),
        api.chat_type,
        api.sender
    )
}

/// A line on its way to the players.
struct Line {
    text: String,
    born: Instant,
    /// Only this connection (full handle) gets it; None: every connection active for GRACE.
    to: Option<u32>,
    /// `type` of this line; None: the configured `chat_type`.
    chat_type: Option<u8>,
    /// Connections (full handles) it goes to, fixed at the first attempt.
    recipients: Option<Vec<u32>>,
    sent: Vec<u32>,
    failed: Vec<(u32, u64)>,
    left: Vec<u32>,
    /// Connections it was sent to without an account (no slot had them): the game hides it there.
    no_account: Vec<u32>,
    /// When each congested connection first refused this line.
    busy_since: Vec<(u32, Instant)>,
    not_before: Option<Instant>,
}

impl Line {
    fn new(text: String, born: Instant) -> Line {
        Line {
            text,
            born,
            to: None,
            chat_type: None,
            recipients: None,
            sent: Vec::new(),
            failed: Vec::new(),
            left: Vec::new(),
            no_account: Vec::new(),
            busy_since: Vec::new(),
            not_before: None,
        }
    }

    fn settled(&self, handle: u32) -> bool {
        self.sent.contains(&handle) || self.left.contains(&handle) || self.failed.iter().any(|&(h, _)| h == handle)
    }

    fn summary(&self) -> String {
        let total = self.recipients.as_ref().map_or(0, Vec::len);
        let mut s = format!("chat line sent to {} of {total} connection(s)", self.sent.len());
        if !self.left.is_empty() {
            s += &format!(", {} left first", self.left.len());
        }
        for (h, code) in &self.failed {
            s += &format!(", connection {h:#x} failed (code {code:#x})");
        }
        if !self.no_account.is_empty() {
            s += &format!(", {} without an account (the game hides it there)", self.no_account.len());
        }
        s + &format!(": {}", self.text)
    }
}

static QUEUE: Mutex<VecDeque<Line>> = Mutex::new(VecDeque::new());
/// When each connection (full handle) was first seen active; only the server thread uses it.
static ACTIVE_SINCE: Mutex<Option<HashMap<u32, Instant>>> = Mutex::new(None);
/// Things for the poll thread to log (the server thread never writes the log itself).
static NOTES: Mutex<VecDeque<String>> = Mutex::new(VecDeque::new());

fn queue() -> MutexGuard<'static, VecDeque<Line>> {
    QUEUE.lock().unwrap_or_else(|e| e.into_inner())
}

/// From the server thread: never waits; a note that cannot be stored at once is dropped.
fn note(text: String) {
    if let Ok(mut n) = NOTES.try_lock() {
        if n.len() < 64 {
            n.push_back(text);
        }
    }
}

/// Lines for deathwatch.log since the last call.
pub fn take_notes() -> Vec<String> {
    NOTES.lock().unwrap_or_else(|e| e.into_inner()).drain(..).collect()
}

#[derive(Debug, PartialEq)]
pub enum Said {
    /// Queued in this many parts; this many lines are waiting now.
    Queued { parts: usize, waiting: usize },
    /// The queue was full: this many parts were not queued.
    Full { dropped: usize },
    /// Nothing left after cleaning.
    Empty,
}

/// `text` on one line (control characters become spaces), trimmed, in parts of at most `max`
/// bytes, cut at a space when there is one in the second half of a part.
pub fn split_line(text: &str, max: usize) -> Vec<String> {
    let clean: String = text.chars().map(|c| if c.is_control() || c == '\u{2028}' || c == '\u{2029}' { ' ' } else { c }).collect();
    let mut rest = clean.trim();
    let mut parts = Vec::new();
    while !rest.is_empty() {
        if rest.len() <= max {
            parts.push(rest.to_string());
            break;
        }
        let mut cut = max;
        while !rest.is_char_boundary(cut) {
            cut -= 1;
        }
        if let Some(space) = rest[..cut].rfind(' ').filter(|&s| s >= max / 2) {
            cut = space;
        }
        parts.push(rest[..cut].trim_end().to_string());
        rest = rest[cut..].trim_start();
    }
    parts
}

/// Queue a line for the players, `prefix` (ASCII, e.g. "[Server] ") before every part; `age` is
/// how long ago it was written.
pub fn say(prefix: &str, text: &str, age: Duration) -> Said {
    queue_line(prefix, text, age, None, None)
}

/// Queue a line for one connection only (full handle, as in the connection table and player slot
/// +0x4), with its own `type` (see `chat_type_allowed`).
pub fn say_to(connection: u32, chat_type: u8, prefix: &str, text: &str) -> Said {
    queue_line(prefix, text, Duration::ZERO, Some(connection), Some(chat_type))
}

fn queue_line(prefix: &str, text: &str, age: Duration, to: Option<u32>, chat_type: Option<u8>) -> Said {
    let parts: Vec<String> = split_line(text, LINE_MAX - prefix.len()).into_iter().map(|p| format!("{prefix}{p}")).collect();
    if parts.is_empty() {
        return Said::Empty;
    }
    let born = Instant::now().checked_sub(age).unwrap_or_else(Instant::now);
    let mut q = queue();
    let room = QUEUE_MAX.saturating_sub(q.len());
    if room < parts.len() {
        return Said::Full { dropped: parts.len() };
    }
    let count = parts.len();
    for p in parts {
        q.push_back(Line { to, chat_type, ..Line::new(p, born) });
    }
    Said::Queued { parts: count, waiting: q.len() }
}

/// Drops the lines that waited longer than EXPIRE without anyone to send them to.
pub fn expire() -> Vec<String> {
    let mut gone = Vec::new();
    queue().retain(|l| {
        let keep = l.recipients.is_some() || l.born.elapsed() < EXPIRE;
        if !keep {
            gone.push(l.text.clone());
        }
        keep
    });
    gone
}

type Fn4 = unsafe extern "C" fn(usize, usize, usize, usize) -> usize;
type Fn3 = unsafe extern "C" fn(usize, usize, usize) -> usize;
type Fn2 = unsafe extern "C" fn(usize, usize) -> usize;

fn u32_at(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(b[at..at + 4].try_into().unwrap())
}
fn usize_at(b: &[u8], at: usize) -> usize {
    u64::from_le_bytes(b[at..at + 8].try_into().unwrap()) as usize
}

/// Full handles of the active connection entries (handle != 0, bit 0 of +4 set), as the relay sees them.
fn active_handles(table: &[u8]) -> Vec<u32> {
    table.chunks_exact(8).filter(|e| u32_at(e, 0) != 0 && e[4] & 1 != 0).map(|e| u32_at(e, 0)).collect()
}

/// What to do with the front line this tick (the pure part of `chat_tick`, for tests).
#[derive(Debug, PartialEq)]
enum Step {
    /// Nobody to send it to yet.
    Wait,
    /// Send to these connections now.
    Send(Vec<u32>),
    /// Every recipient is settled: the line is done.
    Done,
}

fn plan(line: &mut Line, active: &[u32], since: &HashMap<u32, Instant>, now: Instant) -> Step {
    if line.recipients.is_none() && let Some(to) = line.to {
        // One player's line: it goes now or never (a connection gone already counts as left).
        line.recipients = Some(vec![to]);
    }
    if line.recipients.is_none() {
        let ready: Vec<u32> = active.iter().copied().filter(|h| since.get(h).is_some_and(|t| now.duration_since(*t) >= GRACE)).collect();
        if ready.is_empty() {
            return Step::Wait;
        }
        line.recipients = Some(ready);
    }
    let recipients = line.recipients.clone().unwrap_or_default();
    for &h in &recipients {
        if !line.settled(h) && !active.contains(&h) {
            line.left.push(h);
        }
    }
    let todo: Vec<u32> = recipients.into_iter().filter(|&h| !line.settled(h)).collect();
    if todo.is_empty() { Step::Done } else { Step::Send(todo) }
}

/// Alloc status 2: the connection's channel is congested this tick.
const BUSY: u64 = 0x102;

/// Called by the cave at the start of the relay, on the server thread, every tick.
/// Never waits for a lock and never unwinds into game code.
pub extern "C" fn chat_tick(server: usize) {
    TICKS.fetch_add(1, Ordering::Relaxed);
    let _ = std::panic::catch_unwind(|| {
        let Some(api) = API.get() else { return };
        let Some(table) = safe_read(server + api.table, api.entries * 8) else { return };
        let active = active_handles(&table);
        let now = Instant::now();
        let Ok(mut since) = ACTIVE_SINCE.try_lock() else { return };
        let since = since.get_or_insert_with(HashMap::new);
        since.retain(|h, _| active.contains(h));
        for &h in &active {
            since.entry(h).or_insert(now);
        }
        let mut q = match QUEUE.try_lock() {
            Ok(q) => q,
            Err(TryLockError::Poisoned(e)) => e.into_inner(),
            Err(TryLockError::WouldBlock) => return,
        };
        let Some(line) = q.front_mut() else { return };
        if line.not_before.is_some_and(|t| now < t) {
            return;
        }
        match plan(line, &active, since, now) {
            Step::Wait => line.not_before = Some(now + NOBODY_RECHECK),
            Step::Send(todo) => {
                // Each line carries its recipient's own account, or the client drops it.
                let slots = SLOTS.get().and_then(|&(base, stride)| Some((safe_read(server + base, crate::PLAYER_SLOTS * stride)?, stride)));
                for h in todo {
                    let chat_type = line.chat_type.unwrap_or(api.chat_type);
                    let account = slots.as_ref().map_or(0, |(table, stride)| account_for(table, *stride, h));
                    match unsafe { send_to(api, server, h, chat_type, account, &line.text) } {
                        Ok(()) => {
                            line.sent.push(h);
                            if account == 0 {
                                line.no_account.push(h);
                            }
                        }
                        Err(BUSY) => {
                            let since = match line.busy_since.iter().find(|(b, _)| *b == h) {
                                Some(&(_, t)) => t,
                                None => {
                                    line.busy_since.push((h, now));
                                    now
                                }
                            };
                            if now.duration_since(since) >= BUSY_FOR {
                                line.failed.push((h, BUSY));
                            }
                        }
                        Err(code) => line.failed.push((h, code)),
                    }
                }
                if matches!(plan(line, &active, since, now), Step::Done) {
                    let done = q.pop_front().unwrap();
                    drop(q);
                    note(done.summary());
                }
            }
            Step::Done => {
                let done = q.pop_front().unwrap();
                drop(q);
                note(done.summary());
            }
        }
    });
}

/// Sends `text` on the channel of the connection with full handle `handle`, as the relay sends a
/// chat message: alloc, serialise, commit (discard if serialising fails).
unsafe fn send_to(api: &ChatApi, server: usize, handle: u32, chat_type: u8, account: u64, text: &str) -> Result<(), u64> {
    let holder = safe_read(server + api.holder, 8).map(|b| usize_at(&b, 0)).ok_or(2u64)?;
    let session = safe_read(holder, 8).map(|b| usize_at(&b, 0)).ok_or(3u64)?;
    let channels = safe_read(holder + CHANNEL_TABLE, 8).map(|b| usize_at(&b, 0)).ok_or(4u64)?;
    let entry = channels + (handle as usize & 0x7f) * CHANNEL_ENTRY_SIZE;
    let eb = safe_read(entry, CHANNEL_OBJECT + 8).ok_or(5u64)?;
    if u32_at(&eb, 0) != handle {
        return Err(1); // the connection has no channel entry (any more)
    }
    let object = usize_at(&eb, CHANNEL_OBJECT);
    let channel = safe_read(object + api.send, 8).map(|b| usize_at(&b, 0)).ok_or(5u64)?;
    if session == 0 || channel == 0 {
        return Err(1);
    }

    let bytes = text.as_bytes();
    if bytes.is_empty() || bytes.len() > LINE_MAX || !chat_type_allowed(chat_type) {
        return Err(7);
    }
    let mut msg = vec![0u8; MSG_SIZE];
    msg[0] = chat_type;
    msg[MSG_LEN..MSG_LEN + 4].copy_from_slice(&(bytes.len() as u32).to_le_bytes());
    msg[MSG_TEXT..MSG_TEXT + bytes.len()].copy_from_slice(bytes);
    msg[MSG_HANDLE..MSG_HANDLE + 4].copy_from_slice(&api.sender.to_le_bytes());
    msg[MSG_ACCOUNT..MSG_ACCOUNT + 8].copy_from_slice(&account.to_le_bytes());
    debug_assert!(bytes.len() <= MSG_TEXT_MAX);

    // alloc(&result, session, channel, &{size, size, true}); status byte 0 = ok, 2 = congested.
    let want = ((bytes.len() + 0x40) + 3) & !3;
    let mut request = [0u8; 24];
    request[0..8].copy_from_slice(&(want as u64).to_le_bytes());
    request[8..16].copy_from_slice(&(want as u64).to_le_bytes());
    request[16] = 1;
    let mut result = [0u64; 16]; // 0x80 bytes, 8-aligned
    let res = result.as_mut_ptr() as usize;
    unsafe { std::mem::transmute::<usize, Fn4>(api.alloc)(res, session, channel, request.as_ptr() as usize) };
    let status = unsafe { *(res as *const u8) };
    if status != 0 {
        return Err(0x100 | status as u64);
    }
    let data = unsafe { *((res + 0x28) as *const usize) };
    let capacity = unsafe { *((res + 0x30) as *const usize) };

    // serialize(&stream{0, data, bits, 0, 0, error}, &msg, descriptor)
    let mut stream = [0u64; 8];
    stream[1] = data as u64;
    stream[2] = (capacity * 8) as u64;
    let s = stream.as_mut_ptr() as usize;
    unsafe { std::mem::transmute::<usize, Fn3>(api.serialize)(s, msg.as_ptr() as usize, api.descriptor) };
    let failed = unsafe { *((s + 0x28) as *const u8) } != 0;
    if failed {
        unsafe { std::mem::transmute::<usize, Fn2>(api.discard)(session, res + 8) };
        return Err(6);
    }
    let bits = stream[3] as usize;
    let used = ((bits + 31) & !31) >> 3;
    unsafe { *((res + RESULT_USED) as *mut u32) = used as u32 };
    unsafe { std::mem::transmute::<usize, Fn2>(api.commit)(session, res + 8) };
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signatures_parse() {
        for sig in [SIG_CHAT_IN, SIG_ENQUEUE, SIG_RELAY, SIG_ALLOC, SIG_HOLDER, SIG_CHANNEL, SIG_DESCRIPTOR, SIG_SERIALIZE, SIG_COMMIT, SIG_DISCARD] {
            assert!(parse_signature(sig).is_some(), "{sig}");
        }
        let chat_in = parse_signature(SIG_CHAT_IN).unwrap();
        assert_eq!(chat_in.len(), CHAT_IN_CALL + 1);
        assert_eq!(chat_in[CHAT_IN_CALL], Some(0xE8));
        // the hook covers exactly `mov [rsp+20h],eax; mov byte [rbp+20h],0`
        let hooked: Vec<Option<u8>> = [0x89, 0x44, 0x24, 0x20, 0xC6, 0x45, 0x20, 0x00].iter().map(|&b| Some(b)).collect();
        assert_eq!(&chat_in[CHAT_IN_HOOK..CHAT_IN_CALL], &hooked[..]);
    }

    #[test]
    fn senders() {
        assert!(sender_is_safe(u32::MAX));
        assert!(sender_is_safe(0x7f));
        assert!(!sender_is_safe(0));
        assert!(!sender_is_safe(0x80));
        assert!(!sender_is_safe(0x101));
        assert!(!sender_is_safe(0x40)); // slot 0, generation 1: a live player's handle
        assert!(!sender_is_safe(0xC1));
        assert!(sender_is_safe(0x20) && sender_is_safe(0x7FFF_FFE0));
    }

    #[test]
    fn lines_are_split_on_spaces_and_char_boundaries() {
        assert_eq!(split_line("  hello\r\nworld  ", LINE_MAX), vec!["hello  world"]);
        assert!(split_line(" \t ", LINE_MAX).is_empty());
        let words = "word ".repeat(200);
        let parts = split_line(&words, LINE_MAX);
        assert!(parts.len() > 1);
        assert!(parts.iter().all(|p| p.len() <= LINE_MAX && !p.is_empty() && !p.starts_with(' ') && !p.ends_with(' ')));
        assert_eq!(parts.join(" "), words.trim());
        let wide = "é".repeat(400); // 800 bytes, no spaces
        let parts = split_line(&wide, LINE_MAX);
        assert!(parts.iter().all(|p| p.len() <= LINE_MAX));
        assert_eq!(parts.concat(), wide);
    }

    #[test]
    fn active_entries() {
        let mut t = vec![0u8; 8 * 4];
        t[0..4].copy_from_slice(&0x80u32.to_le_bytes());
        t[4] = 1;
        t[8..12].copy_from_slice(&0x101u32.to_le_bytes()); // inactive
        t[16..20].copy_from_slice(&0u32.to_le_bytes());
        t[20] = 1; // active bit but no handle
        t[24..28].copy_from_slice(&0x181u32.to_le_bytes());
        t[28] = 3;
        assert_eq!(active_handles(&t), vec![0x80, 0x181]);
    }

    #[test]
    fn plan_waits_for_grace_then_settles_everyone() {
        let now = Instant::now();
        let old = now - GRACE - Duration::from_secs(1);
        let mut since = HashMap::new();
        since.insert(0x80, old);
        since.insert(0x101, now); // just joined
        let mut line = Line::new("hi".into(), now);
        assert_eq!(plan(&mut line, &[], &since, now), Step::Wait);
        assert_eq!(plan(&mut line, &[0x101], &since, now), Step::Wait);
        assert_eq!(plan(&mut line, &[0x80, 0x101], &since, now), Step::Send(vec![0x80]));
        assert_eq!(line.recipients, Some(vec![0x80]));
        // the recipient set is fixed: a later joiner does not get it
        since.insert(0x101, old);
        assert_eq!(plan(&mut line, &[0x80, 0x101], &since, now), Step::Send(vec![0x80]));
        line.sent.push(0x80);
        assert_eq!(plan(&mut line, &[0x80, 0x101], &since, now), Step::Done);
        assert!(line.summary().starts_with("chat line sent to 1 of 1 connection(s): hi"));
        // a recipient that leaves is settled as left
        let mut line = Line::new("x".into(), now);
        assert_eq!(plan(&mut line, &[0x80, 0x101], &since, now), Step::Send(vec![0x80, 0x101]));
        line.failed.push((0x80, BUSY));
        assert_eq!(plan(&mut line, &[0x80], &since, now), Step::Done);
        assert_eq!(line.left, vec![0x101]);
        assert!(line.summary().contains("1 left first") && line.summary().contains("failed (code 0x102)"));
    }

    #[test]
    fn a_line_for_one_connection() {
        let now = Instant::now();
        let mut since = HashMap::new();
        since.insert(0x80, now - GRACE - Duration::from_secs(1));
        since.insert(0x101, now); // just joined: a line for this connection does not wait for GRACE
        let mut line = Line { to: Some(0x101), chat_type: Some(4), ..Line::new("[Server] chest".into(), now) };
        assert_eq!(plan(&mut line, &[0x80, 0x101], &since, now), Step::Send(vec![0x101]));
        line.sent.push(0x101);
        assert_eq!(plan(&mut line, &[0x80, 0x101], &since, now), Step::Done);
        assert!(line.summary().starts_with("chat line sent to 1 of 1 connection(s)"));
        // gone before it could be sent: settled as left, never sent to anyone else
        let mut line = Line { to: Some(0x181), ..Line::new("x".into(), now) };
        assert_eq!(plan(&mut line, &[0x80], &since, now), Step::Done);
        assert_eq!((line.left.clone(), line.sent.is_empty()), (vec![0x181], true));
        assert!(line.summary().contains("1 left first"));
    }

    #[test]
    fn the_recipients_account() {
        const STRIDE: usize = 0x148;
        let mut table = vec![0u8; crate::PLAYER_SLOTS * STRIDE];
        let mut put = |i: usize, handle: u32, connection: u32, account: u64| {
            let s = &mut table[i * STRIDE..(i + 1) * STRIDE];
            s[crate::SLOT_HANDLE..crate::SLOT_HANDLE + 4].copy_from_slice(&handle.to_le_bytes());
            s[crate::SLOT_CONNECTION..crate::SLOT_CONNECTION + 4].copy_from_slice(&connection.to_le_bytes());
            s[crate::deaths::SLOT_ACCOUNT..crate::deaths::SLOT_ACCOUNT + 8].copy_from_slice(&account.to_le_bytes());
        };
        put(0, 0x40, 0x81, 0x1111_2222_3333_4444);
        put(2, 0x42, 0x102, 0x5555);
        put(5, 0, 0x183, 0x9999); // a free slot keeps its old connection: not used
        assert_eq!(account_for(&table, STRIDE, 0x81), 0x1111_2222_3333_4444);
        assert_eq!(account_for(&table, STRIDE, 0x102), 0x5555);
        assert_eq!(account_for(&table, STRIDE, 0x183), 0);
        assert_eq!(account_for(&table, STRIDE, 0x204), 0);
        assert_eq!(account_for(&table, STRIDE, 0), 0);
        assert_eq!(account_for(&table[..STRIDE], STRIDE, 0x102), 0); // short table
        assert_eq!(account_for(&table, 0x20, 0x81), 0); // stride too small for the account
        let mut line = Line::new("x".into(), Instant::now());
        line.recipients = Some(vec![0x81, 0x183]);
        line.sent = vec![0x81, 0x183];
        line.no_account = vec![0x183];
        assert!(line.summary().starts_with("chat line sent to 2 of 2 connection(s), 1 without an account (the game hides it there): x"));
    }

    #[test]
    fn chat_types() {
        assert!(chat_type_allowed(0) && chat_type_allowed(4));
        for t in [1, 2, 3, 5, 255] {
            assert!(!chat_type_allowed(t), "{t}");
        }
    }

    #[test]
    fn queue_limits_and_expiry() {
        let mut q = queue();
        q.clear();
        drop(q);
        assert_eq!(say("[Server] ", "   ", Duration::ZERO), Said::Empty);
        assert_eq!(say("[Server] ", "hello", Duration::ZERO), Said::Queued { parts: 1, waiting: 1 });
        assert_eq!(say("[Server] ", "old", EXPIRE + Duration::from_secs(1)), Said::Queued { parts: 1, waiting: 2 });
        let gone = expire();
        assert_eq!(gone, vec!["[Server] old".to_string()]);
        queue().clear();
        // every part of a long line carries the prefix and fits
        let long = "word ".repeat(200);
        let Said::Queued { parts, .. } = say("[Server] ", &long, Duration::ZERO) else { panic!() };
        assert!(parts > 1);
        assert!(queue().iter().all(|l| l.text.starts_with("[Server] ") && l.text.len() <= LINE_MAX));
        queue().clear();
        for i in 0..QUEUE_MAX {
            assert!(matches!(say("", &format!("l{i}"), Duration::ZERO), Said::Queued { .. }));
        }
        assert_eq!(say("", "one more", Duration::ZERO), Said::Full { dropped: 1 });
        assert_eq!(say_to(0x80, 0, "", "one more"), Said::Full { dropped: 1 });
        queue().clear();
        // a line for one player keeps its connection and type
        assert_eq!(say_to(0x80, 4, "[Server] ", "chest"), Said::Queued { parts: 1, waiting: 1 });
        let q = queue();
        assert_eq!((q[0].to, q[0].chat_type, q[0].text.as_str()), (Some(0x80), Some(4), "[Server] chest"));
        drop(q);
        queue().clear();
        assert_eq!(say("[Server] ", "all", Duration::ZERO), Said::Queued { parts: 1, waiting: 1 });
        let q = queue();
        assert_eq!((q[0].to, q[0].chat_type), (None, None));
        drop(q);
        queue().clear();
    }

    /// A page-sized, page-aligned buffer standing in for the cave page.
    #[repr(C, align(4096))]
    struct TestPage([u8; cave::PAGE]);

    fn put32(p: &mut TestPage, at: usize, v: u32) {
        p.0[at..at + 4].copy_from_slice(&v.to_le_bytes());
    }

    fn publish(p: &mut TestPage, index: u32, handle: u32, text: &[u8], rejected: bool) {
        let slot = cave::CHAT_IN_RING + (index as usize % cave::CHAT_IN_LEN) * cave::CHAT_IN_SLOT;
        p.0[slot + cave::CI_TYPE] = 0;
        p.0[slot + cave::CI_REJECTED] = rejected as u8;
        put32(p, slot + cave::CI_HANDLE, handle);
        put32(p, slot + cave::CI_LEN, text.len() as u32);
        p.0[slot + cave::CI_ACCOUNT..slot + cave::CI_ACCOUNT + 8].copy_from_slice(&0x1234u64.to_le_bytes());
        p.0[slot + cave::CI_TEXT..slot + cave::CI_TEXT + text.len()].copy_from_slice(text);
        put32(p, slot + cave::CI_SEQ, index + 1);
        put32(p, cave::CHAT_IN_HEAD, index + 1);
    }

    #[test]
    fn chat_ring_drains_in_order_and_counts_losses() {
        let mut p = Box::new(TestPage([0; cave::PAGE]));
        let page = p.0.as_ptr() as usize;
        let mut tail = 0;
        assert_eq!(take_chat_in(page, &mut tail), (vec![], 0));
        publish(&mut p, 0, 0x80, b"hello", false);
        publish(&mut p, 1, 0x101, b"", true);
        let (got, lost) = take_chat_in(page, &mut tail);
        assert_eq!(lost, 0);
        assert_eq!(got.len(), 2);
        assert_eq!((got[0].handle, got[0].account, &got[0].text[..], got[0].rejected), (0x80, 0x1234, &b"hello"[..], false));
        assert!(got[1].rejected);
        assert_eq!(tail, 2);
        assert_eq!(take_chat_in(page, &mut tail), (vec![], 0));
        // claimed but not yet published: wait
        put32(&mut p, cave::CHAT_IN_HEAD, 3);
        assert_eq!(take_chat_in(page, &mut tail).0.len(), 0);
        assert_eq!(tail, 2);
        // the ring wrapped past us: the overwritten ones are counted as lost
        for i in 2..(2 + cave::CHAT_IN_LEN as u32 + 3) {
            publish(&mut p, i, 0x80, format!("m{i}").as_bytes(), false);
        }
        let (got, lost) = take_chat_in(page, &mut tail);
        assert_eq!(lost, 3);
        assert_eq!(got.len(), cave::CHAT_IN_LEN);
        assert_eq!(got[0].text, b"m5".to_vec());
        assert_eq!(tail, 2 + cave::CHAT_IN_LEN as u32 + 3);
    }
}
