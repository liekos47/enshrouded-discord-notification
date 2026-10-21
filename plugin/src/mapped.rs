//! Verification only (scratch copy): maps a server exe into this test process (no imports resolved,
//! no code run), runs every feature's resolve/build step and the full `install` against it, checks
//! each written jump and cave, and dumps everything for the capstone pass (DW_DUMP=<file>).
//! Run one build per process: chat::resolve keeps the first ChatApi in a OnceLock.

use super::*;
use std::fmt::Write as _;
use std::os::windows::ffi::OsStrExt;
use windows_sys::Win32::System::LibraryLoader::{DONT_RESOLVE_DLL_REFERENCES, LoadLibraryExW};

struct Expect {
    path: &'static str,
    timestamp: u32,
    slot_loop: usize,
    died: [usize; 2],
    record: usize,
    sleeper_hook: usize,
    chat_in_hook: usize,
    enqueue: usize,
    relay: usize,
    alloc: usize,
    serialize: usize,
    commit: usize,
    discard: usize,
    descriptor: usize,
    freeze_hook: usize,
    sleep_patch: usize,
    drops_patch: usize,
    harvest_hook: usize,
    chest_hook: usize,
}

const NEW: Expect = Expect {
    path: "server-1269579",
    timestamp: 0x6ad2_025e,
    slot_loop: 0x7b3578,
    died: [0x726a9, 0x851ce],
    record: 0x4dfc0,
    sleeper_hook: 0x103b2e,
    chat_in_hook: 0x7b2d91,
    enqueue: 0x908ce0,
    relay: 0x7aefb0,
    alloc: 0x9f7020,
    serialize: 0x99ace0,
    commit: 0x9ee240,
    discard: 0x9f3060,
    descriptor: 0x149e860,
    freeze_hook: 0xbc5b7,
    sleep_patch: 0x103b69,
    drops_patch: 0x167fea,
    harvest_hook: 0x19f0e3,
    chest_hook: 0x1a5718,
};

const OLD: Expect = Expect {
    path: "server-1267041",
    timestamp: 0x6ad1_0810,
    slot_loop: 0x7b3498,
    died: [0x72659, 0x8517e],
    record: 0x4df70,
    sleeper_hook: 0x103ace,
    chat_in_hook: 0x7b2cb1,
    enqueue: 0x9085d0,
    relay: 0x7aeed0,
    alloc: 0x9f6930,
    serialize: 0x99a5d0,
    commit: 0x9edb50,
    discard: 0x9f2970,
    descriptor: 0x149e860,
    freeze_hook: 0xbc557,
    sleep_patch: 0x103b09,
    drops_patch: 0x167f8a,
    harvest_hook: 0x19efd3,
    chest_hook: 0x1a5658,
};

fn map(src: &str, tag: &str) -> Image {
    // A copy under its own name: a module of its own, apart from harvest's test mapping of `src`.
    let dir = std::env::temp_dir().join(format!("dw-map-{tag}-{}", std::process::id()));
    fs::create_dir_all(&dir).unwrap();
    let dst = dir.join(format!("map_{tag}.exe"));
    fs::copy(src, &dst).unwrap();
    let wide: Vec<u16> = dst.as_os_str().encode_wide().chain(Some(0)).collect();
    let module = unsafe { LoadLibraryExW(wide.as_ptr(), ptr::null_mut(), DONT_RESOLVE_DLL_REFERENCES) };
    assert!(!module.is_null(), "LoadLibraryExW failed for {}", dst.display());
    unsafe { Image::from_base(module as usize) }
}

fn bytes_at(at: usize, len: usize) -> Vec<u8> {
    unsafe { std::slice::from_raw_parts(at as *const u8, len) }.to_vec()
}

fn jmp_target(at: usize) -> usize {
    assert_eq!(unsafe { read::<u8>(at) }, 0xE9, "no jmp at {at:#x}");
    (at as isize + 5 + unsafe { read::<i32>(at + 1) } as isize) as usize
}

fn exe_path(dir: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../reference").join(dir).join("enshrouded_server.exe")
}

fn run(e: &Expect, tag: &str) {
    let path = exe_path(e.path);
    let file = fs::read(&path).unwrap();
    let orig = |rva: usize, len: usize| file[rva - 0xC00..rva - 0xC00 + len].to_vec(); // .text: raw = rva - 0xC00
    let image = map(path.to_str().unwrap(), tag);
    let mut dump = String::new();
    let base = image.base;
    writeln!(dump, "IMAGE {tag} {base:#x} {:#x}", image.timestamp).unwrap();
    assert_eq!(image.timestamp, e.timestamp);
    assert!(KNOWN_BUILDS.contains(&image.timestamp), "build {:#x} not in KNOWN_BUILDS", image.timestamp);

    // --- resolve steps, one by one (nothing written yet) --------------------------------------
    let found = image.find_all(SIG_SLOTS);
    assert_eq!(found.len(), 1, "slots");
    let slot_loop = found[0];
    assert_eq!(image.rva(slot_loop), e.slot_loop);
    let stride = unsafe { read::<u32>(slot_loop + 3) } as usize;
    let table = unsafe { read::<u32>(slot_loop + 14) } as usize;
    assert_eq!((stride, table), (0x148, 0x1E0));
    assert!(stride >= deaths::SLOT_SCAN.max(SLOT_NAME_END));
    let slots_hook = slot_loop + SLOTS_HOOK_OFFSET;

    let died = died_stores(&image).unwrap();
    assert_eq!(died.iter().map(|&d| image.rva(d)).collect::<Vec<_>>(), e.died.to_vec());
    assert!(died.len() <= cave::MAX_DEATH_CAVES);

    let records = image.find_all(SIG_DEATH_RECORD);
    assert_eq!(records.iter().map(|&r| image.rva(r)).collect::<Vec<_>>(), vec![e.record]);

    let (sleeper_hook, cell) = find_sleeper(&image).unwrap();
    assert_eq!((image.rva(sleeper_hook), cell), (e.sleeper_hook, 20));

    let chat_in = chat::resolve_chat_in(&image).unwrap();
    assert_eq!(image.rva(chat_in), e.chat_in_hook);
    let call_at = chat_in + 8;
    assert_eq!(image.rva(jmp_like_call(call_at)), e.enqueue);

    let api = chat::resolve(&image, 0, u32::MAX).unwrap();
    let described = chat::describe(api, &image);
    writeln!(dump, "CHATAPI {described}").unwrap();
    let want = format!(
        "chat relay exe+{:#x}: 17 entries at server+0x16a0, session holder +0x30, channel send +0x98; alloc exe+{:#x}, serialize exe+{:#x}, commit exe+{:#x}, discard exe+{:#x}, descriptor exe+{:#x}; type 0, sender 0xffffffff",
        e.relay, e.alloc, e.serialize, e.commit, e.discard, e.descriptor
    );
    assert_eq!(described, want);
    // resolve already checked the descriptor's name and size and commit's `mov r8d,[rdx+18h]`;
    // show them again from the mapped image.
    let name_ptr = unsafe { read::<usize>(base + e.descriptor) };
    assert_eq!(bytes_at(name_ptr, 24), b"ChatMessageServerMessage");
    assert_eq!(unsafe { read::<usize>(base + e.descriptor + 8) }, 0x420);

    let site = freeze::resolve(&image).unwrap();
    assert_eq!(image.rva(site.hook), e.freeze_hook);
    assert_eq!(site.original, freeze::FREEZE_ORIGINAL);

    // --- every cave built at the real hook addresses on a real page near the image ------------
    let page = memory::alloc_near(base, cave::PAGE);
    assert_ne!(page, 0);
    let slots = slots_feature(page, slots_hook).unwrap();
    let deaths_f = deaths_feature(page, &died).unwrap();
    let record = record_feature(page, records[0]).unwrap();
    let sleepers = sleeper_feature(page, sleeper_hook).unwrap();
    let chat_seen = chat_in_feature(page, chat_in).unwrap();
    let chat_b = chat_feature(page, api).unwrap();
    for f in [&slots, &deaths_f, &record, &sleepers, &chat_seen, &chat_b] {
        assert_eq!(f.code.len(), f.jumps.len());
        for ((cave_at, code), (hook, jump)) in f.code.iter().zip(&f.jumps) {
            assert_eq!(jump[0], 0xE9);
            let target = (*hook as isize + 5 + i32::from_le_bytes(jump[1..5].try_into().unwrap()) as isize) as usize;
            assert_eq!(target, *cave_at, "{}: built jump goes to its cave", f.name);
            let back = &code[code.len() - 5..];
            assert_eq!(back[0], 0xE9);
            let back_to = (cave_at + code.len()) as isize + i32::from_le_bytes(back[1..5].try_into().unwrap()) as isize;
            assert_eq!(back_to as usize, hook + jump.len(), "{}: built cave jumps back past the hooked bytes", f.name);
        }
    }

    // --- the full install, as start() runs it on a trusted build ------------------------------
    let config = Config { chat_broadcast: true, chest_notice: true, ..Config::default() };
    let hooks = install(&image, &config, true).unwrap();
    writeln!(dump, "HOOKS {}", hooks.describe()).unwrap();
    assert_eq!(hooks.describe(), "player slots, deaths, PlayerDeath record, freezing kills, sleepers, chat-to-Discord, chat broadcast, chest notice");
    assert_eq!((hooks.chest_type, hooks.chest_every, hooks.chest_text.as_str()), (4, Duration::from_secs(600), CHEST_TEXT));
    assert_eq!((hooks.slot_base, hooks.slot_stride, hooks.sleeper_cell), (0x1E0, 0x148, 20));
    assert!(hooks.deaths && hooks.records && hooks.sleepers && hooks.chat && hooks.chat_seen && hooks.freeze_page != 0);
    let p = hooks.page;
    let fz = hooks.freeze_page;

    // (name, hook, hooked length, cave address, expected cave bytes)
    let mut sites: Vec<(String, usize, usize, usize, Vec<u8>)> = Vec::new();
    let o7 = |rva| -> [u8; 7] { orig(rva, 7).try_into().unwrap() };
    let o5 = |rva| -> [u8; 5] { orig(rva, 5).try_into().unwrap() };
    let o8 = |rva| -> [u8; 8] { orig(rva, 8).try_into().unwrap() };
    sites.push(("slots".into(), slots_hook, 7, p + cave::SLOTS_CAVE, cave::slots_cave(p, slots_hook, &o7(image.rva(slots_hook))).unwrap()));
    for (i, &d) in died.iter().enumerate() {
        let (at, body) = cave::death_cave(p, i).unwrap();
        // the death cave replays fixed bytes: they must be what the exe has
        assert_eq!(&body[..5], &orig(image.rva(d), 5)[..], "death site {i} original bytes");
        sites.push((format!("death{i}"), d, 5, at, cave::finish_death_cave(at, body, d).unwrap()));
    }
    sites.push(("record".into(), records[0], 5, p + cave::RECORD_CAVE, cave::record_cave(p, records[0], &o5(e.record)).unwrap()));
    // the sleep cave replays fixed bytes too
    assert_eq!(orig(e.sleeper_hook, 7), vec![0x84, 0xC0, 0x74, 0x03, 0x40, 0xFE, 0xC5]);
    sites.push(("sleep".into(), sleeper_hook, 7, p + cave::SLEEP_CAVE, cave::sleep_cave(p, sleeper_hook).unwrap()));
    sites.push(("chat_in".into(), chat_in, 8, p + cave::CHAT_IN_CAVE, cave::chat_in_cave(p, chat_in, &o8(e.chat_in_hook)).unwrap()));
    let relay = base + e.relay;
    sites.push(("chat".into(), relay, 5, p + cave::CHAT_CAVE, cave::chat_cave(p, relay, &o5(e.relay), chat::chat_tick as usize).unwrap()));
    sites.push((
        "freeze".into(),
        site.hook,
        7,
        fz + cave::FZ_CAVE,
        cave::freeze_cave(fz, site.hook, &o7(e.freeze_hook), freeze::ENTITY_IDS, freeze::ENTITY_COUNT).unwrap(),
    ));

    for (name, hook, len, cave_at, expected) in &sites {
        let patched = bytes_at(*hook, *len);
        assert_eq!(patched, cave::jump_patch(*hook, *cave_at, *len).unwrap(), "{name}: jump bytes");
        assert_eq!(jmp_target(*hook), *cave_at, "{name}: jump target");
        let written = bytes_at(*cave_at, expected.len());
        assert_eq!(&written, expected, "{name}: cave bytes on the page");
        let back = jmp_target(cave_at + expected.len() - 5);
        assert_eq!(back, hook + len, "{name}: jump back");
        let h = |b: &[u8]| b.iter().map(|x| format!("{x:02x}")).collect::<Vec<_>>().join("");
        writeln!(
            dump,
            "SITE {name} hook_rva={:#x} len={len} hook={hook:#x} cave={cave_at:#x} page={:#x} orig={} patched={} cave_bytes={}",
            image.rva(*hook),
            if name == "freeze" { fz } else { p },
            h(&orig(image.rva(*hook), *len)),
            h(&patched),
            h(&written)
        )
        .unwrap();
    }
    writeln!(dump, "CALLBACK chat_tick={:#x}", chat::chat_tick as usize).unwrap();

    // --- the chest notice hook (its own page) --------------------------------------------------
    assert_eq!(orig(e.chest_hook, 7), vec![0x0F, 0xB6, 0x44, 0x24, 0x78, 0x89, 0x07]);
    let chest_hook = base + e.chest_hook;
    let cp = hooks.chest_page;
    assert_ne!(cp, 0);
    assert_eq!(bytes_at(chest_hook, 7), chest::jump(chest_hook, cp + chest::CAVE).unwrap().to_vec());
    assert_eq!(jmp_target(chest_hook), cp + chest::CAVE);
    let code = chest::cave(cp, chest_hook).unwrap();
    assert_eq!(bytes_at(cp + chest::CAVE, code.len()), code);
    assert_eq!(jmp_target(cp + chest::CAVE + code.len() - 5), chest_hook + 7);
    let hx = |b: &[u8]| b.iter().map(|x| format!("{x:02x}")).collect::<Vec<_>>().join("");
    writeln!(
        dump,
        "SITE chest hook_rva={:#x} len=7 hook={chest_hook:#x} cave={:#x} page={cp:#x} orig={} patched={} cave_bytes={}",
        e.chest_hook,
        cp + chest::CAVE,
        hx(&orig(e.chest_hook, 7)),
        hx(&bytes_at(chest_hook, 7)),
        hx(&code)
    )
    .unwrap();

    // --- the byte patches and the harvest hook ------------------------------------------------
    assert_eq!(orig(e.sleep_patch, 4), vec![0x41, 0x0F, 0xB6, 0xC6]);
    assert_eq!(sleep::install(&image), Ok(e.sleep_patch));
    assert_eq!(bytes_at(base + e.sleep_patch, 4), vec![0x40, 0x0F, 0xB6, 0xC5]);
    assert!(sleep::install(&image).unwrap_err().contains("matched 0 times"));
    assert_eq!(orig(e.drops_patch, 2), vec![0x74, 0x03]);
    assert_eq!(drops::install(&image), Ok(e.drops_patch));
    assert_eq!(bytes_at(base + e.drops_patch, 2), vec![0x90, 0x90]);
    assert!(drops::install(&image).unwrap_err().contains("matched 0 times"));
    writeln!(dump, "PATCH sleep rva={:#x} orig=410fb6c6 patched=400fb6c5", e.sleep_patch).unwrap();
    writeln!(dump, "PATCH drops rva={:#x} orig=7403 patched=9090", e.drops_patch).unwrap();

    assert_eq!(orig(e.harvest_hook, 6), vec![0x8B, 0x0F, 0x89, 0x4C, 0x24, 0x28]);
    let h = harvest::install(&image).unwrap();
    assert_eq!((h.rva, h.items), (e.harvest_hook, harvest::ITEMS.len()));
    let hook = base + h.rva;
    assert_eq!(bytes_at(hook, 6), harvest::jump(hook, h.page + harvest::CAVE).unwrap().to_vec());
    let code = harvest::cave(h.page, hook, harvest::ITEMS.len()).unwrap();
    assert_eq!(bytes_at(h.page + harvest::CAVE, code.len()), code);
    assert_eq!(jmp_target(h.page + harvest::CAVE + code.len() - 5), hook + 6);
    let tbl: Vec<u8> = harvest::ITEMS.iter().flat_map(|&(id, max, _)| id.to_le_bytes().into_iter().chain((max as u32).to_le_bytes())).collect();
    assert_eq!(bytes_at(h.page + harvest::TABLE, tbl.len()), tbl);
    let hx = |b: &[u8]| b.iter().map(|x| format!("{x:02x}")).collect::<Vec<_>>().join("");
    writeln!(
        dump,
        "SITE harvest hook_rva={:#x} len=6 hook={hook:#x} cave={:#x} page={:#x} orig={} patched={} cave_bytes={}",
        h.rva,
        h.page + harvest::CAVE,
        h.page,
        hx(&orig(h.rva, 6)),
        hx(&bytes_at(hook, 6)),
        hx(&code)
    )
    .unwrap();
    assert!(harvest::install(&image).unwrap_err().contains("matched 0 times"));

    // A second full install finds the hooked sites changed and writes nothing more.
    assert!(install(&image, &config, true).is_err());

    if let Some(out) = std::env::var_os("DW_DUMP") {
        let mut path = PathBuf::from(out);
        path.push(format!("dump_{tag}.txt"));
        fs::write(&path, &dump).unwrap();
    }
    println!("{dump}");
}

/// The rel32 target of the `call` at `at`.
fn jmp_like_call(at: usize) -> usize {
    assert_eq!(unsafe { read::<u8>(at) }, 0xE8, "no call at {at:#x}");
    (at as isize + 5 + unsafe { read::<i32>(at + 1) } as isize) as usize
}

/// One build per process (chat::resolve keeps the first ChatApi in a OnceLock): without
/// DW_MAP_BUILD this re-runs the test binary once per build with it set.
#[test]
fn mapped_builds() {
    if let Ok(tag) = std::env::var("DW_MAP_BUILD") {
        let e = [&OLD, &NEW].into_iter().find(|e| e.path.ends_with(&tag)).unwrap();
        run(e, &tag);
        return;
    }
    for e in [&OLD, &NEW] {
        if !exe_path(e.path).exists() {
            assert!(std::env::var_os("SKIP_REFERENCE_EXE").is_some(), "{} missing", exe_path(e.path).display());
            eprintln!("SKIPPED: {} missing", exe_path(e.path).display());
            continue;
        }
        let tag = e.path.trim_start_matches("server-");
        let out = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "mapped::mapped_builds", "--nocapture", "--test-threads=1"])
            .env("DW_MAP_BUILD", tag)
            .output()
            .unwrap();
        let text = String::from_utf8_lossy(&out.stdout);
        assert!(out.status.success() && text.contains("1 passed"), "build {tag}:\n{text}\n{}", String::from_utf8_lossy(&out.stderr));
        println!("{text}");
    }
}
