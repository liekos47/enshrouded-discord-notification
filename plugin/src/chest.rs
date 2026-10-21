//! Which player just rolled the loot of which chest, for the private chest notice (`chest_notice`).
//!
//! Server 1.0, SVN 1267041; the function is instruction-identical in 1.0.0.2. `random_loot_on_interaction`
//! (exe+0x1a4e60) goes through every InteractionAcceptedEvent {guestEntityId @8 (the player),
//! hostEntityId @0xC (what they opened)}. When the host has a RandomLootContainer whose
//! spawnedLootVersion differs from its loot node's version, it rolls the loot into the inventory,
//! adds a RandomLootLock component (a locked container never rolls again) and stores the node's
//! version: `movzx eax,byte [rsp+78h]; mov [rdi],eax` at exe+0x1a5658. That pair is the hook: the
//! container has just been filled for this player.
//!
//! The lock is saved with the world and nothing in the game removes it. A chest rolls again only
//! after its area resets: the ECS drops an unloaded chunk's saved state 30 minutes after the last
//! player left its range (exe+0x6be520, the 30 minutes are `movabs rax,1A3185C5000h`). So a roll is
//! the first opening since the last reset.
//!
//! The cave replays the two instructions, then copies guest and host into a 16-entry ring on its
//! own page (sequence number last) and jumps back. It calls nothing and uses only rcx, rdx and r8
//! besides: the code it returns to (`jmp` exe+0x1a55a8) starts `xor r8d,r8d; lea rcx,[rbp+1C0h];
//! xor edx,edx; call`, so they and the flags are dead there. r13 points at the event's hostEntityId
//! (`lea r13,[r15+14h]` per event: an 8-byte page header, then +0xC), and the game reads [r13] on
//! this very path, so the guest is [r13-4].
//!
//! Corpses (TransformToLoot) roll through the same code. Only hosts placed in the world are worth a
//! notice: their entity id has bit 31 set (the game prints those as "c:<chunk> u:<n> i:<index>",
//! exe+0x64e800); the poll thread filters on that.

use std::{ptr, sync::atomic::{AtomicU32, Ordering, fence}};

use crate::memory::{Image, alloc_near, read, write};

/// `mov ecx,[r13]; mov r9d,6Dh; mov [rsp+20h],ecx; mov r8b,3; mov rcx,rax; lea rdx,[rax+10h];
/// call add_component; test rax,rax; je hook; mov dword [rax+0Ch],53F8DF2Dh (RandomLootLock);
/// mov word [rax+4Ch],1; mov [rax+6Ch],r12b; movzx eax,byte [rsp+78h]; mov [rdi],eax; jmp`.
/// The hook is the `movzx; mov [rdi]` at +0x33 (1.0 exe+0x1a5658, 1.0.0.2 exe+0x1a5718).
/// (One line each: tools/check_signatures.py reads them.)
const SIG: &str = "41 8B 4D 00 41 B9 6D 00 00 00 89 4C 24 20 41 B0 03 48 8B C8 48 8D 50 10 E8 ?? ?? ?? ?? 48 85 C0 74 11 C7 40 0C 2D DF F8 53 66 C7 40 4C 01 00 44 88 60 6C 0F B6 44 24 78 89 07 E9";
const HOOK_OFFSET: usize = 0x33;
const ORIGINAL: [u8; 7] = [0x0F, 0xB6, 0x44, 0x24, 0x78, 0x89, 0x07];
/// Same function: `lea r13,[r15+14h]; mov [rbp+..],edx; add r13,rax; mov [rsp+30h],ecx;
/// mov edx,[r13]; mov rcx,r14; call` (1.0 exe+0x1a4f76). r13 = &event.hostEntityId. Must be
/// EVENT_TO_HOOK before the hook.
const SIG_EVENT: &str = "4D 8D 6F 14 89 95 ?? ?? ?? ?? 4C 03 E8 89 4C 24 30 41 8B 55 00 49 8B CE E8";
const EVENT_TO_HOOK: usize = 0x6E2;

/// Layout of the chest page (its own allocation near the image).
pub const PAGE: usize = 0x1000;
pub const CAVE: usize = 0x000;
pub const HEAD: usize = 0x200; // u32: rolls seen so far (wraps)
pub const RING: usize = 0x210; // [Entry; RING_LEN]
pub const RING_LEN: usize = 16;
pub const ENTRY: usize = 16; // guest u32, host u32, unused u32, seq u32 (written last)

/// Bit 31 of an entity id: an entity placed in the world (it belongs to a scene chunk).
pub const WORLD_ENTITY: u32 = 0x8000_0000;

#[derive(Debug)]
pub struct Installed {
    pub rva: usize,
    pub page: usize,
}

fn unique(image: &Image, signature: &str, what: &str) -> Result<usize, String> {
    let found = image.find_all(signature);
    match found[..] {
        [at] => Ok(at),
        _ => Err(format!("{what} signature matched {} times", found.len())),
    }
}

/// Checks everything first, writes the game's code last (one 7-byte write): on any error nothing
/// in the game is changed.
pub fn install(image: &Image) -> Result<Installed, String> {
    let hook = unique(image, SIG, "chest roll")? + HOOK_OFFSET;
    let event = unique(image, SIG_EVENT, "chest event pointer")?;
    if event + EVENT_TO_HOOK != hook {
        return Err(format!("chest event pointer at exe+{:#x}, expected {EVENT_TO_HOOK:#x} before the hook", image.rva(event)));
    }
    let current: [u8; 7] = unsafe { read(hook) };
    if current != ORIGINAL {
        return Err(format!("unexpected bytes at exe+{:#x}", image.rva(hook)));
    }
    let page = alloc_near(image.base, PAGE);
    if page == 0 {
        return Err("no memory within jump range of the image".into());
    }
    let code = cave(page, hook).ok_or("chest cave out of range")?;
    let patch = jump(hook, page + CAVE).ok_or("chest jump out of range")?;
    unsafe { ptr::copy_nonoverlapping(code.as_ptr(), (page + CAVE) as *mut u8, code.len()) };
    if !write(hook, &patch) {
        return Err("could not write the hook".into());
    }
    Ok(Installed { rva: image.rva(hook), page })
}

fn rel32(from_end: usize, to: usize) -> Option<[u8; 4]> {
    i32::try_from(to as i64 - from_end as i64).ok().map(i32::to_le_bytes)
}

/// `jmp cave; nop; nop` over the 7 hooked bytes (the nops are never reached: the cave returns to hook+7).
pub fn jump(hook: usize, cave: usize) -> Option<[u8; 7]> {
    let [a, b, c, d] = rel32(hook + 5, cave)?;
    Some([0xE9, a, b, c, d, 0x90, 0x90])
}

/// The cave at `page + CAVE` for the hook at `hook` (7 bytes, see ORIGINAL).
pub fn cave(page: usize, hook: usize) -> Option<Vec<u8>> {
    let at = page + CAVE;
    let mut c: Vec<u8> = Vec::with_capacity(0x60);
    c.extend(ORIGINAL); // movzx eax,byte [rsp+78h]; mov [rdi],eax
    c.extend([0xB9, 0x01, 0x00, 0x00, 0x00]); // mov ecx,1
    c.extend([0xF0, 0x0F, 0xC1, 0x0D]); // lock xadd [rip+HEAD],ecx    ecx = this roll's index
    c.extend(rel32(at + c.len() + 4, page + HEAD)?);
    c.extend([0x8D, 0x51, 0x01]); // lea edx,[rcx+1]               seq = index + 1
    c.extend([0x83, 0xE1, (RING_LEN - 1) as u8]); // and ecx,RING_LEN-1
    c.extend([0xC1, 0xE1, ENTRY.trailing_zeros() as u8]); // shl ecx,4
    c.extend([0x4C, 0x8D, 0x05]); // lea r8,[rip+RING]
    c.extend(rel32(at + c.len() + 4, page + RING)?);
    c.extend([0x49, 0x01, 0xC8]); // add r8,rcx
    c.extend([0x41, 0x8B, 0x4D, 0xFC]); // mov ecx,[r13-4]          guestEntityId
    c.extend([0x41, 0x89, 0x08]); // mov [r8],ecx
    c.extend([0x41, 0x8B, 0x4D, 0x00]); // mov ecx,[r13]            hostEntityId
    c.extend([0x41, 0x89, 0x48, 0x04]); // mov [r8+4],ecx
    c.extend([0x41, 0x89, 0x50, 0x0C]); // mov [r8+0Ch],edx         seq, last
    c.push(0xE9); // jmp hook+7
    c.extend(rel32(at + c.len() + 4, hook + ORIGINAL.len())?);
    (CAVE + c.len() <= HEAD).then_some(c)
}

/// One roll the hook saw: its sequence number (1 = first since start), the player (guest) and
/// the container (host) entity ids.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Rolled {
    pub seq: u32,
    pub guest: u32,
    pub host: u32,
}

#[derive(Debug, Default, PartialEq)]
pub struct Taken {
    pub rolls: Vec<Rolled>,
    /// Rolls that were overwritten before they could be read.
    pub dropped: u32,
}

fn cell(page: usize, offset: usize) -> u32 {
    unsafe { AtomicU32::from_ptr((page + offset) as *mut u32) }.load(Ordering::Acquire)
}

/// The head now: start reading from here so rolls from before the reader started are not told.
pub fn head(page: usize) -> u32 {
    cell(page, HEAD)
}

/// New ring entries of the page at `page` since `tail` (oldest first). An entry is taken only when
/// its sequence number is tail + 1, before and after its fields are read; nothing is ever cleared.
pub fn take(page: usize, tail: &mut u32) -> Taken {
    let head = cell(page, HEAD);
    let mut taken = Taken::default();
    let behind = head.wrapping_sub(*tail);
    if behind as usize > RING_LEN {
        taken.dropped += behind - RING_LEN as u32;
        *tail = head.wrapping_sub(RING_LEN as u32);
    }
    while *tail != head {
        let at = RING + (*tail as usize % RING_LEN) * ENTRY;
        let want = tail.wrapping_add(1);
        let seq = cell(page, at + 12);
        if seq != want {
            if (seq.wrapping_sub(want) as i32) > 0 {
                taken.dropped += 1; // a later roll already reused the slot
                *tail = want;
                continue;
            }
            break; // claimed but not written yet: next poll
        }
        let rolled = Rolled { seq, guest: cell(page, at), host: cell(page, at + 4) };
        fence(Ordering::Acquire);
        if cell(page, at + 12) != want {
            taken.dropped += 1; // overwritten while being read
        } else {
            taken.rolls.push(rolled);
        }
        *tail = want;
    }
    taken
}

/// Placed in the world (a chest, a sack in a ruin): it resets with its area. Corpses and anything
/// else spawned at run time do not have bit 31.
pub fn in_world(entity: u32) -> bool {
    entity & WORLD_ENTITY != 0
}

/// An entity id the way the game logs it: "c:<chunk> u:<n> i:<index>" for world entities
/// (exe+0x64e800), the plain number otherwise.
pub fn entity_text(id: u32) -> String {
    if in_world(id) {
        format!("c:{} u:{} i:{}", (id >> 20) & 0x7FF, (id >> 18) & 3, id & 0x3_FFFF)
    } else {
        format!("{id}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::{matches, parse_signature};

    const PAGE_AT: usize = 0x1_3FFF_0000;
    const HOOK: usize = 0x1_401A_5658;

    fn target(code: &[u8], rel_at: usize) -> usize {
        let rel = i32::from_le_bytes(code[rel_at..rel_at + 4].try_into().unwrap()) as i64;
        ((PAGE_AT + CAVE + rel_at + 4) as i64 + rel) as usize
    }

    #[test]
    fn signatures_and_original() {
        for s in [SIG, SIG_EVENT] {
            assert!(parse_signature(s).is_some(), "{s}");
        }
        let pattern = parse_signature(SIG).unwrap();
        let original: Vec<Option<u8>> = ORIGINAL.iter().map(|&b| Some(b)).collect();
        assert_eq!(&pattern[HOOK_OFFSET..HOOK_OFFSET + ORIGINAL.len()], &original[..]);
        assert_eq!(pattern.len(), HOOK_OFFSET + ORIGINAL.len() + 1); // then the `jmp` back into the loop
        assert_eq!(pattern.last(), Some(&Some(0xE9)));
        // the RandomLootLock type hash is part of the signature
        let lock: Vec<Option<u8>> = 0x53F8_DF2Du32.to_le_bytes().iter().map(|&b| Some(b)).collect();
        assert!(pattern.windows(4).any(|w| w == &lock[..]));
    }

    #[test]
    fn cave_layout() {
        let code = cave(PAGE_AT, HOOK).unwrap();
        assert_eq!(code.len(), 0x3F);
        assert!(CAVE + code.len() <= HEAD);
        assert_eq!(&code[..7], &ORIGINAL);
        assert_eq!(target(&code, 0x10), PAGE_AT + HEAD);
        assert_eq!(target(&code, 0x20), PAGE_AT + RING);
        assert_eq!(target(&code, code.len() - 4), HOOK + 7);
        assert!(!code.contains(&0xE8), "the cave must not call anything");
        assert!(RING + RING_LEN * ENTRY <= PAGE);
        let patch = jump(HOOK, PAGE_AT + CAVE).unwrap();
        assert_eq!(patch[0], 0xE9);
        assert_eq!(&patch[5..], &[0x90, 0x90]);
        let to = (HOOK as i64 + 5 + i32::from_le_bytes(patch[1..5].try_into().unwrap()) as i64) as usize;
        assert_eq!(to, PAGE_AT + CAVE);
        assert!(jump(0x1_4000_0000, 0x7FF0_0000_0000).is_none());
    }

    /// Hand-assembled; disassembled with capstone at these addresses (see README section I).
    const GOLDEN: &str = "0f b6 44 24 78 89 07 b9 01 00 00 00 f0 0f c1 0d ec 01 00 00 8d 51 01 83 e1 0f c1 e1 04 \
        4c 8d 05 ec 01 00 00 49 01 c8 41 8b 4d fc 41 89 08 41 8b 4d 00 41 89 48 04 41 89 50 0c e9 20 56 1b 00";

    #[test]
    fn golden_bytes() {
        let code = cave(PAGE_AT, HOOK).unwrap();
        let golden: Vec<u8> = GOLDEN.split_whitespace().map(|t| u8::from_str_radix(t, 16).unwrap()).collect();
        assert_eq!(code, golden);
    }

    #[test]
    fn entity_ids() {
        assert!(in_world(0x8140_0005));
        assert!(!in_world(1));
        assert!(!in_world(0x0012_3456));
        // c:20 u:1 i:5, as the game would log it
        let id = WORLD_ENTITY | (20 << 20) | (1 << 18) | 5;
        assert_eq!(entity_text(id), "c:20 u:1 i:5");
        assert_eq!(entity_text(7), "7");
        assert_eq!(entity_text(0xFFFF_FFFF), "c:2047 u:3 i:262143");
    }

    /// A fake chest page for the ring reader (8-byte aligned, like the real page).
    struct FakePage(Box<[u64; PAGE / 8]>);

    impl FakePage {
        fn new() -> FakePage {
            FakePage(Box::new([0; PAGE / 8]))
        }
        fn at(&self) -> usize {
            self.0.as_ptr() as usize
        }
        fn set(&mut self, offset: usize, value: u32) {
            unsafe { ptr::write_volatile((self.at() + offset) as *mut u32, value) };
        }
        fn write_entry(&mut self, seq: u32, guest: u32, host: u32) {
            let at = RING + (seq.wrapping_sub(1) as usize % RING_LEN) * ENTRY;
            self.set(at, guest);
            self.set(at + 4, host);
            self.set(at + 12, seq);
        }
        fn push(&mut self, guest: u32, host: u32) {
            let seq = cell(self.at(), HEAD).wrapping_add(1);
            self.set(HEAD, seq);
            self.write_entry(seq, guest, host);
        }
    }

    #[test]
    fn take_in_order_waits_and_counts_overflow() {
        let mut p = FakePage::new();
        let mut tail = head(p.at());
        assert_eq!(take(p.at(), &mut tail), Taken::default());
        p.push(1, 0x8140_0005);
        p.push(2, 77);
        let t = take(p.at(), &mut tail);
        assert_eq!(t.rolls, vec![Rolled { seq: 1, guest: 1, host: 0x8140_0005 }, Rolled { seq: 2, guest: 2, host: 77 }]);
        assert_eq!((t.dropped, tail), (0, 2));
        // claimed but not written yet: nothing, the tail stays
        p.set(HEAD, 3);
        assert_eq!(take(p.at(), &mut tail), Taken::default());
        assert_eq!(tail, 2);
        p.write_entry(3, 3, 0x8000_0001);
        assert_eq!(take(p.at(), &mut tail).rolls.len(), 1);
        // more than RING_LEN between two reads
        for n in 0..40 {
            p.push(n, WORLD_ENTITY | n);
        }
        let t = take(p.at(), &mut tail);
        assert_eq!((t.dropped, t.rolls.len()), (24, 16));
        assert_eq!(t.rolls[0].seq, 3 + 24 + 1);
        assert_eq!(tail, 43);
    }

    #[test]
    fn take_skips_a_slot_reused_by_a_later_roll_and_wraps() {
        let mut p = FakePage::new();
        let mut tail = 0;
        p.push(1, 2); // roll 1
        p.set(HEAD, 2); // roll 2 claimed, its writer stalls
        assert_eq!(take(p.at(), &mut tail).rolls.len(), 1);
        for seq in 3..=18 {
            p.set(HEAD, seq);
            p.write_entry(seq, seq, seq); // roll 18 reuses roll 2's slot
        }
        let t = take(p.at(), &mut tail);
        assert_eq!(t.dropped, 1);
        assert_eq!(t.rolls.iter().map(|r| r.seq).collect::<Vec<_>>(), (3..=18).collect::<Vec<_>>());
        // the sequence wraps at u32::MAX
        let mut p = FakePage::new();
        p.set(HEAD, u32::MAX - 1);
        let mut tail = u32::MAX - 1;
        for _ in 0..3 {
            p.push(1, 2);
        }
        let t = take(p.at(), &mut tail);
        assert_eq!(t.rolls.iter().map(|r| r.seq).collect::<Vec<_>>(), vec![u32::MAX, 0, 1]);
        assert_eq!((t.dropped, tail), (0, 1));
    }

    /// A server build kept in the repo: (folder under reference/, PE timestamp, hook rva).
    const BUILDS: [(&str, u32, usize); 2] = [("server-1267041", 0x6AD1_0810, 0x1A5658), ("server-1269579", 0x6AD2_025E, 0x1A5718)];

    fn reference_path(dir: &str) -> Option<std::path::PathBuf> {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../reference").join(dir).join("enshrouded_server.exe");
        if path.exists() {
            return Some(path);
        }
        if std::env::var_os("SKIP_REFERENCE_EXE").is_some() {
            eprintln!("SKIPPED: {} missing (SKIP_REFERENCE_EXE set)", path.display());
            return None;
        }
        panic!("{} missing: the server exe is needed for this test (set SKIP_REFERENCE_EXE=1 to skip)", path.display());
    }

    /// The signatures against every server exe kept in the repo.
    #[test]
    fn reference_exe() {
        for (dir, timestamp, hook) in BUILDS {
            let Some(path) = reference_path(dir) else { continue };
            let exe = std::fs::read(&path).unwrap();
            let nt = u32::from_le_bytes(exe[0x3C..0x40].try_into().unwrap()) as usize;
            assert_eq!(u32::from_le_bytes(exe[nt + 8..nt + 12].try_into().unwrap()), timestamp, "{dir}: not that build's exe");
            let find = |s: &str| {
                let p = parse_signature(s).unwrap();
                (0..exe.len() - p.len()).filter(|&i| matches(&p, &exe[i..])).collect::<Vec<_>>()
            };
            let (sig, event) = (find(SIG), find(SIG_EVENT));
            assert_eq!((sig.len(), event.len()), (1, 1), "{dir}");
            assert_eq!(event[0] + EVENT_TO_HOOK, sig[0] + HOOK_OFFSET, "{dir}");
            assert_eq!(&exe[sig[0] + HOOK_OFFSET..sig[0] + HOOK_OFFSET + 7], &ORIGINAL);
            // .text: file offset = rva - 0xC00 in both builds (rva 0x1000, raw 0x400)
            assert_eq!(sig[0] + HOOK_OFFSET + 0xC00, hook, "{dir}");
        }
    }

    /// install() on every reference exe mapped as an image in this test process (not run).
    #[cfg(windows)]
    #[test]
    fn install_on_mapped_reference_exe() {
        use std::os::windows::ffi::OsStrExt;
        use windows_sys::Win32::System::LibraryLoader::{DONT_RESOLVE_DLL_REFERENCES, LoadLibraryExW};
        for (dir, timestamp, rva) in BUILDS {
            let Some(src) = reference_path(dir) else { continue };
            // A copy under a name of its own: harvest's and mapped's tests map these exes too.
            let tmp = std::env::temp_dir().join(format!("dw-chest-{}-{dir}", std::process::id()));
            std::fs::create_dir_all(&tmp).unwrap();
            let path = tmp.join("chest_map.exe");
            std::fs::copy(&src, &path).unwrap();
            let wide: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
            let module = unsafe { LoadLibraryExW(wide.as_ptr(), ptr::null_mut(), DONT_RESOLVE_DLL_REFERENCES) };
            assert!(!module.is_null());
            let image = unsafe { Image::from_base(module as usize) };
            assert_eq!(image.timestamp, timestamp, "{dir}");
            let done = install(&image).unwrap();
            assert_eq!(done.rva, rva, "{dir}");
            let hook = image.base + done.rva;
            let patch: [u8; 7] = unsafe { read(hook) };
            assert_eq!(patch, jump(hook, done.page + CAVE).unwrap());
            let expected = cave(done.page, hook).unwrap();
            let written = unsafe { std::slice::from_raw_parts((done.page + CAVE) as *const u8, expected.len()) };
            assert_eq!(written, &expected[..]);
            assert!(install(&image).unwrap_err().contains("matched 0 times"));
        }
    }

    /// Runs the real cave on this CPU with a fake event, a fake RandomLootContainer and canaries.
    #[cfg(all(target_arch = "x86_64", windows))]
    mod run {
        use super::super::*;
        use std::arch::asm;

        const CANARY: u64 = 0x0C0F_FEE0_0C0F_FEE0;

        /// Registers after the cave: rax, rbx, rsi, r9, r10, r11, r13, r15, rdi.
        struct Out {
            regs: [u64; 9],
            stack: [u64; 18],
        }

        /// Enters the cave the way the game does, with rsp 16-aligned before the `call` (so the
        /// cave's [rsp+78h] is our [rsp+70h]), r13 = &event.host, rdi = &spawnedLootVersion and
        /// test values in the other registers. `hook + 7` holds a `ret`, which returns here.
        /// r12 and r14 hold the output buffers across the call (the cave must keep them, or the
        /// stores after it go astray).
        fn enter(cave_at: usize, host_ptr: *const u32, version_cell: *mut u32, version: u8) -> Out {
            let mut stack = [0u64; 18];
            let mut regs = [0u64; 9];
            unsafe {
                asm!(
                    "push rbp",
                    "push rbx",
                    "mov rbp, rsp",
                    "and rsp, -16",
                    "sub rsp, 0x90",
                    "mov r11, {canary}",
                    "xor ecx, ecx",
                    "2:",
                    "mov [rsp + rcx*8], r11",
                    "inc ecx",
                    "cmp ecx, 18",
                    "jb 2b",
                    "mov byte ptr [rsp + 0x70], dl",
                    "mov rbx, 0x1111111111111111",
                    "mov rsi, 0x5555555555555555",
                    "mov r9, 0x9999999999999999",
                    "mov r10, 0xAAAAAAAAAAAAAAAA",
                    "mov r11, 0xBBBBBBBBBBBBBBBB",
                    "mov r15, 0xFFFFFFFFFFFFFFFF",
                    "call rax",
                    "mov [r12], rax",
                    "mov [r12 + 0x08], rbx",
                    "mov [r12 + 0x10], rsi",
                    "mov [r12 + 0x18], r9",
                    "mov [r12 + 0x20], r10",
                    "mov [r12 + 0x28], r11",
                    "mov [r12 + 0x30], r13",
                    "mov [r12 + 0x38], r15",
                    "mov [r12 + 0x40], rdi",
                    "xor ecx, ecx",
                    "3:",
                    "mov rax, [rsp + rcx*8]",
                    "mov [r14 + rcx*8], rax",
                    "inc ecx",
                    "cmp ecx, 18",
                    "jb 3b",
                    "mov rsp, rbp",
                    "pop rbx",
                    "pop rbp",
                    canary = const CANARY,
                    inout("rax") cave_at => _,
                    inout("rdx") version as u64 => _,
                    in("rdi") version_cell,
                    in("r12") regs.as_mut_ptr(),
                    in("r13") host_ptr,
                    in("r14") stack.as_mut_ptr(),
                    out("rcx") _,
                    out("rsi") _,
                    out("r8") _,
                    out("r9") _,
                    out("r10") _,
                    out("r11") _,
                    out("r15") _,
                    clobber_abi("system"),
                );
            }
            Out { regs, stack }
        }

        #[test]
        fn cave_runs() {
            let page = alloc_near(cave_runs as usize, PAGE);
            assert_ne!(page, 0);
            let landing = page + 0xF00;
            unsafe { *(landing as *mut u8) = 0xC3 };
            let code = cave(page, landing - 7).unwrap();
            unsafe { ptr::copy_nonoverlapping(code.as_ptr(), (page + CAVE) as *mut u8, code.len()) };
            let mut tail = head(page);
            for (n, &(guest, host, version)) in [(1u32, 0x8140_0005u32, 2u8), (3, 0x1234, 0xFF), (16, 0xFFFF_FFFF, 0)].iter().enumerate() {
                // an InteractionAcceptedEvent: timeStamp @0, guest @8, host @0xC, offerId @0x10
                let mut event = [0u32; 6];
                event[2] = guest;
                event[3] = host;
                event[4] = 0xDEAD;
                let mut spawned = 0x7777_7777u32;
                let out = enter(page + CAVE, &event[3], &mut spawned, version);
                assert_eq!(spawned, version as u32, "case {n}: replayed mov [rdi],eax");
                let [rax, rbx, rsi, r9, r10, r11, r13, r15, rdi] = out.regs;
                assert_eq!(rax, version as u64, "case {n}: replayed movzx eax,byte [rsp+78h]");
                assert_eq!((rbx, rsi), (0x1111_1111_1111_1111, 0x5555_5555_5555_5555));
                assert_eq!((r9, r10, r11, r15), (0x9999_9999_9999_9999, 0xAAAA_AAAA_AAAA_AAAA, 0xBBBB_BBBB_BBBB_BBBB, 0xFFFF_FFFF_FFFF_FFFF));
                assert_eq!((r13, rdi), (&event[3] as *const u32 as u64, &mut spawned as *mut u32 as u64));
                for (i, &q) in out.stack.iter().enumerate() {
                    if i != 14 {
                        assert_eq!(q, CANARY, "stack qword {i} changed, case {n}");
                    }
                }
                assert_eq!(event, [0, 0, guest, host, 0xDEAD, 0], "the event is only read");
                let t = take(page, &mut tail);
                assert_eq!(t.dropped, 0);
                assert_eq!(t.rolls.len(), 1);
                assert_eq!((t.rolls[0].guest, t.rolls[0].host), (guest, host), "case {n}");
            }
        }
    }
}
