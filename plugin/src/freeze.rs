//! Freezing deaths get a cause.
//!
//! keen::DeathCause has no freezing value, and `bodyheat_depletion` (server 1.0, SVN 1267041:
//! update exe+0xbc130) drains Health without writing a PlayerDeath record: on a player with actor
//! state Freezing (20), not Dead (7), and BodyHeat <= 0 it subtracts ceil(dt * maxHealth) per tick
//! with `sub dword [r8+rcx*4], eax` (exe+0xbc557). `cave::freeze_cave` sits on that instruction and
//! the next (`mov rcx, rbx`, before `call exe+0x4e240`) and queues the entity whose Health it takes
//! from above 0 to 0 or below. The `death` system then raises the usual EntityDiedEvent for that
//! entity; the poll thread pairs the two by entity id and writes `cause=Freezing`.
//!
//! The entity id is read the way exe+0x6539b0 reads it for EntityDiedEvent: r14 is the system's
//! iteration context (bodyheat_depletion's first argument, passed to the dt getter right in the
//! signature), [ctx+8] the 1-based position, [[ctx]+0x828] the ids (16 bytes each) and
//! [[ctx]+0x830] their count, which the iteration step exe+0x6565c0 compares against.

use crate::memory::{Image, read};

/// bodyheat_depletion, from `mov rcx, r14; call <dt>` through `sub dword [r8+rcx*4], eax;
/// mov rcx, rbx; call`: dt * maxHealth, ceil, the Health (0x8EB84995) lookup, the drain.
pub const SIG_FREEZE: &str = "49 8B CE E8 ?? ?? ?? ?? 0F 57 C0 66 0F 6E CB 0F 5B C9 F2 48 0F 2A 00 F2 41 0F 59 C0 66 0F 5A C0 F3 0F 59 C1 E8 ?? ?? ?? ?? 48 8B 4D ?? 0F 28 F0 48 8B 7D ?? 48 85 C9 74 ?? 0F B6 45 ?? 4C 8B 4D ?? 4C 8B 45 ?? 48 8B 55 ?? 88 44 24 ?? 0F B7 45 ?? 66 89 44 24 ?? E8 ?? ?? ?? ?? 48 8B 5D ?? 48 8D 4D ?? 4C 8B C7 BA 95 49 B8 8E E8 ?? ?? ?? ?? 0F B6 4D ?? 84 C9 74 ?? 41 0F B7 C7 EB ?? 48 8B 45 ?? 0F B7 40 0C 0F B7 C8 48 85 DB 74 ?? F6 43 06 01 74 ?? 44 0F B7 43 04 48 8B D7 F3 0F 2C C6 4C 03 C3 41 29 04 88 48 8B CB E8";
/// The hook: the drain and `mov rcx, rbx` (7 bytes; the call after them stays in place).
pub const FREEZE_HOOK_OFFSET: usize = 0xA3;
pub const FREEZE_ORIGINAL: [u8; 7] = [0x41, 0x29, 0x04, 0x88, 0x48, 0x8B, 0xCB];

/// exe+0x6539b0: the entity id at the current iteration position (EntityDiedEvent's deadEntityId).
/// `mov eax,[rcx+8]; ...; lea edx,[rax-1]; mov rax,[rcx]; add rdx,rdx; mov rcx,[rax+ids]; mov eax,[rcx+rdx*8]`
pub const SIG_ENTITY_ID: &str = "8B 41 08 4C 8B C2 85 C0 75 06 89 02 48 8B C2 C3 8D 50 FF 48 8B 01 48 03 D2 48 8B 88 ?? ?? ?? ?? 8B 04 D1 41 89 00 49 8B C0 C3";
const ENTITY_IDS_AT: usize = 28;
/// exe+0x6565c0, the iteration step: `mov r8,[rcx]; ...; mov eax,[rcx+8]; ...; cmp rax,[r8+count]; jne; xor al,al`.
pub const SIG_ITER_NEXT: &str = "40 57 48 83 EC 20 4C 8B 01 48 8B FA 8B 41 08 4C 8B C9 49 3B 80 ?? ?? ?? ?? 75 ?? 32 C0";
const ENTITY_COUNT_AT: usize = 21;
/// What the cave is built with; install refuses the hook unless the game's own code uses the same.
pub const ENTITY_IDS: u32 = 0x828;
pub const ENTITY_COUNT: u32 = 0x830;

pub struct Site {
    pub hook: usize,
    pub original: [u8; 7],
}

/// Finds and checks everything the freezing cave relies on; Err (and nothing hooked) otherwise.
pub fn resolve(image: &Image) -> Result<Site, String> {
    let found = image.find_all(SIG_FREEZE);
    let [at] = found[..] else { return Err(format!("bodyheat drain signature matched {} times", found.len())) };
    let hook = at + FREEZE_HOOK_OFFSET;
    let original: [u8; 7] = unsafe { read(hook) };
    if original != FREEZE_ORIGINAL {
        return Err(format!("unexpected bytes at exe+{:#x}", image.rva(hook)));
    }
    let offset = |signature: &str, at: usize, what: &str| -> Result<u32, String> {
        let found = image.find_all(signature);
        let [start] = found[..] else { return Err(format!("{what} signature matched {} times", found.len())) };
        Ok(unsafe { read::<u32>(start + at) })
    };
    let ids = offset(SIG_ENTITY_ID, ENTITY_IDS_AT, "entity-id helper")?;
    let count = offset(SIG_ITER_NEXT, ENTITY_COUNT_AT, "iteration step")?;
    if (ids, count) != (ENTITY_IDS, ENTITY_COUNT) {
        return Err(format!("entity table at +{ids:#x}/+{count:#x}, the cave expects +{ENTITY_IDS:#x}/+{ENTITY_COUNT:#x}"));
    }
    Ok(Site { hook, original })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::parse_signature;

    #[test]
    fn signatures_cover_what_is_read() {
        let freeze = parse_signature(SIG_FREEZE).unwrap();
        let want: Vec<Option<u8>> = FREEZE_ORIGINAL.iter().map(|&b| Some(b)).collect();
        assert_eq!(&freeze[FREEZE_HOOK_OFFSET..FREEZE_HOOK_OFFSET + 7], &want[..]);
        assert_eq!(freeze[FREEZE_HOOK_OFFSET + 7], Some(0xE8)); // the call the cave returns to
        assert_eq!(&freeze[..3], &[Some(0x49), Some(0x8B), Some(0xCE)]); // r14 is the context argument
        assert_eq!(freeze.len(), FREEZE_HOOK_OFFSET + 8);
        let ids = parse_signature(SIG_ENTITY_ID).unwrap();
        assert!(ids[ENTITY_IDS_AT..ENTITY_IDS_AT + 4].iter().all(Option::is_none));
        assert_eq!(&ids[ENTITY_IDS_AT - 3..ENTITY_IDS_AT], &[Some(0x48), Some(0x8B), Some(0x88)]); // mov rcx,[rax+disp32]
        let next = parse_signature(SIG_ITER_NEXT).unwrap();
        assert!(next[ENTITY_COUNT_AT..ENTITY_COUNT_AT + 4].iter().all(Option::is_none));
        assert_eq!(&next[ENTITY_COUNT_AT - 3..ENTITY_COUNT_AT], &[Some(0x49), Some(0x3B), Some(0x80)]); // cmp rax,[r8+disp32]
    }
}
