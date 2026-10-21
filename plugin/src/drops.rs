//! Consumables (berries, mushrooms, food...) follow `resourceDropStackAmountFactor` too.
//!
//! Every place the server scales a drop stack by the setting (server 1.0, SVN 1267041:
//! `loot_pickup_item` exe+0x196b16, `loot_pickup_in_range` exe+0x1966a5, the loot roll of
//! `random_loot_on_interaction` / inventories exe+0x19b731) first asks exe+0x167f80 whether the
//! item's `ItemCategory` (ItemInfo +0xcc) may be scaled. The game says yes only for BuildTools (6),
//! Ammunition (8) and Materials (9), so a wild berry pickup (PickupItem x2) gives its usual 2 at
//! factor 2. Dropping the `cmp cl, 7; je` lets Consumables (7) through as well (potions, bandages,
//! flasks and Scroll of Experience included); the amount then goes through the game's own scaling
//! (exe+0x167770: amount * factor, random rounding, at least 1, at most a stack). Planted and wild
//! bush and crop harvests never reach these sites (immediate_loot_action adds countMax directly):
//! harvest.rs covers them.

use crate::memory::{Image, write};

/// `lea eax, [rcx-6]; test al, 0xfc; jne no; cmp cl, 7; je no; mov al, 1; ret; no: xor al, al; ret`
const SIG: &str = "8D 41 FA A8 FC 75 08 80 F9 07 74 03 B0 01 C3 32 C0 C3";
const OFFSET: usize = 10;
const ORIGINAL: [u8; 2] = [0x74, 0x03]; // je no  (Consumables: not scaled)
const PATCHED: [u8; 2] = [0x90, 0x90]; // nop nop (Consumables: scaled)

pub fn install(image: &Image) -> Result<usize, String> {
    let found = image.find_all(SIG);
    let [at] = found[..] else { return Err(format!("drop-category signature matched {} times", found.len())) };
    let site = at + OFFSET;
    let current: [u8; 2] = unsafe { crate::memory::read(site) };
    if current != ORIGINAL {
        return Err(format!("unexpected bytes at exe+{:#x}", image.rva(site)));
    }
    if !write(site, &PATCHED) {
        return Err("could not write the patch".into());
    }
    Ok(image.rva(site))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn patch_is_same_length_and_inside_the_signature() {
        let pattern = crate::memory::parse_signature(SIG).unwrap();
        let original: Vec<Option<u8>> = ORIGINAL.iter().map(|&b| Some(b)).collect();
        assert_eq!(&pattern[OFFSET..OFFSET + 2], &original[..]);
        assert_eq!(ORIGINAL.len(), PATCHED.len());
    }
}
