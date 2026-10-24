//! Plant and bush harvests follow `resourceDropStackAmountFactor`.
//!
//! Server 1.0, SVN 1267041. The harvest stages of planted and wild plants (berry bushes, crops,
//! herbs, fibre and twig bushes, reeds, mushrooms, night plants) are DefaultInventory + DestroyOnLoot
//! entities with no Inventory. `immediate_loot_action` (exe+0x19eb30) loots them: for each root stack
//! of the DefaultInventory it calls the add-item function exe+0x1ab820 with the stack's countMax
//! (loop exe+0x19efa0) and never applies the setting, so a berry bush gives 2 at any factor.
//!
//! The hook replaces `mov ecx,[rdi]; mov [rsp+28h],ecx` (exe+0x19efd3, the count argument). The cave
//! is a leaf: it calls nothing. It looks the stack's item id (eax) up in `ITEMS`, a table of the 52
//! plant crops this loop can grant (copied to the cave page), and for those only sets
//! count = max(1, round_half_up(count * factor)), at most max(maxStackSize, count).
//! The factor is read on every stack from GameSettings +0x38 through the system's BalancingRegistry
//! ([rbp+0xf8], +0x90): the same object and offsets the game's getter exe+0x9346d0 reads when it
//! scales pickups, so a changed setting applies at once. Any other item (seedlings, weapons, bait,
//! fog nest resources, flame essence, shroud cores and spores, bones, fur), a zero count, a null
//! pointer or a factor that is not > 0 keeps the game's count.
//!
//! Every stack the loop asks add_item for is also written to a 16-entry ring (item, countMax, count
//! requested, sequence number) that a plugin thread logs to `logs/deathwatch.log`. It is written
//! before the call: a harvest the game rolls back (no room in the inventory) still logs its request.
//! The ring is diagnostics only; under a burst of more than 16 stacks during one read an entry can
//! be logged with another stack's fields.

use std::{
    collections::HashSet,
    ptr,
    sync::atomic::{AtomicUsize, Ordering},
};

use crate::memory::{Image, alloc_near, read, safe_read, write};

/// The loop body in `immediate_loot_action` up to `call add_item`; the hook is the
/// `mov ecx,[rdi]; mov [rsp+28h],ecx` at +0x33 (exe+0x19efd3).
/// (One line each: tools/check_signatures.py reads them.)
const SIG: &str = "8B 47 F8 48 8D 4C 24 78 4C 8B 0D ?? ?? ?? ?? 48 8D 95 20 02 00 00 45 8B 07 48 89 4C 24 40 48 8D 8D 58 74 00 00 48 89 4C 24 38 48 8D 4D 80 48 89 4C 24 30 8B 0F 89 4C 24 28 48 8D 4D A0 40 88 74 24 7C 40 88 B5 59 74 00 00 48 89 5D 80 89 44 24 20 E8";
const HOOK_OFFSET: usize = 0x33;
const ORIGINAL: [u8; 6] = [0x8B, 0x0F, 0x89, 0x4C, 0x24, 0x28];
/// Same function, exe+0x19ed96: the loot context gets ItemRegistry from [rbp+0x108] (+0x10) and
/// BalancingRegistry from [rbp+0xf8] (+0x18), the slot the cave reads. Must be CTX_TO_HOOK before the hook.
const SIG_CTX: &str = "48 8B 85 08 01 00 00 49 8B D5 4C 8B 85 58 01 00 00 40 32 F6 48 89 45 10 48 8B 85 F8 00 00 00 48 89 45 18";
const CTX_TO_HOOK: usize = 0x23D;
/// The game's drop factor getter exe+0x9346d0: `mov rax,[rcx+90h]; movss xmm0,[rax+38h]; ret`.
/// Not called; it pins the +0x90 / +0x38 the cave reads.
const SIG_FACTOR: &str = "48 8B 81 90 00 00 00 F3 0F 10 40 38 C3";
/// Where pickups are scaled (exe+0x196688 and exe+0x196af9): `mov rcx,[r12]` (the BalancingRegistry)
/// `call <getter>`, result into the category gate and scaler. Every match must call SIG_FACTOR's
/// function (rel32 at FACTOR_USE_CALL), which makes it the resourceDropStackAmountFactor getter.
const SIG_FACTOR_USE: &str = "49 8B 0C 24 E8 ?? ?? ?? ?? 48 8B 47 08 0F 28 F0 41 0F B6 8D CC 00 00 00 44 0F B7 60 1A E8";
const FACTOR_USE_CALL: usize = 4;

/// The plant crops the loop can grant (item id, maxStackSize, name), from the 1.0 game data
/// (enshrouded_server.kfc md5 ca4b4201, kfc_resources md5 d4f60990): every Consumables and
/// Materials item in the root DefaultInventory stacks of the 472 templates that take this loop,
/// minus 13 that are not plants: Material_T1_Flame_Essence_Spark, Material_T1_Fog_Core01_ShroudCore,
/// Material_T1_Fog_Essence01_ShroudSpores, Material_T1..T7_Fognest_Ressource, Material_T1_Bones,
/// Material_T1_Animal_Fur_Patch and Consumable_Potion_Health_T1 (only on a base template).
pub const ITEMS: &[(u32, u16, &str)] = &[
    (0xDCF8790D, 20, "Food_T1_raw_fruit_Red_Berries"),
    (0xB9E52CAA, 20, "Food_T1_raw_grain_Corncob"),
    (0xF927BC27, 100, "Food_T1_raw_herb_StJohnsWort"),
    (0x23D06EC5, 20, "Food_T1_raw_mushroom_Mushroom_brown"),
    (0x910C1368, 250, "Food_T1_raw_nightplant_NightLily"),
    (0x3DC85885, 20, "Food_T1_raw_vegetable_Tomato"),
    (0x4DC5E916, 20, "Food_T2_raw_bad_mushroom_AzureRussula"),
    (0xCF65EBD7, 20, "Food_T2_raw_fruit_Strawberry"),
    (0x888C46FD, 100, "Food_T2_raw_herb_StingingNettle"),
    (0xBD24D89C, 250, "Food_T2_raw_nightplant_NightBerry"),
    (0xD32B42E1, 20, "Food_T2_raw_vegetable_ForestBeet"),
    (0xD4577120, 100, "Food_T3_raw_herb_Sage_Leaves"),
    (0x9270781A, 20, "Food_T3_raw_sweets_SugarCane"),
    (0xF40A4E3F, 20, "Food_T3_raw_vegetable_RedPepper"),
    (0x7B1C9FF6, 100, "Food_T4_raw_herb_DevilsClaw"),
    (0x645B00E2, 20, "Food_T5_raw_bad_mushroom_YellowFogMushroom"),
    (0xE1448D02, 100, "Food_T5_raw_herb_Gentian"),
    (0xFC6438AF, 250, "Food_T5_raw_vegetables_Pumpkin"),
    (0x91ECD8D2, 20, "Food_T6_raw_bad_herb_AlgaeBuds"),
    (0x9018EBF2, 20, "Food_T6_raw_bad_vegetable_Taro"),
    (0x300C7868, 20, "Food_T6_raw_herb_Algae"),
    (0xC7F4B939, 20, "Food_T6_raw_mushroom_Shiitake"),
    (0x3086213D, 20, "Food_T6_raw_vegetable_Ginger"),
    (0xC5BD9D64, 20, "Food_T7_raw_bad_vegetable_Beans"),
    (0x4ECB067B, 20, "Food_T7_raw_fruit_Pomegranate"),
    (0xCEA600E9, 20, "Food_T7_raw_herb_Thyme"),
    (0x334C64A4, 250, "Material_T1_MushroomDrop_ShroudLiquid"),
    (0xC5A97B68, 250, "Material_T1_Plant_Fibre"),
    (0x6B356A28, 250, "Material_T1_Twigs"),
    (0xCF5B015A, 250, "Material_T2_Chamomile"),
    (0xE863AF88, 250, "Material_T2_Flax"),
    (0xFEE6A7A9, 250, "Material_T2_Indigo_Plant"),
    (0x05664746, 250, "Material_T3_MushroomDrop_GreenMushroomMeat"),
    (0x8B8DE9ED, 250, "Material_T3_Night_AurumLily"),
    (0x61119BEE, 250, "Material_T3_Rooibos"),
    (0x3E69D113, 250, "Material_T3_ShroudAdhesive"),
    (0xE9BA3050, 250, "Material_T3_Straw"),
    (0x91256DD9, 250, "Material_T3_Wheat_Grains"),
    (0x3D132B37, 250, "Material_T4_Desert_Flower"),
    (0xF3E3D74D, 250, "Material_T4_MushroomDrop_BrittleShroudFlakes"),
    (0x0FF44BE6, 250, "Material_T4_Night_DesertFlower"),
    (0xDC4F0FED, 250, "Material_T4_Saffron"),
    (0x12831338, 250, "Material_T5_Night_Blackflower"),
    (0xD3826A6D, 250, "Material_T5_Night_PinkGentian"),
    (0x50C4BDFD, 250, "Material_T5_Wolfsbane"),
    (0x711B27C8, 250, "Material_T6_Daylily_Flower"),
    (0xCFD0AF9C, 250, "Material_T6_MushroomDrop_PinkMushroomMeat"),
    (0x7FE23ED5, 250, "Material_T6_Night_GleamRoot_under_water"),
    (0xF7442A68, 250, "Material_T6_Night_Passion_Flower_above_water"),
    (0x3D29ABCA, 250, "Material_T6_PaperReed"),
    (0x17AA352C, 250, "Material_T6_raw_CoffeeBeans"),
    (0x8D8CC80B, 250, "Material_T6_raw_Rice"),
];

/// Layout of the harvest page (its own allocation near the image).
pub const PAGE: usize = 0x1000;
pub const CAVE: usize = 0x000;
pub const SETTINGS: usize = 0x200; // u64: GameSettings the cave last read (for the log)
pub const HEAD: usize = 0x208; // u32: stacks seen so far (wraps)
pub const RING: usize = 0x210; // [Entry; RING_LEN]
pub const RING_LEN: usize = 16;
pub const ENTRY: usize = 16; // item u32, countMax u32, given u32, seq u32 (written last)
pub const TABLE: usize = 0x400; // ITEMS as {id u32, maxStackSize u32}
pub const TABLE_END: usize = 0x800;
const GAME_SETTINGS_FACTOR: usize = 0x38;
/// Every stack is logged for this many stacks after a start; after that the first stack of each item.
const VERBOSE_STACKS: u32 = 200;
/// One "N stacks since start" line per this many stacks.
const SUMMARY_EVERY: u32 = 1000;

static INSTALLED_PAGE: AtomicUsize = AtomicUsize::new(0);

#[derive(Debug)]
pub struct Installed {
    pub rva: usize,
    pub page: usize,
    pub items: usize,
}

fn unique(image: &Image, signature: &str, what: &str) -> Result<usize, String> {
    let found = image.find_all(signature);
    match found[..] {
        [at] => Ok(at),
        _ => Err(format!("{what} signature matched {} times", found.len())),
    }
}

fn rel32_target(at: usize) -> usize {
    let rel = unsafe { read::<i32>(at + 1) } as isize;
    (at as isize + 5 + rel) as usize
}

/// Checks everything first, writes the game's code last (one 6-byte write): on any error nothing
/// in the game is changed.
pub fn install(image: &Image) -> Result<Installed, String> {
    let hook = unique(image, SIG, "harvest loop")? + HOOK_OFFSET;
    let ctx = unique(image, SIG_CTX, "harvest context")?;
    if ctx + CTX_TO_HOOK != hook {
        return Err(format!("harvest context at exe+{:#x}, expected {CTX_TO_HOOK:#x} before the hook", image.rva(ctx)));
    }
    let getter = unique(image, SIG_FACTOR, "drop factor getter")?;
    let uses = image.find_all(SIG_FACTOR_USE);
    if uses.is_empty() || uses.iter().any(|&u| rel32_target(u + FACTOR_USE_CALL) != getter) {
        return Err(format!("drop factor getter not confirmed by its callers ({} found)", uses.len()));
    }
    let current: [u8; 6] = unsafe { read(hook) };
    if current != ORIGINAL {
        return Err(format!("unexpected bytes at exe+{:#x}", image.rva(hook)));
    }
    let table = table().ok_or("item table does not fit the page")?;
    let page = alloc_near(image.base, PAGE);
    if page == 0 {
        return Err("no memory within jump range of the image".into());
    }
    let code = cave(page, hook, ITEMS.len()).ok_or("harvest cave out of range")?;
    let patch = jump(hook, page + CAVE).ok_or("harvest jump out of range")?;
    unsafe {
        ptr::copy_nonoverlapping(table.as_ptr(), (page + TABLE) as *mut u8, table.len());
        ptr::copy_nonoverlapping(code.as_ptr(), (page + CAVE) as *mut u8, code.len());
    }
    if !write(hook, &patch) {
        return Err("could not write the hook".into());
    }
    INSTALLED_PAGE.store(page, Ordering::Release);
    Ok(Installed { rva: image.rva(hook), page, items: ITEMS.len() })
}

/// ITEMS as the cave reads them: {id u32, maxStackSize u32} each. None if it would not fit.
fn table() -> Option<Vec<u8>> {
    let bytes: Vec<u8> = ITEMS.iter().flat_map(|&(id, max, _)| id.to_le_bytes().into_iter().chain((max as u32).to_le_bytes())).collect();
    (!ITEMS.is_empty() && TABLE + bytes.len() <= TABLE_END).then_some(bytes)
}

fn rel32(from_end: usize, to: usize) -> Option<[u8; 4]> {
    i32::try_from(to as i64 - from_end as i64).ok().map(i32::to_le_bytes)
}

/// `jmp cave; nop` over the 6 hooked bytes (the nop is never reached: the cave returns to hook+6).
pub fn jump(hook: usize, cave: usize) -> Option<[u8; 6]> {
    let [a, b, c, d] = rel32(hook + 5, cave)?;
    Some([0xE9, a, b, c, d, 0x90])
}

/// The cave at `page + CAVE` for the hook at `hook` (6 bytes, see ORIGINAL), with `items` table
/// entries at `page + TABLE`.
///
/// At the hook: eax = item id, rdi = &stack.countMax, rdx/r8/r9 = add_item arguments, rbp = the
/// system's frame, [rsp+28h] = add_item's count argument. rcx, r10, r11, xmm0, xmm1 and the flags
/// are dead there (rcx is reloaded at hook+6; nothing reads the others before the call, which
/// clobbers them). The cave uses only those, never touches the stack except [rsp+28h] (which the
/// original writes) and calls nothing.
pub fn cave(page: usize, hook: usize, items: usize) -> Option<Vec<u8>> {
    let at = page + CAVE;
    let items = u32::try_from(items).ok().filter(|&n| n > 0)?;
    let mut c: Vec<u8> = Vec::with_capacity(0x100);
    let mut to_store: Vec<usize> = Vec::new();
    let jcc_store = |c: &mut Vec<u8>, to_store: &mut Vec<usize>, op: u8| {
        c.extend([0x0F, op]);
        to_store.push(c.len());
        c.extend([0; 4]);
    };
    c.extend([0x8B, 0x0F]); // mov ecx,[rdi]                 count = countMax (original)
    c.extend([0x85, 0xC9]); // test ecx,ecx
    jcc_store(&mut c, &mut to_store, 0x84); // je store
    c.extend([0x4C, 0x8D, 0x15]); // lea r10,[rip+TABLE]
    c.extend(rel32(at + c.len() + 4, page + TABLE)?);
    c.extend([0x41, 0xBB]); // mov r11d,items
    c.extend(items.to_le_bytes());
    let find = c.len();
    c.extend([0x41, 0x3B, 0x02]); // find: cmp eax,[r10]
    let je_hit = c.len();
    c.extend([0x74, 0x00]); // je hit (rel8, set below)
    c.extend([0x49, 0x83, 0xC2, 0x08]); // add r10,8
    c.extend([0x41, 0xFF, 0xCB]); // dec r11d
    c.extend([0x75, (find as isize - (c.len() + 2) as isize) as i8 as u8]); // jne find
    c.push(0xE9); // jmp store                               not a listed crop
    to_store.push(c.len());
    c.extend([0; 4]);
    c[je_hit + 1] = u8::try_from(c.len() - (je_hit + 2)).ok()?;
    c.extend([0x45, 0x8B, 0x5A, 0x04]); // hit: mov r11d,[r10+4]  maxStackSize
    c.extend([0x4C, 0x8B, 0x95, 0xF8, 0x00, 0x00, 0x00]); // mov r10,[rbp+0F8h]  BalancingRegistry
    c.extend([0x4D, 0x85, 0xD2]); // test r10,r10
    jcc_store(&mut c, &mut to_store, 0x84);
    c.extend([0x4D, 0x8B, 0x92, 0x90, 0x00, 0x00, 0x00]); // mov r10,[r10+90h]  GameSettings
    c.extend([0x4D, 0x85, 0xD2]); // test r10,r10
    jcc_store(&mut c, &mut to_store, 0x84);
    c.extend([0x4C, 0x89, 0x15]); // mov [rip+SETTINGS],r10
    c.extend(rel32(at + c.len() + 4, page + SETTINGS)?);
    c.extend([0xF3, 0x41, 0x0F, 0x10, 0x4A, GAME_SETTINGS_FACTOR as u8]); // movss xmm1,[r10+38h]  factor
    c.extend([0x0F, 0x57, 0xC0]); // xorps xmm0,xmm0
    c.extend([0x0F, 0x2F, 0xC8]); // comiss xmm1,xmm0
    jcc_store(&mut c, &mut to_store, 0x86); // jbe store                factor <= 0 or NaN
    c.extend([0x41, 0x39, 0xCB]); // cmp r11d,ecx
    c.extend([0x44, 0x0F, 0x42, 0xD9]); // cmovb r11d,ecx       bound = max(maxStackSize, count)
    c.extend([0xF3, 0x0F, 0x2A, 0xC1]); // cvtsi2ss xmm0,ecx
    c.extend([0xF3, 0x0F, 0x59, 0xC1]); // mulss xmm0,xmm1      count * factor
    c.extend([0x41, 0xBA, 0x00, 0x00, 0x00, 0x3F]); // mov r10d,3F000000h  0.5f
    c.extend([0x66, 0x41, 0x0F, 0x6E, 0xCA]); // movd xmm1,r10d
    c.extend([0xF3, 0x0F, 0x58, 0xC1]); // addss xmm0,xmm1      + 0.5
    c.extend([0xF3, 0x41, 0x0F, 0x2A, 0xCB]); // cvtsi2ss xmm1,r11d
    c.extend([0xF3, 0x0F, 0x5D, 0xC1]); // minss xmm0,xmm1      at most the bound: no overflow below
    c.extend([0xF3, 0x44, 0x0F, 0x2C, 0xD0]); // cvttss2si r10d,xmm0  round half up
    c.extend([0x41, 0x83, 0xFA, 0x01]); // cmp r10d,1
    c.extend([0x73, 0x06]); // jae +6
    c.extend([0x41, 0xBA, 0x01, 0x00, 0x00, 0x00]); // mov r10d,1      at least 1
    c.extend([0x44, 0x89, 0xD1]); // mov ecx,r10d             new count
    let store = c.len();
    for &p in &to_store {
        c[p..p + 4].copy_from_slice(&i32::try_from(store - (p + 4)).ok()?.to_le_bytes());
    }
    c.extend([0x89, 0x4C, 0x24, 0x28]); // store: mov [rsp+28h],ecx  (original)
    c.extend([0x41, 0xBA, 0x01, 0x00, 0x00, 0x00]); // mov r10d,1
    c.extend([0xF0, 0x44, 0x0F, 0xC1, 0x15]); // lock xadd [rip+HEAD],r10d  r10d = this stack's index
    c.extend(rel32(at + c.len() + 4, page + HEAD)?);
    c.extend([0x45, 0x8D, 0x5A, 0x01]); // lea r11d,[r10+1]     seq = index + 1
    c.extend([0x41, 0x83, 0xE2, (RING_LEN - 1) as u8]); // and r10d,RING_LEN-1
    c.extend([0x41, 0xC1, 0xE2, ENTRY.trailing_zeros() as u8]); // shl r10d,4
    c.extend([0x48, 0x8D, 0x0D]); // lea rcx,[rip+RING]
    c.extend(rel32(at + c.len() + 4, page + RING)?);
    c.extend([0x4C, 0x01, 0xD1]); // add rcx,r10
    c.extend([0x89, 0x01]); // mov [rcx],eax                 item
    c.extend([0x44, 0x8B, 0x17]); // mov r10d,[rdi]           countMax
    c.extend([0x44, 0x89, 0x51, 0x04]); // mov [rcx+4],r10d
    c.extend([0x44, 0x8B, 0x54, 0x24, 0x28]); // mov r10d,[rsp+28h]  count given
    c.extend([0x44, 0x89, 0x51, 0x08]); // mov [rcx+8],r10d
    c.extend([0x44, 0x89, 0x59, 0x0C]); // mov [rcx+0Ch],r11d   seq, last
    c.push(0xE9); // jmp hook+6
    c.extend(rel32(at + c.len() + 4, hook + ORIGINAL.len())?);
    (CAVE + c.len() <= SETTINGS).then_some(c)
}

/// One stack the hook saw: its sequence number (1 = first since start), item id, the game's
/// count (countMax) and the count given.
#[derive(Debug, PartialEq)]
pub struct Entry {
    pub seq: u32,
    pub item: u32,
    pub count: u32,
    pub given: u32,
}

#[derive(Debug, Default, PartialEq)]
pub struct Taken {
    pub entries: Vec<Entry>,
    /// Stacks that were overwritten before they could be read.
    pub dropped: u32,
}

fn cell(page: usize, offset: usize) -> u32 {
    unsafe { ptr::read_volatile((page + offset) as *const u32) }
}

/// New ring entries of the page at `page` since `tail` (oldest first). An entry is taken only when
/// its sequence number is tail + 1, before and after its fields are read; nothing is ever cleared.
fn take_from(page: usize, tail: &mut u32) -> Taken {
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
                taken.dropped += 1; // a later stack already reused the slot
                *tail = want;
                continue;
            }
            break; // claimed but not written yet: next poll
        }
        let entry = Entry { seq, item: cell(page, at), count: cell(page, at + 4), given: cell(page, at + 8) };
        if cell(page, at + 12) != want {
            taken.dropped += 1; // overwritten while being read
        } else {
            taken.entries.push(entry);
        }
        *tail = want;
    }
    taken
}

/// resourceDropStackAmountFactor through the GameSettings pointer the cave last stored.
fn factor_at(page: usize) -> Option<f32> {
    let settings = unsafe { ptr::read_volatile((page + SETTINGS) as *const usize) };
    let bytes = safe_read(settings.checked_add(GAME_SETTINGS_FACTOR)?, 4)?;
    Some(f32::from_le_bytes(bytes[..4].try_into().ok()?))
}

pub fn item_name(id: u32) -> Option<&'static str> {
    ITEMS.iter().find(|&&(i, _, _)| i == id).map(|&(_, _, name)| name)
}

/// What the log thread remembers between polls.
#[derive(Default)]
pub struct LogState {
    tail: u32,
    items: HashSet<u32>,
    summarized: u32,
}

/// Log lines for the stacks granted since the last call (empty if the hook is not installed).
pub fn poll(state: &mut LogState) -> Vec<String> {
    match INSTALLED_PAGE.load(Ordering::Acquire) {
        0 => Vec::new(),
        page => poll_page(page, state),
    }
}

fn poll_page(page: usize, state: &mut LogState) -> Vec<String> {
    let taken = take_from(page, &mut state.tail);
    let mut lines = Vec::new();
    for e in &taken.entries {
        let first = state.items.insert(e.item);
        if e.seq <= VERBOSE_STACKS || first {
            let what = match item_name(e.item) {
                Some(name) => {
                    let factor = factor_at(page).map_or("?".into(), |f| format!("{f:.2}"));
                    format!("{name} (factor {factor})")
                }
                None => "not a listed crop, unchanged".into(),
            };
            lines.push(format!("harvest: stack {}: item {:#010x} count {} -> {} requested ({what})", e.seq, e.item, e.count, e.given));
        }
    }
    if taken.dropped > 0 {
        lines.push(format!("harvest: {} stack(s) not logged (more than {RING_LEN} between two polls)", taken.dropped));
    }
    let head = cell(page, HEAD);
    if head / SUMMARY_EVERY != state.summarized / SUMMARY_EVERY {
        lines.push(format!("harvest: {head} stacks since start"));
    }
    state.summarized = head;
    lines
}

/// What the cave computes (the reference model for the tests).
#[cfg(test)]
pub fn scaled(count: u32, factor: f32, item: u32) -> u32 {
    let Some(&(_, max_stack, _)) = ITEMS.iter().find(|&&(i, _, _)| i == item) else { return count };
    if count == 0 || !(factor > 0.0) {
        return count;
    }
    let bound = (max_stack as u32).max(count);
    let x = (count as i32 as f32 * factor + 0.5).min(bound as i32 as f32);
    (x as u32).max(1)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::{matches, parse_signature};

    const PAGE_AT: usize = 0x1_3FFF_0000;
    const HOOK: usize = 0x1_4019_EFD3;
    const RED_BERRIES: u32 = 0xDCF8_790D;
    const PLANT_FIBRE: u32 = 0xC5A9_7B68;
    const TWIGS: u32 = 0x6B35_6A28;
    const TOMATO_SEEDLING: u32 = 0x55C4_687E; // BuildTools: a planted seedling picked up unripe
    const NOT_PLANTS: [u32; 13] = [
        0x5B93_29B8, 0x5B1C_6F3A, 0x9894_6174, 0x6A40_E93A, 0x4EE1_9490, 0xEA2B_EB3F, 0xD448_0073, 0xE525_6405,
        0x18E4_EB33, 0x7F4A_B528, 0x7A64_07EA, 0x2766_7708, 0xCCD4_6F7A,
    ];

    /// Hand-encoded, disassembled with capstone at these addresses (design-harvest-v2/cave2.py) with 52 items.
    const GOLDEN: &str = "8b 0f 85 c9 0f 84 98 00 00 00 4c 8d 15 ef 03 00 00 41 bb 34 00 00 00 41 3b 02 74 0e \
        49 83 c2 08 41 ff cb 75 f2 e9 78 00 00 00 45 8b 5a 04 4c 8b 95 f8 00 00 00 4d 85 d2 0f 84 64 00 00 00 \
        4d 8b 92 90 00 00 00 4d 85 d2 0f 84 54 00 00 00 4c 89 15 ab 01 00 00 f3 41 0f 10 4a 38 0f 57 c0 0f 2f \
        c8 0f 86 3b 00 00 00 41 39 cb 44 0f 42 d9 f3 0f 2a c1 f3 0f 59 c1 41 ba 00 00 00 3f 66 41 0f 6e ca f3 \
        0f 58 c1 f3 41 0f 2a cb f3 0f 5d c1 f3 44 0f 2c d0 41 83 fa 01 73 06 41 ba 01 00 00 00 44 89 d1 89 4c \
        24 28 41 ba 01 00 00 00 f0 44 0f c1 15 53 01 00 00 45 8d 5a 01 41 83 e2 0f 41 c1 e2 04 48 8d 0d 48 01 \
        00 00 4c 01 d1 89 01 44 8b 17 44 89 51 04 44 8b 54 24 28 44 89 51 08 44 89 59 0c e9 f3 ee 1a 00";

    fn target(code: &[u8], rel_at: usize) -> usize {
        let rel = i32::from_le_bytes(code[rel_at..rel_at + 4].try_into().unwrap()) as i64;
        ((PAGE_AT + CAVE + rel_at + 4) as i64 + rel) as usize
    }

    #[test]
    fn signatures_and_original() {
        for s in [SIG, SIG_CTX, SIG_FACTOR, SIG_FACTOR_USE] {
            assert!(parse_signature(s).is_some(), "{s}");
        }
        let pattern = parse_signature(SIG).unwrap();
        let original: Vec<Option<u8>> = ORIGINAL.iter().map(|&b| Some(b)).collect();
        assert_eq!(&pattern[HOOK_OFFSET..HOOK_OFFSET + 6], &original[..]);
        assert_eq!(pattern.last(), Some(&Some(0xE8))); // ends at `call add_item`
        let uses = parse_signature(SIG_FACTOR_USE).unwrap();
        assert_eq!(uses[FACTOR_USE_CALL], Some(0xE8));
    }

    #[test]
    fn items_table() {
        assert_eq!(ITEMS.len(), 52);
        let ids: HashSet<u32> = ITEMS.iter().map(|&(id, _, _)| id).collect();
        assert_eq!(ids.len(), ITEMS.len(), "duplicate id");
        assert!(!ids.contains(&0));
        assert!(ITEMS.iter().all(|&(_, max, name)| max >= 20 && !name.is_empty()));
        for id in [RED_BERRIES, PLANT_FIBRE, TWIGS] {
            assert!(ids.contains(&id), "{id:#x}");
        }
        for id in NOT_PLANTS.iter().chain([&TOMATO_SEEDLING]) {
            assert!(!ids.contains(id), "{id:#x} must keep the game's count");
        }
        let t = table().unwrap();
        assert_eq!(t.len(), ITEMS.len() * 8);
        assert!(TABLE + t.len() <= TABLE_END);
        assert_eq!(&t[..8], &[0x0D, 0x79, 0xF8, 0xDC, 20, 0, 0, 0]);
    }

    #[test]
    fn golden_bytes() {
        let code = cave(PAGE_AT, HOOK, ITEMS.len()).unwrap();
        let golden: Vec<u8> = GOLDEN.split_whitespace().map(|t| u8::from_str_radix(t, 16).unwrap()).collect();
        assert_eq!(code, golden);
    }

    #[test]
    fn targets() {
        let code = cave(PAGE_AT, HOOK, ITEMS.len()).unwrap();
        assert_eq!(code.len(), 0xE6);
        assert!(CAVE + code.len() <= SETTINGS);
        assert_eq!(&code[..2], &ORIGINAL[..2]);
        let store = 0xA2;
        assert_eq!(&code[store..store + 4], &ORIGINAL[2..]);
        for p in [0x06, 0x26, 0x3A, 0x4A, 0x63] {
            assert_eq!(target(&code, p), PAGE_AT + CAVE + store, "fixup at {p:#x}");
        }
        assert_eq!(target(&code, 0x0D), PAGE_AT + TABLE);
        assert_eq!(u32::from_le_bytes(code[0x13..0x17].try_into().unwrap()), ITEMS.len() as u32);
        assert_eq!(&code[0x1A..0x1C], &[0x74, 0x0E]); // je hit (0x2A)
        assert_eq!(&code[0x23..0x25], &[0x75, 0xF2]); // jne find (0x17)
        assert_eq!(target(&code, 0x51), PAGE_AT + SETTINGS);
        assert_eq!(target(&code, 0xB1), PAGE_AT + HEAD);
        assert_eq!(target(&code, 0xC4), PAGE_AT + RING);
        assert_eq!(target(&code, code.len() - 4), HOOK + 6);
        assert!(RING + RING_LEN * ENTRY <= TABLE && TABLE_END <= PAGE);
        assert!(!code.contains(&0xE8), "the cave must not call anything");
        let patch = jump(HOOK, PAGE_AT + CAVE).unwrap();
        assert_eq!(patch, [0xE9, 0x28, 0x10, 0xE5, 0xFF, 0x90]); // jmp 0x13fff0000 from 0x14019efd3 (capstone)
        assert!(jump(0x1_4000_0000, 0x7FF0_0000_0000).is_none());
        assert!(cave(PAGE_AT, HOOK, 0).is_none());
    }

    #[test]
    fn scaled_model() {
        assert_eq!(scaled(2, 2.0, RED_BERRIES), 4); // server 2
        assert_eq!(scaled(2, 4.0, RED_BERRIES), 8); // server 1
        assert_eq!(scaled(4, 2.0, PLANT_FIBRE), 8);
        assert_eq!(scaled(1, 2.0, TOMATO_SEEDLING), 1);
        assert_eq!(scaled(3, 2.0, NOT_PLANTS[0]), 3); // flame essence
        assert_eq!(scaled(3, 1.5, RED_BERRIES), 5); // 4.5 rounds up
        assert_eq!(scaled(2, 0.1, RED_BERRIES), 1); // at least 1
        assert_eq!(scaled(15, 2.0, RED_BERRIES), 20); // one stack
        assert_eq!(scaled(25, 2.0, RED_BERRIES), 25); // never below the game's own count
        assert_eq!(scaled(2, 1e30, RED_BERRIES), 20);
        assert_eq!(scaled(2, f32::INFINITY, RED_BERRIES), 20);
        assert_eq!(scaled(2, f32::NAN, RED_BERRIES), 2);
        assert_eq!(scaled(2, 0.0, RED_BERRIES), 2);
        assert_eq!(scaled(0, 2.0, RED_BERRIES), 0);
    }

    /// A fake harvest page for the ring reader (8-byte aligned, like the real page).
    struct FakePage(Box<[u64; PAGE / 8]>);

    impl FakePage {
        fn new() -> FakePage {
            FakePage(Box::new([0; PAGE / 8]))
        }
        fn at(&self) -> usize {
            self.0.as_ptr() as usize
        }
        fn get(&self, offset: usize) -> u32 {
            unsafe { ptr::read_volatile((self.at() + offset) as *const u32) }
        }
        fn set(&mut self, offset: usize, value: u32) {
            unsafe { ptr::write_volatile((self.at() + offset) as *mut u32, value) };
        }
        /// Writes stack `seq`'s entry (seq = index + 1, into slot index % RING_LEN), seq last.
        fn write_entry(&mut self, seq: u32, item: u32, count: u32, given: u32) {
            let at = RING + (seq.wrapping_sub(1) as usize % RING_LEN) * ENTRY;
            self.set(at, item);
            self.set(at + 4, count);
            self.set(at + 8, given);
            self.set(at + 12, seq);
        }
        /// What the cave does for one stack: claim the next index (head), then write the entry.
        fn push(&mut self, item: u32, count: u32, given: u32) {
            let seq = self.get(HEAD).wrapping_add(1);
            self.set(HEAD, seq);
            self.write_entry(seq, item, count, given);
        }
    }

    #[test]
    fn take_in_order_and_waits_for_unwritten() {
        let mut p = FakePage::new();
        let mut tail = 0;
        assert_eq!(take_from(p.at(), &mut tail), Taken::default());
        p.push(RED_BERRIES, 2, 4);
        p.push(PLANT_FIBRE, 4, 8);
        let t = take_from(p.at(), &mut tail);
        assert_eq!(t.dropped, 0);
        assert_eq!(t.entries, vec![Entry { seq: 1, item: RED_BERRIES, count: 2, given: 4 }, Entry { seq: 2, item: PLANT_FIBRE, count: 4, given: 8 }]);
        assert_eq!(tail, 2);
        // Stack 3 claimed (head moved) but not written yet: nothing, and the tail stays.
        p.set(HEAD, 3);
        assert_eq!(take_from(p.at(), &mut tail), Taken::default());
        assert_eq!(tail, 2);
        p.write_entry(3, TWIGS, 2, 4);
        let t = take_from(p.at(), &mut tail);
        assert_eq!(t.entries, vec![Entry { seq: 3, item: TWIGS, count: 2, given: 4 }]);
        // Nothing is cleared, and reading again from the same tail gives nothing new.
        assert_eq!(take_from(p.at(), &mut tail), Taken::default());
        assert_eq!(p.get(RING + 12), 1);
    }

    #[test]
    fn take_overflow_counts_dropped() {
        let mut p = FakePage::new();
        let mut tail = 0;
        for n in 0..40 {
            p.push(RED_BERRIES, 2, n);
        }
        let t = take_from(p.at(), &mut tail);
        assert_eq!(t.dropped, 24);
        assert_eq!(t.entries.len(), 16);
        assert_eq!((t.entries[0].seq, t.entries[15].seq), (25, 40));
        assert_eq!(t.entries[0].given, 24);
        assert_eq!(tail, 40);
    }

    #[test]
    fn take_skips_a_slot_reused_by_a_later_stack() {
        let mut p = FakePage::new();
        let mut tail = 0;
        p.push(RED_BERRIES, 2, 4); // stack 1
        p.set(HEAD, 2); // stack 2 claimed, its writer stalls
        assert_eq!(take_from(p.at(), &mut tail).entries.len(), 1);
        assert_eq!(tail, 1);
        for seq in 3..=17 {
            p.set(HEAD, seq);
            p.write_entry(seq, PLANT_FIBRE, 4, 8); // stack 17 reuses stack 1's slot
        }
        // 16 behind: stack 2 is still awaited.
        assert_eq!(take_from(p.at(), &mut tail), Taken::default());
        // Stack 18 reuses stack 2's slot: stack 2 is counted as lost and the rest follow.
        p.set(HEAD, 18);
        p.write_entry(18, TWIGS, 2, 4);
        let t = take_from(p.at(), &mut tail);
        assert_eq!(t.dropped, 1);
        assert_eq!(t.entries.iter().map(|e| e.seq).collect::<Vec<_>>(), (3..=18).collect::<Vec<_>>());
        assert_eq!(tail, 18);
        // A slot already holding a later stack than the one wanted (written after head was read).
        let mut tail = 18;
        p.set(HEAD, 19);
        p.write_entry(35, TWIGS, 2, 4); // stack 35 lands in stack 19's slot
        let t = take_from(p.at(), &mut tail);
        assert_eq!((t.entries.len(), t.dropped, tail), (0, 1, 19));
    }

    #[test]
    fn take_wraps_at_u32_max() {
        let mut p = FakePage::new();
        p.set(HEAD, u32::MAX - 1);
        let mut tail = u32::MAX - 1;
        for _ in 0..3 {
            p.push(TWIGS, 1, 2);
        }
        let t = take_from(p.at(), &mut tail);
        assert_eq!(t.entries.iter().map(|e| e.seq).collect::<Vec<_>>(), vec![u32::MAX, 0, 1]);
        assert_eq!((t.dropped, tail), (0, 1));
    }

    #[test]
    fn log_lines() {
        let mut p = FakePage::new();
        let mut settings = Box::new([0u8; 0x40]);
        settings[0x38..0x3C].copy_from_slice(&2.0f32.to_le_bytes());
        unsafe { ptr::write((p.at() + SETTINGS) as *mut usize, settings.as_ptr() as usize) };
        let mut state = LogState::default();
        p.push(RED_BERRIES, 2, 4);
        p.push(TOMATO_SEEDLING, 1, 1);
        let lines = poll_page(p.at(), &mut state);
        assert_eq!(lines, vec![
            "harvest: stack 1: item 0xdcf8790d count 2 -> 4 requested (Food_T1_raw_fruit_Red_Berries (factor 2.00))".to_string(),
            "harvest: stack 2: item 0x55c4687e count 1 -> 1 requested (not a listed crop, unchanged)".to_string(),
        ]);
        // After VERBOSE_STACKS only the first stack of each item is logged, plus the summary.
        p.set(HEAD, 998);
        state.tail = 998;
        state.summarized = 998;
        p.push(RED_BERRIES, 2, 4); // 999: berries seen before
        p.push(PLANT_FIBRE, 4, 8); // 1000: first fibre
        let lines = poll_page(p.at(), &mut state);
        assert_eq!(lines, vec![
            "harvest: stack 1000: item 0xc5a97b68 count 4 -> 8 requested (Material_T1_Plant_Fibre (factor 2.00))".to_string(),
            "harvest: 1000 stacks since start".to_string(),
        ]);
        for _ in 0..20 {
            p.push(TWIGS, 2, 4);
        }
        let lines = poll_page(p.at(), &mut state);
        assert!(lines.iter().any(|l| l.contains("4 stack(s) not logged")), "{lines:?}");
    }

    /// A server build kept in the repo: (folder under reference/, PE timestamp, hook rva, factor
    /// getter rva, its two pickup callers' SIG_FACTOR_USE rvas).
    struct Build {
        dir: &'static str,
        timestamp: u32,
        hook: usize,
        getter: usize,
        uses: [usize; 2],
    }
    const BUILDS: [Build; 3] = [
        // 1.0, SVN 1267041
        Build { dir: "server-1267041", timestamp: 0x6AD1_0810, hook: 0x19EFD3, getter: 0x9346D0, uses: [0x196688, 0x196AF9] },
        // 1.0.0.2 hotfix, SVN 1269579 (Steam build 25988414)
        Build { dir: "server-1269579", timestamp: 0x6AD2_025E, hook: 0x19F0E3, getter: 0x934DE0, uses: [0x196798, 0x196C09] },
        // 1.0.0.3, SVN 1273043 (Steam build 26083076)
        Build { dir: "server-1273043", timestamp: 0x6AD7_7F14, hook: 0x19FF93, getter: 0x937430, uses: [0x197648, 0x197AB9] },
    ];

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
        for b in &BUILDS {
            let Some(path) = reference_path(b.dir) else { continue };
            let exe = std::fs::read(&path).unwrap();
            let nt = u32::from_le_bytes(exe[0x3C..0x40].try_into().unwrap()) as usize;
            assert_eq!(u32::from_le_bytes(exe[nt + 8..nt + 12].try_into().unwrap()), b.timestamp, "{}: not that build's exe", b.dir);
            let find = |s: &str| {
                let p = parse_signature(s).unwrap();
                (0..exe.len() - p.len()).filter(|&i| matches(&p, &exe[i..])).collect::<Vec<_>>()
            };
            let (sig, ctx, getter, uses) = (find(SIG), find(SIG_CTX), find(SIG_FACTOR), find(SIG_FACTOR_USE));
            assert_eq!((sig.len(), ctx.len(), getter.len(), uses.len()), (1, 1, 1, 2), "{}", b.dir);
            assert_eq!(ctx[0] + CTX_TO_HOOK, sig[0] + HOOK_OFFSET);
            assert_eq!(&exe[sig[0] + HOOK_OFFSET..sig[0] + HOOK_OFFSET + 6], &ORIGINAL);
            // .text: file offset = rva - 0xC00 in both builds (rva 0x1000, raw 0x400)
            assert_eq!(sig[0] + HOOK_OFFSET + 0xC00, b.hook, "{}", b.dir);
            assert_eq!(getter[0] + 0xC00, b.getter, "{}", b.dir);
            assert_eq!(uses.iter().map(|u| u + 0xC00).collect::<Vec<_>>(), b.uses.to_vec(), "{}", b.dir);
            for u in uses {
                let at = u + FACTOR_USE_CALL;
                let rel = i32::from_le_bytes(exe[at + 1..at + 5].try_into().unwrap()) as isize;
                assert_eq!((at as isize + 5 + rel) as usize, getter[0]);
            }
        }
    }

    /// install() on every reference exe mapped as an image in this test process (not run): finds
    /// everything, writes the table, the cave and the jump; a second install finds the loop changed
    /// and does nothing. Each exe is its own module (different path), so the builds do not meet.
    #[cfg(windows)]
    #[test]
    fn install_on_mapped_reference_exe() {
        use std::os::windows::ffi::OsStrExt;
        use windows_sys::Win32::System::LibraryLoader::{DONT_RESOLVE_DLL_REFERENCES, LoadLibraryExW};
        for b in &BUILDS {
            let Some(path) = reference_path(b.dir) else { continue };
            let wide: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
            let module = unsafe { LoadLibraryExW(wide.as_ptr(), ptr::null_mut(), DONT_RESOLVE_DLL_REFERENCES) };
            assert!(!module.is_null());
            let image = unsafe { Image::from_base(module as usize) };
            assert_eq!(image.timestamp, b.timestamp, "{}", b.dir);
            let done = install(&image).unwrap();
            assert_eq!((done.rva, done.items), (b.hook, ITEMS.len()), "{}", b.dir);
            let hook = image.base + done.rva;
            let patch: [u8; 6] = unsafe { read(hook) };
            assert_eq!(patch, jump(hook, done.page + CAVE).unwrap());
            let expected = cave(done.page, hook, ITEMS.len()).unwrap();
            let written = unsafe { std::slice::from_raw_parts((done.page + CAVE) as *const u8, expected.len()) };
            assert_eq!(written, &expected[..]);
            let t = table().unwrap();
            let written = unsafe { std::slice::from_raw_parts((done.page + TABLE) as *const u8, t.len()) };
            assert_eq!(written, &t[..]);
            assert!(install(&image).unwrap_err().contains("matched 0 times"));
        }
    }

    /// Runs the real cave on this CPU against a fake frame and settings, with the real item table.
    #[cfg(all(target_arch = "x86_64", windows))]
    mod run {
        use super::super::*;
        use super::{NOT_PLANTS, PLANT_FIBRE, RED_BERRIES, TOMATO_SEEDLING, TWIGS};
        use std::arch::asm;

        struct Out {
            count: u32,
            rax: u64,
            rdx: u64,
            r8: u64,
            r9: u64,
            rdi: u64,
            stack: [u64; 9],
        }

        const CANARY: u64 = 0x0C0F_FEE0_0C0F_FEE0;

        /// Enters the cave the way the game does: rsp 16-aligned, [rsp+28h] the count slot, the rest
        /// of the frame full of canaries. `hook + 6` holds a `ret`, which returns here.
        fn enter(cave_at: usize, frame: *const u8, item: u32, count_ptr: *const u32) -> Out {
            let (mut rax, mut rdx, mut r8, mut r9) = (0xAAAA_0000_0000_0000u64 | item as u64, 0x1111_2222_3333_4444u64, 0x5555_6666_7777_8888u64, 0x9999_AAAA_BBBB_CCCCu64);
            let mut rdi = count_ptr as u64;
            let mut stack = [0u64; 9];
            unsafe {
                asm!(
                    "push rbp",
                    "mov rbp, rsi",
                    "mov r12, rsp",
                    "and rsp, -16",
                    "sub rsp, 0x48",
                    "mov r15, {canary}",
                    "mov [rsp], r15", "mov [rsp + 0x08], r15", "mov [rsp + 0x10], r15", "mov [rsp + 0x18], r15",
                    "mov [rsp + 0x20], r15", "mov [rsp + 0x28], r15", "mov [rsp + 0x30], r15", "mov [rsp + 0x38], r15",
                    "mov [rsp + 0x40], r15",
                    "mov dword ptr [rsp + 0x20], 0xDEADBEEF",
                    "call r14",
                    "mov r15, rax",
                    "mov rax, [rsp]", "mov [r13], rax", "mov rax, [rsp + 0x08]", "mov [r13 + 0x08], rax",
                    "mov rax, [rsp + 0x10]", "mov [r13 + 0x10], rax", "mov rax, [rsp + 0x18]", "mov [r13 + 0x18], rax",
                    "mov rax, [rsp + 0x20]", "mov [r13 + 0x20], rax", "mov rax, [rsp + 0x28]", "mov [r13 + 0x28], rax",
                    "mov rax, [rsp + 0x30]", "mov [r13 + 0x30], rax", "mov rax, [rsp + 0x38]", "mov [r13 + 0x38], rax",
                    "mov rax, [rsp + 0x40]", "mov [r13 + 0x40], rax",
                    "mov rax, r15",
                    "mov rsp, r12",
                    "pop rbp",
                    canary = const CANARY,
                    in("rsi") frame,
                    in("r14") cave_at,
                    in("r13") stack.as_mut_ptr(),
                    inout("rax") rax,
                    inout("rdx") rdx,
                    inout("r8") r8,
                    inout("r9") r9,
                    inout("rdi") rdi,
                    out("r12") _,
                    out("r15") _,
                    clobber_abi("system"),
                );
            }
            Out { count: stack[4] as u32, rax, rdx, r8, r9, rdi, stack }
        }

        #[test]
        fn cave_runs() {
            let mut settings = Box::new([0u8; 0x40]);
            let mut balancing = Box::new([0u8; 0x100]);
            balancing[0x90..0x98].copy_from_slice(&(settings.as_ptr() as u64).to_le_bytes());
            let mut frame = Box::new([0u8; 0x200]);
            frame[0xF8..0x100].copy_from_slice(&(balancing.as_ptr() as u64).to_le_bytes());

            let page = alloc_near(cave_runs as usize, PAGE);
            assert_ne!(page, 0);
            let landing = page + 0xF00;
            unsafe { *(landing as *mut u8) = 0xC3 };
            let code = cave(page, landing - 6, ITEMS.len()).unwrap();
            let t = table().unwrap();
            unsafe {
                ptr::copy_nonoverlapping(t.as_ptr(), (page + TABLE) as *mut u8, t.len());
                ptr::copy_nonoverlapping(code.as_ptr(), (page + CAVE) as *mut u8, code.len());
            }
            let rice = ITEMS[ITEMS.len() - 1].0; // last table entry
            let cases: &[(u32, u32, f32, u32)] = &[
                (RED_BERRIES, 2, 2.0, 4),
                (RED_BERRIES, 2, 4.0, 8),
                (PLANT_FIBRE, 4, 2.0, 8),
                (TWIGS, 2, 2.0, 4),
                (rice, 1, 2.0, 2),
                (PLANT_FIBRE, 3, 1.5, 5),
                (RED_BERRIES, 15, 2.0, 20),
                (RED_BERRIES, 25, 2.0, 25),
                (RED_BERRIES, 2, 0.1, 1),
                (RED_BERRIES, 2, 1e30, 20),
                (RED_BERRIES, 2, f32::INFINITY, 20),
                (RED_BERRIES, 2, 0.0, 2),
                (RED_BERRIES, 2, -1.0, 2),
                (RED_BERRIES, 2, f32::NAN, 2),
                (RED_BERRIES, 0, 2.0, 0),
                (TOMATO_SEEDLING, 1, 2.0, 1),
                (NOT_PLANTS[0], 3, 2.0, 3),
                (NOT_PLANTS[3], 10, 2.0, 10),
                (0x0BAD_0BAD, 3, 2.0, 3),
                (0, 3, 2.0, 3),
            ];
            for (n, &(item, count, factor, want)) in cases.iter().enumerate() {
                assert_eq!(scaled(count, factor, item), want, "model, case {n}");
                settings[0x38..0x3C].copy_from_slice(&factor.to_le_bytes());
                let stack: [u32; 10] = [0, 0, 0, 0, item, 1, count, 0, 0, 0]; // item +0x10, countMax +0x18
                let head = unsafe { ptr::read_volatile((page + HEAD) as *const u32) };
                let out = enter(page + CAVE, frame.as_ptr(), item, &stack[6]);
                assert_eq!(out.count, want, "case {n}: item {item:#x} count {count} factor {factor}");
                assert_eq!(out.rax, 0xAAAA_0000_0000_0000 | item as u64, "rax");
                assert_eq!((out.rdx, out.r8, out.r9), (0x1111_2222_3333_4444, 0x5555_6666_7777_8888, 0x9999_AAAA_BBBB_CCCC));
                assert_eq!(out.rdi, &stack[6] as *const u32 as u64);
                for (i, &q) in out.stack.iter().enumerate() {
                    if i != 4 {
                        assert_eq!(q, CANARY, "stack qword {i} changed, case {n}");
                    }
                }
                assert_eq!(out.stack[4] >> 32, CANARY >> 32, "only the low dword of [rsp+28h] is written");
                let e = page + RING + (head as usize % RING_LEN) * ENTRY;
                let f = |o: usize| unsafe { ptr::read_volatile((e + o) as *const u32) };
                assert_eq!((f(0), f(4), f(8), f(12)), (item, count, want, head.wrapping_add(1)), "ring entry, case {n}");
                assert_eq!(unsafe { ptr::read_volatile((page + HEAD) as *const u32) }, head.wrapping_add(1));
            }
            let seen = unsafe { ptr::read_volatile((page + SETTINGS) as *const u64) };
            assert_eq!(seen, settings.as_ptr() as u64);
            // a missing GameSettings or BalancingRegistry leaves the count alone
            settings[0x38..0x3C].copy_from_slice(&2.0f32.to_le_bytes());
            balancing[0x90..0x98].copy_from_slice(&0u64.to_le_bytes());
            let stack: [u32; 10] = [0, 0, 0, 0, RED_BERRIES, 2, 2, 0, 0, 0];
            assert_eq!(enter(page + CAVE, frame.as_ptr(), RED_BERRIES, &stack[6]).count, 2);
            frame[0xF8..0x100].copy_from_slice(&0u64.to_le_bytes());
            assert_eq!(enter(page + CAVE, frame.as_ptr(), RED_BERRIES, &stack[6]).count, 2);
            // the log reader sees every stack above in order
            let mut tail = 0;
            let t = take_from(page, &mut tail);
            assert_eq!(t.entries.len() as u32 + t.dropped, cases.len() as u32 + 2);
        }
    }
}
