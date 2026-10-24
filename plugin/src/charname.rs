//! Character names (`character_names`): the name a player gave their character, next to the
//! account name the game log shows, so Discord can post "theodore47 (Astrid) joined".
//!
//! Server 1.0.0.3 (SVN 1273043; the same code in 1.0 and 1.0.0.2). The server never logs it, but
//! its ban handler (exe+0x79de40, "[server] Unable to find character name for '%s'") looks it up
//! for the ban list, from the player slot's entity id:
//!
//! ```text
//! exe+0x79e122  mov r9d,[r14+1F8h]          ; slot+0x18: entity id (r14 = server + i*0x148)
//!               mov r8d,[rip+..]            ; 0x0E699564 = keen::ecs::CustomPlayerString
//!               mov rdx,[r15+1D0h]          ; the ECS world
//!               call getComponent           ; exe+0x647df0 -> &component (8 bytes: stringId)
//!               mov r8,[[rax]]              ; CustomStringId
//!               mov rdx,[r15+58h]           ; the custom string registry
//!               call findCustomString       ; exe+0x92be30 -> optional string view
//! ```
//!
//! Every step below `getComponent` and `findCustomString` is a lookup in open-addressing hash
//! maps (occupancy bitmap, key array, value array), so the poll thread repeats it with
//! `safe_read` and calls nothing: a layout that changed gives a wrong pointer or no match, never a
//! fault. The five functions are matched byte for byte, with only call and rip-relative targets
//! left out, so every offset the reads use is fixed by a signature; the one offset that is read
//! from the code is the ECS registry inside the world object (`lea rdi,[rdx+imm32]`), which moves
//! when the world object grows.

use crate::memory::{Image, matches, parse_signature, read, safe_read};

/// The ban handler's lookup (exe+0x79e122): `mov r9d,[r14+slot entity]` .. second call.
pub const SIG_BAN: &str = "45 8B 8E ?? ?? ?? ?? 48 8D 4C 24 20 44 8B 05 ?? ?? ?? ?? 4C 8D 25 ?? ?? ?? ?? 49 8B 97 ?? ?? ?? ?? 48 8B DE E8 ?? ?? ?? ?? 4C 8B 00 4D 85 C0 0F 84 ?? ?? ?? ?? 4D 8B 00 48 8D 4C 24 20 49 8B 57 ?? E8 ?? ?? ?? ?? 38 5C 24 20 75";
/// Offsets in SIG_BAN: the slot's entity field (u32), the component-type constant (rip disp32),
/// the world (u32), the registry (u8), and the two calls.
const BAN_ENTITY: usize = 3;
const BAN_TYPE_DISP: usize = 0x0F;
const BAN_WORLD: usize = 0x1D;
const BAN_GET_CALL: usize = 0x24;
const BAN_REGISTRY: usize = 0x40;
const BAN_NAME_CALL: usize = 0x41;

/// getComponent (exe+0x647df0): rdi = world + imm32 (the ECS registry), component map at
/// [registry]+0x88, then the per-entity lookup.
const SIG_GET: &str = "48 89 5C 24 08 48 89 74 24 10 57 48 83 EC 20 48 8D BA ?? ?? ?? ?? 44 89 44 24 40 48 8B F1 48 8D 54 24 40 48 8B 0F 41 8B D9 48 81 C1 88 00 00 00 E8 ?? ?? ?? ?? 4C 8B C0 44 8B CB 48 8B D7 48 8B CE E8 ?? ?? ?? ?? 48 8B 5C 24 30 48 8B C6 48 8B 74 24 38 48 83 C4 20 5F C3";
const GET_REGISTRY: usize = 0x12;
const GET_MAP_CALL: usize = 0x30;
const GET_RECORD_CALL: usize = 0x41;

/// Component-type map lookup (exe+0x646ce0): key u32, index = key & (capacity-1), u16 values.
const SIG_TYPE_MAP: &str = "48 89 5C 24 08 48 89 7C 24 10 83 79 54 00 4C 8B C9 48 8B 59 10 74 53 44 8B 12 48 8D 43 FF 48 8B 79 08 49 23 C2 48 8B D0 0F B6 C8 48 C1 EA 06 4C 8B 04 D7 49 D3 E8 41 F6 C0 01 74 2E 4D 8B 59 28 45 39 14 83 74 31 48 8D 48 01 33 C0 48 3B CB 48 0F 42 C1 48 8B D0 0F B6 C8 48 C1 EA 06 4C 8B 04 D7 49 D3 E8 41 F6 C0 01 75 D6 33 C0 48 8B 5C 24 08 48 8B 7C 24 10 C3 48 3B C3 73 EE 49 8B 49 40 48 8B 5C 24 08 48 8B 7C 24 10 48 8D 04 41 C3";

/// Entity record lookup (exe+0x647b20): entity map at registry+0x148, record = [values+i*8];
/// component data = [rec+0x20] + column[c] + [rec+0x30] * size[c], column/size u16 arrays at
/// archetype+0x84 / +0xA84, archetype = [rec+0x18] (bitmap of its components first).
const SIG_RECORD: &str = "48 89 5C 24 08 48 89 74 24 10 44 89 4C 24 20 57 48 83 EC 20 48 8D BA 48 01 00 00 48 8B D9 48 8B CF 48 8D 54 24 48 49 8B F0 E8 ?? ?? ?? ?? 48 3B 47 10 0F 83 94 00 00 00 48 8B 57 40 4C 8D 04 C2 4D 85 C0 0F 84 83 00 00 00 4D 8B 00 4D 85 C0 74 7B 48 85 F6 74 76 44 0F B7 0E 4D 8B 50 18 41 8B C1 48 C1 E8 06 41 0F B6 C9 49 8B 14 C2 48 D3 EA F6 C2 01 75 1C 33 D2 48 8B C3 48 89 13 48 89 53 08 48 8B 5C 24 30 48 8B 74 24 38 48 83 C4 20 5F C3 43 0F B7 94 4A 84 0A 00 00 41 8B 40 30 43 0F B7 8C 4A 84 00 00 00 48 0F AF C2 48 03 C8 48 8B C3 49 03 48 20 48 89 0B 48 89 53 08";
const RECORD_MAP_CALL: usize = 0x29;

/// Entity map lookup (exe+0x649cd0): key u32 hashed (x ^= x>>16; x *= 0x45d9f3b, twice; x ^= x>>16).
/// A generic template: 17 copies in the exe, so it is only checked at the call from SIG_RECORD.
const SIG_ENTITY_MAP: &str = "48 89 5C 24 08 48 89 7C 24 10 83 79 54 00 4C 8B C9 4C 8B 59 10 74 75 8B 1A 8B C3 49 8B 79 08 C1 E8 10 33 C3 69 D0 3B 9F 5D 04 8B C2 C1 E8 10 33 C2 69 C0 3B 9F 5D 04 8B C8 48 C1 E8 10 48 33 C1 49 8D 4B FF 48 23 C1 48 8B D0 0F B6 C8 48 C1 EA 06 4C 8B 04 D7 49 D3 E8 41 F6 C0 01 74 2E 4D 8B 51 28 41 39 1C 82 74 27 48 8D 48 01 33 C0 49 3B CB 48 0F 42 C1 48 8B D0 0F B6 C8 48 C1 EA 06 4C 8B 04 D7 49 D3 E8 41 F6 C0 01 75 D6 49 8B C3 48 8B 5C 24 08 48 8B 7C 24 10 C3";

/// findCustomString (exe+0x92be30): capacity +0x1A0, count u32 +0x1E4, bitmap +0x198, u64 keys
/// +0x1B8 (index = low 32 bits & (capacity-1)), values +0x1D0 -> entry with the text at +0x18
/// (pointer) and +0x20 (length).
const SIG_FIND_STRING: &str = "48 89 5C 24 08 48 89 6C 24 10 48 89 74 24 18 48 89 7C 24 20 48 8B BA A0 01 00 00 33 ED 4C 8B DA 4C 8B D1 39 AA E4 01 00 00 74 60 48 8B B2 98 01 00 00 48 8D 47 FF 45 8B C8 49 23 C1 48 8B D0 0F B6 C8 48 C1 EA 06 4C 8B 0C D6 49 D3 E9 41 F6 C1 01 74 38 49 8B 9B B8 01 00 00 66 0F 1F 44 00 00 4C 39 04 C3 74 4D 48 8D 48 01 48 8B C5 48 3B CF 48 0F 42 C1 48 8B D0 0F B6 C8 48 C1 EA 06 4C 8B 0C D6 49 D3 E9 41 F6 C1 01 75 D5 49 89 6A 08 49 89 6A 10 41 C6 02 1F 48 8B 5C 24 08 49 8B C2 48 8B 74 24 18 48 8B 7C 24 20 41 89 6A 04 48 8B 6C 24 10 C3 48 3B C7 73 D3 49 8B 8B D0 01 00 00 48 8D 04 C1 48 85 C0 74 C3 48 8B 00 48 85 C0 74 BB 48 8B 48 20 48 8B 40 18 49 89 42 08 49 89 4A 10 41 88 2A EB B2";

/// FNV-1a 32 of "keen::ecs::CustomPlayerString", the ECS type id the ban handler passes.
pub const CUSTOM_PLAYER_STRING: u32 = 0x0E69_9564;

// Fixed by the signatures above.
const TYPE_MAP: usize = 0x88; // in [registry]
const ENTITY_MAP: usize = 0x148; // in registry
const MAP_BITMAP: usize = 0x08;
const MAP_CAPACITY: usize = 0x10;
const MAP_KEYS: usize = 0x28;
const MAP_VALUES: usize = 0x40;
const MAP_COUNT: usize = 0x54;
const REC_ARCHETYPE: usize = 0x18;
const REC_DATA: usize = 0x20;
const REC_ROW: usize = 0x30;
const ARCH_COLUMN: usize = 0x84;
const ARCH_SIZE: usize = 0xA84;
const STR_BITMAP: usize = 0x198;
const STR_CAPACITY: usize = 0x1A0;
const STR_KEYS: usize = 0x1B8;
const STR_VALUES: usize = 0x1D0;
const STR_COUNT: usize = 0x1E4;
const ENTRY_TEXT: usize = 0x18;
const ENTRY_LEN: usize = 0x20;

/// The longest name read; the game's own limit is far below.
pub const MAX_NAME: usize = 256;
/// Hash maps larger than this are taken as a misread.
const MAX_CAPACITY: u64 = 1 << 24;

/// Where the reads start, from the code.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Layout {
    /// Server object -> ECS world pointer.
    pub world: usize,
    /// Server object -> custom string registry pointer.
    pub registry: usize,
    /// World -> ECS registry (not a pointer: inside the world object).
    pub ecs: usize,
    /// Where the ban handler's lookup is, for the log.
    pub site: usize,
}

fn rel32_target(at: usize) -> usize {
    (at as isize + 5 + unsafe { read::<i32>(at + 1) } as isize) as usize
}

/// `signature` matches at `at` exactly (bytes read from the mapped image).
fn fits(image: &Image, at: usize, signature: &str) -> bool {
    let Some(pattern) = parse_signature(signature) else { return false };
    image.is_code(at, pattern.len()) && matches(&pattern, unsafe { std::slice::from_raw_parts(at as *const u8, pattern.len()) })
}

/// Finds and checks the lookup; `slot_entity` is the slot table offset + SLOT_ENTITY (the field
/// the ban handler reads must be the one the mod reads).
pub fn resolve(image: &Image, slot_entity: usize) -> Result<Layout, String> {
    let found = image.find_all(SIG_BAN);
    let [site] = found[..] else { return Err(format!("ban lookup signature matched {} times", found.len())) };
    let entity = unsafe { read::<u32>(site + BAN_ENTITY) } as usize;
    if entity != slot_entity {
        return Err(format!("the ban handler reads the entity at slot+{entity:#x}, the mod at {slot_entity:#x}"));
    }
    let type_at = (site as isize + BAN_TYPE_DISP as isize + 4 + unsafe { read::<i32>(site + BAN_TYPE_DISP) } as isize) as usize;
    let type_id = safe_read(type_at, 4).map(|b| u32::from_le_bytes(b.try_into().unwrap()));
    if type_id != Some(CUSTOM_PLAYER_STRING) {
        return Err(format!("component type {type_id:x?}, not CustomPlayerString"));
    }
    let get = rel32_target(site + BAN_GET_CALL);
    let find = rel32_target(site + BAN_NAME_CALL);
    if !fits(image, get, SIG_GET) {
        return Err(format!("getComponent exe+{:#x} does not match", image.rva(get)));
    }
    if !fits(image, find, SIG_FIND_STRING) {
        return Err(format!("findCustomString exe+{:#x} does not match", image.rva(find)));
    }
    let type_map = rel32_target(get + GET_MAP_CALL);
    let record = rel32_target(get + GET_RECORD_CALL);
    if !fits(image, type_map, SIG_TYPE_MAP) || !fits(image, record, SIG_RECORD) {
        return Err("component lookup helpers do not match".into());
    }
    let entity_map = rel32_target(record + RECORD_MAP_CALL);
    if !fits(image, entity_map, SIG_ENTITY_MAP) {
        return Err(format!("entity map lookup exe+{:#x} does not match", image.rva(entity_map)));
    }
    Ok(Layout {
        world: unsafe { read::<u32>(site + BAN_WORLD) } as usize,
        registry: unsafe { read::<u8>(site + BAN_REGISTRY) } as usize,
        ecs: unsafe { read::<u32>(get + GET_REGISTRY) } as usize,
        site,
    })
}

/// Reads game memory: `read(address, len)`, None when unreadable. `safe_read` in the server;
/// a fake memory in the tests.
pub trait Memory {
    fn read(&self, address: usize, len: usize) -> Option<Vec<u8>>;

    fn u16(&self, a: usize) -> Option<u16> {
        Some(u16::from_le_bytes(self.read(a, 2)?.try_into().ok()?))
    }
    fn u32(&self, a: usize) -> Option<u32> {
        Some(u32::from_le_bytes(self.read(a, 4)?.try_into().ok()?))
    }
    fn u64(&self, a: usize) -> Option<u64> {
        Some(u64::from_le_bytes(self.read(a, 8)?.try_into().ok()?))
    }
    fn ptr(&self, a: usize) -> Option<usize> {
        self.u64(a).filter(|&p| p >= 0x10000).map(|p| p as usize)
    }
}

pub struct Process;

impl Memory for Process {
    fn read(&self, address: usize, len: usize) -> Option<Vec<u8>> {
        safe_read(address, len)
    }
}

/// The entity map's hash of a u32 key (exe+0x649cd0).
pub fn entity_hash(key: u32) -> u64 {
    let x = (key >> 16) ^ key;
    let x = x.wrapping_mul(0x045D_9F3B);
    let x = (x >> 16) ^ x;
    let x = x.wrapping_mul(0x045D_9F3B);
    ((x >> 16) ^ x) as u64
}

/// Index of `key` in an open-addressing map of u32 keys (bitmap, keys, capacity, count at the
/// MAP_* offsets), probing from `start`; None when absent or the map looks wrong.
fn find_u32(m: &dyn Memory, map: usize, key: u32, hash: u64) -> Result<usize, &'static str> {
    if m.u32(map + MAP_COUNT).ok_or("map unreadable")? == 0 {
        return Err("map empty");
    }
    let capacity = m.u64(map + MAP_CAPACITY).ok_or("map unreadable")?;
    if capacity == 0 || capacity > MAX_CAPACITY || !capacity.is_power_of_two() {
        return Err("map capacity implausible");
    }
    let bitmap = m.ptr(map + MAP_BITMAP).ok_or("map bitmap unreadable")?;
    let keys = m.ptr(map + MAP_KEYS).ok_or("map keys unreadable")?;
    let mut i = hash & (capacity - 1);
    for _ in 0..capacity {
        let word = m.u64(bitmap + (i >> 6) as usize * 8).ok_or("map bitmap unreadable")?;
        if (word >> (i & 63)) & 1 == 0 {
            return Err("not in map");
        }
        if m.u32(keys + i as usize * 4).ok_or("map keys unreadable")? == key {
            return Ok(i as usize);
        }
        i = if i + 1 < capacity { i + 1 } else { 0 };
    }
    Err("not in map")
}

/// The character name of the player whose entity is `entity`, read the way the ban handler
/// looks it up. Err says which step failed (for the log).
pub fn read_name(m: &dyn Memory, layout: &Layout, server: usize, entity: u32) -> Result<String, &'static str> {
    // getComponent(world, CustomPlayerString, entity)
    let world = m.ptr(server + layout.world).ok_or("no ECS world")?;
    let registry = world + layout.ecs;
    let components = m.ptr(registry).ok_or("no component registry")?;
    let type_map = components + TYPE_MAP;
    let t = find_u32(m, type_map, CUSTOM_PLAYER_STRING, CUSTOM_PLAYER_STRING as u64)?;
    let values = m.ptr(type_map + MAP_VALUES).ok_or("component map unreadable")?;
    let component = m.u16(values + t * 2).ok_or("component index unreadable")? as usize;
    let entities = registry + ENTITY_MAP;
    let e = find_u32(m, entities, entity, entity_hash(entity)).map_err(|_| "entity not found")?;
    let records = m.ptr(entities + MAP_VALUES).ok_or("entity map unreadable")?;
    let record = m.ptr(records + e * 8).ok_or("no entity record")?;
    let archetype = m.ptr(record + REC_ARCHETYPE).ok_or("no archetype")?;
    let word = m.u64(archetype + (component >> 6) * 8).ok_or("archetype unreadable")?;
    if (word >> (component & 63)) & 1 == 0 {
        return Err("player entity has no CustomPlayerString yet");
    }
    let column = m.u16(archetype + ARCH_COLUMN + component * 2).ok_or("archetype unreadable")? as usize;
    let size = m.u16(archetype + ARCH_SIZE + component * 2).ok_or("archetype unreadable")? as usize;
    if size < 8 {
        return Err("CustomPlayerString size implausible");
    }
    let row = m.u32(record + REC_ROW).ok_or("entity record unreadable")? as usize;
    let data = m.ptr(record + REC_DATA).ok_or("no component data")? + column + row * size;
    let string_id = m.u64(data).ok_or("component unreadable")?;
    if string_id == 0 {
        return Err("no character name set");
    }

    // findCustomString(registry, stringId)
    let strings = m.ptr(server + layout.registry).ok_or("no string registry")?;
    if m.u32(strings + STR_COUNT).ok_or("string registry unreadable")? == 0 {
        return Err("string registry empty");
    }
    let capacity = m.u64(strings + STR_CAPACITY).ok_or("string registry unreadable")?;
    if capacity == 0 || capacity > MAX_CAPACITY || !capacity.is_power_of_two() {
        return Err("string registry capacity implausible");
    }
    let bitmap = m.ptr(strings + STR_BITMAP).ok_or("string registry unreadable")?;
    let keys = m.ptr(strings + STR_KEYS).ok_or("string registry unreadable")?;
    let mut i = (string_id & 0xFFFF_FFFF) & (capacity - 1);
    for _ in 0..capacity {
        let word = m.u64(bitmap + (i >> 6) as usize * 8).ok_or("string registry unreadable")?;
        if (word >> (i & 63)) & 1 == 0 {
            return Err("character name not in the string registry");
        }
        if m.u64(keys + i as usize * 8).ok_or("string registry unreadable")? == string_id {
            let values = m.ptr(strings + STR_VALUES).ok_or("string registry unreadable")?;
            let entry = m.ptr(values + i as usize * 8).ok_or("no string entry")?;
            let text = m.ptr(entry + ENTRY_TEXT).ok_or("no string text")?;
            let len = m.u64(entry + ENTRY_LEN).ok_or("string entry unreadable")? as usize;
            if len == 0 || len > MAX_NAME {
                return Err("character name length implausible");
            }
            let bytes = m.read(text, len).ok_or("character name unreadable")?;
            let name = String::from_utf8_lossy(&bytes).chars().filter(|c| !c.is_control()).collect::<String>();
            let name = name.trim().to_string();
            return if name.is_empty() { Err("character name empty") } else { Ok(name) };
        }
        i = if i + 1 < capacity { i + 1 } else { 0 };
    }
    Err("character name not in the string registry")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    /// Sparse memory: little-endian values written at addresses.
    #[derive(Default)]
    struct Fake(BTreeMap<usize, u8>);

    impl Fake {
        fn put(&mut self, at: usize, bytes: &[u8]) {
            for (i, b) in bytes.iter().enumerate() {
                self.0.insert(at + i, *b);
            }
        }
        fn put16(&mut self, at: usize, v: u16) {
            self.put(at, &v.to_le_bytes());
        }
        fn put32(&mut self, at: usize, v: u32) {
            self.put(at, &v.to_le_bytes());
        }
        fn put64(&mut self, at: usize, v: u64) {
            self.put(at, &v.to_le_bytes());
        }
        /// An open-addressing map: bitmap, keys and values arrays at fixed places.
        fn map32(&mut self, map: usize, capacity: u64, entries: &[(u32, u64, &[u8])], hash: fn(u32) -> u64, value_size: usize, arrays: usize) {
            let (bitmap, keys, values) = (arrays, arrays + 0x1000, arrays + 0x2000);
            self.put32(map + MAP_COUNT, entries.len() as u32);
            self.put64(map + MAP_CAPACITY, capacity);
            self.put64(map + MAP_BITMAP, bitmap as u64);
            self.put64(map + MAP_KEYS, keys as u64);
            self.put64(map + MAP_VALUES, values as u64);
            let mut used = vec![false; capacity as usize];
            for &(key, _, value) in entries {
                let mut i = (hash(key) & (capacity - 1)) as usize;
                while used[i] {
                    i = (i + 1) % capacity as usize;
                }
                used[i] = true;
                self.put32(keys + i * 4, key);
                self.put(values + i * value_size, value);
            }
            for w in 0..(capacity as usize).div_ceil(64) {
                let bits = (0..64).filter(|b| used.get(w * 64 + b) == Some(&true)).fold(0u64, |a, b| a | 1 << b);
                self.put64(bitmap + w * 8, bits);
            }
        }
    }

    impl Memory for Fake {
        fn read(&self, address: usize, len: usize) -> Option<Vec<u8>> {
            (address..address + len).map(|a| self.0.get(&a).copied()).collect()
        }
    }

    const LAYOUT: Layout = Layout { world: 0x1D0, registry: 0x58, ecs: 0xE1_5DC0, site: 0 };
    const SERVER: usize = 0x10_0000;
    const WORLD: usize = 0x20_0000;
    const COMPONENTS: usize = 0x40_0000;
    const RECORD: usize = 0x50_0000;
    const ARCH: usize = 0x51_0000;
    const DATA: usize = 0x52_0000;
    const STRINGS: usize = 0x60_0000;
    const ENTRY: usize = 0x61_0000;
    const TEXT: usize = 0x62_0000;

    /// A world where entity 3 has CustomPlayerString (component 70, column 0x40, size 8, row 2)
    /// with string id `sid`, and the registry holds `sid` -> `name` (plus a colliding key).
    fn world(sid: u64, name: &str, has_component: bool) -> Fake {
        let mut m = Fake::default();
        m.put64(SERVER + 0x1D0, WORLD as u64);
        m.put64(SERVER + 0x58, STRINGS as u64);
        let registry = WORLD + 0xE1_5DC0;
        m.put64(registry, COMPONENTS as u64);
        // component type map: CustomPlayerString -> 70 (and another type)
        m.map32(COMPONENTS + TYPE_MAP, 64, &[(0x1234_5678, 0, &5u16.to_le_bytes()), (CUSTOM_PLAYER_STRING, 0, &70u16.to_le_bytes())], |k| k as u64, 2, 0x41_0000);
        // entity map: entity 1 -> elsewhere, entity 3 -> RECORD
        m.map32(registry + ENTITY_MAP, 16, &[(1, 0, &0x7777_0000u64.to_le_bytes()), (3, 0, &(RECORD as u64).to_le_bytes())], entity_hash, 8, 0x42_0000);
        m.put64(RECORD + REC_ARCHETYPE, ARCH as u64);
        m.put64(RECORD + REC_DATA, DATA as u64);
        m.put32(RECORD + REC_ROW, 2);
        m.put64(ARCH + 8, if has_component { 1 << (70 - 64) } else { 0 });
        m.put16(ARCH + ARCH_COLUMN + 70 * 2, 0x40);
        m.put16(ARCH + ARCH_SIZE + 70 * 2, 8);
        m.put64(DATA + 0x40 + 2 * 8, sid);
        // string registry, capacity 8: a key with the same slot first, then ours
        let (bitmap, keys, values) = (0x63_0000, 0x64_0000, 0x65_0000);
        m.put32(STRINGS + STR_COUNT, 2);
        m.put64(STRINGS + STR_CAPACITY, 8);
        m.put64(STRINGS + STR_BITMAP, bitmap);
        m.put64(STRINGS + STR_KEYS, keys);
        m.put64(STRINGS + STR_VALUES, values);
        let first = (sid & 0xFFFF_FFFF & 7) as usize;
        let second = (first + 1) % 8;
        m.put64(bitmap as usize, (1 << first) | (1 << second));
        m.put64(keys as usize + first * 8, sid ^ 0xFFFF_0000_0000_0000); // same low 32 bits, other id
        m.put64(keys as usize + second * 8, sid);
        m.put64(values as usize + second * 8, ENTRY as u64);
        m.put64(ENTRY + ENTRY_TEXT, TEXT as u64);
        m.put64(ENTRY + ENTRY_LEN, name.len() as u64);
        m.put(TEXT, name.as_bytes());
        m
    }

    #[test]
    fn hash_matches_the_game() {
        // x ^= x>>16; x *= 0x45d9f3b; x ^= x>>16; x *= 0x45d9f3b; x ^= x>>16 (u32)
        assert_eq!(entity_hash(0), 0);
        assert_eq!(entity_hash(1), 0x3125_1BA7);
        assert_eq!(entity_hash(3), 0xDFB6_D245);
        assert_eq!(entity_hash(0x1_0001), 0x7F12_288B);
        assert_eq!(entity_hash(0xDEAD_BEEF), 0x5353_E2E9);
    }

    #[test]
    fn reads_the_name() {
        let m = world(0xABCD_0000_0000_0013, "Astrid Ironside", true);
        assert_eq!(read_name(&m, &LAYOUT, SERVER, 3), Ok("Astrid Ironside".into()));
        assert_eq!(read_name(&m, &LAYOUT, SERVER, 2), Err("entity not found"));
    }

    #[test]
    fn without_the_component_or_id() {
        let m = world(0x13, "Astrid", false);
        assert_eq!(read_name(&m, &LAYOUT, SERVER, 3), Err("player entity has no CustomPlayerString yet"));
        let m = world(0, "Astrid", true);
        assert_eq!(read_name(&m, &LAYOUT, SERVER, 3), Err("no character name set"));
    }

    #[test]
    fn rejects_bad_reads() {
        let mut m = world(0x13, "Astrid", true);
        m.put64(ENTRY + ENTRY_LEN, 100_000);
        assert_eq!(read_name(&m, &LAYOUT, SERVER, 3), Err("character name length implausible"));
        let mut m = world(0x13, "Astrid", true);
        m.put64(STRINGS + STR_CAPACITY, 12);
        assert_eq!(read_name(&m, &LAYOUT, SERVER, 3), Err("string registry capacity implausible"));
        let m = Fake::default();
        assert_eq!(read_name(&m, &LAYOUT, SERVER, 3), Err("no ECS world"));
        let m = world(0x13, "Ast\nrid\u{7}", true);
        assert_eq!(read_name(&m, &LAYOUT, SERVER, 3), Ok("Astrid".into()));
    }
}
