//! Machine code for the hooks. Pure functions of addresses, so they can be unit-tested
//! and disassembled (`cargo test -- --nocapture dump` | python ../tools/check_caves.py).
//!
//! The death, record, sleeper, slot and freezing caves call nothing: game threads only store a
//! value into memory that this plugin's own thread polls. That keeps the code in the game's hot
//! path tiny and leaves no stack, ABI or locking concerns. So does the chat-in cave (it copies the
//! message into a ring); only the broadcast cave (`chat_cave`) calls into Rust.
//!
//! Every generator checks its length against the start of the next region of its page.

/// Layout of the shared page allocated near the image (the freezing hook has its own, FZ_*).
pub const SERVER_SLOT: usize = 0x000; // u64: the server object (rsi in 1.0's player-slot loop)
pub const HEAD: usize = 0x008; // u32: deaths written so far (wraps)
pub const RING: usize = 0x010; // [u32; RING_LEN]: entity id + 1, 0 = empty
pub const RING_LEN: usize = 64;
pub const RECORD_HEAD: usize = 0x00C; // u32: PlayerDeath records written so far (wraps)
pub const SLOTS_CAVE: usize = 0x200;
pub const DEATH_CAVES: usize = 0x240;
pub const DEATH_CAVE_SIZE: usize = 0x40;
pub const RECORD_CAVE: usize = 0x340; // after up to 4 death caves
pub const RECORDS: usize = 0x400; // [Record; RECORDS_LEN]
pub const RECORD_SIZE: usize = 0x40; // 0x30 PlayerDeath copy + u32 ready flag at +0x30
pub const RECORD_BYTES: usize = 0x30; // sizeof(keen::PlayerDeath)
pub const RECORDS_LEN: usize = 16;
pub const SLEEP_CAVE: usize = 0x390; // after the record cave (66 bytes from 0x340)
pub const SLEEPERS: usize = 0x800; // 16 x u32 entity ids; cell = SLEEPERS + (loop offset >> 5) * 4
pub const SLEEPERS_END: usize = 0xA00; // room for a player step of up to 0x100 bytes
pub const CHAT_CAVE: usize = 0xA00; // after the sleeper cells
/// Chat to Discord: store-only cave before the receive handler's `call enqueue` (chat.rs).
pub const CHAT_IN_CAVE: usize = 0xB00;
pub const CHAT_IN_CAVE_END: usize = 0xC00;
/// u32: messages claimed so far (lock xadd), wraps.
pub const CHAT_IN_HEAD: usize = 0x1000;
/// [slot; CHAT_IN_LEN], CHAT_IN_SLOT bytes each.
pub const CHAT_IN_RING: usize = 0x1040;
pub const CHAT_IN_LEN: usize = 16; // power of two
pub const CHAT_IN_SLOT: usize = 0x420;
pub const CHAT_IN_TEXT_MAX: usize = 0x400;
// One slot: seq u32 (claim index + 1, written last; 0 while being written), type u8, rejected u8
// (length over 0x400: the game drops the message, nothing was copied), sender handle u32,
// length u32, accountIdHash u64, text.
pub const CI_SEQ: usize = 0x00;
pub const CI_TYPE: usize = 0x04;
pub const CI_REJECTED: usize = 0x05;
pub const CI_HANDLE: usize = 0x08;
pub const CI_LEN: usize = 0x0C;
pub const CI_ACCOUNT: usize = 0x10;
pub const CI_TEXT: usize = 0x20;
/// Caller's [rsp+30h] (handle) and [rsp+38h] (account) after the cave pushed 0x30 bytes.
const CI_STACK_HANDLE: u8 = 0x60;
const CI_STACK_ACCOUNT: u8 = 0x68;
const _: () = assert!(
    SERVER_SLOT + 8 <= HEAD
        && HEAD + 4 <= RECORD_HEAD
        && RECORD_HEAD + 4 <= RING
        && RING + RING_LEN * 4 <= SLOTS_CAVE
        && SLOTS_CAVE < DEATH_CAVES
        && DEATH_CAVES + 2 * DEATH_CAVE_SIZE <= RECORD_CAVE
        && RECORD_CAVE < SLEEP_CAVE
        && SLEEP_CAVE < RECORDS
        && RECORDS + RECORDS_LEN * RECORD_SIZE <= SLEEPERS
        && SLEEPERS < SLEEPERS_END
        && SLEEPERS_END <= CHAT_CAVE
        && CHAT_CAVE < CHAT_IN_CAVE
        && CHAT_IN_CAVE < CHAT_IN_CAVE_END
        && CHAT_IN_CAVE_END <= CHAT_IN_HEAD
        && CHAT_IN_HEAD + 4 <= CHAT_IN_RING
        && CHAT_IN_RING + CHAT_IN_LEN * CHAT_IN_SLOT <= PAGE
        && CHAT_IN_LEN.is_power_of_two()
        && CI_TEXT + CHAT_IN_TEXT_MAX <= CHAT_IN_SLOT
        && RING_LEN.is_power_of_two()
        && RECORDS_LEN.is_power_of_two()
        && RECORD_SIZE.is_power_of_two()
        && RECORD_BYTES + 4 <= RECORD_SIZE
);

/// Chat to Discord, entered by `jmp` from the 8 bytes before the receive handler's `call
/// enqueue` (1.0 exe+0x7b2cb1). Replays them, then copies type (r8b), the sender's handle and
/// account (the call's 7th and 8th arguments) and the text (r9 = &{ptr, len}) into the next ring
/// slot and publishes it. No calls, every register and flag preserved; jumps back to the call.
/// A text over 0x400 bytes (the game refuses it before reading it) is published as rejected,
/// without touching the pointer.
pub fn chat_in_cave(page: usize, hook: usize, original: &[u8; 8]) -> Option<Vec<u8>> {
    let cave = page + CHAT_IN_CAVE;
    let mut c: Vec<u8> = Vec::new();
    c.extend(original); // mov [rsp+20h],eax; mov byte [rbp+20h],0
    c.extend([0x9C, 0x50, 0x51, 0x52, 0x56, 0x57]); // pushfq; push rax, rcx, rdx, rsi, rdi
    c.extend([0xB8, 0x01, 0x00, 0x00, 0x00]); // mov eax,1
    c.extend([0xF0, 0x0F, 0xC1, 0x05]); // lock xadd [rip+head],eax
    c.extend(rel32(cave + c.len() + 4, page + CHAT_IN_HEAD)?);
    c.extend([0x8D, 0x50, 0x01]); // lea edx,[rax+1]: seq to publish
    c.extend([0x83, 0xE0, (CHAT_IN_LEN - 1) as u8]); // and eax, LEN-1
    c.extend([0x69, 0xC0]); // imul eax,eax,SLOT
    c.extend((CHAT_IN_SLOT as u32).to_le_bytes());
    c.extend([0x48, 0x8D, 0x3D]); // lea rdi,[rip+ring]
    c.extend(rel32(cave + c.len() + 4, page + CHAT_IN_RING)?);
    c.extend([0x48, 0x01, 0xC7]); // add rdi,rax
    c.extend([0xC7, 0x07, 0x00, 0x00, 0x00, 0x00]); // mov dword [rdi+seq],0
    c.extend([0x44, 0x88, 0x47, CI_TYPE as u8]); // mov [rdi+type],r8b
    c.extend([0x8B, 0x44, 0x24, CI_STACK_HANDLE]); // mov eax,[rsp+60h]
    c.extend([0x89, 0x47, CI_HANDLE as u8]); // mov [rdi+handle],eax
    c.extend([0x48, 0x8B, 0x44, 0x24, CI_STACK_ACCOUNT]); // mov rax,[rsp+68h]
    c.extend([0x48, 0x89, 0x47, CI_ACCOUNT as u8]); // mov [rdi+account],rax
    c.extend([0x49, 0x8B, 0x49, 0x08]); // mov rcx,[r9+8]: length
    c.extend([0x48, 0x81, 0xF9]); // cmp rcx,0x400
    c.extend((CHAT_IN_TEXT_MAX as u32).to_le_bytes());
    // rejected: flag it, length 0, publish
    let rejected = [0xC6, 0x47, CI_REJECTED as u8, 0x01, 0xC7, 0x47, CI_LEN as u8, 0x00, 0x00, 0x00, 0x00]; // mov byte [rdi+rej],1; mov dword [rdi+len],0
    let copy = [
        0xC6, 0x47, CI_REJECTED as u8, 0x00, // mov byte [rdi+rej],0
        0x89, 0x4F, CI_LEN as u8, // mov [rdi+len],ecx
        0x49, 0x8B, 0x31, // mov rsi,[r9]
        0x57, // push rdi
        0x48, 0x83, 0xC7, CI_TEXT as u8, // add rdi,text
        0xFC, 0xF3, 0xA4, // cld; rep movsb
        0x5F, // pop rdi
    ];
    c.extend([0x76, (rejected.len() + 2) as u8]); // jbe copy
    c.extend(rejected);
    c.extend([0xEB, copy.len() as u8]); // jmp publish
    c.extend(copy);
    c.extend([0x89, 0x17]); // publish: mov [rdi+seq],edx
    c.extend([0x5F, 0x5E, 0x5A, 0x59, 0x58, 0x9D]); // pop rdi, rsi, rdx, rcx, rax; popfq
    c.push(0xE9); // jmp hook+8 (the untouched call)
    c.extend(rel32(cave + c.len() + 4, hook + 8)?);
    (c.len() <= CHAT_IN_CAVE_END - CHAT_IN_CAVE).then_some(c)
}
pub const PAGE: usize = 0x6000;
pub const MAX_DEATH_CAVES: usize = (RECORD_CAVE - DEATH_CAVES) / DEATH_CAVE_SIZE;

/// Hook over the chat relay's first instruction (`original`, 5 bytes, `mov [rsp+20h],rbx`):
/// call `callback(rcx)` (rcx = the server object, the relay's own argument) with every volatile
/// integer register preserved, then run the relay as normal. At function entry rsp = 8 mod 16;
/// seven pushes and 0x20 bytes of shadow space leave it 16-aligned for the call.
/// The callback must not touch xmm0-5 beyond what Rust's ABI allows: they are volatile and the
/// relay takes no float arguments, so nothing needs saving there.
pub fn chat_cave(page: usize, hook: usize, original: &[u8; 5], callback: usize) -> Option<Vec<u8>> {
    let cave = page + CHAT_CAVE;
    let mut c: Vec<u8> = vec![
        0x50, 0x51, 0x52, // push rax, rcx, rdx
        0x41, 0x50, 0x41, 0x51, 0x41, 0x52, 0x41, 0x53, // push r8, r9, r10, r11
        0x48, 0x83, 0xEC, 0x20, // sub rsp, 0x20
        0x48, 0xB8, // mov rax, imm64
    ];
    c.extend((callback as u64).to_le_bytes());
    c.extend([
        0xFF, 0xD0, // call rax
        0x48, 0x83, 0xC4, 0x20, // add rsp, 0x20
        0x41, 0x5B, 0x41, 0x5A, 0x41, 0x59, 0x41, 0x58, // pop r11, r10, r9, r8
        0x5A, 0x59, 0x58, // pop rdx, rcx, rax
    ]);
    c.extend(original);
    c.push(0xE9); // jmp hook+5
    c.extend(rel32(cave + c.len() + 4, hook + 5)?);
    (c.len() <= CHAT_IN_CAVE - CHAT_CAVE).then_some(c)
}

/// Hook over `test al,al; je +3; inc bpl` (7 bytes) in `server_nighttime_skip`'s player loop,
/// where a player with the Sleeping flag is counted. Redo that, and for a sleeper also store its
/// entity id (ebx) at SLEEPERS + (rsi >> 5) * 4; rsi is the loop offset (1.0: 0xA0 per player,
/// 0.9: 0x60), a multiple of 32, so each player gets its own cell. The thread reads and clears them.
/// The cave does not bound rsi: install checks the loop's own bound first (lib.rs `sleeper_cells`).
pub fn sleep_cave(page: usize, hook: usize) -> Option<Vec<u8>> {
    let cave = page + SLEEP_CAVE;
    let mut c: Vec<u8> = vec![
        0x84, 0xC0, // test al, al
        0x74, 0x00, // je done (distance filled in below)
        0x40, 0xFE, 0xC5, // inc bpl
        0x50, 0x52, // push rax, rdx
        0x48, 0x89, 0xF0, // mov rax, rsi
        0x48, 0xC1, 0xE8, 0x05, // shr rax, 5
        0x48, 0x8D, 0x15, // lea rdx, [rip+d]
    ];
    c.extend(rel32(cave + c.len() + 4, page + SLEEPERS)?);
    c.extend([
        0x89, 0x1C, 0x82, // mov [rdx+rax*4], ebx
        0x5A, 0x58, // pop rdx, pop rax
    ]);
    c[3] = u8::try_from(c.len() - 4).ok()?; // je lands on the jmp below
    c.push(0xE9); // done: jmp hook+7
    c.extend(rel32(cave + c.len() + 4, hook + 7)?);
    (c.len() <= RECORDS - SLEEP_CAVE).then_some(c)
}

/// Hook over the first 5 bytes (`original`, 1.0: `mov [rsp+20h],rbx`) of the function the fall,
/// fog, oxygen and damage deaths call with `r8 = &PlayerDeath` (cause, position, killer guid): copy
/// the record into the next queue slot, mark it ready, redo the 5 bytes, continue. Registers and
/// flags are preserved.
pub fn record_cave(page: usize, hook: usize, original: &[u8; 5]) -> Option<Vec<u8>> {
    let cave = page + RECORD_CAVE;
    let mut c: Vec<u8> = vec![
        0x9C, // pushfq
        0x50, 0x51, 0x56, 0x57, // push rax, rcx, rsi, rdi
        0xB8, 0x01, 0x00, 0x00, 0x00, // mov eax, 1
        0xF0, 0x0F, 0xC1, 0x05, // lock xadd [rip+d], eax
    ];
    c.extend(rel32(cave + c.len() + 4, page + RECORD_HEAD)?);
    c.extend([0x83, 0xE0, (RECORDS_LEN - 1) as u8]); // and eax, RECORDS_LEN-1
    c.extend([0xC1, 0xE0, RECORD_SIZE.trailing_zeros() as u8]); // shl eax, log2(RECORD_SIZE)
    c.extend([0x48, 0x8D, 0x3D]); // lea rdi, [rip+d]
    c.extend(rel32(cave + c.len() + 4, page + RECORDS)?);
    c.extend([
        0x48, 0x01, 0xC7, // add rdi, rax
        0x4C, 0x89, 0xC6, // mov rsi, r8
        0xB9, RECORD_BYTES as u8, 0x00, 0x00, 0x00, // mov ecx, 0x30
        0xFC, // cld
        0xF3, 0xA4, // rep movsb       (rdi ends at the ready flag)
        0xC7, 0x07, 0x01, 0x00, 0x00, 0x00, // mov dword [rdi], 1
        0x5F, 0x5E, 0x59, 0x58, // pop rdi, rsi, rcx, rax
        0x9D, // popfq
    ]);
    c.extend(original);
    c.push(0xE9); // jmp hook+5
    c.extend(rel32(cave + c.len() + 4, hook + 5)?);
    (c.len() <= SLEEP_CAVE - RECORD_CAVE).then_some(c)
}

/// Freezing kills: a page of its own, allocated apart from the shared page above so this layout
/// cannot collide with it. Data first, code after.
pub const FZ_HEAD: usize = 0x000; // u32: freezing kills written so far (wraps)
pub const FZ_RING: usize = 0x040; // [u32; FZ_RING_LEN]: entity id + 1, 0 = empty
pub const FZ_RING_LEN: usize = 16;
pub const FZ_CAVE: usize = 0x100;
pub const FZ_PAGE: usize = 0x1000;
const _: () = assert!(FZ_HEAD + 4 <= FZ_RING && FZ_RING + FZ_RING_LEN * 4 <= FZ_CAVE && FZ_RING_LEN.is_power_of_two());

/// Hook over `sub dword [r8+rcx*4], eax; mov rcx, rbx` (7 bytes, `original`) in
/// `bodyheat_depletion`, the freezing drain of Health (r8+rcx*4 = the current entity's Health,
/// eax = this tick's drain, r14 = the system's iteration context). Redo the subtraction; when it
/// takes Health from above 0 to 0 or below, append the current entity id + 1 to the ring. The id is
/// read the way exe+0x6539b0 reads it for EntityDiedEvent: ids[[r14+8] - 1], ids = [[r14] +
/// `entity_ids`], 16 bytes per entity, the index checked against the count at [[r14] +
/// `entity_count`] first. Then redo `mov rcx, rbx` and continue at the game's call (hook+7).
/// Registers and flags are preserved; nothing is called.
pub fn freeze_cave(page: usize, hook: usize, original: &[u8; 7], entity_ids: u32, entity_count: u32) -> Option<Vec<u8>> {
    let cave = page + FZ_CAVE;
    let mut c: Vec<u8> = Vec::new();
    c.extend_from_slice(&original[..4]); // sub dword [r8+rcx*4], eax   (the game's drain)
    c.extend([0x9C, 0x50, 0x51, 0x52]); // pushfq; push rax, rcx, rdx
    c.extend([0x41, 0x8B, 0x14, 0x88]); // mov edx, [r8+rcx*4]       Health after the drain
    c.extend([0x85, 0xD2]); // test edx, edx
    let mut skips = vec![c.len()];
    c.extend([0x7F, 0x00]); // jg restore                still alive
    c.extend([0x01, 0xC2]); // add edx, eax              Health before the drain
    skips.push(c.len());
    c.extend([0x7E, 0x00]); // jle restore               already at 0: not this drain's kill
    c.extend([0x41, 0x8B, 0x46, 0x08]); // mov eax, [r14+8]  iteration position, 1-based
    c.extend([0x85, 0xC0]); // test eax, eax
    skips.push(c.len());
    c.extend([0x74, 0x00]); // je restore
    c.extend([0xFF, 0xC8]); // dec eax                  entity index
    c.extend([0x49, 0x8B, 0x0E]); // mov rcx, [r14]
    c.extend([0x48, 0x3B, 0x81]); // cmp rax, [rcx+entity_count]
    c.extend(entity_count.to_le_bytes());
    skips.push(c.len());
    c.extend([0x73, 0x00]); // jae restore
    c.extend([0x48, 0x8B, 0x89]); // mov rcx, [rcx+entity_ids]
    c.extend(entity_ids.to_le_bytes());
    c.extend([0x48, 0x85, 0xC9]); // test rcx, rcx
    skips.push(c.len());
    c.extend([0x74, 0x00]); // je restore
    c.extend([0x48, 0xC1, 0xE0, 0x04]); // shl rax, 4
    c.extend([0x8B, 0x0C, 0x01]); // mov ecx, [rcx+rax]       entity id
    c.extend([0xFF, 0xC1]); // inc ecx                  (0 stays "empty")
    skips.push(c.len());
    c.extend([0x74, 0x00]); // je restore
    c.extend([0xB8, 0x01, 0x00, 0x00, 0x00]); // mov eax, 1
    c.extend([0xF0, 0x0F, 0xC1, 0x05]); // lock xadd [rip+d], eax   (eax = old head)
    c.extend(rel32(cave + c.len() + 4, page + FZ_HEAD)?);
    c.extend([0x83, 0xE0, (FZ_RING_LEN - 1) as u8]); // and eax, FZ_RING_LEN-1
    c.extend([0x48, 0x8D, 0x15]); // lea rdx, [rip+d]
    c.extend(rel32(cave + c.len() + 4, page + FZ_RING)?);
    c.extend([0x89, 0x0C, 0x82]); // mov [rdx+rax*4], ecx
    let restore = c.len();
    c.extend([0x5A, 0x59, 0x58, 0x9D]); // pop rdx, rcx, rax; popfq
    c.extend_from_slice(&original[4..]); // mov rcx, rbx   (the game's next instruction)
    c.push(0xE9); // jmp hook+7 (the game's call)
    c.extend(rel32(cave + c.len() + 4, hook + 7)?);
    for at in skips {
        c[at + 1] = u8::try_from(restore - (at + 2)).ok().filter(|d| *d < 0x80)?;
    }
    (FZ_CAVE + c.len() <= FZ_PAGE).then_some(c)
}

fn rel32(from_end: usize, to: usize) -> Option<[u8; 4]> {
    let delta = to as i64 - from_end as i64;
    i32::try_from(delta).ok().map(i32::to_le_bytes)
}

/// `jmp cave` written over the hooked instructions, padded with nops to `len` bytes.
pub fn jump_patch(hook: usize, cave: usize, len: usize) -> Option<Vec<u8>> {
    let mut bytes = vec![0xE9];
    bytes.extend(rel32(hook + 5, cave)?);
    bytes.resize(len, 0x90);
    Some(bytes)
}

/// Hook over `add r14, imm32` (7 bytes, `original`) in 1.0's player-slot loop:
/// remember rsi (the server object), redo the add, jump back.
pub fn slots_cave(page: usize, hook: usize, original: &[u8; 7]) -> Option<Vec<u8>> {
    let cave = page + SLOTS_CAVE;
    let mut c = vec![0x48, 0x89, 0x35]; // mov [rip+d], rsi
    c.extend(rel32(cave + 7, page + SERVER_SLOT)?);
    c.extend(original); // add r14, imm32
    c.push(0xE9); // jmp hook+7
    c.extend(rel32(cave + c.len() + 4, hook + 7)?);
    (c.len() <= DEATH_CAVES - SLOTS_CAVE).then_some(c)
}

/// Hook over `mov ecx,[rax]; mov [rbx+8],ecx` (5 bytes), where an EntityDiedEvent gets its
/// deadEntityId: redo both, then append id+1 to the ring, preserving every register and flag.
/// `index` < MAX_DEATH_CAVES; each cave gets DEATH_CAVE_SIZE bytes (checked by finish_death_cave).
pub fn death_cave(page: usize, index: usize) -> Option<(usize, Vec<u8>)> {
    if index >= MAX_DEATH_CAVES {
        return None;
    }
    let cave = page + DEATH_CAVES + index * DEATH_CAVE_SIZE;
    let mut c: Vec<u8> = vec![
        0x8B, 0x08, // mov ecx, [rax]
        0x89, 0x4B, 0x08, // mov [rbx+8], ecx
        0x9C, // pushfq
        0x50, 0x51, 0x52, // push rax, rcx, rdx
        0xB8, 0x01, 0x00, 0x00, 0x00, // mov eax, 1
        0xF0, 0x0F, 0xC1, 0x05, // lock xadd [rip+d], eax   (eax = old head)
    ];
    c.extend(rel32(cave + c.len() + 4, page + HEAD)?);
    c.extend([0x83, 0xE0, (RING_LEN - 1) as u8]); // and eax, RING_LEN-1
    c.extend([0x48, 0x8D, 0x15]); // lea rdx, [rip+d]
    c.extend(rel32(cave + c.len() + 4, page + RING)?);
    c.extend([
        0xFF, 0xC1, // inc ecx            (0 stays "empty")
        0x89, 0x0C, 0x82, // mov [rdx+rax*4], ecx
        0x5A, 0x59, 0x58, // pop rdx, rcx, rax
        0x9D, // popfq
        0xE9, // jmp back
    ]);
    Some((cave, c))
}

/// The jump back at the end of a death cave needs the hook address; patched in separately.
pub fn finish_death_cave(cave: usize, mut code: Vec<u8>, hook: usize) -> Option<Vec<u8>> {
    code.extend(rel32(cave + code.len() + 4, hook + 5)?);
    (code.len() <= DEATH_CAVE_SIZE).then_some(code)
}

#[cfg(test)]
mod tests {
    use super::*;

    const PAGE_AT: usize = 0x1_3FFF_0000;
    const HOOK: usize = 0x1_4006_B3F6;
    /// Live-like addresses (Tartaros, Proton): the server image, the shared page alloc_near takes
    /// first (base - 0x10000) and the freezing page after it (base - 0x20000).
    const IMAGE: usize = 0x6FFF_FBD5_0000;
    const LIVE_PAGE: usize = IMAGE - 0x1_0000;
    const LIVE_FREEZE_PAGE: usize = IMAGE - 0x2_0000;
    /// Hook sites of every reference build, from check_signatures.py.
    struct Sites {
        slots: usize,
        died: [usize; 2],
        record: usize,
        sleeper: usize,
        relay: usize,
        chat_in: usize,
        freeze: usize,
    }
    const SITES: [Sites; 2] = [
        // 1.0, SVN 1267041
        Sites { slots: 0x7b34a3, died: [0x72659, 0x8517e], record: 0x4df70, sleeper: 0x103ace, relay: 0x7aeed0, chat_in: 0x7b2cb1, freeze: 0xbc557 },
        // 1.0.0.2, SVN 1269579
        Sites { slots: 0x7b3583, died: [0x726a9, 0x851ce], record: 0x4dfc0, sleeper: 0x103b2e, relay: 0x7aefb0, chat_in: 0x7b2d91, freeze: 0xbc5b7 },
    ];
    const CHAT_IN_ORIGINAL: [u8; 8] = [0x89, 0x44, 0x24, 0x20, 0xC6, 0x45, 0x20, 0x00];
    const SLOTS_ORIGINAL: [u8; 7] = [0x49, 0x81, 0xC6, 0xE0, 0x01, 0x00, 0x00];
    const ENTRY_ORIGINAL: [u8; 5] = [0x48, 0x89, 0x5C, 0x24, 0x20];

    #[test]
    fn sizes_and_targets() {
        let patch = jump_patch(HOOK, PAGE_AT + SLOTS_CAVE, 7).unwrap();
        assert_eq!(patch.len(), 7);
        assert_eq!(&patch[5..], &[0x90, 0x90]);

        let slots = slots_cave(PAGE_AT, HOOK, &SLOTS_ORIGINAL).unwrap();
        assert_eq!(slots.len(), 19);
        assert_eq!(&slots[..3], &[0x48, 0x89, 0x35]); // mov [rip+d], rsi
        // mov [rip+d], rsi must land on SERVER_SLOT
        let d = i32::from_le_bytes(slots[3..7].try_into().unwrap()) as i64;
        assert_eq!((PAGE_AT + SLOTS_CAVE + 7) as i64 + d, (PAGE_AT + SERVER_SLOT) as i64);
        // jump back lands right after the 7 hooked bytes
        let j = i32::from_le_bytes(slots[15..19].try_into().unwrap()) as i64;
        assert_eq!((PAGE_AT + SLOTS_CAVE + 19) as i64 + j, (HOOK + 7) as i64);

        let (cave, code) = death_cave(PAGE_AT, 1).unwrap();
        let code = finish_death_cave(cave, code, HOOK).unwrap();
        assert_eq!(code.len(), 46);
        let back = i32::from_le_bytes(code[42..46].try_into().unwrap()) as i64;
        assert_eq!((cave + 46) as i64 + back, (HOOK + 5) as i64);
        assert!(death_cave(PAGE_AT, MAX_DEATH_CAVES).is_none()); // no cave over the record cave
    }

    #[test]
    fn too_far_is_refused() {
        assert!(jump_patch(0x1_4000_0000, 0x7FF0_0000_0000, 5).is_none());
    }

    /// Prints the caves as hex for disassembly: `cargo test dump -- --nocapture`.
    #[test]
    fn dump() {
        let hex = |b: &[u8]| b.iter().map(|x| format!("{x:02x}")).collect::<Vec<_>>().join(" ");
        let slots = slots_cave(PAGE_AT, HOOK, &SLOTS_ORIGINAL).unwrap();
        println!("CAVE slots {:#x} {}", PAGE_AT + SLOTS_CAVE, hex(&slots));
        let (cave, code) = death_cave(PAGE_AT, 0).unwrap();
        println!("CAVE death {:#x} {}", cave, hex(&finish_death_cave(cave, code, HOOK).unwrap()));
        let record = record_cave(PAGE_AT, HOOK, &ENTRY_ORIGINAL).unwrap();
        println!("CAVE record {:#x} {}", PAGE_AT + RECORD_CAVE, hex(&record));
        println!("CAVE sleep {:#x} {}", PAGE_AT + SLEEP_CAVE, hex(&sleep_cave(PAGE_AT, HOOK).unwrap()));
        let chat = chat_cave(PAGE_AT, HOOK, &ENTRY_ORIGINAL, 0x7FF8_1234_5678).unwrap();
        println!("CAVE chat {:#x} {}", PAGE_AT + CHAT_CAVE, hex(&chat));
        let chat_in = chat_in_cave(PAGE_AT, HOOK, &CHAT_IN_ORIGINAL).unwrap();
        println!("CAVE chat_in {:#x} {}", PAGE_AT + CHAT_IN_CAVE, hex(&chat_in));
        let freeze = freeze_cave(FREEZE_PAGE_AT, HOOK, &FREEZE_ORIGINAL, 0x828, 0x830).unwrap();
        println!("CAVE freeze {:#x} {}", FREEZE_PAGE_AT + FZ_CAVE, hex(&freeze));
    }

    /// Every cave of the shared page built at live-like addresses for the 1.0 hook sites (generated
    /// lengths), plus the data regions: nothing overlaps and everything fits in the page.
    #[test]
    fn all_caves_fit_without_overlap() {
        for site in &SITES {
            caves_fit(site);
        }
    }

    fn caves_fit(site: &Sites) {
        let page = LIVE_PAGE;
        let mut regions: Vec<(usize, usize, String)> = vec![
            (SERVER_SLOT, 8, "server object".into()),
            (HEAD, 4, "death head".into()),
            (RECORD_HEAD, 4, "record head".into()),
            (RING, RING_LEN * 4, "death ring".into()),
            (RECORDS, RECORDS_LEN * RECORD_SIZE, "records".into()),
            (SLEEPERS, SLEEPERS_END - SLEEPERS, "sleeper cells".into()),
            (CHAT_IN_HEAD, 4, "chat-in head".into()),
            (CHAT_IN_RING, CHAT_IN_LEN * CHAT_IN_SLOT, "chat-in ring".into()),
        ];
        let slots = slots_cave(page, IMAGE + site.slots, &SLOTS_ORIGINAL).unwrap();
        regions.push((SLOTS_CAVE, slots.len(), "slots cave".into()));
        for index in 0..MAX_DEATH_CAVES {
            let (at, body) = death_cave(page, index).unwrap();
            let code = finish_death_cave(at, body, IMAGE + site.died[index % 2]).unwrap();
            regions.push((at - page, code.len(), format!("death cave {index}")));
        }
        let record = record_cave(page, IMAGE + site.record, &ENTRY_ORIGINAL).unwrap();
        regions.push((RECORD_CAVE, record.len(), "record cave".into()));
        let sleep = sleep_cave(page, IMAGE + site.sleeper).unwrap();
        regions.push((SLEEP_CAVE, sleep.len(), "sleep cave".into()));
        let chat = chat_cave(page, IMAGE + site.relay, &ENTRY_ORIGINAL, crate::chat::chat_tick as usize).unwrap();
        regions.push((CHAT_CAVE, chat.len(), "chat cave".into()));
        let chat_in = chat_in_cave(page, IMAGE + site.chat_in, &CHAT_IN_ORIGINAL).unwrap();
        regions.push((CHAT_IN_CAVE, chat_in.len(), "chat-in cave".into()));
        assert!(CHAT_IN_CAVE + chat_in.len() <= CHAT_IN_CAVE_END);

        regions.sort();
        for pair in regions.windows(2) {
            let ((a, len, first), (b, _, second)) = (&pair[0], &pair[1]);
            assert!(a + len <= *b, "{first} ({a:#x} + {len:#x}) overlaps {second} ({b:#x})");
        }
        let (last, len, name) = regions.last().unwrap();
        assert!(last + len <= PAGE, "{name} reaches past the page");
        // The live hook sites reach the page.
        for (hook, cave) in [(site.slots, SLOTS_CAVE), (site.record, RECORD_CAVE), (site.sleeper, SLEEP_CAVE), (site.chat_in, CHAT_IN_CAVE), (site.relay, CHAT_CAVE)] {
            assert!(jump_patch(IMAGE + hook, page + cave, 5).is_some());
        }
    }

    #[test]
    fn chat_in_cave_layout() {
        let orig = [0x89, 0x44, 0x24, 0x20, 0xC6, 0x45, 0x20, 0x00];
        let c = chat_in_cave(PAGE_AT, HOOK, &orig).unwrap();
        assert_eq!(&c[..8], &orig);
        let rel_at = |i: usize| (PAGE_AT + CHAT_IN_CAVE + i + 4).wrapping_add_signed(i32::from_le_bytes(c[i..i + 4].try_into().unwrap()) as isize);
        let xadd = c.windows(4).position(|w| w == [0xF0, 0x0F, 0xC1, 0x05]).unwrap() + 4;
        assert_eq!(rel_at(xadd), PAGE_AT + CHAT_IN_HEAD);
        let lea = c.windows(3).position(|w| w == [0x48, 0x8D, 0x3D]).unwrap() + 3;
        assert_eq!(rel_at(lea), PAGE_AT + CHAT_IN_RING);
        assert_eq!(c[c.len() - 5], 0xE9);
        assert_eq!(rel_at(c.len() - 4), HOOK + 8);
        assert!(CHAT_IN_CAVE + c.len() <= CHAT_IN_CAVE_END);
        assert!(CHAT_IN_RING + CHAT_IN_LEN * CHAT_IN_SLOT <= PAGE);
        assert!(CHAT_IN_CAVE_END <= CHAT_IN_HEAD && CHAT_IN_HEAD + 4 <= CHAT_IN_RING);
    }

    /// Runs the real chat-in cave on this CPU, entered the way the receive handler enters it.
    #[cfg(all(target_arch = "x86_64", windows))]
    mod run_chat_in {
        use super::super::*;
        use super::CHAT_IN_ORIGINAL;
        use std::arch::asm;
        use std::ptr;

        const CANARY: u64 = 0x0C0F_FEE0_0C0F_FEE0;
        const RAX: u64 = 0x1111_0000_1234_5678;
        const RCX: u64 = 0x2222_3333_4444_5555;
        const RDX: u64 = 0x6666_7777_8888_9999;
        const RSI: u64 = 0xAAAA_BBBB_CCCC_DDDD;
        const RDI: u64 = 0xEEEE_FFFF_0000_1111;

        #[repr(C)]
        struct View {
            ptr: *const u8,
            len: u64,
        }

        /// [0..8): the caller's 0x40-byte frame after the call, [8]: rflags before, [9]: after.
        type Out = [u64; 10];

        /// rsp at the cave is the game's rsp: [rsp+30h] = handle, [rsp+38h] = account. `call`
        /// pushes 8 bytes, so they go at [rsp+28h] / [rsp+30h] here. The two replayed instructions
        /// write the dword at [rsp+20h] (here [rsp+18h]) = eax and byte [rbp+20h] = 0.
        fn enter(cave_at: usize, frame: *mut u8, chat_type: u8, view: *const View, handle: u32, account: u64) -> ([u64; 7], Out) {
            let mut out: Out = [0; 10];
            let (mut rax, mut rcx, mut rdx, mut rsi, mut rdi) = (RAX, RCX, RDX, RSI, RDI);
            let mut r8 = 0x5555_0000_0000_0000u64 | chat_type as u64;
            let mut r9 = view as u64;
            unsafe {
                asm!(
                    "push rbp",
                    "mov rbp, r12",
                    "mov r12, rsp",
                    "and rsp, -16",
                    "sub rsp, 0x40",
                    "mov r15, {canary}",
                    "mov [rsp], r15", "mov [rsp + 0x08], r15", "mov [rsp + 0x10], r15", "mov [rsp + 0x18], r15",
                    "mov [rsp + 0x20], r15", "mov [rsp + 0x28], r15", "mov [rsp + 0x30], r15", "mov [rsp + 0x38], r15",
                    "mov dword ptr [rsp + 0x28], r10d",
                    "mov [rsp + 0x30], r11",
                    "stc",
                    "pushfq",
                    "pop r15",
                    "mov [r13 + 0x40], r15",
                    "call r14",
                    "pushfq",
                    "pop r15",
                    "mov [r13 + 0x48], r15",
                    "mov r15, [rsp]", "mov [r13], r15", "mov r15, [rsp + 0x08]", "mov [r13 + 0x08], r15",
                    "mov r15, [rsp + 0x10]", "mov [r13 + 0x10], r15", "mov r15, [rsp + 0x18]", "mov [r13 + 0x18], r15",
                    "mov r15, [rsp + 0x20]", "mov [r13 + 0x20], r15", "mov r15, [rsp + 0x28]", "mov [r13 + 0x28], r15",
                    "mov r15, [rsp + 0x30]", "mov [r13 + 0x30], r15", "mov r15, [rsp + 0x38]", "mov [r13 + 0x38], r15",
                    "mov rsp, r12",
                    "pop rbp",
                    canary = const CANARY,
                    inout("r12") frame => _,
                    in("r14") cave_at,
                    in("r13") out.as_mut_ptr(),
                    in("r10") handle,
                    in("r11") account,
                    inout("rax") rax,
                    inout("rcx") rcx,
                    inout("rdx") rdx,
                    inout("rsi") rsi,
                    inout("rdi") rdi,
                    inout("r8") r8,
                    inout("r9") r9,
                    out("r15") _,
                    clobber_abi("system"),
                );
            }
            ([rax, rcx, rdx, rsi, rdi, r8, r9], out)
        }

        #[test]
        fn chat_in_cave_runs() {
            let page = crate::memory::alloc_near(chat_in_cave_runs as usize, PAGE);
            assert_ne!(page, 0);
            let landing = page + 0xF00; // between the cave and the ring head
            unsafe { *(landing as *mut u8) = 0xC3 };
            let code = chat_in_cave(page, landing - 8, &CHAT_IN_ORIGINAL).unwrap();
            unsafe { ptr::copy_nonoverlapping(code.as_ptr(), (page + CHAT_IN_CAVE) as *mut u8, code.len()) };
            let mut frame = Box::new([0xFFu8; 0x40]);
            let long = vec![b'x'; CHAT_IN_TEXT_MAX];
            let cases: Vec<(u8, View, u32, u64, Option<&[u8]>)> = vec![
                (0, View { ptr: b"hello there".as_ptr(), len: 11 }, 0x80, 0x1122_3344_5566_7788, Some(&b"hello there"[..])),
                (4, View { ptr: b"".as_ptr(), len: 0 }, 0x101, 0, Some(&b""[..])),
                (0, View { ptr: long.as_ptr(), len: long.len() as u64 }, 0x181, 7, Some(&long[..])),
                // over 0x400: the pointer must not be touched (1 would fault)
                (0, View { ptr: 1 as *const u8, len: CHAT_IN_TEXT_MAX as u64 + 1 }, 0x80, 9, None),
            ];
            for (n, (chat_type, view, handle, account, text)) in cases.iter().enumerate() {
                frame[0x20] = 0xFF;
                let head = unsafe { ptr::read_volatile((page + CHAT_IN_HEAD) as *const u32) };
                let (regs, out) = enter(page + CHAT_IN_CAVE, frame.as_mut_ptr(), *chat_type, view, *handle, *account);
                assert_eq!(regs, [RAX, RCX, RDX, RSI, RDI, 0x5555_0000_0000_0000 | *chat_type as u64, view as *const View as u64], "case {n}");
                assert_eq!(out[8] & 0xCD5, out[9] & 0xCD5, "flags, case {n}"); // CF PF AF ZF SF OF DF
                assert_eq!(out[8] & 1, 1);
                assert_eq!(frame[0x20], 0, "replayed mov byte [rbp+20h],0, case {n}");
                assert_eq!(out[3], (CANARY & !0xFFFF_FFFF) | (RAX & 0xFFFF_FFFF), "replayed mov [rsp+20h],eax, case {n}");
                assert_eq!(out[5], (CANARY & !0xFFFF_FFFF) | *handle as u64);
                assert_eq!(out[6], *account);
                for i in [0, 1, 2, 4, 7] {
                    assert_eq!(out[i], CANARY, "stack qword {i}, case {n}");
                }
                assert_eq!(unsafe { ptr::read_volatile((page + CHAT_IN_HEAD) as *const u32) }, head.wrapping_add(1));
                let slot = page + CHAT_IN_RING + (head as usize % CHAT_IN_LEN) * CHAT_IN_SLOT;
                let r8 = |o: usize| unsafe { ptr::read_volatile((slot + o) as *const u8) };
                let r32 = |o: usize| unsafe { ptr::read_volatile((slot + o) as *const u32) };
                let r64 = |o: usize| unsafe { ptr::read_volatile((slot + o) as *const u64) };
                assert_eq!(r32(CI_SEQ), head.wrapping_add(1), "published, case {n}");
                assert_eq!((r8(CI_TYPE), r32(CI_HANDLE), r64(CI_ACCOUNT)), (*chat_type, *handle, *account));
                match text {
                    Some(t) => {
                        assert_eq!((r8(CI_REJECTED), r32(CI_LEN) as usize), (0, t.len()));
                        let copied = unsafe { std::slice::from_raw_parts((slot + CI_TEXT) as *const u8, t.len()) };
                        assert_eq!(copied, *t);
                    }
                    None => assert_eq!((r8(CI_REJECTED), r32(CI_LEN)), (1, 0)),
                }
            }
            // the poll side reads back what the cave wrote
            let mut tail = 0;
            let (got, lost) = crate::chat::take_chat_in(page, &mut tail);
            assert_eq!((got.len(), lost), (cases.len(), 0));
            assert_eq!(got[0].text, b"hello there".to_vec());
            assert!(got[3].rejected);
        }
    }

    #[test]
    fn chat_cave_layout() {
        let code = chat_cave(PAGE_AT, HOOK, &ENTRY_ORIGINAL, 0x7FF8_1234_5678).unwrap();
        let pushes = code[..11].iter().filter(|&&b| b == 0x50 || b == 0x51 || b == 0x52 || b == 0x53).count();
        assert_eq!(pushes, 7); // 7 pushes + 0x20 keeps the call 16-byte aligned
        assert_eq!(u64::from_le_bytes(code[17..25].try_into().unwrap()), 0x7FF8_1234_5678);
        let back = i32::from_le_bytes(code[code.len() - 4..].try_into().unwrap()) as i64;
        assert_eq!((PAGE_AT + CHAT_CAVE + code.len()) as i64 + back, (HOOK + 5) as i64);
        assert_eq!(code.len(), 52);
        assert!(CHAT_CAVE + code.len() <= CHAT_IN_CAVE);
    }

    #[test]
    fn sleep_cave_layout() {
        let code = sleep_cave(PAGE_AT, HOOK).unwrap();
        // the je must land exactly on the final jmp
        assert_eq!(2 + 2 + code[3] as usize, code.len() - 5);
        let back = i32::from_le_bytes(code[code.len() - 4..].try_into().unwrap()) as i64;
        assert_eq!((PAGE_AT + SLEEP_CAVE + code.len()) as i64 + back, (HOOK + 7) as i64);
        assert!(SLEEP_CAVE + code.len() <= RECORDS);
        assert!(SLEEPERS + (15 * 0x100 >> 5) * 4 + 4 <= SLEEPERS_END); // player steps up to 0x100 (1.0: 0xA0)
    }

    #[test]
    fn record_cave_targets() {
        let code = record_cave(PAGE_AT, HOOK, &ENTRY_ORIGINAL).unwrap();
        let cave = PAGE_AT + RECORD_CAVE;
        let back = i32::from_le_bytes(code[code.len() - 4..].try_into().unwrap()) as i64;
        assert_eq!((cave + code.len()) as i64 + back, (HOOK + 5) as i64);
        assert_eq!(&code[code.len() - 10..code.len() - 5], &ENTRY_ORIGINAL);
        assert_eq!(code.len(), 66);
        assert!(RECORD_CAVE + code.len() <= SLEEP_CAVE); // the sleep cave follows, not the records
        assert!(MAX_DEATH_CAVES >= 2);
    }

    const FREEZE_ORIGINAL: [u8; 7] = [0x41, 0x29, 0x04, 0x88, 0x48, 0x8B, 0xCB];
    const FREEZE_PAGE_AT: usize = 0x1_3FFE_0000;

    #[test]
    fn freeze_cave_layout() {
        let code = freeze_cave(FREEZE_PAGE_AT, HOOK, &FREEZE_ORIGINAL, 0x828, 0x830).unwrap();
        let cave = FREEZE_PAGE_AT + FZ_CAVE;
        let at = |i: usize| i32::from_le_bytes(code[i..i + 4].try_into().unwrap()) as i64;
        // Disassembled with capstone at these addresses (scratchpad design-deathcauses/cave.py).
        let golden = "41 29 04 88 9c 50 51 52 41 8b 14 88 85 d2 7f 4b 01 c2 7e 47 41 8b 46 08 85 c0 74 3f \
                      ff c8 49 8b 0e 48 3b 81 30 08 00 00 73 31 48 8b 89 28 08 00 00 48 85 c9 74 25 48 c1 \
                      e0 04 8b 0c 01 ff c1 74 1a b8 01 00 00 00 f0 0f c1 05 b2 fe ff ff 83 e0 0f 48 8d 15 \
                      e8 fe ff ff 89 0c 82 5a 59 58 9d 48 8b cb e9 96 b2 08 00";
        let want: Vec<u8> = golden.split_whitespace().map(|t| u8::from_str_radix(t, 16).unwrap()).collect();
        assert_eq!(code, want);
        assert_eq!(code.len(), 0x67);
        assert_eq!(&code[..4], &FREEZE_ORIGINAL[..4]); // the drain runs first, unchanged
        assert_eq!(&code[0x5F..0x62], &FREEZE_ORIGINAL[4..]); // then mov rcx, rbx
        assert_eq!((cave + 0x4E) as i64 + at(0x4A), (FREEZE_PAGE_AT + FZ_HEAD) as i64); // lock xadd target
        assert_eq!((cave + 0x58) as i64 + at(0x54), (FREEZE_PAGE_AT + FZ_RING) as i64); // lea target
        assert_eq!((cave + code.len()) as i64 + at(code.len() - 4), (HOOK + 7) as i64); // back to the call
        for j in [0x0E, 0x12, 0x1A, 0x28, 0x34, 0x3F] {
            assert_eq!(j + 2 + code[j + 1] as usize, 0x5B, "skip at +{j:#x} must land on the pops");
        }
        assert!(FZ_CAVE + code.len() <= FZ_PAGE);
    }

    #[test]
    fn freeze_cave_at_live_addresses() {
        for site in &SITES {
            let hook = IMAGE + site.freeze;
            let code = freeze_cave(LIVE_FREEZE_PAGE, hook, &FREEZE_ORIGINAL, 0x828, 0x830).unwrap();
            let cave = LIVE_FREEZE_PAGE + FZ_CAVE;
            let at = |i: usize| i32::from_le_bytes(code[i..i + 4].try_into().unwrap()) as i64;
            assert_eq!(code.len(), 0x67);
            assert_eq!((cave + 0x4E) as i64 + at(0x4A), (LIVE_FREEZE_PAGE + FZ_HEAD) as i64);
            assert_eq!((cave + 0x58) as i64 + at(0x54), (LIVE_FREEZE_PAGE + FZ_RING) as i64);
            assert_eq!((cave + code.len()) as i64 + at(code.len() - 4), (hook + 7) as i64);
            let patch = jump_patch(hook, cave, 7).unwrap();
            assert_eq!(&patch[5..], &[0x90, 0x90]);
            assert_eq!((hook + 5) as i64 + i32::from_le_bytes(patch[1..5].try_into().unwrap()) as i64, cave as i64);
        }
    }
}
