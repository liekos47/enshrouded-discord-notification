//! One sleeper skips the night.
//!
//! `server_nighttime_skip` (server 1.0, SVN 1267041: update exe+0x103a10, patch exe+0x103b09; 0.9 had
//! it at exe+0xc9670) counts, every tick at night, the
//! players online and those with actor state flag 11 (Sleeping), then sets the time speed:
//! 1x with nobody asleep, else `60 / (players / sleepers)`. Replacing the player count with the
//! sleeper count makes that `60 / 1`: full speed as soon as one player sleeps. Nobody asleep
//! still takes the game's own 1x branch, and daytime is untouched.

use std::{
    collections::HashMap,
    time::{Duration, Instant},
};

use crate::memory::{Image, write};

/// A player not seen sleeping for this long counts as awake again.
pub const SLEEP_GONE: Duration = Duration::from_secs(10);
/// At most one "sleeps" message per player in this time.
pub const SLEEP_REPEAT: Duration = Duration::from_secs(120);

/// A sleeper: (entity id, slot handle). The game gives the next player in a slot the same entity
/// id (slot index + 1) but a new handle (the bits above the slot index count sessions), so the
/// handle keeps one player's sleep from silencing the next one's. Handle 0: slot not known.
pub type SleeperKey = (u32, u32);

/// Who is asleep while the night is skipped, and when each was last announced.
#[derive(Default)]
pub struct Sleepers {
    asleep: HashMap<SleeperKey, Instant>,
    announced: HashMap<SleeperKey, Instant>,
}

impl Sleepers {
    /// `key` was seen sleeping at `now`. True when that is worth a "sleeps" message: they were not
    /// asleep a moment ago, and were not announced in the last SLEEP_REPEAT.
    pub fn seen(&mut self, key: SleeperKey, now: Instant) -> bool {
        let fresh = self.asleep.get(&key).is_none_or(|t| now.saturating_duration_since(*t) > SLEEP_GONE);
        self.asleep.insert(key, now);
        let repeat = self.announced.get(&key).is_some_and(|t| now.saturating_duration_since(*t) < SLEEP_REPEAT);
        if fresh && !repeat {
            self.announced.insert(key, now);
        }
        fresh && !repeat
    }

    /// Players seen sleeping within SLEEP_GONE of `now`.
    pub fn sleeping(&self, now: Instant) -> usize {
        self.asleep.values().filter(|t| now.saturating_duration_since(**t) < SLEEP_GONE).count()
    }

    /// The player with this slot handle left: forget them.
    pub fn left(&mut self, handle: u32) {
        self.asleep.retain(|&(_, h), _| h != handle);
        self.announced.retain(|&(_, h), _| h != handle);
    }

    /// Drop entries too old to matter.
    pub fn prune(&mut self, now: Instant) {
        self.asleep.retain(|_, t| now.saturating_duration_since(*t) < SLEEP_GONE * 6);
        self.announced.retain(|_, t| now.saturating_duration_since(*t) < SLEEP_REPEAT);
    }
}

/// `movss xmm6, [60.0]; movzx eax, r14b (players); movd xmm1, eax; movzx eax, bpl (sleepers);
/// cvtdq2ps xmm1, xmm1; movd xmm0, eax; cvtdq2ps xmm0, xmm0; divss xmm1, xmm0; divss xmm6, xmm1`
const SIG: &str = "F3 0F 10 35 ?? ?? ?? ?? 41 0F B6 C6 66 0F 6E C8 40 0F B6 C5 0F 5B C9 66 0F 6E C0 0F 5B C0 F3 0F 5E C8 F3 0F 5E F1";
const OFFSET: usize = 8;
const ORIGINAL: [u8; 4] = [0x41, 0x0F, 0xB6, 0xC6]; // movzx eax, r14b  (players)
const PATCHED: [u8; 4] = [0x40, 0x0F, 0xB6, 0xC5]; // movzx eax, bpl   (sleepers)

pub fn install(image: &Image) -> Result<usize, String> {
    let found = image.find_all(SIG);
    let [at] = found[..] else { return Err(format!("night-skip signature matched {} times", found.len())) };
    let site = at + OFFSET;
    let current: [u8; 4] = unsafe { crate::memory::read(site) };
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
        assert_eq!(&pattern[OFFSET..OFFSET + 4], &original[..]);
        assert_eq!(ORIGINAL.len(), PATCHED.len());
    }

    fn secs(n: u64) -> Duration {
        Duration::from_secs(n)
    }

    #[test]
    fn sleep_messages_per_player_session() {
        let t = Instant::now();
        let mut s = Sleepers::default();
        let ann = (1, 0x40); // entity 1 in slot 0, first session
        assert!(s.seen(ann, t));
        // Still asleep on the next polls: no new message.
        assert!(!s.seen(ann, t + secs(1)));
        assert!(!s.seen(ann, t + secs(5)));
        assert_eq!(s.sleeping(t + secs(5)), 1);
        // Woke up and slept again within SLEEP_REPEAT: still quiet.
        assert!(!s.seen(ann, t + secs(30)));
        // Asleep again after SLEEP_REPEAT: announced.
        assert!(s.seen(ann, t + secs(200)));
        // Ann leaves; Bob gets slot 0 and entity 1 back, with a new handle: his sleep is announced.
        s.left(0x40);
        let bob = (1, 0x80);
        assert!(s.seen(bob, t + secs(201)));
        assert_eq!(s.sleeping(t + secs(201)), 1); // Ann's entry is gone
    }

    #[test]
    fn same_entity_new_handle_is_another_player_even_without_a_leave() {
        let t = Instant::now();
        let mut s = Sleepers::default();
        assert!(s.seen((1, 0x40), t));
        assert!(s.seen((1, 0x80), t + secs(20)));
        assert!(!s.seen((1, 0x80), t + secs(21)));
    }

    #[test]
    fn counts_and_pruning() {
        let t = Instant::now();
        let mut s = Sleepers::default();
        s.seen((1, 0x40), t);
        s.seen((2, 0x41), t + secs(8));
        assert_eq!(s.sleeping(t + secs(9)), 2);
        assert_eq!(s.sleeping(t + secs(12)), 1); // 1 not seen for over SLEEP_GONE
        s.prune(t + SLEEP_REPEAT + secs(10));
        assert_eq!(s.sleeping(t + SLEEP_REPEAT + secs(10)), 0);
        assert!(s.asleep.is_empty() && s.announced.is_empty());
    }
}
