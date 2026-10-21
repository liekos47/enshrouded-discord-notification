//! Which cause belongs to a player death, and whether the death is posted at all.
//!
//! No game memory here: the poll thread hands in what it read, so every rule is unit-tested.
//! - A PlayerDeath record pairs by the accountIdHash at slot +0x48, exactly. By time only when the
//!   slot's account is unknown (no server object, unreadable slot, 0) or the record carries none,
//!   and only within PAIR_WINDOW of the death.
//! - A freezing kill (cave::freeze_cave) pairs by entity id.
//! - A death with neither, soon after the player arrived in the slot, is a character that was
//!   saved dead and restored with Health 0 (`attribute_save` writes Health = max * saved ratio): the
//!   game raises EntityDiedEvent again and no record exists. It is logged, not posted, but only when
//!   both cause hooks are in (or this account already had a death posted by this process), because
//!   otherwise a real cause-less death could look the same.

use std::time::{Duration, Instant};

use crate::{PAIR_WINDOW, PLAYER_SLOTS, Record, SLOT_ENTITY, SLOT_HANDLE};

/// accountIdHash in a 1.0 player slot (the PlayerDeath record's account is found exactly here live).
pub const SLOT_ACCOUNT: usize = 0x48;
/// Bytes of a slot the poll thread reads for handle, entity and account.
pub const SLOT_SCAN: usize = SLOT_ACCOUNT + 8;
/// Records nobody claimed are dropped after this (freezing kills after FREEZE_LEAD + PAIR_WINDOW).
pub const KEEP: Duration = Duration::from_secs(6);
/// A cause-less death this soon after the player arrived in the slot is a restore of a dead save.
/// Live (Enshrouded 2, 2026-10-16) it came 0-2 s after "logged in"; that log line and the slot's
/// entity id are written together (exe+0x7b40a8, exe+0x7b4130).
pub const REJOIN_WINDOW: Duration = Duration::from_secs(15);
/// A freezing kill can precede its EntityDiedEvent by this much (the death system waits while the
/// player is still Spawning; bodyheat_depletion does not). It covers the whole rejoin window, so a
/// player who freezes right after arriving is posted, not taken for a restored dead save. A slot's
/// kills are dropped when a new player arrives in it, and kills match by exact entity id.
pub const FREEZE_LEAD: Duration = Duration::from_secs(REJOIN_WINDOW.as_secs() + 3);
/// A slot change seen at death time but not by the scan counts as "just arrived" only if that scan
/// is this recent (otherwise the scans are failing and the arrival time is unknown).
const RECENT_SCAN: Duration = Duration::from_secs(1);

/// Handle, entity and account of one player slot.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct SlotSeen {
    pub handle: u32,
    pub entity: u32,
    pub account: u64,
}

impl SlotSeen {
    /// From bytes read at the slot start (at least SLOT_SCAN of them).
    pub fn parse(slot: &[u8]) -> Option<SlotSeen> {
        let u32_at = |o: usize| Some(u32::from_le_bytes(slot.get(o..o + 4)?.try_into().ok()?));
        Some(SlotSeen {
            handle: u32_at(SLOT_HANDLE)?,
            entity: u32_at(SLOT_ENTITY)?,
            account: u64::from_le_bytes(slot.get(SLOT_ACCOUNT..SLOT_ACCOUNT + 8)?.try_into().ok()?),
        })
    }

    /// The account to pair records by; None when the slot has none.
    pub fn account(&self) -> Option<u64> {
        (self.account != 0).then_some(self.account)
    }
}

/// When each slot's current player arrived, from the poll thread's scans of the slot table.
#[derive(Default)]
pub struct SlotTracker {
    seen: [SlotSeen; PLAYER_SLOTS],
    arrived: [Option<Instant>; PLAYER_SLOTS],
    last_scan: Option<Instant>,
}

impl SlotTracker {
    /// One slot of a scan. True when a player has just arrived in it (new handle or entity).
    /// Slots already taken at the first scan get no arrival time.
    pub fn scan(&mut self, i: usize, now: SlotSeen, at: Instant) -> bool {
        let before = std::mem::replace(&mut self.seen[i], now);
        if now.handle == 0 || now.entity == 0 {
            self.arrived[i] = None;
            return false;
        }
        if self.last_scan.is_none() {
            return false;
        }
        if (before.handle, before.entity) != (now.handle, now.entity) {
            self.arrived[i] = Some(at);
            return true;
        }
        false
    }

    /// Call after scanning every slot.
    pub fn scanned(&mut self, at: Instant) {
        self.last_scan = Some(at);
    }

    /// What the last scan saw in slot `i` (all zero before any scan).
    pub fn seen(&self, i: usize) -> SlotSeen {
        self.seen.get(i).copied().unwrap_or_default()
    }

    /// The slot that held entity `id` (non-zero) in the last scan.
    pub fn find_entity(&self, id: u32) -> Option<(usize, SlotSeen)> {
        if id == 0 {
            return None;
        }
        self.seen.iter().position(|s| s.handle != 0 && s.entity == id).map(|i| (i, self.seen[i]))
    }

    /// How long before `at` the player now in slot `i` (`now`, read at death time) arrived.
    /// None when unknown: never seen arriving, or the scans have stopped working.
    pub fn since_arrival(&self, i: usize, now: SlotSeen, at: Instant) -> Option<Duration> {
        let seen = self.seen.get(i)?;
        if (seen.handle, seen.entity) == (now.handle, now.entity) {
            return self.arrived[i].map(|t| at.saturating_duration_since(t));
        }
        // Changed after the last scan: arrived just now, if that scan was recent.
        self.last_scan.filter(|t| at.saturating_duration_since(*t) <= RECENT_SCAN).map(|_| Duration::ZERO)
    }
}

fn apart(a: Instant, b: Instant) -> Duration {
    a.saturating_duration_since(b).max(b.saturating_duration_since(a))
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum PairedBy {
    Account,
    Time,
}

/// The record (index into `records`, oldest first) for the death of the player whose slot holds
/// `account`. Same account: the oldest such record, whenever it came. Otherwise the record closest
/// in time within PAIR_WINDOW among those that cannot belong to anyone else: any record when the
/// slot's account is unknown, else only records that carry no account.
pub fn pick_record(account: Option<u64>, records: &[(Record, Instant)], death_at: Instant) -> Option<(usize, PairedBy)> {
    if let Some(a) = account {
        if let Some(i) = records.iter().position(|(r, _)| r.account == a) {
            return Some((i, PairedBy::Account));
        }
    }
    records
        .iter()
        .enumerate()
        .filter(|(_, (r, _))| account.is_none() || r.account == 0)
        .map(|(i, (_, t))| (i, apart(*t, death_at)))
        .filter(|&(_, d)| d <= PAIR_WINDOW)
        .min_by_key(|&(_, d)| d)
        .map(|(i, _)| (i, PairedBy::Time))
}

/// The freezing kill of `entity` that belongs to a death seen at `death_at`: the kill may come up
/// to FREEZE_LEAD before the death, or PAIR_WINDOW after it.
pub fn pick_freeze(entity: u32, freezes: &[(u32, Instant)], death_at: Instant) -> Option<usize> {
    freezes.iter().position(|&(id, t)| {
        id == entity && death_at.saturating_duration_since(t) <= FREEZE_LEAD && t.saturating_duration_since(death_at) <= PAIR_WINDOW
    })
}

#[derive(Debug, PartialEq)]
pub enum Verdict {
    /// Not paired yet; ask again next poll.
    Wait,
    Post,
    /// A character restored dead: log it, do not post it.
    Suppress,
}

pub struct Facts {
    /// A record or a freezing kill was paired.
    pub paired: bool,
    /// Time since the death was seen.
    pub waited: Duration,
    /// Time from the player's arrival in the slot to the death; None if unknown.
    pub since_arrival: Option<Duration>,
    /// The PlayerDeath record hook is in.
    pub records_hook: bool,
    /// The freezing hook is in.
    pub freeze_hook: bool,
    /// This process already posted a death for this account.
    pub died_before: bool,
}

pub fn decide(f: &Facts) -> Verdict {
    if f.paired {
        return Verdict::Post;
    }
    if (f.records_hook || f.freeze_hook) && f.waited < PAIR_WINDOW {
        return Verdict::Wait;
    }
    let restored_dead =
        f.records_hook && f.since_arrival.is_some_and(|d| d <= REJOIN_WINDOW) && (f.freeze_hook || f.died_before);
    if restored_dead { Verdict::Suppress } else { Verdict::Post }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(account: u64, cause: u8) -> Record {
        Record { account, user: 0, cause, position: [0.0; 3], cause_guid: [0; 16], deadly_fog: false, drowned: false }
    }
    fn ms(n: u64) -> Duration {
        Duration::from_millis(n)
    }
    const A: u64 = 0xA36A_FE43_8476_4589; // a live accountIdHash (server 1, 2026-10-16)
    const B: u64 = 0x1111_2222_3333_4444;

    #[test]
    fn slot_account_is_read_at_0x48_only() {
        // A 0x400-byte read (what the old ACCOUNT_SCAN covered): slot k at 0, slot k+1 at 0x148.
        let mut bytes = vec![0u8; 0x400];
        bytes[SLOT_HANDLE..SLOT_HANDLE + 4].copy_from_slice(&0x40u32.to_le_bytes());
        bytes[SLOT_ENTITY..SLOT_ENTITY + 4].copy_from_slice(&1u32.to_le_bytes());
        bytes[0x48..0x50].copy_from_slice(&A.to_le_bytes());
        bytes[0x190..0x198].copy_from_slice(&B.to_le_bytes()); // slot k+1's account (0x148 + 0x48)
        let k = SlotSeen::parse(&bytes).unwrap();
        assert_eq!((k.handle, k.entity, k.account()), (0x40, 1, Some(A)));
        let t = Instant::now();
        // Slot k+1's record is never taken for slot k.
        assert_eq!(pick_record(k.account(), &[(record(B, 0), t)], t), None);
        assert_eq!(SlotSeen::parse(&bytes[..SLOT_SCAN - 1]), None);
        assert_eq!(SlotSeen::parse(&[0u8; SLOT_SCAN]).unwrap().account(), None);
    }

    #[test]
    fn adjacent_players_dying_within_a_second_keep_their_own_records() {
        let t = Instant::now();
        let records = [(record(B, 1), t), (record(A, 0), t + ms(300))];
        assert_eq!(pick_record(Some(A), &records, t + ms(700)), Some((1, PairedBy::Account)));
        assert_eq!(pick_record(Some(B), &records, t + ms(100)), Some((0, PairedBy::Account)));
    }

    #[test]
    fn a_death_without_a_record_does_not_take_another_players() {
        let t = Instant::now();
        let records = [(record(B, 0), t)];
        assert_eq!(pick_record(Some(A), &records, t), None);
    }

    #[test]
    fn time_fallback_only_without_an_account_and_only_close_in_time() {
        let t = Instant::now();
        // The record carries no account: closest within PAIR_WINDOW.
        let records = [(record(0, 2), t), (record(0, 1), t + ms(1000))];
        assert_eq!(pick_record(Some(A), &records, t + ms(900)), Some((1, PairedBy::Time)));
        assert_eq!(pick_record(Some(A), &[(record(0, 2), t)], t + ms(3000)), None);
        // The slot's account is unknown: any record, still only within PAIR_WINDOW.
        assert_eq!(pick_record(None, &[(record(B, 0), t)], t + ms(200)), Some((0, PairedBy::Time)));
        assert_eq!(pick_record(None, &[(record(B, 0), t)], t + ms(2000)), None);
        // An exact account match wins over a closer record without one.
        let records = [(record(0, 2), t + ms(500)), (record(A, 0), t)];
        assert_eq!(pick_record(Some(A), &records, t + ms(500)), Some((1, PairedBy::Account)));
    }

    #[test]
    fn freezing_kills_pair_by_entity() {
        let t = Instant::now();
        let freezes = [(2, t), (1, t + ms(100))];
        assert_eq!(pick_freeze(1, &freezes, t + ms(400)), Some(1));
        assert_eq!(pick_freeze(3, &freezes, t), None);
        assert_eq!(pick_freeze(1, &freezes, t + ms(100) + FREEZE_LEAD + ms(1)), None); // too old
        assert_eq!(pick_freeze(2, &[(2, t + ms(1600))], t), None); // too far after the death
    }

    fn facts() -> Facts {
        Facts { paired: false, waited: PAIR_WINDOW, since_arrival: Some(ms(1500)), records_hook: true, freeze_hook: true, died_before: false }
    }

    #[test]
    fn decisions() {
        // Paired: posted at once, even right after arriving.
        assert_eq!(decide(&Facts { paired: true, waited: Duration::ZERO, ..facts() }), Verdict::Post);
        // Not paired yet: wait out PAIR_WINDOW.
        assert_eq!(decide(&Facts { waited: ms(1000), ..facts() }), Verdict::Wait);
        // Cause-less 1.5 s after arriving, both hooks in: restored dead.
        assert_eq!(decide(&facts()), Verdict::Suppress);
        // Cause-less mid-session (admin or debug kill, unknown path): posted bare.
        assert_eq!(decide(&Facts { since_arrival: Some(Duration::from_secs(60)), ..facts() }), Verdict::Post);
        // Arrival unknown (occupied at the first scan, scans failing): posted.
        assert_eq!(decide(&Facts { since_arrival: None, ..facts() }), Verdict::Post);
        // Without the record hook every death is cause-less: never suppressed, never waits for it.
        assert_eq!(decide(&Facts { records_hook: false, freeze_hook: false, waited: Duration::ZERO, ..facts() }), Verdict::Post);
        assert_eq!(decide(&Facts { records_hook: false, ..facts() }), Verdict::Post);
        // Freezing hook missing: a cause-less death after arriving could be a real freezing death,
        // so it is only suppressed when this account's death was already posted by this process.
        assert_eq!(decide(&Facts { freeze_hook: false, ..facts() }), Verdict::Post);
        assert_eq!(decide(&Facts { freeze_hook: false, died_before: true, ..facts() }), Verdict::Suppress);
    }

    #[test]
    fn freezing_right_after_a_rejoin_is_posted() {
        // Saved alive with BodyHeat 0 in the cold: the drain kills within seconds of arriving.
        let t = Instant::now();
        let freezes = [(1, t)];
        let paired = pick_freeze(1, &freezes, t + ms(800)).is_some();
        assert!(paired);
        assert_eq!(decide(&Facts { paired, waited: Duration::ZERO, since_arrival: Some(ms(2000)), ..facts() }), Verdict::Post);
    }

    #[test]
    fn arrivals() {
        let t = Instant::now();
        let mut slots = SlotTracker::default();
        let jase = SlotSeen { handle: 0x40, entity: 1, account: A };
        // Taken before the first scan: arrival unknown.
        assert!(!slots.scan(0, jase, t));
        slots.scanned(t);
        assert_eq!(slots.since_arrival(0, jase, t + ms(500)), None);
        // Leaves; a new session (new handle generation) gets the same entity id back.
        assert!(!slots.scan(0, SlotSeen::default(), t + ms(250)));
        slots.scanned(t + ms(250));
        let again = SlotSeen { handle: 0x80, entity: 0, account: A }; // connected, not in game yet
        assert!(!slots.scan(0, again, t + ms(500)));
        slots.scanned(t + ms(500));
        let in_game = SlotSeen { entity: 1, ..again };
        assert!(slots.scan(0, in_game, t + ms(750)));
        slots.scanned(t + ms(750));
        assert_eq!(slots.since_arrival(0, in_game, t + ms(2000)), Some(ms(1250)));
        // Unchanged scans keep the arrival time.
        assert!(!slots.scan(0, in_game, t + ms(1000)));
        slots.scanned(t + ms(1000));
        assert_eq!(slots.since_arrival(0, in_game, t + ms(60_750)), Some(Duration::from_secs(60)));
        // Changed after the last scan (seen only at death time): just arrived, if that scan is recent.
        let other = SlotSeen { handle: 0xC0, entity: 1, account: B };
        assert_eq!(slots.since_arrival(0, other, t + ms(1200)), Some(Duration::ZERO));
        assert_eq!(slots.since_arrival(0, other, t + ms(9000)), None);
        // A handle swap without passing through a free slot is an arrival too.
        assert!(slots.scan(0, other, t + ms(1250)));
    }

    #[test]
    fn last_scan_lookups() {
        let t = Instant::now();
        let mut slots = SlotTracker::default();
        assert_eq!(slots.seen(3), SlotSeen::default());
        assert_eq!(slots.find_entity(2), None);
        let ann = SlotSeen { handle: 0x41, entity: 2, account: A };
        slots.scan(1, ann, t);
        slots.scan(2, SlotSeen { handle: 0x82, entity: 0, account: B }, t); // connected, no entity yet
        slots.scanned(t);
        assert_eq!(slots.seen(1), ann);
        assert_eq!(slots.find_entity(2), Some((1, ann)));
        assert_eq!(slots.find_entity(0), None); // entity 0 is "none", never a match
        assert_eq!(slots.seen(PLAYER_SLOTS), SlotSeen::default()); // out of range
        // The entity id goes to the next player in that slot: the lookup follows the last scan.
        let bob = SlotSeen { handle: 0x81, entity: 2, account: B };
        slots.scan(1, bob, t + ms(250));
        assert_eq!(slots.find_entity(2), Some((1, bob)));
    }
}
