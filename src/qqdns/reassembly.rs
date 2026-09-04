//! Port of QQ-Tunnel's `data_handler.py` — the per-datagram fragment
//! reassembler.
//!
//! Fragments of one datagram share a `data_offset` (the reassembly key);
//! each carries its `fragment_part` index (0..=63) and a last-fragment flag.
//! A datagram is complete once the last fragment is seen and every index up
//! to it has arrived, at which point the fragments' base32 chunks are
//! concatenated in order and handed back (the caller base32-decodes the
//! whole thing).
//!
//! Mirrors the reference reassembler's defences exactly: duplicate
//! fragments are ignored, and structurally inconsistent sets (two
//! "last" fragments, or a fragment beyond an already-seen last) poison the
//! whole key so a spoofed fragment can't corrupt a real datagram. Completed
//! and poisoned keys expire after `assemble_time` so their offsets can be
//! reused when the sender's counter wraps.
//!
//! Concurrency: the reference uses one `asyncio.Lock`; we use a
//! `std::sync::Mutex` because the critical section never awaits. A periodic
//! sweeper task frees expired slots for memory hygiene, but correctness does
//! not depend on it — every access lazily expires its own key first.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const NUM_SLOTS: usize = 64;

struct Assembly {
    /// One slot per fragment index; `None` until that fragment arrives.
    parts: Vec<Option<Vec<u8>>>,
    /// Number of distinct fragments received.
    rec_nums: usize,
    /// One past the highest fragment index seen.
    biggest_index_plus_one: usize,
    /// Whether the last-fragment flag has been seen.
    seen_last_fragment: bool,
}

enum Slot {
    /// No fragment seen (or expired back to empty).
    Empty,
    /// Assembling; `created_at` is when the first fragment arrived.
    Assembling {
        asm: Box<Assembly>,
        created_at: Instant,
    },
    /// Completed and emitted — dedup marker until it expires.
    Done { created_at: Instant },
    /// Poisoned by an inconsistent fragment set — reject until it expires.
    Rejected { created_at: Instant },
}

struct Inner {
    slots: Vec<Slot>,
    assemble_time: Duration,
}

/// Fragment reassembler keyed by `data_offset`.
///
/// # Slots are not bound to a sender, and cannot be
///
/// Any host that can reach the listener with a correctly suffixed query can
/// occupy a slot, because the wire format carries no client identifier — the
/// upstream protocol's own "one instance, one client endpoint" limitation.
/// Binding a slot to its first sender's address is *not* a fix: queries arrive
/// via public recursive resolvers, `dns_ips` is a list, and anycast means one
/// client's fragments legitimately arrive from several source addresses. Such
/// a check would break ordinary operation while an attacker just spoofs the
/// resolver's address.
///
/// What is bounded instead is the damage: the slot array is a fixed
/// `TOTAL_DATA_OFFSET` (2^15) entries, each holding at most `NUM_SLOTS` (64)
/// fragments, and `dns::handle_question` caps a fragment at one DNS name (255
/// octets). Worst-case resident memory is therefore fixed, not a function of
/// attacker traffic, and the sweeper reclaims abandoned slots. Injected
/// fragments corrupt a message rather than disclose one — the tunnel payload
/// is encrypted, so a forged fragment fails authentication downstream.
#[derive(Clone)]
pub struct DataHandler {
    inner: Arc<Mutex<Inner>>,
}

impl DataHandler {
    /// `offsets_size` is the offset space (`TOTAL_DATA_OFFSET`);
    /// `assemble_time` is how long a partial/completed key lives before its
    /// offset may be reused.
    pub fn new(offsets_size: usize, assemble_time: Duration) -> Self {
        let mut slots = Vec::with_capacity(offsets_size);
        for _ in 0..offsets_size {
            slots.push(Slot::Empty);
        }
        DataHandler {
            inner: Arc::new(Mutex::new(Inner {
                slots,
                assemble_time,
            })),
        }
    }

    /// Spawn a background task that periodically clears expired slots. Purely
    /// for memory hygiene — abandoned partial datagrams would otherwise hold
    /// their buffers until their offset is reused. Returns the task handle.
    pub fn spawn_sweeper(&self) -> tokio::task::JoinHandle<()> {
        let inner = Arc::clone(&self.inner);
        tokio::spawn(async move {
            // Sweep at half the assemble interval; bounded to a sane range.
            let period = {
                let g = inner.lock().unwrap();
                g.assemble_time.max(Duration::from_secs(1)) / 2
            };
            let mut ticker = tokio::time::interval(period.max(Duration::from_millis(500)));
            loop {
                ticker.tick().await;
                let now = Instant::now();
                let mut g = inner.lock().unwrap();
                let at = g.assemble_time;
                for slot in g.slots.iter_mut() {
                    let expired = match slot {
                        Slot::Empty => false,
                        Slot::Assembling { created_at, .. }
                        | Slot::Done { created_at }
                        | Slot::Rejected { created_at } => now.duration_since(*created_at) >= at,
                    };
                    if expired {
                        *slot = Slot::Empty;
                    }
                }
            }
        })
    }

    /// Feed one fragment. Returns `Some(joined_base32)` when this fragment
    /// completes the datagram, otherwise `None` (stored / duplicate /
    /// rejected). Faithful port of `new_data_event`.
    pub fn new_data_event(
        &self,
        key: u32,
        fragment_part: usize,
        last_fragment: bool,
        data: Vec<u8>,
    ) -> Option<Vec<u8>> {
        if fragment_part >= NUM_SLOTS {
            return None;
        }
        let key = key as usize;
        let now = Instant::now();
        let mut g = self.inner.lock().unwrap();
        if key >= g.slots.len() {
            return None;
        }
        let assemble_time = g.assemble_time;

        // Lazy expiry: a stale key behaves as Empty (offset reuse after wrap).
        let expired = match &g.slots[key] {
            Slot::Empty => false,
            Slot::Assembling { created_at, .. }
            | Slot::Done { created_at }
            | Slot::Rejected { created_at } => now.duration_since(*created_at) >= assemble_time,
        };
        if expired {
            g.slots[key] = Slot::Empty;
        }

        match &mut g.slots[key] {
            Slot::Done { .. } | Slot::Rejected { .. } => None,
            Slot::Empty => {
                let biggest_index_plus_one = fragment_part + 1;
                // Single-fragment datagram: fragment 0 flagged last.
                if last_fragment && biggest_index_plus_one == 1 {
                    g.slots[key] = Slot::Done { created_at: now };
                    return Some(data);
                }
                let mut parts: Vec<Option<Vec<u8>>> = (0..NUM_SLOTS).map(|_| None).collect();
                parts[fragment_part] = Some(data);
                g.slots[key] = Slot::Assembling {
                    asm: Box::new(Assembly {
                        parts,
                        rec_nums: 1,
                        biggest_index_plus_one,
                        seen_last_fragment: last_fragment,
                    }),
                    created_at: now,
                };
                None
            }
            Slot::Assembling { asm, .. } => {
                if asm.parts[fragment_part].is_some() {
                    return None; // duplicate fragment
                }
                asm.parts[fragment_part] = Some(data);
                let rec_nums = asm.rec_nums + 1;
                let fp_po = fragment_part + 1;
                let p_biggest = asm.biggest_index_plus_one;
                let (biggest_updated, biggest_index_plus_one) = if fp_po > p_biggest {
                    (true, fp_po)
                } else {
                    (false, p_biggest)
                };
                let p_seen_last = asm.seen_last_fragment;

                // Inconsistent: a second "last", a fragment past the seen
                // last, or a "last" that is not the highest index.
                //
                // Left as three explicit disjuncts, one per case named
                // above, rather than the factored form clippy suggests
                // (`(!biggest_updated || p_seen_last) && (biggest_updated
                // || last_fragment)`) — the factored version is equivalent
                // but no longer readable against upstream's reject rules.
                #[allow(clippy::nonminimal_bool)]
                if (last_fragment && p_seen_last)
                    || (biggest_updated && p_seen_last)
                    || (!biggest_updated && last_fragment)
                {
                    g.slots[key] = Slot::Rejected { created_at: now };
                    return None;
                }

                let seen_last = last_fragment || p_seen_last;
                if seen_last && rec_nums == biggest_index_plus_one {
                    // Complete: concatenate fragments 0..rec_nums in order.
                    let mut joined = Vec::new();
                    for part in asm.parts[..rec_nums].iter() {
                        joined.extend_from_slice(part.as_deref().unwrap_or(&[]));
                    }
                    g.slots[key] = Slot::Done { created_at: now };
                    return Some(joined);
                }

                asm.rec_nums = rec_nums;
                if last_fragment {
                    asm.seen_last_fragment = true;
                }
                if biggest_updated {
                    asm.biggest_index_plus_one = biggest_index_plus_one;
                }
                None
            }
        }
    }
}
