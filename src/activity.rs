//! Per-client activity history for the AmneziaWG interface — **RAM only**.
//!
//! `awg show <if> dump` is a *snapshot*: it reports the counters the kernel
//! holds right now, and those counters restart at zero every time the
//! interface is torn down. Reading it per request — which is all this project
//! did before — means the UI's "lifetime transfer" figure silently resets on
//! every `awg-quick down/up`, and no question about the past is answerable at
//! all ("was this peer connected last Tuesday?", "which peers went quiet
//! three weeks ago?").
//!
//! This module adds the missing memory, and adds it **only** to memory.
//!
//! ## Why none of this is in SQLite
//!
//! Per-peer connection history is the single most sensitive thing this
//! service could accumulate: who connected, when, from where, and how much
//! they moved. Everything in the SQLite schema is written to a file when
//! `IN_MEMORY=false`, and is copied verbatim into the durable snapshot when
//! `COFFEEBLACK_PERSIST_DB` is set — so a table, even in the `:memory:` database,
//! is one config flag away from being a durable record of exactly that.
//!
//! Keeping the history in process memory makes the guarantee structural
//! rather than conditional: there is no code path from this store to a file,
//! in any mode, so no operator setting can turn it into one. It dies with the
//! process, which is the intended lifetime.
//!
//! The one thing that *does* stay in the DB is the retention **setting**
//! (`general_table.activity_retention_days`). That is configuration, not a
//! record of anyone's connections — and it has to survive a restart, because
//! an operator who set it to `0` (off) must not find collection silently
//! switched back on by the next reboot.
//!
//! ## Shape of the data
//!
//! Each tick folds into two things, both per client:
//!
//! - **Monotonic lifetime totals**, accumulated from clamped deltas so an
//!   interface restart costs nothing.
//! - **One bucket per UTC day**, which is what the heatmap renders.
//!
//! The daily rollup is deliberate: keeping raw samples would cost
//! `clients × 2880` entries/day at a 30 s cadence and grow without bound,
//! while the rollup is `clients × retention_days` no matter how often the
//! poller runs. The price is that intra-day resolution is gone for good — a
//! peer that connected once for ten minutes and one that connected three
//! times for ten minutes look alike within a day's bucket. The heatmap paints
//! one cell per peer-day and never needed finer than that.
//!
//! **`sample_hits` is a tick count, not a duration.** There are no
//! connect/disconnect events to work from, only periodic samples, so
//! `hits × POLL_INTERVAL_SECS` is an estimate of connected time and is
//! labelled as one everywhere it surfaces.

use std::collections::{BTreeMap, HashMap};
use std::sync::{LazyLock, RwLock, RwLockReadGuard, RwLockWriteGuard};
use std::time::Duration;

use crate::{datetime, db, wg};

/// Sampling cadence. Paired with WireGuard's typical 25 s keepalive this
/// reliably catches a live peer at least once per interval, and it is the
/// unit `sample_hits` counts in — so it is exported to the API (and from
/// there to the UI) rather than being duplicated as a magic 30 in the
/// frontend's duration estimate.
pub const POLL_INTERVAL_SECS: u64 = 30;

/// Hard ceiling on retained days per client, independent of the configured
/// retention window. The retention prune runs on UTC-day rollover; this is
/// the backstop that bounds memory if that never happens (clock jumps
/// backwards, a prune that keeps failing), so the store cannot grow without
/// limit inside a long-lived process. One day above the maximum settable
/// window, so it never truncates a legitimately configured retention.
const MAX_DAYS_PER_CLIENT: usize = (db::MAX_ACTIVITY_RETENTION_DAYS as usize) + 1;

// ---------------------------------------------------------------------------
// Store
// ---------------------------------------------------------------------------

/// One `(client, UTC day)` bucket.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DayCell {
    /// Poll ticks on that day that saw a live handshake. A tick count, *not*
    /// a measured session duration.
    pub sample_hits: i64,
    pub rx_bytes: i64,
    pub tx_bytes: i64,
}

/// Everything remembered about one client.
#[derive(Debug, Clone, Default)]
pub struct ClientActivity {
    /// Monotonic lifetime counters. Unlike the `awg show dump` values these
    /// survive an interface restart, because only clamped deltas are added.
    pub total_rx_bytes: i64,
    pub total_tx_bytes: i64,
    /// Last raw counter reading, kept only so the next tick can diff against
    /// it. `None` means "never sampled", which must stay distinguishable from
    /// a genuine zero: diffing an already-large kernel counter against 0
    /// would book a peer's entire pre-existing traffic as one delta — a
    /// phantom spike landing in a single day's bucket which, because heatmap
    /// intensity is relative to each day's busiest peer, flattens every other
    /// day to blank.
    pub last_sampled_rx_bytes: Option<i64>,
    pub last_sampled_tx_bytes: Option<i64>,
    /// Last tick at which the kernel reported a handshake. `None` for a
    /// client that has never connected.
    ///
    /// Deliberately *not* accompanied by the endpoint the peer was reached
    /// from. `awg show dump` offers it, and it is the single most
    /// identifying field available here — a peer's real public IP is exactly
    /// what a VPN exists not to retain, and unlike a key it cannot be
    /// rotated after a compromise. The live value is still shown in the peer
    /// list straight from the kernel; it is simply never accumulated into a
    /// history that outlives the connection.
    pub last_seen_at: Option<String>,
    /// UTC day (`YYYY-MM-DD`) → bucket. `BTreeMap` because every consumer
    /// wants these in chronological order, and fixed-width ISO-8601 sorts
    /// lexicographically the same as it sorts chronologically.
    pub days: BTreeMap<String, DayCell>,
}

impl ClientActivity {
    /// This client's series for `days`, in the same order, with absent days
    /// emitted as explicit zeros rather than gaps.
    pub fn series(&self, days: &[String]) -> Vec<DayCell> {
        days.iter()
            .map(|d| self.days.get(d).copied().unwrap_or_default())
            .collect()
    }
}

/// The whole store: `client_id` → activity. Bounded by
/// `clients × retention_days`.
static STORE: LazyLock<RwLock<HashMap<i64, ClientActivity>>> =
    LazyLock::new(|| RwLock::new(HashMap::new()));

/// Read the store, recovering from a poisoned lock rather than propagating
/// the panic. A poisoned lock means some thread panicked while holding it;
/// the map is a plain value with no torn intermediate state to observe, and
/// turning one stray panic into a permanently unreadable store would be
/// strictly worse. Mirrors the same reasoning as `db::conn`.
fn read() -> RwLockReadGuard<'static, HashMap<i64, ClientActivity>> {
    STORE
        .read()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn write() -> RwLockWriteGuard<'static, HashMap<i64, ClientActivity>> {
    STORE
        .write()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// One client's raw counters as read from `awg show dump` on a single tick.
/// Deltas are derived inside [`record_samples`], not by the caller, so the
/// read-modify-write of the baseline stays under one lock acquisition.
/// Note there is no endpoint field: the peer's source address is never
/// carried into the store. See [`ClientActivity::last_seen_at`].
#[derive(Debug, Clone)]
pub struct ActivitySample {
    pub client_id: i64,
    pub rx_total: i64,
    pub tx_total: i64,
}

/// Fold one poll tick into the per-client totals and the `day` bucket.
///
/// Two cases contribute 0 bytes rather than a delta:
///
/// - **No baseline** (`last_sampled_* == None`): nothing to diff against, so
///   this tick only anchors the baseline (see [`ClientActivity`]).
/// - **Negative delta**: the kernel counter was reset by an interface
///   restart. Clamped to 0 so the totals stay monotonic.
///
/// Both still count a `sample_hit` — the peer *was* observed, which is what
/// that field records. Incrementing once per client per call is what makes it
/// a count of ticks-with-a-live-handshake rather than a duration.
///
/// Returns the number of clients updated.
pub fn record_samples(day: &str, seen_at: &str, samples: &[ActivitySample]) -> usize {
    if samples.is_empty() {
        return 0;
    }
    let mut store = write();
    for s in samples {
        let entry = store.entry(s.client_id).or_default();

        let rx_delta = entry
            .last_sampled_rx_bytes
            .map_or(0, |prev| (s.rx_total - prev).max(0));
        let tx_delta = entry
            .last_sampled_tx_bytes
            .map_or(0, |prev| (s.tx_total - prev).max(0));

        entry.total_rx_bytes += rx_delta;
        entry.total_tx_bytes += tx_delta;
        entry.last_sampled_rx_bytes = Some(s.rx_total);
        entry.last_sampled_tx_bytes = Some(s.tx_total);
        entry.last_seen_at = Some(seen_at.to_string());

        let cell = entry.days.entry(day.to_string()).or_default();
        cell.sample_hits += 1;
        cell.rx_bytes += rx_delta;
        cell.tx_bytes += tx_delta;

        // Backstop against unbounded growth; drops oldest-first.
        while entry.days.len() > MAX_DAYS_PER_CLIENT {
            let oldest = match entry.days.keys().next() {
                Some(k) => k.clone(),
                None => break,
            };
            entry.days.remove(&oldest);
        }
    }
    samples.len()
}

/// Snapshot one client's activity, or `None` if it has never been sampled.
/// Returns a clone so no caller holds the lock while rendering.
pub fn client_activity(client_id: i64) -> Option<ClientActivity> {
    read().get(&client_id).cloned()
}

/// Every client id the store currently holds a record for, ascending. Note
/// this can include ids the database no longer has, until the next poll tick
/// reconciles — see [`retain_clients`].
pub fn client_ids() -> Vec<i64> {
    let mut ids: Vec<i64> = read().keys().copied().collect();
    ids.sort_unstable();
    ids
}

/// Snapshot the activity for many clients at once, under a single lock
/// acquisition — the list and metrics endpoints need every client's numbers
/// and should not re-lock per row.
pub fn client_activity_map(client_ids: &[i64]) -> HashMap<i64, ClientActivity> {
    let store = read();
    client_ids
        .iter()
        .filter_map(|id| store.get(id).map(|a| (*id, a.clone())))
        .collect()
}

/// Drop every bucket older than `cutoff_day`. Returns how many were removed.
///
/// Clients left with no buckets *and* no lifetime totals are removed from the
/// map entirely, so a peer that stopped connecting long ago stops costing an
/// entry once its history ages out.
pub fn prune_before(cutoff_day: &str) -> usize {
    let mut store = write();
    let mut removed = 0;
    for activity in store.values_mut() {
        // `split_off` keeps `>= cutoff`; what stays behind is the old part.
        let keep = activity.days.split_off(cutoff_day);
        removed += activity.days.len();
        activity.days = keep;
    }
    store.retain(|_, a| !a.days.is_empty() || a.total_rx_bytes > 0 || a.total_tx_bytes > 0);
    removed
}

/// Erase everything: buckets, lifetime totals, baselines and last-seen.
///
/// This is the privacy switch, so it drops the whole map rather than only the
/// day buckets — leaving the totals and `last_seen_at` behind would keep
/// answering "has this peer ever connected, and roughly how much" after the
/// operator asked for the history to be gone. Clearing the baselines also
/// means the next tick re-anchors against the live counter and books nothing,
/// instead of crediting the entire pre-purge counter as one delta.
///
/// Returns the number of day buckets discarded.
pub fn purge() -> usize {
    let mut store = write();
    let n = store.values().map(|a| a.days.len()).sum();
    store.clear();
    n
}

/// Forget one client — called when the peer is deleted. History that can no
/// longer be attributed to a named peer is pure liability.
pub fn forget_client(client_id: i64) {
    write().remove(&client_id);
}

/// Drop every entry whose client no longer exists. Returns how many went.
///
/// [`forget_client`] handles the ordinary delete, but it cannot close the
/// window between the poller reading the client list and writing the samples
/// it derived from it: a peer deleted inside that window would have its entry
/// recreated by the write, *after* the delete already removed it. The store
/// has no database access of its own to re-check ids against, so the poller —
/// which holds a fresh client list every tick anyway — reconciles instead.
/// That makes a deleted peer's record disappear within one interval no matter
/// how the two interleave, and it bounds the map against any other path that
/// might record an id that no longer exists.
pub fn retain_clients(live_ids: &[i64]) -> usize {
    let live: std::collections::HashSet<i64> = live_ids.iter().copied().collect();
    let mut store = write();
    let before = store.len();
    store.retain(|id, _| live.contains(id));
    before - store.len()
}

/// Reset the store between tests. Not used at runtime.
#[doc(hidden)]
pub fn reset_for_tests() {
    write().clear();
}

// ---------------------------------------------------------------------------
// Poller
// ---------------------------------------------------------------------------

/// Spawn the background poller. Returns immediately; the task runs for the
/// lifetime of the process.
pub fn spawn(iface_name: String) {
    tokio::spawn(async move { run(iface_name).await });
}

async fn run(iface_name: String) {
    // `interval` fires its first tick immediately, and that is wanted here:
    // the store is empty at startup, so the sooner a baseline is anchored the
    // smaller the window in which traffic goes unattributed.
    let mut tick = tokio::time::interval(Duration::from_secs(POLL_INTERVAL_SECS));
    // Skip missed ticks rather than replaying them: a burst of catch-up ticks
    // after the runtime was blocked would inflate `sample_hits` for time the
    // peer was not observed at all.
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    // Day of the last retention pass. Pruning on day rollover (rather than on
    // a fixed 24 h timer) means a restart doesn't reset the countdown and
    // leave an over-long window standing until the timer next fires.
    let mut last_prune_day = String::new();
    // Whether the disabled-state purge has already run. Without this the
    // poller would clear an already-empty store every 30 s for as long as the
    // feature is off.
    let mut purged_while_disabled = false;

    loop {
        tick.tick().await;

        let retention_days = match db::get_general() {
            Ok(g) => g.activity_retention_days,
            Err(e) => {
                crate::warn!("activity poll skipped (general read failed): {e}");
                continue;
            }
        };

        if retention_days <= 0 {
            if !purged_while_disabled {
                let n = purge();
                if n > 0 {
                    crate::info!("activity history disabled — purged {n} recorded day(s)");
                }
                purged_while_disabled = true;
            }
            continue;
        }
        purged_while_disabled = false;

        if let Err(e) = poll_once(&iface_name).await {
            // Never let a failed tick kill the task — the interface may
            // simply be down, and the next tick should get another shot.
            crate::warn!("activity poll failed: {e:#}");
        }

        let today = datetime::today_utc();
        if today != last_prune_day {
            let n = prune_before(&datetime::day_utc_ago(retention_days));
            if n > 0 {
                crate::info!(
                    "activity retention: pruned {n} day bucket(s) older than {retention_days}d"
                );
            }
            last_prune_day = today;
        }
    }
}

/// One sampling pass: read the dump, match peers to clients by public key,
/// and fold the raw counters into the store.
///
/// Only peers the kernel reports a handshake for are recorded. A configured
/// but never-connected peer has no handshake and must not be credited with a
/// `sample_hits` bump — otherwise the heatmap would show a solid band of
/// activity for a client that has never once connected.
pub async fn poll_once(iface_name: &str) -> anyhow::Result<usize> {
    let peers = wg::dump_peers_async(iface_name.to_string()).await?;
    if peers.is_empty() {
        return Ok(0);
    }

    let clients = tokio::task::spawn_blocking(db::get_all_clients).await??;

    // Reconcile before recording, so a peer deleted since the last tick is
    // gone from memory even if this tick's samples were derived before the
    // delete landed.
    let dropped = retain_clients(&clients.iter().map(|c| c.id).collect::<Vec<_>>());
    if dropped > 0 {
        crate::debug!("activity: dropped {dropped} record(s) for deleted peer(s)");
    }

    let samples: Vec<ActivitySample> = clients
        .iter()
        .filter_map(|client| {
            let peer = peers.iter().find(|p| p.public_key == client.public_key)?;
            peer.latest_handshake?;
            Some(ActivitySample {
                client_id: client.id,
                rx_total: peer.transfer_rx,
                tx_total: peer.transfer_tx,
            })
        })
        .collect();

    if samples.is_empty() {
        return Ok(0);
    }

    let n = record_samples(&datetime::today_utc(), &datetime::now_rfc3339(), &samples);
    crate::debug!("activity poll: recorded {n} peer sample(s)");
    Ok(n)
}
