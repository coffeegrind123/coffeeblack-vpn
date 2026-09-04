//! Activity-history tests — delta clamping, day bucketing, retention,
//! purge, and the UTC-day helpers the whole feature is keyed on.
//!
//! The history is a process-global in-memory store, so these are
//! `#[serial(db)]` for the same reason the DB tests are: one shared global,
//! reset between tests.

use coffeeblack_vpn::{activity, datetime, db};
use serial_test::serial;

fn seed() {
    db::init_test_db();
    activity::reset_for_tests();
}

/// Create a client and return its id. Activity rows are FK'd to
/// `clients_table`, so every test needs at least one real client.
/// One flattened bucket, named so the assertions below read as statements
/// about content rather than about tuple positions.
#[derive(Debug, Clone)]
struct Cell {
    client_id: i64,
    day: String,
    sample_hits: i64,
    rx_bytes: i64,
    tx_bytes: i64,
}

/// Every non-empty `(client, day)` bucket on or after `from_day`, ordered by
/// client then day.
fn cells_since(from_day: &str) -> Vec<Cell> {
    let mut out = Vec::new();
    for client_id in activity::client_ids() {
        let Some(a) = activity::client_activity(client_id) else {
            continue;
        };
        for (day, cell) in &a.days {
            if day.as_str() >= from_day {
                out.push(Cell {
                    client_id,
                    day: day.clone(),
                    sample_hits: cell.sample_hits,
                    rx_bytes: cell.rx_bytes,
                    tx_bytes: cell.tx_bytes,
                });
            }
        }
    }
    out.sort_by(|a, b| (a.client_id, &a.day).cmp(&(b.client_id, &b.day)));
    out
}

fn make_client(name: &str, ip: &str) -> i64 {
    db::create_client(&db::CreateClientParams {
        user_id: None,
        interface_id: Some("cb0".into()),
        name: name.into(),
        ipv4_address: Some(ip.into()),
        ipv6_address: None,
        private_key: format!("pk-{name}"),
        public_key: format!("pub-{name}"),
        pre_shared_key: None,
        pre_up: None, post_up: None, pre_down: None, post_down: None,
        expires_at: None,
        allowed_ips: Some(r#"["0.0.0.0/0"]"#.into()),
        server_allowed_ips: None, firewall_ips: None,
        persistent_keepalive: 0,
        mtu: 1420,
        j_c: None, j_min: None, j_max: None,
        i1: None, i2: None, i3: None, i4: None, i5: None,
        dns: None,
        server_endpoint: None,
        advanced_security: None,
        enabled: true,
    })
    .unwrap()
}

fn sample(client_id: i64, rx: i64, tx: i64) -> activity::ActivitySample {
    activity::ActivitySample {
        client_id,
        rx_total: rx,
        tx_total: tx,
    }
}

// ---------------------------------------------------------------------------
// Day helpers
// ---------------------------------------------------------------------------

#[test]
fn today_utc_is_fixed_width_iso() {
    let day = datetime::today_utc();
    assert_eq!(day.len(), 10, "day key must be fixed-width: {day}");
    let parts: Vec<&str> = day.split('-').collect();
    assert_eq!(parts.len(), 3);
    assert_eq!(parts[0].len(), 4);
    assert_eq!(parts[1].len(), 2);
    assert_eq!(parts[2].len(), 2);
}

#[test]
fn last_n_days_is_ascending_and_ends_today() {
    let days = datetime::last_n_days(30);
    assert_eq!(days.len(), 30);
    assert_eq!(days[29], datetime::today_utc());
    // Lexicographic order must equal chronological order — the whole
    // text-range-scan design depends on it.
    let mut sorted = days.clone();
    sorted.sort();
    assert_eq!(days, sorted);
    // No duplicates: a repeated day would double-render a heatmap column.
    sorted.dedup();
    assert_eq!(sorted.len(), 30);
}

#[test]
fn last_n_days_boundaries() {
    assert!(datetime::last_n_days(0).is_empty());
    assert!(datetime::last_n_days(-5).is_empty());
    assert_eq!(datetime::last_n_days(1), vec![datetime::today_utc()]);
}

#[test]
fn day_utc_ago_matches_window_start() {
    // The retention cutoff and the first column of an N-day window are the
    // same date computed two ways; they must agree or retention would prune
    // a day the heatmap still asks for.
    let days = datetime::last_n_days(30);
    assert_eq!(days[0], datetime::day_utc_ago(29));
    assert_eq!(datetime::day_utc_ago(0), datetime::today_utc());
}

// ---------------------------------------------------------------------------
// Recording
// ---------------------------------------------------------------------------

#[test]
#[serial(db)]
fn first_sample_books_no_traffic_but_counts_a_hit() {
    seed();
    let id = make_client("phone", "10.8.0.2");
    let day = datetime::today_utc();

    // The first tick has no previous reading to diff against. Crediting the
    // raw counter would book traffic that predates the measurement (the
    // upgrade case: an existing peer already at gigabytes). It anchors the
    // baseline and books zero bytes — but still counts the hit, because the
    // peer genuinely was observed.
    let n = activity::record_samples(&day, &datetime::now_rfc3339(), &[sample(id, 5_000, 3_000)]);
    assert_eq!(n, 1);

    let cells = cells_since(&day);
    assert_eq!(cells.len(), 1);
    assert_eq!(cells[0].sample_hits, 1);
    assert_eq!(cells[0].rx_bytes, 0, "baseline tick books no traffic");
    assert_eq!(cells[0].tx_bytes, 0);

    let c = activity::client_activity(id).unwrap_or_default();
    assert_eq!(c.total_rx_bytes, 0);
    assert_eq!(c.total_tx_bytes, 0);
    assert_eq!(c.last_sampled_rx_bytes, Some(5_000));
    assert_eq!(c.last_sampled_tx_bytes, Some(3_000));
    assert!(c.last_seen_at.is_some());
}

#[test]
#[serial(db)]
fn deltas_accumulate_across_ticks() {
    seed();
    let id = make_client("laptop", "10.8.0.3");
    let day = datetime::today_utc();
    let now = datetime::now_rfc3339();

    activity::record_samples(&day, &now, &[sample(id, 1_000, 500)]);
    activity::record_samples(&day, &now, &[sample(id, 1_600, 900)]);
    activity::record_samples(&day, &now, &[sample(id, 2_000, 1_000)]);

    let cells = cells_since(&day);
    assert_eq!(cells.len(), 1, "three ticks on one day = one row");
    assert_eq!(cells[0].sample_hits, 3);
    // Deltas only, and the 1000/500 first reading is the baseline rather than
    // traffic: 600 + 400 for rx, 400 + 100 for tx.
    assert_eq!(cells[0].rx_bytes, 1_000);
    assert_eq!(cells[0].tx_bytes, 500);

    let c = activity::client_activity(id).unwrap_or_default();
    assert_eq!(c.total_rx_bytes, 1_000);
    assert_eq!(c.total_tx_bytes, 500);
    assert_eq!(c.last_sampled_rx_bytes, Some(2_000));
}

#[test]
#[serial(db)]
fn counter_reset_contributes_zero_not_a_negative() {
    seed();
    let id = make_client("tablet", "10.8.0.4");
    let day = datetime::today_utc();
    let now = datetime::now_rfc3339();

    activity::record_samples(&day, &now, &[sample(id, 10_000, 8_000)]); // baseline
    activity::record_samples(&day, &now, &[sample(id, 14_000, 9_000)]);
    let before = activity::client_activity(id).unwrap_or_default();
    assert_eq!(before.total_rx_bytes, 4_000);

    // Interface restarted: the kernel counters are back near zero. A naive
    // subtraction would book -13,900 and drive the total backwards — the
    // exact bug the clamp exists to prevent.
    activity::record_samples(&day, &now, &[sample(id, 100, 50)]);
    let after = activity::client_activity(id).unwrap_or_default();
    assert_eq!(after.total_rx_bytes, 4_000, "reset must not decrease the total");
    assert_eq!(after.total_tx_bytes, 1_000);
    assert_eq!(
        after.last_sampled_rx_bytes,
        Some(100),
        "baseline must re-anchor to the new counter"
    );

    // And the next tick after the reset diffs against the new baseline.
    activity::record_samples(&day, &now, &[sample(id, 700, 250)]);
    let resumed = activity::client_activity(id).unwrap_or_default();
    assert_eq!(resumed.total_rx_bytes, 4_600);
    assert_eq!(resumed.total_tx_bytes, 1_200);

    let cells = cells_since(&day);
    assert!(cells[0].rx_bytes >= 0);
    assert_eq!(cells[0].sample_hits, 4, "a reset tick is still an observation");
}

#[test]
#[serial(db)]
fn separate_days_get_separate_rows() {
    seed();
    let id = make_client("phone", "10.8.0.2");
    let now = datetime::now_rfc3339();
    let yesterday = datetime::day_utc_ago(1);
    let today = datetime::today_utc();

    activity::record_samples(&yesterday, &now, &[sample(id, 1_000, 1_000)]);
    activity::record_samples(&yesterday, &now, &[sample(id, 2_000, 2_000)]);
    activity::record_samples(&today, &now, &[sample(id, 5_000, 5_000)]);

    let cells = cells_since(&yesterday);
    assert_eq!(cells.len(), 2);
    let y = cells.iter().find(|c| c.day == yesterday).unwrap();
    let t = cells.iter().find(|c| c.day == today).unwrap();
    assert_eq!(y.sample_hits, 2);
    assert_eq!(t.sample_hits, 1);
    // Yesterday: 1000 was the baseline, then +1000. Today: +3000 on top of
    // the 2000 carried over. The rollover splits the deltas by the day they
    // were observed on, and does not restate yesterday's.
    assert_eq!(y.rx_bytes, 1_000);
    assert_eq!(t.rx_bytes, 3_000);
}

#[test]
#[serial(db)]
fn multiple_clients_are_tracked_independently() {
    seed();
    let a = make_client("a", "10.8.0.2");
    let b = make_client("b", "10.8.0.3");
    let day = datetime::today_utc();
    let now = datetime::now_rfc3339();

    activity::record_samples(&day, &now, &[sample(a, 100, 100), sample(b, 100, 100)]);
    activity::record_samples(&day, &now, &[sample(a, 900, 100), sample(b, 200, 100)]);

    let cells = cells_since(&day);
    assert_eq!(cells.len(), 2);
    // One batch must not leak a delta between clients: a advanced 800, b 100.
    assert_eq!(cells.iter().find(|c| c.client_id == a).unwrap().rx_bytes, 800);
    assert_eq!(cells.iter().find(|c| c.client_id == b).unwrap().rx_bytes, 100);
}

#[test]
#[serial(db)]
fn records_for_vanished_clients_are_reconciled_away() {
    seed();
    let live = make_client("live", "10.8.0.2");
    let day = datetime::today_utc();
    let now = datetime::now_rfc3339();

    // A peer can be deleted between the poller reading the client list and
    // writing the samples derived from it, which would recreate an entry the
    // delete already removed. The store cannot re-check ids itself, so the
    // poller reconciles against the live list every tick.
    activity::record_samples(&day, &now, &[sample(live, 500, 500), sample(9_999, 500, 500)]);
    assert_eq!(cells_since(&day).len(), 2, "both are recorded at write time");

    let dropped = activity::retain_clients(&[live]);
    assert_eq!(dropped, 1);
    let cells = cells_since(&day);
    assert_eq!(cells.len(), 1);
    assert_eq!(cells[0].client_id, live);
    assert!(activity::client_activity(9_999).is_none());
}

#[test]
#[serial(db)]
fn empty_batch_is_a_no_op() {
    seed();
    let day = datetime::today_utc();
    assert_eq!(activity::record_samples(&day, &datetime::now_rfc3339(), &[]), 0);
    assert!(cells_since(&day).is_empty());
}

#[test]
#[serial(db)]
fn activity_since_is_ordered_and_bounded() {
    seed();
    let id = make_client("phone", "10.8.0.2");
    let now = datetime::now_rfc3339();
    for back in [0, 1, 2, 5] {
        let day = datetime::day_utc_ago(back);
        activity::record_samples(&day, &now, &[sample(id, 100 * (back + 1), 0)]);
    }

    // A 3-day window must exclude the 5-day-old row.
    let cells = cells_since(&datetime::day_utc_ago(2));
    assert_eq!(cells.len(), 3);
    let days: Vec<&str> = cells.iter().map(|c| c.day.as_str()).collect();
    let mut sorted = days.clone();
    sorted.sort();
    assert_eq!(days, sorted, "rows must come back day-ascending per client");
}

// ---------------------------------------------------------------------------
// Retention and purge
// ---------------------------------------------------------------------------

#[test]
#[serial(db)]
fn prune_drops_only_rows_older_than_the_cutoff() {
    seed();
    let id = make_client("phone", "10.8.0.2");
    let now = datetime::now_rfc3339();
    for back in [0, 5, 40, 100] {
        activity::record_samples(&datetime::day_utc_ago(back), &now, &[sample(id, 10, 10)]);
    }
    assert_eq!(cells_since(&datetime::day_utc_ago(365)).len(), 4);

    let deleted = activity::prune_before(&datetime::day_utc_ago(30));
    assert_eq!(deleted, 2, "the 40- and 100-day-old rows");
    let left = cells_since(&datetime::day_utc_ago(365));
    assert_eq!(left.len(), 2);
    assert!(left.iter().all(|c| c.day >= datetime::day_utc_ago(30)));

    // Boundary: the cutoff day itself is kept (strict `<`).
    let kept_boundary = activity::prune_before(&datetime::day_utc_ago(5));
    assert_eq!(kept_boundary, 0);
    assert_eq!(cells_since(&datetime::day_utc_ago(365)).len(), 2);
}

#[test]
#[serial(db)]
fn purge_erases_history_and_derived_columns() {
    seed();
    let id = make_client("phone", "10.8.0.2");
    let now = datetime::now_rfc3339();
    activity::record_samples(&datetime::today_utc(), &now, &[sample(id, 1_000, 1_000)]);
    activity::record_samples(&datetime::today_utc(), &now, &[sample(id, 9_000, 9_000)]);
    assert!(activity::client_activity(id).unwrap().total_rx_bytes > 0);

    let deleted = activity::purge();
    assert_eq!(deleted, 1);
    assert!(cells_since(&datetime::day_utc_ago(365)).is_empty());

    // The privacy switch must not leave the derived answers behind.
    let c = activity::client_activity(id).unwrap_or_default();
    assert_eq!(c.total_rx_bytes, 0);
    assert_eq!(c.total_tx_bytes, 0);
    assert_eq!(c.last_sampled_rx_bytes, None);
    assert_eq!(c.last_sampled_tx_bytes, None);
    assert!(c.last_seen_at.is_none());
}

#[test]
#[serial(db)]
fn purge_rebaselines_so_the_next_tick_books_no_phantom_delta() {
    seed();
    let id = make_client("phone", "10.8.0.2");
    let now = datetime::now_rfc3339();
    let day = datetime::today_utc();

    activity::record_samples(&day, &now, &[sample(id, 50_000_000, 50_000_000)]);
    activity::record_samples(&day, &now, &[sample(id, 60_000_000, 60_000_000)]);
    activity::purge();
    assert_eq!(activity::client_activity(id).unwrap_or_default().last_sampled_rx_bytes, None);

    // The kernel counter keeps climbing after a purge. The next tick must
    // re-anchor against it and book nothing — not credit the whole 60 MB
    // that accrued before the operator asked for the history to be erased.
    activity::record_samples(&day, &now, &[sample(id, 60_000_100, 60_000_100)]);
    let c = activity::client_activity(id).unwrap_or_default();
    assert_eq!(c.total_rx_bytes, 0, "purge must not be undone by the next tick");
    assert_eq!(c.last_sampled_rx_bytes, Some(60_000_100));

    // And normal delta tracking resumes from the new anchor.
    activity::record_samples(&day, &now, &[sample(id, 60_000_600, 60_000_600)]);
    assert_eq!(activity::client_activity(id).unwrap_or_default().total_rx_bytes, 500);
}

// ---------------------------------------------------------------------------
// Retention setting
// ---------------------------------------------------------------------------

#[test]
#[serial(db)]
fn retention_setting_defaults_and_round_trips() {
    seed();
    assert_eq!(
        db::get_general().unwrap().activity_retention_days,
        db::DEFAULT_ACTIVITY_RETENTION_DAYS
    );

    let mut fields = db::UpdateMap::new();
    fields.insert("activity_retention_days".into(), "0".into());
    db::update_general(&fields).unwrap();
    assert_eq!(db::get_general().unwrap().activity_retention_days, 0);

    let mut fields = db::UpdateMap::new();
    fields.insert("activity_retention_days".into(), "365".into());
    db::update_general(&fields).unwrap();
    assert_eq!(db::get_general().unwrap().activity_retention_days, 365);
}

// ---------------------------------------------------------------------------
// The RAM-only guarantee
// ---------------------------------------------------------------------------

#[test]
#[serial(db)]
fn history_never_reaches_the_database() {
    seed();
    let id = make_client("phone", "10.8.0.2");
    let now = datetime::now_rfc3339();
    for back in [0, 1, 2] {
        activity::record_samples(&datetime::day_utc_ago(back), &now, &[sample(id, 9_000, 9_000)]);
    }
    assert!(!cells_since(&datetime::day_utc_ago(7)).is_empty());

    // Nothing may name activity in the schema. A table added later would be
    // persisted to disk under IN_MEMORY=false and copied into the snapshot
    // under COFFEEBLACK_PERSIST_DB, which is exactly what this feature must not
    // do — so assert on the schema itself rather than on today's code paths.
    let tables = db::table_names().unwrap();
    for t in &tables {
        assert!(
            !t.contains("activity"),
            "activity history must not have a table: found {t}"
        );
    }

    // Nor may it hide in a column on the client row.
    let cols = db::column_names("clients_table").unwrap();
    for c in &cols {
        assert!(
            !(c.contains("activity")
                || c.contains("total_rx")
                || c.contains("total_tx")
                || c.contains("last_seen")
                || c.contains("last_sampled")),
            "activity history must not have a clients_table column: found {c}"
        );
    }
}

#[test]
#[serial(db)]
fn retention_setting_does_persist() {
    // The *setting* is the deliberate exception: it is configuration, not a
    // record of anyone's connections, and it has to survive a restart so that
    // an operator who turned collection off does not find it back on after a
    // reboot.
    seed();
    let mut fields = db::UpdateMap::new();
    fields.insert("activity_retention_days".into(), "0".into());
    db::update_general(&fields).unwrap();

    let cols = db::column_names("general_table").unwrap();
    assert!(cols.iter().any(|c| c == "activity_retention_days"));
    assert_eq!(db::get_general().unwrap().activity_retention_days, 0);
}

#[test]
#[serial(db)]
fn deleting_a_client_forgets_it_immediately() {
    seed();
    let id = make_client("phone", "10.8.0.2");
    activity::record_samples(&datetime::today_utc(), &datetime::now_rfc3339(), &[sample(id, 100, 100)]);
    assert!(activity::client_activity(id).is_some());

    db::delete_client(id).unwrap();
    assert!(
        activity::client_activity(id).is_none(),
        "a deleted peer's record must not outlive the peer that labels it"
    );
}

#[test]
#[serial(db)]
fn peer_source_addresses_are_never_recorded() {
    // The store must not carry the endpoint a peer was reached from. It is
    // the most identifying field `awg show dump` offers, and unlike a key it
    // cannot be rotated after the fact. This asserts on the recorded shape so
    // that re-adding the field has to break a test, not just pass review.
    seed();
    let id = make_client("phone", "10.8.0.2");
    activity::record_samples(
        &datetime::today_utc(),
        &datetime::now_rfc3339(),
        &[sample(id, 1_000, 1_000)],
    );
    let recorded = activity::client_activity(id).unwrap();
    let rendered = format!("{recorded:?}");
    assert!(
        !rendered.to_lowercase().contains("endpoint"),
        "no endpoint field may appear in the stored activity: {rendered}"
    );
    // The sample type carries no endpoint either, so there is nothing for a
    // caller to hand over even by mistake — `ActivitySample` has exactly the
    // three fields below, and adding a fourth would fail to compile here.
    let activity::ActivitySample {
        client_id: _,
        rx_total: _,
        tx_total: _,
    } = sample(id, 1, 1);
}
