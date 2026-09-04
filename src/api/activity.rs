//! Activity-history handlers — the peers × days matrix behind the heatmap.
//!
//! | Method | Route                    | Description                        |
//! |--------|--------------------------|------------------------------------|
//! | GET    | /api/activity/heatmap    | Clients × days activity matrix     |
//! | DELETE | /api/activity            | Erase all recorded history (admin) |
//!
//! History is written by [`crate::activity`] and lives in process memory
//! only, never in the database — see that module for why. This layer just
//! reads it back in the shape the UI paints.

use crate::http::{Query, State};
use crate::http::StatusCode;
use crate::http::Json;
use crate::http::CookieJar;
use serde::Deserialize;
use serde_json::{json, Value};

use super::admin::require_admin;
use super::{api_err, map_err, ok_success, require_auth, AppState};
use crate::{activity, datetime, db};

/// Default width of the heatmap window. A month of days fits on screen
/// without horizontal scrolling on a typical display and covers the "recent
/// pattern" question the view exists to answer; the retention window (90d by
/// default) is deliberately wider so a longer `days` value has data to show.
const DEFAULT_WINDOW_DAYS: i64 = 30;

#[derive(Deserialize, Default)]
pub struct HeatmapQuery {
    pub days: Option<i64>,
}

// ---------------------------------------------------------------------------
// GET /api/activity/heatmap
// ---------------------------------------------------------------------------

/// Clients × days activity matrix.
///
/// Every row carries all three series — `sampleHits`, `rxBytes`, `txBytes` —
/// positionally aligned with `days`, so the UI can switch between colouring
/// by connection presence and by traffic volume without a second round trip.
/// Days with no row in the table are emitted as explicit zeros rather than
/// gaps, which keeps the client free of index arithmetic against a sparse map.
pub async fn heatmap(
    State(state): State<AppState>,
    jar: CookieJar,
    Query(q): Query<HeatmapQuery>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let user = require_auth(&jar, &state)?;
    let general = db::get_general().map_err(map_err)?;

    // Clamp rather than reject: `days` is a display preference, and the only
    // thing an out-of-range value can do is ask for a wider window than the
    // retention policy could ever have filled.
    let days_len = q
        .days
        .unwrap_or(DEFAULT_WINDOW_DAYS)
        .clamp(1, db::MAX_ACTIVITY_RETENTION_DAYS);
    let days = datetime::last_n_days(days_len);

    let clients = db::get_all_clients().map_err(map_err)?;
    // Same visibility rule as GET /api/client: a non-admin sees only their
    // own clients. Without this the heatmap would be a side channel exposing
    // every other user's connection pattern to any logged-in account.
    let visible: Vec<&db::Client> = clients
        .iter()
        .filter(|c| user.role != 0 || c.user_id == Some(user.id))
        .collect();

    // Snapshot every visible client's activity under one lock acquisition,
    // then render from the clone — no lock is held while building JSON.
    let ids: Vec<i64> = visible.iter().map(|c| c.id).collect();
    let store = activity::client_activity_map(&ids);

    let rows: Vec<Value> = visible
        .iter()
        .map(|client| {
            // A client with no entry has simply never been sampled; its
            // series are all-zero, which is what `unwrap_or_default` yields.
            let recorded = store.get(&client.id).cloned().unwrap_or_default();
            let series = recorded.series(&days);
            json!({
                "id": client.id,
                "name": client.name,
                "enabled": client.enabled,
                "sampleHits": series.iter().map(|c| c.sample_hits).collect::<Vec<_>>(),
                "rxBytes": series.iter().map(|c| c.rx_bytes).collect::<Vec<_>>(),
                "txBytes": series.iter().map(|c| c.tx_bytes).collect::<Vec<_>>(),
                "totalRx": recorded.total_rx_bytes,
                "totalTx": recorded.total_tx_bytes,
                "lastSeenAt": recorded.last_seen_at,
            })
        })
        .collect();

    Ok(Json(json!({
        "days": days,
        "clients": rows,
        // The UI turns `sampleHits` into an estimated connected time, which
        // is only meaningful against the cadence that produced them. Sending
        // it beats hardcoding 30 in the frontend and having the two drift.
        "pollIntervalSeconds": activity::POLL_INTERVAL_SECS,
        "retentionDays": general.activity_retention_days,
        "enabled": general.activity_retention_days > 0,
    })))
}

// ---------------------------------------------------------------------------
// DELETE /api/activity
// ---------------------------------------------------------------------------

/// Erase all recorded activity — the daily buckets, the lifetime totals, and
/// the last-seen fields. Admin only: it destroys data for every user's
/// clients, not just the caller's.
pub async fn purge(
    State(state): State<AppState>,
    jar: CookieJar,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let _admin = require_admin(&jar, &state)?;
    let deleted = activity::purge();
    crate::info!("activity history purged by admin ({deleted} day bucket(s) discarded)");
    Ok(ok_success())
}

/// Shared by the admin general-settings handler: validate an operator-supplied
/// retention window. Kept here so the bound lives next to the feature it
/// bounds rather than in the middle of the unrelated settings whitelist.
pub fn validate_retention_days(n: i64) -> Result<i64, (StatusCode, Json<Value>)> {
    if (0..=db::MAX_ACTIVITY_RETENTION_DAYS).contains(&n) {
        Ok(n)
    } else {
        Err(api_err(
            StatusCode::BAD_REQUEST,
            &format!(
                "activityRetentionDays must be between 0 (disabled) and {}",
                db::MAX_ACTIVITY_RETENTION_DAYS
            ),
        ))
    }
}
