//! Lifecycle supervisor for the in-process QQ-Tunnel UDP-over-DNS engine.
//!
//! Mirrors the facade of the other transports — `ensure_running` / `status`
//! / `shutdown_for_exit`, plus `apply_and_reconcile` for the admin API — but
//! drives an in-process Tokio task set (see [`crate::qqdns::engine`]) instead
//! of a child process. A config change tears the old engine down and binds a
//! fresh one; the peer re-establishes on its next keepalive.
//!
//! Unlike `proxy::supervisor`, enabling this does **not** rebind AmneziaWG or
//! touch the firewall: the engine is a side-channel that reaches the existing
//! AmneziaWG loopback socket, so the native UDP port keeps serving direct
//! clients unchanged.

use std::time::Instant;

use anyhow::Result;
use serde::Serialize;
use tokio::sync::Mutex;

use crate::db;
use crate::qqdns::config;
use crate::qqdns::engine::{self, EngineHandle};

struct Live {
    handle: EngineHandle,
    cfg_sig: u64,
    started_at: Instant,
    listen: String,
    h_in: String,
}

#[derive(Default)]
struct State {
    live: Option<Live>,
    disabled_reason: Option<String>,
    last_error: Option<String>,
}

static STATE: Mutex<Option<State>> = Mutex::const_new(None);

async fn lock_state<'a>() -> tokio::sync::MutexGuard<'a, Option<State>> {
    let mut guard = STATE.lock().await;
    if guard.is_none() {
        *guard = Some(State::default());
    }
    guard
}

/// Public status snapshot for `/api/admin/qqdns/status`.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "state", rename_all = "lowercase")]
pub enum Status {
    Disabled {
        reason: String,
    },
    Running {
        listen: String,
        h_in: String,
        uptime_seconds: u64,
    },
    Crashed {
        last_error: String,
    },
}

/// Reconcile the running engine with the desired DB state. Idempotent: same
/// effective config → left untouched; changed → torn down and rebound;
/// disabled/invalid → torn down with the reason recorded.
pub async fn ensure_running() -> Result<()> {
    let settings = db::get_qqdns_settings()?;
    let iface = db::get_interface()?;

    if let Some(reason) = config::should_remain_disabled(&settings, &iface) {
        let mut guard = lock_state().await;
        let st = guard.as_mut().unwrap();
        if let Some(live) = st.live.take() {
            live.handle.stop();
        }
        st.disabled_reason = Some(reason);
        st.last_error = None;
        return Ok(());
    }

    let cfg = config::build_engine_config(&settings, &iface)?;
    let sig = config::config_signature(&cfg);

    {
        let mut guard = lock_state().await;
        let st = guard.as_mut().unwrap();
        // Already running the same effective config, and healthy? Leave it.
        if let Some(live) = &st.live {
            if live.cfg_sig == sig && live.handle.is_running() {
                st.disabled_reason = None;
                return Ok(());
            }
        }
        // Tear down whatever's there before rebinding.
        if let Some(live) = st.live.take() {
            live.handle.stop();
        }
    }

    // Bind the new engine outside the lock (start() is async and may block
    // briefly on socket setup).
    match engine::start(cfg).await {
        Ok(handle) => {
            let listen = handle.listen_addr().to_string();
            let h_in = handle.h_in_addr().to_string();
            let mut guard = lock_state().await;
            let st = guard.as_mut().unwrap();
            st.live = Some(Live {
                handle,
                cfg_sig: sig,
                started_at: Instant::now(),
                listen,
                h_in,
            });
            st.disabled_reason = None;
            st.last_error = None;
            Ok(())
        }
        Err(e) => {
            let mut guard = lock_state().await;
            let st = guard.as_mut().unwrap();
            st.last_error = Some(format!("{e:#}"));
            Err(e)
        }
    }
}

/// Alias used by the admin API after mutating the settings row.
pub async fn apply_and_reconcile() -> Result<()> {
    ensure_running().await
}

/// Current supervisor status for the admin UI.
pub async fn status() -> Status {
    let mut guard = lock_state().await;
    let st = guard.as_mut().unwrap();
    if let Some(live) = &st.live {
        if live.handle.is_running() {
            return Status::Running {
                listen: live.listen.clone(),
                h_in: live.h_in.clone(),
                uptime_seconds: live.started_at.elapsed().as_secs(),
            };
        }
        // A task died unexpectedly — surface as crashed and drop the handle.
        let dead = st.live.take().unwrap();
        dead.handle.stop();
        let msg = st
            .last_error
            .clone()
            .unwrap_or_else(|| "engine task exited unexpectedly".to_string());
        st.last_error = Some(msg.clone());
        return Status::Crashed { last_error: msg };
    }
    if let Some(err) = &st.last_error {
        return Status::Crashed {
            last_error: err.clone(),
        };
    }
    Status::Disabled {
        reason: st
            .disabled_reason
            .clone()
            .unwrap_or_else(|| "not started".to_string()),
    }
}

/// Tear the engine down on process exit.
pub async fn shutdown_for_exit() {
    let mut guard = lock_state().await;
    if let Some(st) = guard.as_mut() {
        if let Some(live) = st.live.take() {
            live.handle.stop();
        }
    }
}
