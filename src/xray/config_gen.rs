//! Build the Xray `server.json` from the DB.
//!
//! Single inbound, VLESS, Reality stream security. Two transports are
//! supported — switch via `XrayInbound::transport`:
//!
//! * `"tcp"` — classic VLESS+Reality+Vision (default; what every
//!   pre-amnezia-client-2339 reference impl ships).
//! * `"xhttp"` — VLESS+Reality with HTTP framing over a secret path.
//!   Tracks amnezia-client/#2339. Vision flow is TCP-only, so client
//!   entries drop `flow` entirely when transport is xhttp.
//!
//! No fallbacks (all 6 of the focused reference impls we surveyed ship
//! without them — with Vision + a real `dest` the camouflage is the dest
//! itself). Every enabled `XrayClient` row contributes one entry to
//! `inbounds[0].settings.clients[]` (its UUID) AND one entry to
//! `inbounds[0].streamSettings.realitySettings.shortIds[]` (its short-id),
//! so each peer can be revoked individually by removing both.

use anyhow::Result;
use serde_json::{json, Value};

use crate::db;

/// Produce the `server.json` an Xray child process will consume. Always
/// ASCII-only and pretty-printed so operators can diff configs by eye.
pub fn generate_server_config(
    inbound: &db::XrayInbound,
    clients: &[db::XrayClient],
) -> Result<String> {
    let server_names: Value = serde_json::from_str(&inbound.server_names)
        .unwrap_or_else(|_| json!([]));

    let is_xhttp = inbound.transport == "xhttp";

    // VLESS clients carry only `id` (+ optional `flow`); the per-peer
    // short-id lives alongside them in `realitySettings.shortIds[]`. We
    // filter out disabled rows here so toggling "enabled" off in the UI
    // immediately removes the client on next reload.
    //
    // Vision flow (`xtls-rprx-vision`) is TCP-only — Xray rejects it on
    // xhttp transport with `vision can only be used over tcp`. The PR's
    // server template (amnezia-client/#2339 configure_container.sh) emits
    // `"flow": ""` in the xhttp branch; we match that exactly.
    let vless_clients: Vec<Value> = clients
        .iter()
        .filter(|c| c.enabled)
        .map(|c| {
            if is_xhttp {
                json!({
                    "id": c.uuid,
                    "flow": "",
                    "email": c.name,
                })
            } else {
                json!({
                    "id": c.uuid,
                    "flow": "xtls-rprx-vision",
                    "email": c.name,
                })
            }
        })
        .collect();

    let short_ids: Vec<Value> = clients
        .iter()
        .filter(|c| c.enabled)
        .map(|c| Value::String(c.short_id.clone()))
        .collect();

    // Reality has a quirk: shortIds[] MUST contain at least one entry, and
    // an empty string `""` is the wildcard that lets clients without a
    // short-id connect. We don't want the wildcard. If the array would
    // otherwise be empty (no enabled peers), produce a config with no
    // valid short-id so Xray refuses every connection rather than
    // silently allowing wildcard ones.
    let short_ids = if short_ids.is_empty() {
        // A 16-hex placeholder — guaranteed not to match any peer's
        // OsRng-generated id. Xray treats it as a normal short-id.
        vec![Value::String("ffffffffffffffff".into())]
    } else {
        short_ids
    };

    let mut stream_settings = json!({
        "network": if is_xhttp { "xhttp" } else { "tcp" },
        "security": "reality",
        "realitySettings": {
            "show": false,
            "dest": inbound.dest,
            "xver": 0,
            "serverNames": server_names,
            "privateKey": inbound.private_key,
            "shortIds": short_ids,
        },
    });
    if is_xhttp {
        if inbound.xhttp_path.trim().is_empty() {
            return Err(anyhow::anyhow!(
                "xray_inbound.transport is 'xhttp' but xhttp_path is empty \
                 — generate one before enabling the inbound"
            ));
        }
        // `mode: "auto"` lets Xray pick between the streaming variants
        // (packet-up / stream-up / stream-one) based on what each client
        // negotiates. Matches amnezia-client/#2339's template exactly.
        stream_settings["xhttpSettings"] = json!({
            "path": inbound.xhttp_path,
            "mode": "auto",
        });
    }

    let mut inbound_obj = json!({
        "tag": "vless-reality-in",
        "listen": "0.0.0.0",
        "port": inbound.port,
        "protocol": "vless",
        "settings": {
            "clients": vless_clients,
            "decryption": "none",
        },
        "streamSettings": stream_settings,
        "sniffing": {
            "enabled": true,
            "destOverride": ["http", "tls", "quic"],
            "routeOnly": true,
        },
    });

    // Operator escape hatch — merge any keys from `additional_config`
    // (parsed as JSON) on top of the inbound. This lets advanced users
    // add `fallbacks`, sniffing tweaks, etc. without forking the source.
    apply_additional_config(&mut inbound_obj, &inbound.additional_config)?;

    let root = json!({
        "log": {
            "loglevel": "warning",
            // Stdout/stderr only — the supervisor pipes those to tracing.
        },
        "inbounds": [inbound_obj],
        "outbounds": [
            { "tag": "direct",  "protocol": "freedom" },
            { "tag": "blocked", "protocol": "blackhole" },
        ],
        "routing": {
            "domainStrategy": "IPIfNonMatch",
            "rules": [
                // Block BitTorrent — every reference impl we surveyed
                // does this for the same operational reason: a single
                // torrenting peer can take the inbound's bandwidth to
                // zero for everyone else and burn the IP's reputation.
                {
                    "type": "field",
                    "outboundTag": "blocked",
                    "protocol": ["bittorrent"],
                },
                // Block RFC1918 / link-local / loopback / ULA so a
                // misbehaving client can't reach the host's internal
                // services through the proxy. Spelled out explicitly
                // rather than referencing `geoip:private` because the
                // latter requires shipping `geoip.dat` alongside Xray.
                {
                    "type": "field",
                    "outboundTag": "blocked",
                    "ip": [
                        "0.0.0.0/8",
                        "10.0.0.0/8",
                        "100.64.0.0/10",
                        "127.0.0.0/8",
                        "169.254.0.0/16",
                        "172.16.0.0/12",
                        "192.168.0.0/16",
                        "::1/128",
                        "fc00::/7",
                        "fe80::/10"
                    ],
                },
            ],
        },
    });

    Ok(serde_json::to_string_pretty(&root)?)
}

/// Apply the operator-supplied JSON snippet on top of `target`. Accepts
/// either a JSON object (deep-merged) or any other value (replaces the
/// inbound entirely — operator's responsibility). Empty/whitespace-only
/// strings are no-ops.
fn apply_additional_config(target: &mut Value, snippet: &str) -> Result<()> {
    let trimmed = snippet.trim();
    if trimmed.is_empty() {
        return Ok(());
    }
    let extra: Value = serde_json::from_str(trimmed)
        .map_err(|e| anyhow::anyhow!("additional_config is not valid JSON: {e}"))?;
    json_merge(target, extra);
    Ok(())
}

/// Recursive merge: object keys union, with `b` winning on conflict.
/// Non-object values from `b` simply replace whatever was at `a`.
fn json_merge(a: &mut Value, b: Value) {
    match (a, b) {
        (Value::Object(a_map), Value::Object(b_map)) => {
            for (k, v) in b_map {
                if let Some(existing) = a_map.get_mut(&k) {
                    json_merge(existing, v);
                } else {
                    a_map.insert(k, v);
                }
            }
        }
        (a_slot, b_val) => {
            *a_slot = b_val;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn inbound_fixture() -> db::XrayInbound {
        db::XrayInbound {
            id: "xray0".into(),
            port: 443,
            dest: "www.microsoft.com:443".into(),
            server_names: r#"["www.microsoft.com"]"#.into(),
            private_key: "PRIV_KEY".into(),
            public_key: "PUB_KEY".into(),
            fingerprint_default: "chrome".into(),
            transport: "tcp".into(),
            xhttp_path: String::new(),
            additional_config: String::new(),
            enabled: true,
            created_at: "now".into(),
            updated_at: "now".into(),
        }
    }

    fn client_fixture(name: &str, uuid: &str, sid: &str, enabled: bool) -> db::XrayClient {
        db::XrayClient {
            id: 1,
            user_id: None,
            inbound_id: "xray0".into(),
            name: name.into(),
            uuid: uuid.into(),
            short_id: sid.into(),
            expires_at: None,
            additional_config: None,
            enabled,
            created_at: "now".into(),
            updated_at: "now".into(),
        }
    }

    #[test]
    fn generates_valid_json_with_no_clients() {
        let cfg = generate_server_config(&inbound_fixture(), &[]).unwrap();
        let parsed: Value = serde_json::from_str(&cfg).unwrap();
        // No clients -> empty clients array -> Xray would refuse new
        // peers, but the file itself must still be valid Xray JSON.
        let inbound = &parsed["inbounds"][0];
        assert_eq!(inbound["protocol"], "vless");
        assert_eq!(inbound["settings"]["clients"], json!([]));
        // shortIds must be non-empty (Reality requirement); we use a
        // sentinel value so no real peer can connect.
        let sids = inbound["streamSettings"]["realitySettings"]["shortIds"]
            .as_array()
            .unwrap();
        assert_eq!(sids.len(), 1);
    }

    #[test]
    fn includes_only_enabled_clients() {
        let clients = vec![
            client_fixture("alice", "aaaa-uuid", "0000aaaa", true),
            client_fixture("bob",   "bbbb-uuid", "0000bbbb", false),
            client_fixture("carol", "cccc-uuid", "0000cccc", true),
        ];
        let cfg = generate_server_config(&inbound_fixture(), &clients).unwrap();
        let parsed: Value = serde_json::from_str(&cfg).unwrap();
        let inbound = &parsed["inbounds"][0];
        let vless_clients = inbound["settings"]["clients"].as_array().unwrap();
        let names: Vec<_> = vless_clients
            .iter()
            .map(|c| c["email"].as_str().unwrap())
            .collect();
        assert_eq!(names, ["alice", "carol"]);
        let sids: Vec<_> = inbound["streamSettings"]["realitySettings"]["shortIds"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap())
            .collect();
        assert_eq!(sids, ["0000aaaa", "0000cccc"]);
    }

    #[test]
    fn vision_flow_is_hardcoded() {
        let clients = vec![client_fixture("alice", "aaaa-uuid", "0000aaaa", true)];
        let cfg = generate_server_config(&inbound_fixture(), &clients).unwrap();
        let parsed: Value = serde_json::from_str(&cfg).unwrap();
        assert_eq!(
            parsed["inbounds"][0]["settings"]["clients"][0]["flow"],
            "xtls-rprx-vision"
        );
        assert_eq!(
            parsed["inbounds"][0]["streamSettings"]["network"],
            "tcp"
        );
        // tcp transport must not emit xhttpSettings — that would confuse
        // clients that switch on the presence of the field rather than
        // reading `network`.
        assert!(parsed["inbounds"][0]["streamSettings"]["xhttpSettings"].is_null());
    }

    #[test]
    fn xhttp_transport_emits_xhttp_settings_and_empty_flow() {
        let mut inbound = inbound_fixture();
        inbound.transport = "xhttp".into();
        inbound.xhttp_path = "/deadbeefdeadbeefdeadbeefdeadbeef".into();
        let clients = vec![client_fixture("alice", "aaaa-uuid", "0000aaaa", true)];
        let cfg = generate_server_config(&inbound, &clients).unwrap();
        let parsed: Value = serde_json::from_str(&cfg).unwrap();
        let stream = &parsed["inbounds"][0]["streamSettings"];
        assert_eq!(stream["network"], "xhttp");
        // Reality stays on — xhttp wraps it, doesn't replace it. This is
        // exactly what amnezia-client/#2339's server template does.
        assert_eq!(stream["security"], "reality");
        assert_eq!(stream["xhttpSettings"]["path"], "/deadbeefdeadbeefdeadbeefdeadbeef");
        assert_eq!(stream["xhttpSettings"]["mode"], "auto");
        // Vision flow is TCP-only; we must drop it on xhttp.
        assert_eq!(
            parsed["inbounds"][0]["settings"]["clients"][0]["flow"],
            ""
        );
    }

    #[test]
    fn xhttp_without_path_is_a_hard_error() {
        let mut inbound = inbound_fixture();
        inbound.transport = "xhttp".into();
        // xhttp_path intentionally left empty — the supervisor would
        // refuse to run such a config anyway (Xray rejects empty
        // xhttpSettings.path) but we want a clearer error at config-gen
        // time so admin UI surfaces it.
        let res = generate_server_config(&inbound, &[]);
        assert!(res.is_err());
        assert!(res.unwrap_err().to_string().contains("xhttp_path"));
    }

    #[test]
    fn additional_config_is_deep_merged() {
        let mut inbound = inbound_fixture();
        inbound.additional_config = r#"{"streamSettings":{"realitySettings":{"show":true}}}"#.into();
        let cfg = generate_server_config(&inbound, &[]).unwrap();
        let parsed: Value = serde_json::from_str(&cfg).unwrap();
        // Deep-merge must keep `dest`, `serverNames`, etc. and only flip `show`.
        let reality = &parsed["inbounds"][0]["streamSettings"]["realitySettings"];
        assert_eq!(reality["show"], true);
        assert_eq!(reality["dest"], "www.microsoft.com:443");
    }

    #[test]
    fn additional_config_invalid_json_errors() {
        let mut inbound = inbound_fixture();
        inbound.additional_config = "not json".into();
        let res = generate_server_config(&inbound, &[]);
        assert!(res.is_err());
    }

    #[test]
    fn bittorrent_blocked_by_default() {
        let cfg = generate_server_config(&inbound_fixture(), &[]).unwrap();
        let parsed: Value = serde_json::from_str(&cfg).unwrap();
        let rules = parsed["routing"]["rules"].as_array().unwrap();
        let has_bt_block = rules.iter().any(|r| {
            r["protocol"]
                .as_array()
                .map(|p| p.iter().any(|v| v == "bittorrent"))
                .unwrap_or(false)
                && r["outboundTag"] == "blocked"
        });
        assert!(has_bt_block);
    }

    /// End-to-end: generate a config, hand it to the bundled `xray run -test`,
    /// assert the binary parses and validates it. This is the real
    /// regression net — Xray's JSON schema is a moving target across
    /// releases, and a bump that adds a required field will be caught
    /// here rather than at deploy time.
    ///
    /// Serialized against `xray_validates_xhttp_config` because both set
    /// the process-wide `COFFEEBLACK_XRAY_DIR` env var and `cargo test` runs
    /// tests in parallel by default — without serial they race on the
    /// bundled-binary extraction and one of them sees the partial file
    /// before the rename.
    #[cfg(xray_bundled)]
    #[tokio::test]
    #[serial_test::serial(xray_e2e_env)]
    #[ignore = "spawns real xray subprocess + writes CONFIG.xray_dir; run with --ignored"]
    async fn xray_validates_generated_config() {
        // Use a Reality keypair that's known-good (fresh from `xray x25519`).
        let inbound = db::XrayInbound {
            private_key: "WNBaVNH48CG9SumFGQPEVCs1oSoZWS_hbclKHISa3ng".into(),
            public_key: "7qWmW4TmzGw3YcFUZg6xiI4TDbeS5TTVZO8S1-1SUgg".into(),
            // Bind a non-privileged port for the test process.
            port: 14443,
            ..inbound_fixture()
        };
        let clients = vec![client_fixture(
            "alice",
            "11111111-2222-3333-4444-555555555555",
            "0123456789abcdef",
            true,
        )];
        let cfg = generate_server_config(&inbound, &clients).unwrap();

        // Per-test temp dir to avoid races with other xray e2e tests.
        let dir = format!(
            "/tmp/coffeeblack-vpn-cfg-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.subsec_nanos())
                .unwrap_or(0),
        );
        std::env::set_var("COFFEEBLACK_XRAY_DIR", &dir);
        let path = std::path::PathBuf::from(&dir).join("server.json");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(&path, &cfg).unwrap();

        let bin = crate::xray::runtime::resolve_binary().expect("resolve xray binary");
        let output = tokio::process::Command::new(&bin)
            .args(["run", "-test", "-c"])
            .arg(&path)
            .output()
            .await
            .expect("spawn xray run -test");

        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            output.status.success(),
            "xray rejected our config\nstdout:\n{stdout}\nstderr:\n{stderr}",
        );
        assert!(
            stdout.contains("Configuration OK"),
            "xray printed something but didn't say Configuration OK:\n{stdout}",
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Same shape as the tcp e2e but with transport='xhttp'. Catches
    /// the case where a future Xray bump tightens xhttpSettings
    /// validation — also confirms the path we generate is actually
    /// accepted (Xray's parser rejects empty / non-slash-prefixed
    /// paths) and that vision flow doesn't accidentally creep back in.
    /// Shares the `xray_e2e_env` serial key with the tcp e2e.
    #[cfg(xray_bundled)]
    #[tokio::test]
    #[serial_test::serial(xray_e2e_env)]
    #[ignore = "spawns real xray subprocess + writes CONFIG.xray_dir; run with --ignored"]
    async fn xray_validates_xhttp_config() {
        let inbound = db::XrayInbound {
            private_key: "WNBaVNH48CG9SumFGQPEVCs1oSoZWS_hbclKHISa3ng".into(),
            public_key: "7qWmW4TmzGw3YcFUZg6xiI4TDbeS5TTVZO8S1-1SUgg".into(),
            // Distinct port from the tcp e2e — both can run in parallel
            // (cargo test interleaves) and we don't want them fighting
            // over a listener that xray briefly opens during `run -test`.
            port: 14444,
            transport: "xhttp".into(),
            xhttp_path: "/0123456789abcdef0123456789abcdef".into(),
            ..inbound_fixture()
        };
        let clients = vec![client_fixture(
            "alice",
            "11111111-2222-3333-4444-555555555555",
            "0123456789abcdef",
            true,
        )];
        let cfg = generate_server_config(&inbound, &clients).unwrap();

        let dir = format!(
            "/tmp/coffeeblack-vpn-xhttp-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.subsec_nanos())
                .unwrap_or(0),
        );
        std::env::set_var("COFFEEBLACK_XRAY_DIR", &dir);
        let path = std::path::PathBuf::from(&dir).join("server.json");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(&path, &cfg).unwrap();

        let bin = crate::xray::runtime::resolve_binary().expect("resolve xray binary");
        let output = tokio::process::Command::new(&bin)
            .args(["run", "-test", "-c"])
            .arg(&path)
            .output()
            .await
            .expect("spawn xray run -test");

        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            output.status.success(),
            "xray rejected our xhttp config\nstdout:\n{stdout}\nstderr:\n{stderr}",
        );
        assert!(
            stdout.contains("Configuration OK"),
            "xray printed something but didn't say Configuration OK:\n{stdout}",
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
