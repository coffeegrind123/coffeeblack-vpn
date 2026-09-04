//! Per-client `client_config.toml` + resolver-list generator + share-bundle
//! helpers for MasterDnsVPN.
//!
//! The user-side artifacts are:
//!
//! 1. `client_config.toml` — a TOML config the upstream `mdnsvpn` client
//!    binary reads with `-config <path>`. Embeds the same encryption key
//!    and tunnel domain(s) the operator's server runs.
//! 2. `client_resolvers.txt` — one public DNS resolver per line. **Not
//!    optional** (see below).
//! 3. `client_config.json` — same content as the TOML but in JSON form,
//!    suitable for `mdnsvpn -json <path>` or for base64-encoding into
//!    `mdnsvpn -json_base64 <blob>`.
//! 4. The base64 share blob (`mdnsvpn://b64?<base64>&resolvers=…`).
//! 5. `bundle.zip` — every file a peer needs plus a launcher, so one
//!    download is a working client.
//!
//! ## How the client *actually* loads resolvers — read before editing
//!
//! The resolver list is **never** read from the config body. Upstream tags
//! both `Resolvers` and `ResolversFilePath` `toml:"-"`
//! (`internal/config/client.go`), and the JSON loader skips fields whose toml
//! tag is empty or `-` (`internal/config/json_config.go`). So a
//! `RESOLVERS = […]` key in the TOML, or a `"RESOLVERS"` member in the JSON /
//! base64 blob, is **silently ignored** — we used to emit both, which made a
//! per-client resolver override look effective when it was not.
//!
//! Resolvers come from a *file*, resolved by `ClientConfig::ResolversPath()`:
//!
//! | Invocation                          | Where the file must be           |
//! |-------------------------------------|----------------------------------|
//! | `mdnsvpn -config <dir>/config.toml` | `<dir>/client_resolvers.txt`     |
//! | `mdnsvpn -json_base64 <blob>`       | `./client_resolvers.txt` (cwd)   |
//! | `mdnsvpn … -resolvers <path>`       | `<path>` (wins in every mode)    |
//! | `mdnsvpn <config> <resolvers>`      | second positional argument       |
//!
//! A missing file is **fatal**, not a fallback: `LoadClientResolvers` returns
//! `resolver file not found: <path>` and `finalizeClientConfig` propagates it.
//! That is why the base64 blob alone cannot start a client, and why
//! `bundle.zip` exists.
//!
//! ## Public resolver list
//!
//! When a per-client `resolvers` field is empty (the default), we emit a
//! curated baseline list of well-known public resolvers. The operator
//! can edit per-client to scope a peer to a different mix.

use anyhow::{anyhow, Result};
use serde_json::{json, Value};
use std::fmt::Write as _;

use crate::db::{MdnsvpnClient, MdnsvpnInbound};

/// Curated baseline of "always works almost everywhere" public DNS
/// resolvers. Used when a per-client `resolvers` column is empty so the
/// operator doesn't have to hand-curate one for every new peer. Mirrors
/// the upstream sample's `client_resolvers.simple` ethos.
pub const DEFAULT_RESOLVERS: &[&str] = &[
    "8.8.8.8",
    "8.8.4.4",
    "1.1.1.1",
    "1.0.0.1",
    "9.9.9.9",
    "149.112.112.112",
    "208.67.222.222",
    "208.67.220.220",
    "94.140.14.14",
    "94.140.15.15",
];

/// Filename the client looks for when no `-resolvers` override is given.
/// Hard-coded upstream in `ClientConfig::ResolversPath()`, so the name is not
/// ours to choose — the peer's file must be called exactly this.
pub const RESOLVERS_FILENAME: &str = "client_resolvers.txt";

/// Filename we ship the config under inside `bundle.zip`. Any name works with
/// `-config`, but keeping upstream's default means `mdnsvpn` with no arguments
/// finds it too.
pub const CONFIG_FILENAME: &str = "client_config.toml";

/// Bundle of share artifacts a peer needs.
#[derive(Debug, Clone)]
pub struct ShareBundle {
    pub config_toml: String,
    pub resolvers_txt: String,
    pub config_json: String,
    /// `mdnsvpn -json_base64 <blob>` payload — base64-encoded JSON.
    ///
    /// Standard base64 with padding: upstream decodes with
    /// `base64.StdEncoding` (`decodeBase64ConfigJSON`), which rejects the
    /// URL-safe alphabet and unpadded input. Do not "fix" this to base64url.
    pub config_json_base64: String,
    /// Resolvers this peer resolved to, after the per-client override /
    /// baseline fallback. Carried so the share URL and the zip can both use
    /// the same list without re-deriving it.
    pub resolvers: Vec<String>,
}

/// Build the `mdnsvpn://` share string for a rendered bundle.
///
/// Shape: `mdnsvpn://b64?<standard-base64>&resolvers=<comma-list>`
///
/// * The base64 segment is byte-identical to what `mdnsvpn -json_base64`
///   expects, so it stays copy-pasteable. Standard base64's alphabet is
///   `A-Za-z0-9+/=`, which cannot contain `&`, so splitting on the first `&`
///   is unambiguous.
/// * `resolvers=` is an **awg-easy-rs extension** the upstream client does not
///   read (it has no config path for an inline list — see the module docs). It
///   exists so scanning the QR does not lose the resolver list: everything
///   needed to write both files is in the one string.
pub fn share_url(bundle: &ShareBundle) -> String {
    let mut url = format!("mdnsvpn://b64?{}", bundle.config_json_base64);
    if !bundle.resolvers.is_empty() {
        url.push_str("&resolvers=");
        url.push_str(&bundle.resolvers.join(","));
    }
    url
}

/// Render every share artifact for `client` against the singleton
/// `inbound`. Returns the bundle by value (small struct) so the API
/// layer can pick whichever piece each endpoint serves.
pub fn render_bundle(
    inbound: &MdnsvpnInbound,
    client: &MdnsvpnClient,
) -> Result<ShareBundle> {
    let domains = parse_string_array(&inbound.domains)
        .map_err(|e| anyhow!("inbound domains: {e}"))?;
    if domains.is_empty() {
        return Err(anyhow!(
            "MasterDnsVPN inbound has no `domains` set — cannot generate client config"
        ));
    }
    let resolvers = client_resolver_list(client);

    let config_toml = render_client_toml(inbound, client, &domains);
    let resolvers_txt = render_resolvers_txt(&resolvers);
    let config_json_value = render_client_json(inbound, client, &domains);
    let config_json = serde_json::to_string_pretty(&config_json_value)
        .unwrap_or_else(|_| "{}".to_string());
    let config_json_compact = serde_json::to_string(&config_json_value)
        .unwrap_or_else(|_| "{}".to_string());
    let config_json_base64 = crate::encoding::b64_encode(config_json_compact.as_bytes());

    Ok(ShareBundle {
        config_toml,
        resolvers_txt,
        config_json,
        config_json_base64,
        resolvers,
    })
}

/// Resolve the per-client resolver list. Falls back to the curated
/// baseline `DEFAULT_RESOLVERS` when the client column is empty / null /
/// an empty JSON array — so every peer always ships with *some* working
/// list, even if the operator never edits it.
fn client_resolver_list(client: &MdnsvpnClient) -> Vec<String> {
    let raw = client.resolvers.trim();
    if raw.is_empty() {
        return DEFAULT_RESOLVERS.iter().map(|s| s.to_string()).collect();
    }
    // Two acceptable storage formats:
    //  - JSON array of strings (preferred — UI emits this)
    //  - one resolver per line (operator pasted-in)
    if raw.starts_with('[') {
        if let Ok(arr) = parse_string_array(raw) {
            if arr.is_empty() {
                return DEFAULT_RESOLVERS.iter().map(|s| s.to_string()).collect();
            }
            return arr;
        }
    }
    raw.lines()
        .map(|l| l.trim().to_string())
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .collect()
}

fn parse_string_array(s: &str) -> std::result::Result<Vec<String>, String> {
    let trimmed = s.trim();
    if trimmed.is_empty() {
        return Ok(Vec::new());
    }
    let v: Value = serde_json::from_str(trimmed)
        .map_err(|e| format!("not valid JSON: {e}"))?;
    let arr = v
        .as_array()
        .ok_or_else(|| "JSON value is not an array".to_string())?;
    let mut out = Vec::with_capacity(arr.len());
    for entry in arr {
        let s = entry
            .as_str()
            .ok_or_else(|| "array entry is not a string".to_string())?;
        out.push(s.to_string());
    }
    Ok(out)
}

fn render_client_toml(
    inbound: &MdnsvpnInbound,
    client: &MdnsvpnClient,
    domains: &[String],
) -> String {
    let mut body = String::new();
    // Strip control chars (esp. newlines) from the name before embedding it in
    // this comment line — otherwise a name containing `\n` would break out of
    // the comment into the TOML body, unlike every value field below which goes
    // through `toml_string`.
    let safe_name: String = client.name.chars().filter(|c| !c.is_control()).collect();
    writeln!(body, "# Generated by awg-easy-rs for client \"{}\"", safe_name).unwrap();
    writeln!(body, "# This config bundles the operator's tunnel parameters").unwrap();
    writeln!(body, "# (domain, encryption key, encryption method) and a per-").unwrap();
    writeln!(body, "# client local SOCKS5 listen address.").unwrap();
    writeln!(body, "#").unwrap();
    writeln!(
        body,
        "# REQUIRED: `{RESOLVERS_FILENAME}` must sit in this same directory."
    )
    .unwrap();
    writeln!(
        body,
        "# The resolver list cannot live in this file — mdnsvpn only reads it"
    )
    .unwrap();
    writeln!(
        body,
        "# from a separate file, and a missing file is a fatal startup error"
    )
    .unwrap();
    writeln!(body, "# (\"resolver file not found\"), not a fallback. Either:").unwrap();
    writeln!(body, "#").unwrap();
    writeln!(
        body,
        "#   mdnsvpn -config {CONFIG_FILENAME}                      # finds it beside this file"
    )
    .unwrap();
    writeln!(
        body,
        "#   mdnsvpn -config {CONFIG_FILENAME} -resolvers /path/to/{RESOLVERS_FILENAME}"
    )
    .unwrap();
    writeln!(body, "#").unwrap();
    writeln!(
        body,
        "# Download it from the same place you got this file, or use bundle.zip"
    )
    .unwrap();
    writeln!(body, "# which contains both plus a launcher.").unwrap();
    body.push('\n');

    // ------------------------------------------------------------------
    // 1) Tunnel identity & security
    // ------------------------------------------------------------------
    writeln!(body, "DOMAINS = {}", toml_string_array(domains)).unwrap();
    writeln!(
        body,
        "DATA_ENCRYPTION_METHOD = {}",
        inbound.encryption_method
    )
    .unwrap();
    writeln!(
        body,
        "ENCRYPTION_KEY = {}",
        toml_string(&inbound.encryption_key)
    )
    .unwrap();
    body.push('\n');

    // ------------------------------------------------------------------
    // 2) Local proxy listener
    // ------------------------------------------------------------------
    writeln!(body, "PROTOCOL_TYPE = \"SOCKS5\"").unwrap();
    writeln!(body, "LISTEN_IP = \"127.0.0.1\"").unwrap();
    writeln!(body, "LISTEN_PORT = {}", client.listen_port).unwrap();
    let socks5_auth = !client.socks5_user.is_empty();
    writeln!(body, "SOCKS5_AUTH = {}", bool_lit(socks5_auth)).unwrap();
    if socks5_auth {
        writeln!(body, "SOCKS5_USER = {}", toml_string(&client.socks5_user)).unwrap();
        writeln!(body, "SOCKS5_PASS = {}", toml_string(&client.socks5_pass)).unwrap();
    }
    body.push('\n');

    // No `RESOLVERS = [...]` here on purpose: the key does not exist in
    // mdnsvpn's config schema (`Resolvers` is `toml:"-"`), so emitting it
    // would be a no-op that reads like a working setting. See the module docs.

    // ------------------------------------------------------------------
    // Sensible defaults for lossy networks. These match the upstream
    // sample's "biased toward lossy / high-latency links" profile —
    // appropriate for the censorship-circumvention use case mdnsvpn is
    // built for.
    // ------------------------------------------------------------------
    writeln!(body, "RESOLVER_BALANCING_STRATEGY = 5").unwrap();
    writeln!(body, "PACKET_DUPLICATION_COUNT = 3").unwrap();
    writeln!(body, "SETUP_PACKET_DUPLICATION_COUNT = 4").unwrap();
    writeln!(body, "AUTO_REMOVE_LOW_MTU_SERVERS = true").unwrap();
    writeln!(body, "RECHECK_INACTIVE_SERVERS_ENABLED = true").unwrap();
    writeln!(body, "AUTO_DISABLE_TIMEOUT_SERVERS = true").unwrap();
    writeln!(body, "LOG_LEVEL = \"INFO\"").unwrap();
    body.push('\n');

    // Verbatim per-client escape hatch.
    if let Some(extra) = client.additional_config_toml.as_deref() {
        let extra = extra.trim();
        if !extra.is_empty() {
            writeln!(body, "# --- per-client additional_config (verbatim) ---").unwrap();
            body.push_str(extra);
            if !body.ends_with('\n') {
                body.push('\n');
            }
        }
    }

    body
}

fn render_resolvers_txt(resolvers: &[String]) -> String {
    let mut body = String::new();
    writeln!(body, "# Generated by awg-easy-rs.").unwrap();
    writeln!(
        body,
        "# Save as `{RESOLVERS_FILENAME}` next to your client config — mdnsvpn"
    )
    .unwrap();
    writeln!(
        body,
        "# will not start without it (\"resolver file not found\")."
    )
    .unwrap();
    writeln!(body, "# One resolver per line.").unwrap();
    writeln!(body, "# Supported formats:").unwrap();
    writeln!(body, "#   8.8.8.8").unwrap();
    writeln!(body, "#   1.1.1.1:5353").unwrap();
    writeln!(body, "#   192.168.1.0/30").unwrap();
    writeln!(body, "#   192.168.1.0/30:5353").unwrap();
    writeln!(body, "#   [2001:4860:4860::8888]:53").unwrap();
    body.push('\n');
    for r in resolvers {
        writeln!(body, "{r}").unwrap();
    }
    body
}

fn render_client_json(
    inbound: &MdnsvpnInbound,
    client: &MdnsvpnClient,
    domains: &[String],
) -> Value {
    // Map every TOML key emitted by render_client_toml into the
    // equivalent JSON field. mdnsvpn's `-json_base64` parser accepts the
    // same set of keys as the TOML loader; the only delta is that JSON
    // wants the values typed.
    //
    // Deliberately no "RESOLVERS" member: the JSON decoder keys off the toml
    // tag and skips `-`, so it would be dropped on the floor. The resolver
    // list travels as a file (or in the share URL's `resolvers=` extension).
    let socks5_auth = !client.socks5_user.is_empty();
    let mut obj = serde_json::Map::new();
    obj.insert("DOMAINS".into(), json!(domains));
    obj.insert("DATA_ENCRYPTION_METHOD".into(), json!(inbound.encryption_method));
    obj.insert("ENCRYPTION_KEY".into(), json!(inbound.encryption_key));
    obj.insert("PROTOCOL_TYPE".into(), json!("SOCKS5"));
    obj.insert("LISTEN_IP".into(), json!("127.0.0.1"));
    obj.insert("LISTEN_PORT".into(), json!(client.listen_port));
    obj.insert("SOCKS5_AUTH".into(), json!(socks5_auth));
    if socks5_auth {
        obj.insert("SOCKS5_USER".into(), json!(client.socks5_user));
        obj.insert("SOCKS5_PASS".into(), json!(client.socks5_pass));
    }
    obj.insert("RESOLVER_BALANCING_STRATEGY".into(), json!(5));
    obj.insert("PACKET_DUPLICATION_COUNT".into(), json!(3));
    obj.insert("SETUP_PACKET_DUPLICATION_COUNT".into(), json!(4));
    obj.insert("AUTO_REMOVE_LOW_MTU_SERVERS".into(), json!(true));
    obj.insert("RECHECK_INACTIVE_SERVERS_ENABLED".into(), json!(true));
    obj.insert("AUTO_DISABLE_TIMEOUT_SERVERS".into(), json!(true));
    obj.insert("LOG_LEVEL".into(), json!("INFO"));
    Value::Object(obj)
}

fn bool_lit(b: bool) -> &'static str {
    if b {
        "true"
    } else {
        "false"
    }
}

fn toml_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for ch in s.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                let _ = std::fmt::Write::write_fmt(
                    &mut out,
                    format_args!("\\u{:04X}", c as u32),
                );
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

fn toml_string_array(items: &[String]) -> String {
    let mut out = String::from("[");
    for (i, s) in items.iter().enumerate() {
        if i > 0 {
            out.push_str(", ");
        }
        out.push_str(&toml_string(s));
    }
    out.push(']');
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_inbound() -> MdnsvpnInbound {
        MdnsvpnInbound {
            id: "mdnsvpn0".into(),
            domains: r#"["v.example.com"]"#.into(),
            port: 53,
            bind: "0.0.0.0".into(),
            encryption_method: 5,
            encryption_key: "deadbeefcafebabe1234567890abcdef".into(),
            protocol_type: "SOCKS5".into(),
            dns_upstream_servers: r#"["1.1.1.1:53"]"#.into(),
            forward_ip: String::new(),
            forward_port: 0,
            use_external_socks5: false,
            socks5_auth: false,
            socks5_user: String::new(),
            socks5_pass: String::new(),
            additional_config: String::new(),
            enabled: true,
            created_at: "now".into(),
            updated_at: "now".into(),
        }
    }

    fn fixture_client() -> MdnsvpnClient {
        MdnsvpnClient {
            id: 1,
            user_id: None,
            inbound_id: "mdnsvpn0".into(),
            name: "alice".into(),
            resolvers: String::new(),
            listen_port: 18000,
            socks5_user: String::new(),
            socks5_pass: String::new(),
            expires_at: None,
            additional_config_toml: None,
            enabled: true,
            created_at: "now".into(),
            updated_at: "now".into(),
        }
    }

    #[test]
    fn renders_full_bundle_with_defaults() {
        let bundle = render_bundle(&fixture_inbound(), &fixture_client()).unwrap();

        // TOML basics
        assert!(bundle.config_toml.contains(r#"DOMAINS = ["v.example.com"]"#));
        assert!(bundle.config_toml.contains("DATA_ENCRYPTION_METHOD = 5"));
        assert!(bundle.config_toml.contains(
            r#"ENCRYPTION_KEY = "deadbeefcafebabe1234567890abcdef""#
        ));
        assert!(bundle.config_toml.contains("LISTEN_PORT = 18000"));
        assert!(bundle.config_toml.contains("SOCKS5_AUTH = false"));

        // Resolver file
        assert!(bundle.resolvers_txt.contains("8.8.8.8"));
        assert!(bundle.resolvers_txt.contains("1.1.1.1"));
        // ...and the same list is exposed structurally.
        assert!(bundle.resolvers.contains(&"8.8.8.8".to_string()));

        // JSON
        let parsed: Value = serde_json::from_str(&bundle.config_json).unwrap();
        assert_eq!(parsed["LISTEN_PORT"], 18000);
        assert_eq!(parsed["DATA_ENCRYPTION_METHOD"], 5);
        assert_eq!(parsed["DOMAINS"][0], "v.example.com");
        assert_eq!(parsed["SOCKS5_AUTH"], false);

        // Base64
        let decoded = crate::encoding::b64_decode(&bundle.config_json_base64).unwrap();
        let s = std::str::from_utf8(&decoded).unwrap();
        assert!(s.contains("v.example.com"));
        assert!(s.contains("deadbeefcafebabe1234567890abcdef"));
    }

    #[test]
    fn per_client_socks5_auth_renders() {
        let mut client = fixture_client();
        client.socks5_user = "alice".into();
        client.socks5_pass = "verysecret".into();
        let bundle = render_bundle(&fixture_inbound(), &client).unwrap();
        assert!(bundle.config_toml.contains("SOCKS5_AUTH = true"));
        assert!(bundle.config_toml.contains(r#"SOCKS5_USER = "alice""#));
        assert!(bundle.config_toml.contains(r#"SOCKS5_PASS = "verysecret""#));

        let parsed: Value = serde_json::from_str(&bundle.config_json).unwrap();
        assert_eq!(parsed["SOCKS5_AUTH"], true);
        assert_eq!(parsed["SOCKS5_USER"], "alice");
        assert_eq!(parsed["SOCKS5_PASS"], "verysecret");
    }

    #[test]
    fn per_client_resolvers_override_default() {
        let mut client = fixture_client();
        client.resolvers = r#"["10.10.10.10","[2001:db8::1]:53"]"#.into();
        let bundle = render_bundle(&fixture_inbound(), &client).unwrap();
        assert_eq!(
            bundle.resolvers,
            vec!["10.10.10.10".to_string(), "[2001:db8::1]:53".to_string()]
        );
        // resolvers_txt has a documentation header that mentions 8.8.8.8
        // as a format example — strip that before checking.
        let payload: String = bundle
            .resolvers_txt
            .lines()
            .filter(|l| !l.starts_with('#'))
            .collect::<Vec<_>>()
            .join("\n");
        assert!(!payload.contains("8.8.8.8"));
        assert!(payload.contains("10.10.10.10"));
        assert!(payload.contains("[2001:db8::1]:53"));
    }

    #[test]
    fn per_client_resolvers_line_format_accepted() {
        // Operators may paste line-per-resolver content directly.
        let mut client = fixture_client();
        client.resolvers = "9.9.9.9\n9.9.9.10\n# comment ignored\n  ".into();
        let bundle = render_bundle(&fixture_inbound(), &client).unwrap();
        assert!(bundle.resolvers_txt.contains("9.9.9.9"));
        assert!(bundle.resolvers_txt.contains("9.9.9.10"));
        assert_eq!(
            bundle.resolvers,
            vec!["9.9.9.9".to_string(), "9.9.9.10".to_string()]
        );
    }

    /// Regression guard for the whole point of this change: neither artifact
    /// may carry a `RESOLVERS` key, because the client's config schema has no
    /// such field (`Resolvers` is `toml:"-"`) and the JSON decoder skips it.
    /// Emitting it made per-client resolver overrides look effective when they
    /// were silently discarded.
    #[test]
    fn no_artifact_emits_the_nonexistent_resolvers_key() {
        let bundle = render_bundle(&fixture_inbound(), &fixture_client()).unwrap();

        assert!(
            !bundle.config_toml.contains("RESOLVERS ="),
            "TOML still emits a dead RESOLVERS key:\n{}",
            bundle.config_toml
        );
        let parsed: Value = serde_json::from_str(&bundle.config_json).unwrap();
        assert!(
            parsed.get("RESOLVERS").is_none(),
            "JSON still emits a dead RESOLVERS member"
        );
        let decoded = crate::encoding::b64_decode(&bundle.config_json_base64).unwrap();
        let blob: Value = serde_json::from_slice(&decoded).unwrap();
        assert!(blob.get("RESOLVERS").is_none());
    }

    /// The config must tell the peer that the resolver file is mandatory —
    /// otherwise the failure mode is a startup abort naming a file they were
    /// never told to fetch.
    #[test]
    fn config_documents_the_mandatory_resolver_file() {
        let bundle = render_bundle(&fixture_inbound(), &fixture_client()).unwrap();
        assert!(bundle.config_toml.contains(RESOLVERS_FILENAME));
        assert!(bundle.config_toml.contains("resolver file not found"));
        assert!(bundle.resolvers_txt.contains(RESOLVERS_FILENAME));
    }

    #[test]
    fn share_url_keeps_the_base64_payload_verbatim_and_appends_resolvers() {
        let bundle = render_bundle(&fixture_inbound(), &fixture_client()).unwrap();
        let url = share_url(&bundle);

        assert!(url.starts_with("mdnsvpn://b64?"));
        // Standard base64's alphabet cannot contain '&', so the first '&'
        // unambiguously terminates the payload a peer pastes into
        // `-json_base64`. Verify the segment round-trips.
        let query = url.strip_prefix("mdnsvpn://b64?").unwrap();
        let payload = query.split('&').next().unwrap();
        assert_eq!(payload, bundle.config_json_base64);
        let decoded = crate::encoding::b64_decode(payload).expect("payload must stay valid std base64");
        let blob: Value = serde_json::from_slice(&decoded).unwrap();
        assert_eq!(blob["DOMAINS"][0], "v.example.com");

        // ...and the resolver list is not lost when the QR is scanned.
        assert!(url.contains("&resolvers=8.8.8.8,"));
        for r in &bundle.resolvers {
            assert!(url.contains(r.as_str()), "resolver {r} missing from {url}");
        }
    }

    #[test]
    fn share_url_omits_the_param_when_there_are_no_resolvers() {
        let mut bundle = render_bundle(&fixture_inbound(), &fixture_client()).unwrap();
        bundle.resolvers.clear();
        let url = share_url(&bundle);
        assert!(!url.contains("resolvers="));
        assert!(url.ends_with(&bundle.config_json_base64));
    }

    #[test]
    fn additional_config_appended_verbatim() {
        let mut client = fixture_client();
        client.additional_config_toml = Some("LOCAL_DNS_ENABLED = true\nLOCAL_DNS_PORT = 5353".into());
        let bundle = render_bundle(&fixture_inbound(), &client).unwrap();
        assert!(bundle.config_toml.contains("# --- per-client additional_config (verbatim) ---"));
        assert!(bundle.config_toml.contains("LOCAL_DNS_ENABLED = true"));
        assert!(bundle.config_toml.contains("LOCAL_DNS_PORT = 5353"));
    }

    #[test]
    fn rejects_inbound_without_domains() {
        let mut inbound = fixture_inbound();
        inbound.domains = "[]".into();
        assert!(render_bundle(&inbound, &fixture_client()).is_err());
    }

    #[test]
    fn json_base64_round_trips() {
        let bundle = render_bundle(&fixture_inbound(), &fixture_client()).unwrap();
        let decoded = crate::encoding::b64_decode(&bundle.config_json_base64).unwrap();
        let v: Value = serde_json::from_slice(&decoded).unwrap();
        assert_eq!(v["DOMAINS"][0], "v.example.com");
        assert_eq!(v["LISTEN_PORT"], 18000);
    }
}
