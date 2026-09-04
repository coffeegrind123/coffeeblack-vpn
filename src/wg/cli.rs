//! Shell command execution and awg CLI wrappers.
//!
//! All AmneziaWG commands go through this module.
//! Binary is always `awg` / `awg-quick`.
//!
//! Every command is executed argv-style with no shell involvement, so the
//! interface name (read from the database and in principle settable to a
//! malicious value by an admin) cannot be used to inject arbitrary shell
//! commands. There is deliberately no `bash -c` helper here.

use std::process::{Command, Stdio};
use std::io::Write;
use anyhow::{Result, anyhow};

/// Check whether the awg binary is available on this system.
fn cb_available() -> bool {
    Command::new("which")
        .arg("awg")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Run `prog arg1 arg2 ...` with no shell involvement. Returns trimmed stdout.
/// This is the preferred entry point for any command that takes
/// caller-controlled arguments.
pub fn run(prog: &str, args: &[&str]) -> Result<String> {
    run_argv(prog, args)
}

fn run_argv(prog: &str, args: &[&str]) -> Result<String> {
    if !cfg!(target_os = "linux") || !cb_available() {
        return Ok(String::new());
    }
    let output = Command::new(prog).args(args).output()?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(anyhow!(
            "Command failed: {} {:?}: {}",
            prog,
            args,
            stderr
        ));
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

/// Validate an interface name — argv-style execution prevents shell
/// injection, but a malformed name can still confuse `awg-quick`. Allow
/// only the AmneziaWG-conventional pattern.
fn validate_iface_name(name: &str) -> Result<()> {
    if name.is_empty() || name.len() > 15 {
        return Err(anyhow!("Invalid interface name length"));
    }
    if !name.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-')) {
        return Err(anyhow!("Invalid characters in interface name"));
    }
    Ok(())
}

/// Bring up an AmneziaWG interface with awg-quick.
///
/// Routed through the privileged helper when one is configured, so the web
/// process needs no `CAP_NET_ADMIN` of its own. Falls back to executing
/// directly otherwise — that is the original single-process behaviour and
/// stays the default until an operator opts in.
pub fn cb_up(name: &str) -> Result<()> {
    validate_iface_name(name)?;
    if crate::privhelper::is_enabled() {
        return crate::privhelper::call(&crate::privhelper::Request::WgUp).map(|_| ());
    }
    run_argv("awg-quick", &["up", name]).map(|_| ())
}

/// Take down an AmneziaWG interface with awg-quick.
pub fn cb_down(name: &str) -> Result<()> {
    validate_iface_name(name)?;
    if crate::privhelper::is_enabled() {
        return crate::privhelper::call(&crate::privhelper::Request::WgDown).map(|_| ());
    }
    run_argv("awg-quick", &["down", name]).map(|_| ())
}

/// Sync config without restarting the interface.
/// Uses process substitution: awg syncconf <name> <(awg-quick strip <name>)
pub fn cb_sync(name: &str) -> Result<()> {
    validate_iface_name(name)?;
    if !cfg!(target_os = "linux") || !cb_available() {
        return Ok(());
    }
    // Capture `awg-quick strip <name>` first, then pipe via stdin to
    // `awg syncconf <name> /dev/stdin`. Avoids the bash-only `<(...)`
    // syntax and the associated shell-injection surface.
    let stripped = run_argv("awg-quick", &["strip", name])?;
    let mut child = Command::new("awg")
        .args(["syncconf", name, "/dev/stdin"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    if let Some(mut sin) = child.stdin.take() {
        sin.write_all(stripped.as_bytes())?;
    }
    let out = child.wait_with_output()?;
    if !out.status.success() {
        return Err(anyhow!(
            "awg syncconf failed: {}",
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    Ok(())
}

/// A single peer's runtime status from `awg show <if> dump`.
#[derive(Debug, Clone)]
pub struct PeerDump {
    pub public_key: String,
    pub endpoint: Option<String>,
    pub latest_handshake: Option<time::OffsetDateTime>,
    pub transfer_rx: i64,
    pub transfer_tx: i64,
}

/// Dump AmneziaWG peer status for an interface.
/// Parses tab-separated output from `awg show <name> dump`.
pub fn cb_dump(name: &str) -> Result<Vec<PeerDump>> {
    validate_iface_name(name)?;
    let output = if crate::privhelper::is_enabled() {
        crate::privhelper::call(&crate::privhelper::Request::WgShow)?
    } else {
        run_argv("awg", &["show", name, "dump"])?
    };
    let mut peers = Vec::new();

    for line in output.lines().skip(1) {
        // skip header line
        let fields: Vec<&str> = line.split('\t').collect();
        if fields.len() >= 8 {
            let handshake = if fields[4] == "0" {
                None
            } else {
                fields[4]
                    .parse::<i64>()
                    .ok()
                    .and_then(crate::datetime::from_unix)
            };
            peers.push(PeerDump {
                public_key: fields[0].to_string(),
                endpoint: if fields[2] == "(none)" {
                    None
                } else {
                    Some(fields[2].to_string())
                },
                latest_handshake: handshake,
                transfer_rx: fields[5].parse().unwrap_or(0),
                transfer_tx: fields[6].parse().unwrap_or(0),
            });
        }
    }
    Ok(peers)
}
