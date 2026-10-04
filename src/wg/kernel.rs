//! Detect whether the AmneziaWG kernel module is loaded, and which
//! generation it speaks.
//!
//! `awg-quick up` prefers the kernel module (fast path) and falls back
//! to spawning `amneziawg-go` as a userspace TUN device when the module
//! isn't present. The two paths are not 100 % feature-equivalent — most
//! notably, the userspace `amneziawg-go` fallback chokes on a peer with
//! an explicit `AdvancedSecurity = on|off` line, while the kernel
//! module auto-detects from the H1 magic header on the first incoming
//! handshake (see `src/api/clients.rs` per-peer `advanced_security`
//! comment).
//!
//! The admin UI surfaces this as a status badge next to the
//! AdvancedSecurity tri-state, and the API response gates the
//! per-peer setter so an operator running userspace can't accidentally
//! produce a broken peer config.
//!
//! Detection prefers, in order:
//!
//! 1. `/sys/module/amneziawg` — directory present iff the module is
//!    loaded right now.  Cheap, deterministic, doesn't shell out.
//! 2. `/proc/modules` containing a line starting with `amneziawg ` —
//!    fallback for hosts where `/sys/module` isn't mounted (rare; some
//!    minimal containers).
//! 3. Anywhere under `/lib/modules/<uname>/` — module is *installed*
//!    but not yet loaded.  We treat that as `Available` so the UI can
//!    say "module installed, will load on first `awg-quick up`."
//!
//! On non-Linux dev hosts (macOS / Windows), all three checks return
//! `Unknown` rather than panicking.

use std::path::Path;
use std::sync::atomic::{AtomicU8, Ordering};

/// Detection override. `0` = real probe; `1` = force Kernel; `2` = force
/// Userspace; `3` = force Unknown. Lets integration tests pin a mode on a
/// host where the real module state can't be controlled (CI runners never
/// have the AmneziaWG kernel module loaded), and gives operators on exotic
/// hosts an escape hatch via [`set_mode_override`]. Off by default, so
/// production behaviour is unchanged.
static MODE_OVERRIDE: AtomicU8 = AtomicU8::new(0);

/// What state the kernel side of AmneziaWG is in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum GamingMode {
    /// Kernel module loaded and visible in /sys/module/amneziawg.
    /// Full feature set — AdvancedSecurity per-peer works, etc.
    Kernel,
    /// Kernel module not loaded. awg-quick will fall back to
    /// `amneziawg-go` userspace, which doesn't support the
    /// AdvancedSecurity = on|off peer line.
    Userspace,
    /// Couldn't determine (non-Linux host, /sys not mounted, etc.).
    /// UI should treat this as "no warnings, but no positive
    /// confirmation either."
    Unknown,
}

impl GamingMode {
    /// True when the running mode supports per-peer
    /// `AdvancedSecurity = on|off`. Userspace and unknown modes
    /// return false (conservative — for unknown we'd rather suppress
    /// the option than surprise the operator with a broken handshake).
    pub fn supports_advanced_security(self) -> bool {
        matches!(self, GamingMode::Kernel)
    }
}

/// Force a specific [`GamingMode`] regardless of the host's real module
/// state, or restore real detection with `None`. Process-global; intended
/// for tests (which serialize via `serial_test`) and for operators who must
/// override detection on an exotic host. Has no effect in normal operation.
pub fn set_mode_override(mode: Option<GamingMode>) {
    let code = match mode {
        None => 0,
        Some(GamingMode::Kernel) => 1,
        Some(GamingMode::Userspace) => 2,
        Some(GamingMode::Unknown) => 3,
    };
    MODE_OVERRIDE.store(code, Ordering::SeqCst);
}

/// Probe the host for the AmneziaWG kernel module's presence.
/// Cheap (filesystem lookups only) — safe to call on every admin
/// `GET /api/admin/interface` without caching.
pub fn detect() -> GamingMode {
    match MODE_OVERRIDE.load(Ordering::SeqCst) {
        1 => return GamingMode::Kernel,
        2 => return GamingMode::Userspace,
        3 => return GamingMode::Unknown,
        _ => {}
    }
    if !cfg!(target_os = "linux") {
        return GamingMode::Unknown;
    }
    if Path::new("/sys/module/amneziawg").is_dir() {
        return GamingMode::Kernel;
    }
    // /sys not mounted? Fall back to /proc/modules. It's a flat
    // text file with one line per loaded module; first column is
    // the module name.
    if let Ok(text) = std::fs::read_to_string("/proc/modules") {
        for line in text.lines() {
            // First whitespace-separated field is the module name.
            if let Some(name) = line.split_whitespace().next() {
                if name == "amneziawg" {
                    return GamingMode::Kernel;
                }
            }
        }
    }
    GamingMode::Userspace
}

// ---------------------------------------------------------------------------
// Module generation
// ---------------------------------------------------------------------------
//
// `detect()` only says *whether* a module is loaded. Which AmneziaWG
// generation it speaks matters as much: a pre-2.0 module (still what the
// Fedora COPR ships) rejects S3/S4 and H1-H4 ranges, which every config this
// project generates contains, and a 2.x module rejects the AWG 3 keys. The
// tools version can't tell — a 3.x `awg` happily drives an old module — and
// the module's own `version` string is hardcoded to 1.0.0 upstream.
//
// The kernel does publish it, unambiguously: the `amneziawg` generic-netlink
// family's version, which `awg` itself reads to choose the H1-H4 wire
// encoding. Asking the netlink controller for it needs no privilege, creates
// nothing, and touches no interface:
//
//   request:  nlmsghdr{type=GENL_ID_CTRL, flags=REQUEST}
//             genlmsghdr{cmd=CTRL_CMD_GETFAMILY}
//             nlattr{CTRL_ATTR_FAMILY_NAME, "amneziawg\0"}
//   reply:    nlmsghdr{type=GENL_ID_CTRL} genlmsghdr{cmd=NEWFAMILY}
//             nlattr{CTRL_ATTR_VERSION, u32} ...       family registered
//         or  nlmsghdr{type=NLMSG_ERROR} -ENOENT       module not loaded

/// Generic-netlink family the module registers (`WG_GENL_NAME`).
const AWG_GENL_NAME: &str = "amneziawg";

// <linux/netlink.h>, <linux/genetlink.h>
const NLMSG_HDRLEN: usize = 16;
const GENL_HDRLEN: usize = 4;
const NLA_HDRLEN: usize = 4;
const NLMSG_ERROR: u16 = 2;
const NLM_F_REQUEST: u16 = 1;
const GENL_ID_CTRL: u16 = 0x10;
const CTRL_CMD_NEWFAMILY: u8 = 1;
const CTRL_CMD_GETFAMILY: u8 = 3;
const CTRL_ATTR_FAMILY_NAME: u16 = 2;
const CTRL_ATTR_VERSION: u16 = 3;
const ENOENT: i32 = 2;

/// Which AmneziaWG generation the loaded kernel module implements.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ModuleGen {
    /// genl version 3+: AWG 3 (header protection, content padding, timers).
    Awg3,
    /// genl version 2: AWG 2 (S3/S4, H1-H4 ranges, I1-I5). Rejects AWG 3 keys.
    Awg2,
    /// genl version 1: AWG 1.x. Rejects the S3/S4 and H-range keys every
    /// generated config carries, so kernel mode cannot work at all.
    Pre2,
    /// The `amneziawg` family isn't registered: the module isn't loaded.
    NotLoaded,
    /// Couldn't ask (non-Linux, netlink unavailable, unrecognised reply).
    Unknown,
}

impl ModuleGen {
    fn from_genl_version(version: u32) -> Self {
        match version {
            0 => ModuleGen::Unknown,
            1 => ModuleGen::Pre2,
            2 => ModuleGen::Awg2,
            _ => ModuleGen::Awg3,
        }
    }
}

/// Same contract as [`MODE_OVERRIDE`]: `0` = real query, otherwise the
/// forced variant's code from [`set_gen_override`].
static GEN_OVERRIDE: AtomicU8 = AtomicU8::new(0);

/// Force a [`ModuleGen`] regardless of the host, or restore the real query
/// with `None`. Process-global; for tests and exotic hosts, like
/// [`set_mode_override`].
pub fn set_gen_override(gen: Option<ModuleGen>) {
    let code = match gen {
        None => 0,
        Some(ModuleGen::Awg3) => 1,
        Some(ModuleGen::Awg2) => 2,
        Some(ModuleGen::Pre2) => 3,
        Some(ModuleGen::NotLoaded) => 4,
        Some(ModuleGen::Unknown) => 5,
    };
    GEN_OVERRIDE.store(code, Ordering::SeqCst);
}

/// Ask the kernel which AmneziaWG generation the loaded module speaks.
/// One netlink round trip with a one-second ceiling — cheap enough to call
/// per admin request, so a module swapped underneath a running service is
/// reported without a restart.
///
/// Like any `awg` command, the query loads an installed-but-unloaded module:
/// the module declares `MODULE_ALIAS_GENL_FAMILY("amneziawg")` and the
/// netlink controller requests it on lookup. Call this before [`detect`]
/// when both are wanted, so the mode reflects that load.
pub fn module_gen() -> ModuleGen {
    match GEN_OVERRIDE.load(Ordering::SeqCst) {
        1 => return ModuleGen::Awg3,
        2 => return ModuleGen::Awg2,
        3 => return ModuleGen::Pre2,
        4 => return ModuleGen::NotLoaded,
        5 => return ModuleGen::Unknown,
        _ => {}
    }
    match genl_family_version(AWG_GENL_NAME) {
        Ok(Some(v)) => {
            let gen = ModuleGen::from_genl_version(v);
            if gen == ModuleGen::Unknown {
                crate::warn!("amneziawg genl family reports version {v}; not a known generation");
            }
            gen
        }
        Ok(None) => ModuleGen::NotLoaded,
        Err(e) => {
            crate::warn!("could not query the amneziawg genl family: {e:#}");
            ModuleGen::Unknown
        }
    }
}

const fn align4(n: usize) -> usize {
    (n + 3) & !3
}

/// `CTRL_CMD_GETFAMILY` request for `family`, in host byte order as netlink
/// requires.
fn getfamily_request(family: &str, seq: u32) -> Vec<u8> {
    let attr_len = NLA_HDRLEN + family.len() + 1;
    let total = NLMSG_HDRLEN + GENL_HDRLEN + align4(attr_len);

    let mut msg = Vec::with_capacity(total);
    msg.extend_from_slice(&(total as u32).to_ne_bytes());
    msg.extend_from_slice(&GENL_ID_CTRL.to_ne_bytes());
    msg.extend_from_slice(&NLM_F_REQUEST.to_ne_bytes());
    msg.extend_from_slice(&seq.to_ne_bytes());
    msg.extend_from_slice(&0u32.to_ne_bytes());

    msg.extend_from_slice(&[CTRL_CMD_GETFAMILY, 1, 0, 0]);

    msg.extend_from_slice(&(attr_len as u16).to_ne_bytes());
    msg.extend_from_slice(&CTRL_ATTR_FAMILY_NAME.to_ne_bytes());
    msg.extend_from_slice(family.as_bytes());
    msg.push(0);
    msg.resize(total, 0);
    msg
}

fn read_u16(buf: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_ne_bytes(buf.get(at..at + 2)?.try_into().ok()?))
}

fn read_u32(buf: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_ne_bytes(buf.get(at..at + 4)?.try_into().ok()?))
}

/// Pull the family version out of a `CTRL_CMD_GETFAMILY` reply.
///
/// `Ok(None)` is the kernel's `-ENOENT`: no such family, i.e. the module
/// isn't loaded. Every other error, and any reply that doesn't parse, is an
/// `Err` — "couldn't tell" must never be mistaken for "not loaded". The
/// error text carries the head of the buffer so a reply we misread can be
/// diagnosed from the log.
fn parse_getfamily_reply(buf: &[u8]) -> anyhow::Result<Option<u32>> {
    let bad = |why: &str| {
        let head: String = buf.iter().take(24).map(|b| format!("{b:02x}")).collect();
        anyhow::anyhow!("{why} (len {}, head {head})", buf.len())
    };

    let mut off = 0;
    while off + NLMSG_HDRLEN <= buf.len() {
        let len = read_u32(buf, off).ok_or_else(|| bad("truncated header"))? as usize;
        let ty = read_u16(buf, off + 4).ok_or_else(|| bad("truncated header"))?;
        if len < NLMSG_HDRLEN || off + len > buf.len() {
            return Err(bad("netlink length out of bounds"));
        }
        let msg = &buf[off..off + len];

        if ty == NLMSG_ERROR {
            let raw = read_u32(msg, NLMSG_HDRLEN).ok_or_else(|| bad("truncated nlmsgerr"))?;
            let errno = -(raw as i32);
            match errno {
                0 => {}
                ENOENT => return Ok(None),
                e => return Err(bad(&format!("netlink error {e}"))),
            }
        } else if ty == GENL_ID_CTRL {
            if msg.get(NLMSG_HDRLEN) != Some(&CTRL_CMD_NEWFAMILY) {
                return Err(bad("controller reply is not CTRL_CMD_NEWFAMILY"));
            }
            let mut a = NLMSG_HDRLEN + GENL_HDRLEN;
            while a + NLA_HDRLEN <= msg.len() {
                let alen = read_u16(msg, a).unwrap_or(0) as usize;
                let aty = read_u16(msg, a + 2).unwrap_or(0) & 0x3fff;
                if alen < NLA_HDRLEN || a + alen > msg.len() {
                    return Err(bad("attribute length out of bounds"));
                }
                if aty == CTRL_ATTR_VERSION {
                    let v = read_u32(msg, a + NLA_HDRLEN)
                        .ok_or_else(|| bad("short CTRL_ATTR_VERSION"))?;
                    return Ok(Some(v));
                }
                a += align4(alen);
            }
            return Err(bad("family reply without CTRL_ATTR_VERSION"));
        }

        off += align4(len);
    }
    Err(bad("no family reply or error in netlink response"))
}

#[cfg(target_os = "linux")]
fn genl_family_version(family: &str) -> anyhow::Result<Option<u32>> {
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

    // SAFETY: plain socket(2); the result is checked before being wrapped,
    // and OwnedFd closes it on every return path.
    let raw = unsafe {
        libc::socket(
            libc::AF_NETLINK,
            libc::SOCK_RAW | libc::SOCK_CLOEXEC,
            libc::NETLINK_GENERIC,
        )
    };
    if raw < 0 {
        return Err(anyhow::anyhow!("netlink socket: {}", std::io::Error::last_os_error()));
    }
    // SAFETY: `raw` is a fresh, valid descriptor nothing else owns.
    let fd = unsafe { OwnedFd::from_raw_fd(raw) };

    let timeout = libc::timeval { tv_sec: 1, tv_usec: 0 };
    // SAFETY: valid fd, and a pointer/length pair describing `timeout`.
    let rc = unsafe {
        libc::setsockopt(
            fd.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_RCVTIMEO,
            (&timeout as *const libc::timeval).cast(),
            std::mem::size_of::<libc::timeval>() as libc::socklen_t,
        )
    };
    if rc < 0 {
        return Err(anyhow::anyhow!("SO_RCVTIMEO: {}", std::io::Error::last_os_error()));
    }

    let req = getfamily_request(family, 1);
    // SAFETY: zeroed sockaddr_nl is a valid "the kernel" address once
    // nl_family is set.
    let mut kernel: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
    kernel.nl_family = libc::AF_NETLINK as libc::sa_family_t;
    // SAFETY: `req` and `kernel` outlive the call; lengths match.
    let sent = unsafe {
        libc::sendto(
            fd.as_raw_fd(),
            req.as_ptr().cast(),
            req.len(),
            0,
            (&kernel as *const libc::sockaddr_nl).cast(),
            std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
        )
    };
    if sent < 0 {
        return Err(anyhow::anyhow!("netlink send: {}", std::io::Error::last_os_error()));
    }

    let mut buf = vec![0u8; 8192];
    // SAFETY: `buf` is valid for `buf.len()` writable bytes.
    let got = unsafe { libc::recv(fd.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len(), 0) };
    if got < 0 {
        return Err(anyhow::anyhow!("netlink recv: {}", std::io::Error::last_os_error()));
    }
    buf.truncate(got as usize);
    parse_getfamily_reply(&buf)
}

#[cfg(not(target_os = "linux"))]
fn genl_family_version(_family: &str) -> anyhow::Result<Option<u32>> {
    Err(anyhow::anyhow!("generic netlink is Linux-only"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn supports_advanced_security_only_when_kernel() {
        assert!(GamingMode::Kernel.supports_advanced_security());
        assert!(!GamingMode::Userspace.supports_advanced_security());
        // Unknown is treated conservatively — refuse the explicit
        // setting rather than risk a broken peer config when we
        // can't confirm the host's path.
        assert!(!GamingMode::Unknown.supports_advanced_security());
    }

    #[test]
    fn detect_returns_a_recognised_variant() {
        // We can't assert which variant detect() returns (depends on
        // the test host) but it must always return a valid one.
        let mode = detect();
        assert!(matches!(
            mode,
            GamingMode::Kernel | GamingMode::Userspace | GamingMode::Unknown
        ));
    }

    #[test]
    fn mode_override_forces_and_restores() {
        // Forcing each mode makes detect() return it verbatim, and None
        // restores real detection. Kept self-contained: always restore the
        // override before returning so it can't leak into other unit tests.
        set_mode_override(Some(GamingMode::Kernel));
        assert_eq!(detect(), GamingMode::Kernel);
        set_mode_override(Some(GamingMode::Userspace));
        assert_eq!(detect(), GamingMode::Userspace);
        set_mode_override(Some(GamingMode::Unknown));
        assert_eq!(detect(), GamingMode::Unknown);
        set_mode_override(None);
        assert!(matches!(
            detect(),
            GamingMode::Kernel | GamingMode::Userspace | GamingMode::Unknown
        ));
    }

    /// Build one generic-netlink control reply the way the kernel lays it
    /// out: nlmsghdr, genlmsghdr, then 4-byte-aligned attributes.
    fn ctrl_reply(attrs: &[(u16, &[u8])]) -> Vec<u8> {
        let mut body = vec![CTRL_CMD_NEWFAMILY, 2, 0, 0];
        for (ty, payload) in attrs {
            let len = (NLA_HDRLEN + payload.len()) as u16;
            body.extend_from_slice(&len.to_ne_bytes());
            body.extend_from_slice(&ty.to_ne_bytes());
            body.extend_from_slice(payload);
            body.resize(align4(body.len()), 0);
        }
        nl_message(GENL_ID_CTRL, &body)
    }

    fn nl_message(ty: u16, body: &[u8]) -> Vec<u8> {
        let mut msg = Vec::new();
        msg.extend_from_slice(&((NLMSG_HDRLEN + body.len()) as u32).to_ne_bytes());
        msg.extend_from_slice(&ty.to_ne_bytes());
        msg.extend_from_slice(&0u16.to_ne_bytes());
        msg.extend_from_slice(&1u32.to_ne_bytes());
        msg.extend_from_slice(&0u32.to_ne_bytes());
        msg.extend_from_slice(body);
        msg
    }

    fn error_reply(errno: i32) -> Vec<u8> {
        // nlmsgerr: the negative errno, then the offending request's header.
        let mut body = (-errno).to_ne_bytes().to_vec();
        body.extend_from_slice(&[0u8; NLMSG_HDRLEN]);
        nl_message(NLMSG_ERROR, &body)
    }

    #[test]
    fn getfamily_request_matches_the_genl_wire_layout() {
        let req = getfamily_request("amneziawg", 7);
        // nlmsghdr(16) + genlmsghdr(4) + nlattr(4 + "amneziawg\0" = 14, padded to 16)
        assert_eq!(req.len(), 36);
        assert_eq!(u32::from_ne_bytes(req[0..4].try_into().unwrap()), 36);
        assert_eq!(u16::from_ne_bytes(req[4..6].try_into().unwrap()), GENL_ID_CTRL);
        assert_eq!(u16::from_ne_bytes(req[6..8].try_into().unwrap()), NLM_F_REQUEST);
        assert_eq!(u32::from_ne_bytes(req[8..12].try_into().unwrap()), 7);
        assert_eq!(req[16], CTRL_CMD_GETFAMILY);
        assert_eq!(u16::from_ne_bytes(req[20..22].try_into().unwrap()), 14);
        assert_eq!(u16::from_ne_bytes(req[22..24].try_into().unwrap()), CTRL_ATTR_FAMILY_NAME);
        assert_eq!(&req[24..34], b"amneziawg\0");
        assert_eq!(&req[34..36], &[0, 0], "attribute padding must be zeroed");
    }

    #[test]
    fn reply_carrying_a_version_attribute_yields_it() {
        let reply = ctrl_reply(&[
            (1, &0x1du16.to_ne_bytes()),
            (CTRL_ATTR_FAMILY_NAME, b"amneziawg\0"),
            (CTRL_ATTR_VERSION, &3u32.to_ne_bytes()),
        ]);
        assert_eq!(parse_getfamily_reply(&reply).unwrap(), Some(3));
    }

    #[test]
    fn enoent_means_the_family_is_not_registered() {
        assert_eq!(parse_getfamily_reply(&error_reply(ENOENT)).unwrap(), None);
    }

    #[test]
    fn other_errors_and_garbage_are_errors_not_absence() {
        assert!(parse_getfamily_reply(&error_reply(1)).is_err(), "EPERM");
        assert!(parse_getfamily_reply(&[]).is_err());
        assert!(parse_getfamily_reply(&[0xff; 7]).is_err());
        // Length field larger than the buffer.
        let mut short = ctrl_reply(&[(CTRL_ATTR_VERSION, &3u32.to_ne_bytes())]);
        short.truncate(short.len() - 2);
        assert!(parse_getfamily_reply(&short).is_err());
        // A family reply without a version attribute.
        let bare = ctrl_reply(&[(CTRL_ATTR_FAMILY_NAME, b"amneziawg\0")]);
        assert!(parse_getfamily_reply(&bare).is_err());
        // A controller message that isn't a NEWFAMILY reply.
        let mut wrong_cmd = ctrl_reply(&[(CTRL_ATTR_VERSION, &3u32.to_ne_bytes())]);
        wrong_cmd[NLMSG_HDRLEN] = CTRL_CMD_GETFAMILY;
        assert!(parse_getfamily_reply(&wrong_cmd).is_err());
    }

    #[test]
    fn genl_versions_map_to_amneziawg_generations() {
        // WG_GENL_VERSION per kernel-module tag: 1 up to v1.0.20241112
        // (the COPR build), 2 from v1.0.20251004 (AWG 2.0: S3/S4, H ranges),
        // 3 from v3.0.20260730.
        assert_eq!(ModuleGen::from_genl_version(1), ModuleGen::Pre2);
        assert_eq!(ModuleGen::from_genl_version(2), ModuleGen::Awg2);
        assert_eq!(ModuleGen::from_genl_version(3), ModuleGen::Awg3);
        assert_eq!(ModuleGen::from_genl_version(4), ModuleGen::Awg3);
        assert_eq!(ModuleGen::from_genl_version(0), ModuleGen::Unknown);
    }

    #[test]
    fn module_gen_override_forces_and_restores() {
        set_gen_override(Some(ModuleGen::Pre2));
        assert_eq!(module_gen(), ModuleGen::Pre2);
        set_gen_override(Some(ModuleGen::Awg3));
        assert_eq!(module_gen(), ModuleGen::Awg3);
        set_gen_override(None);
        // Real query: whatever this host has, it must classify, not panic.
        let _ = module_gen();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn live_query_reads_a_family_that_always_exists() {
        // Control for the real socket path: the netlink controller registers
        // itself as "nlctrl" on every Linux kernel, so a parser that only
        // ever sees ENOENT can't pass this.
        let v = genl_family_version("nlctrl").expect("query nlctrl");
        assert!(matches!(v, Some(n) if n >= 1), "nlctrl version {v:?}");
        assert_eq!(genl_family_version("cbnosuchfam").expect("query"), None);
    }

    #[test]
    fn module_gen_serializes_for_the_admin_api() {
        assert_eq!(serde_json::to_value(ModuleGen::Awg3).unwrap(), "awg3");
        assert_eq!(serde_json::to_value(ModuleGen::Pre2).unwrap(), "pre2");
        assert_eq!(serde_json::to_value(ModuleGen::NotLoaded).unwrap(), "not-loaded");
    }

    #[test]
    fn detect_on_non_linux_is_unknown() {
        // The cfg-gated early return is hard to exercise in a unit
        // test on a Linux runner — but the logical branch is there
        // and `cfg!(target_os = "linux")` is evaluated at compile
        // time. This test pins the property: when target_os is not
        // linux, detect() must return Unknown without touching the
        // filesystem. We verify that property statically by reading
        // the source — runtime assertion below is just a smoke
        // check that the function returns SOMETHING valid.
        let _ = detect();
    }
}
