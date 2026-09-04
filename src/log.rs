//! Structured logging: level filter, formatter, and the `error!`/`warn!`/
//! `info!`/`debug!`/`trace!` macros.
//!
//! Replaces `tracing` + `tracing-subscriber`, which between them pulled ten
//! crates (a regex engine among them, for `EnvFilter`) to do what this module
//! does in one file. The codebase never opened a span — every call site is a
//! flat event with a message and at most a handful of fields — so the whole
//! span/subscriber/registry machinery was dead weight.
//!
//! What is preserved exactly:
//!
//! * **Call-site syntax.** The macros accept `tracing`'s field grammar:
//!   `error = %e` (Display), `error = ?e` (Debug), `kind = expr`, and the
//!   `pid` / `%reason` / `?resp` shorthands, followed by a format string.
//! * **Output shape.** `<rfc3339> <LEVEL> <target>: <message> k=v k=v`, the
//!   same ordering `tracing_subscriber::fmt` produces.
//! * **`RUST_LOG` semantics.** A bare level (`debug`), per-target directives
//!   (`coffeeblack_vpn=debug,hyper=warn`), a bare target (trace for that target),
//!   `off`, and longest-prefix-wins resolution. Default is `info`.
//! * **`release_max_level_info`.** `debug!`/`trace!` compile out entirely in
//!   release builds — the proxy data path logs per packet, and an accidental
//!   `RUST_LOG=debug` in production must not be able to collapse throughput.
//! * **The `log` bridge.** `rustls` and friends emit through the `log` facade;
//!   [`init`] installs this logger there too, exactly as `tracing-log` did.

use std::io::Write;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{Mutex, OnceLock};

use time::macros::format_description;

/// Severity, ordered so that `level <= max` is "enabled".
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum Level {
    /// Nothing is logged at this level; only reachable as a filter setting.
    Off = 0,
    /// An operation failed in a way the operator must know about.
    Error = 1,
    /// Something is wrong but the process carried on.
    Warn = 2,
    /// Normal lifecycle milestones.
    Info = 3,
    /// Diagnostics for debugging; compiled out in release builds.
    Debug = 4,
    /// Per-packet / per-iteration detail; compiled out in release builds.
    Trace = 5,
}

impl Level {
    fn as_str(self) -> &'static str {
        match self {
            Level::Off => "OFF",
            Level::Error => "ERROR",
            Level::Warn => "WARN",
            Level::Info => "INFO",
            Level::Debug => "DEBUG",
            Level::Trace => "TRACE",
        }
    }

    fn parse(s: &str) -> Option<Level> {
        match s.trim().to_ascii_lowercase().as_str() {
            "off" => Some(Level::Off),
            "error" => Some(Level::Error),
            "warn" => Some(Level::Warn),
            "info" => Some(Level::Info),
            "debug" => Some(Level::Debug),
            "trace" => Some(Level::Trace),
            _ => None,
        }
    }

    /// ANSI colour for the level word, matching `tracing_subscriber::fmt`'s
    /// palette (red / yellow / green / blue / purple).
    fn colour(self) -> &'static str {
        match self {
            Level::Error => "\x1b[31m",
            Level::Warn => "\x1b[33m",
            Level::Info => "\x1b[32m",
            Level::Debug => "\x1b[34m",
            Level::Trace => "\x1b[35m",
            Level::Off => "",
        }
    }
}

/// One `RUST_LOG` directive: a module-path prefix and the maximum level
/// enabled beneath it.
#[derive(Debug, Clone)]
struct Directive {
    target: String,
    level: Level,
}

struct Filter {
    /// Level for targets no directive matches.
    default: Level,
    /// Sorted longest-target-first so the first match is the most specific.
    directives: Vec<Directive>,
}

static FILTER: OnceLock<Filter> = OnceLock::new();
/// Cheap pre-check: the highest level any directive can enable. Lets a
/// disabled call site skip the target walk entirely.
static MAX_LEVEL: AtomicU8 = AtomicU8::new(Level::Info as u8);
static ANSI: AtomicU8 = AtomicU8::new(0);

fn filter() -> &'static Filter {
    FILTER.get_or_init(|| parse_env_filter(None))
}

/// Parse a `RUST_LOG`-style filter string.
///
/// Unparsable directives are skipped with a note on stderr rather than
/// failing the process — `EnvFilter` behaves the same way, and a typo in a
/// debug variable must never stop a VPN server from booting.
fn parse_env_filter(spec: Option<&str>) -> Filter {
    let mut default = Level::Info;
    let mut directives: Vec<Directive> = Vec::new();

    if let Some(spec) = spec {
        for part in spec.split(',') {
            let part = part.trim();
            if part.is_empty() {
                continue;
            }
            match part.split_once('=') {
                // `target=level`
                Some((target, level)) => {
                    let target = target.trim();
                    match Level::parse(level) {
                        Some(level) if !target.is_empty() => directives.push(Directive {
                            target: target.to_string(),
                            level,
                        }),
                        _ => {
                            eprintln!("RUST_LOG: ignoring unparsable directive `{part}`");
                        }
                    }
                }
                // A bare word is a level if it names one, else a target at
                // TRACE — the `EnvFilter` rule.
                None => match Level::parse(part) {
                    Some(level) => default = level,
                    None => directives.push(Directive {
                        target: part.to_string(),
                        level: Level::Trace,
                    }),
                },
            }
        }
    }

    // Longest target first: `coffeeblack_vpn::proxy` must win over `coffeeblack_vpn`.
    directives.sort_by_key(|d| std::cmp::Reverse(d.target.len()));

    let max = directives
        .iter()
        .map(|d| d.level)
        .chain(std::iter::once(default))
        .max()
        .unwrap_or(Level::Info);
    MAX_LEVEL.store(max as u8, Ordering::Relaxed);

    Filter {
        default,
        directives,
    }
}

/// Whether a directive's target covers `target`: an exact match, or a module
/// prefix ending at a `::` boundary (so `hyper` matches `hyper::client` but
/// never `hyperactive`).
fn covers(directive_target: &str, target: &str) -> bool {
    target == directive_target
        || (target.len() > directive_target.len()
            && target.starts_with(directive_target)
            && target.as_bytes()[directive_target.len()..].starts_with(b"::"))
}

/// Whether an event at `level` from `target` passes the filter.
#[inline]
pub fn enabled(level: Level, target: &str) -> bool {
    if level as u8 > MAX_LEVEL.load(Ordering::Relaxed) {
        return false;
    }
    let f = filter();
    let effective = f
        .directives
        .iter()
        .find(|d| covers(&d.target, target))
        .map(|d| d.level)
        .unwrap_or(f.default);
    level != Level::Off && level <= effective
}

/// Serializes writes so two threads can't interleave halves of a line.
fn out_lock() -> &'static Mutex<()> {
    static LOCK: Mutex<()> = Mutex::new(());
    &LOCK
}

/// UTC timestamp in the shape `tracing_subscriber`'s default formatter uses.
fn timestamp() -> String {
    let fmt = format_description!(
        "[year]-[month]-[day]T[hour]:[minute]:[second].[subsecond digits:6]Z"
    );
    crate::datetime::now_utc().format(&fmt).unwrap_or_default()
}

/// Write one formatted event. Called by the macros; not meant for direct use.
pub fn emit(level: Level, target: &str, message: &str) {
    let ansi = ANSI.load(Ordering::Relaxed) == 1;
    let line = if ansi {
        format!(
            "{} {}{:>5}\x1b[0m \x1b[2m{}\x1b[0m: {}\n",
            timestamp(),
            level.colour(),
            level.as_str(),
            target,
            message
        )
    } else {
        format!(
            "{} {:>5} {}: {}\n",
            timestamp(),
            level.as_str(),
            target,
            message
        )
    };
    let _guard = out_lock().lock();
    // A failed write to stdout (closed pipe, full disk) must not panic a
    // running VPN server, and there is nowhere left to report it to.
    let mut stdout = std::io::stdout().lock();
    let _ = stdout.write_all(line.as_bytes());
    let _ = stdout.flush();
}

/// Install the logger: read `RUST_LOG`, decide on colour, and take over the
/// `log` facade so crates that use it (rustls, hyper) are visible too.
///
/// Idempotent, and safe to call from tests.
pub fn init() {
    let spec = std::env::var("RUST_LOG").ok();
    let _ = FILTER.set(parse_env_filter(spec.as_deref()));
    // Colour only for a real terminal — never when journald, Docker, or a
    // pipe is on the other end, where escape codes are just noise.
    // SAFETY: isatty takes a raw fd and only inspects it.
    let tty = unsafe { libc::isatty(libc::STDOUT_FILENO) } == 1;
    ANSI.store(u8::from(tty), Ordering::Relaxed);

    static LOGGER: LogBridge = LogBridge;
    let _ = log::set_logger(&LOGGER);
    log::set_max_level(match filter_max() {
        Level::Off => log::LevelFilter::Off,
        Level::Error => log::LevelFilter::Error,
        Level::Warn => log::LevelFilter::Warn,
        Level::Info => log::LevelFilter::Info,
        Level::Debug => log::LevelFilter::Debug,
        Level::Trace => log::LevelFilter::Trace,
    });
}

fn filter_max() -> Level {
    match MAX_LEVEL.load(Ordering::Relaxed) {
        0 => Level::Off,
        1 => Level::Error,
        2 => Level::Warn,
        3 => Level::Info,
        4 => Level::Debug,
        _ => Level::Trace,
    }
}

/// Adapter that funnels `log` records into [`emit`] — the job `tracing-log`
/// used to do.
struct LogBridge;

impl log::Log for LogBridge {
    fn enabled(&self, metadata: &log::Metadata<'_>) -> bool {
        enabled(from_log_level(metadata.level()), metadata.target())
    }

    fn log(&self, record: &log::Record<'_>) {
        let level = from_log_level(record.level());
        if enabled(level, record.target()) {
            emit(level, record.target(), &record.args().to_string());
        }
    }

    fn flush(&self) {}
}

fn from_log_level(l: log::Level) -> Level {
    match l {
        log::Level::Error => Level::Error,
        log::Level::Warn => Level::Warn,
        log::Level::Info => Level::Info,
        log::Level::Debug => Level::Debug,
        log::Level::Trace => Level::Trace,
    }
}

// ---------------------------------------------------------------------------
// Macros
// ---------------------------------------------------------------------------

/// Field-grammar muncher shared by every level macro.
///
/// Accumulates `tracing`'s field syntax into a `String` **after** the message,
/// which is the order `tracing_subscriber::fmt` prints them in. Each rule
/// consumes one field and recurses; the terminal rule is the format string.
#[doc(hidden)]
#[macro_export]
macro_rules! __log_fields {
    // `name = %expr` — record the value's Display form.
    ($msg:ident, $name:ident = %$val:expr, $($rest:tt)*) => {{
        $msg.push_str(&::std::format!(" {}={}", ::std::stringify!($name), $val));
        $crate::__log_fields!($msg, $($rest)*)
    }};
    // `name = ?expr` — record the value's Debug form.
    ($msg:ident, $name:ident = ?$val:expr, $($rest:tt)*) => {{
        $msg.push_str(&::std::format!(" {}={:?}", ::std::stringify!($name), $val));
        $crate::__log_fields!($msg, $($rest)*)
    }};
    // `name = expr`
    ($msg:ident, $name:ident = $val:expr, $($rest:tt)*) => {{
        $msg.push_str(&::std::format!(" {}={}", ::std::stringify!($name), $val));
        $crate::__log_fields!($msg, $($rest)*)
    }};
    // `%name` shorthand — Display of the variable, keyed by its own name.
    ($msg:ident, %$name:ident, $($rest:tt)*) => {{
        $msg.push_str(&::std::format!(" {}={}", ::std::stringify!($name), $name));
        $crate::__log_fields!($msg, $($rest)*)
    }};
    // `?name` shorthand — Debug of the variable.
    ($msg:ident, ?$name:ident, $($rest:tt)*) => {{
        $msg.push_str(&::std::format!(" {}={:?}", ::std::stringify!($name), $name));
        $crate::__log_fields!($msg, $($rest)*)
    }};
    // `name` shorthand — Display of the variable.
    ($msg:ident, $name:ident, $($rest:tt)*) => {{
        $msg.push_str(&::std::format!(" {}={}", ::std::stringify!($name), $name));
        $crate::__log_fields!($msg, $($rest)*)
    }};
    // Terminal: the message itself, which is always a format string.
    ($msg:ident, $fmt:literal $(, $arg:expr)* $(,)?) => {{
        $msg.insert_str(0, &::std::format!($fmt $(, $arg)*));
    }};
}

/// Emit an event at `$level` from `$target` if the filter admits it. The
/// message is built only when it will actually be printed.
#[doc(hidden)]
#[macro_export]
macro_rules! __log_event {
    ($level:expr, $target:expr, $($rest:tt)+) => {{
        let __level = $level;
        let __target: &str = $target;
        if $crate::log::enabled(__level, __target) {
            let mut __msg = ::std::string::String::new();
            $crate::__log_fields!(__msg, $($rest)+);
            $crate::log::emit(__level, __target, &__msg);
        }
    }};
}

/// Log an error.
///
/// `target: "name",` overrides the module path, matching `tracing`'s syntax —
/// the supervisors use it to file a child process's stdout under its own name.
#[macro_export]
macro_rules! error {
    (target: $target:expr, $($rest:tt)+) => {
        $crate::__log_event!($crate::log::Level::Error, $target, $($rest)+)
    };
    ($($rest:tt)+) => {
        $crate::__log_event!($crate::log::Level::Error, ::std::module_path!(), $($rest)+)
    };
}

/// Log a warning.
///
/// `target: "name",` overrides the module path, matching `tracing`'s syntax —
/// the supervisors use it to file a child process's stdout under its own name.
#[macro_export]
macro_rules! warn {
    (target: $target:expr, $($rest:tt)+) => {
        $crate::__log_event!($crate::log::Level::Warn, $target, $($rest)+)
    };
    ($($rest:tt)+) => {
        $crate::__log_event!($crate::log::Level::Warn, ::std::module_path!(), $($rest)+)
    };
}

/// Log an informational message.
///
/// `target: "name",` overrides the module path, matching `tracing`'s syntax —
/// the supervisors use it to file a child process's stdout under its own name.
#[macro_export]
macro_rules! info {
    (target: $target:expr, $($rest:tt)+) => {
        $crate::__log_event!($crate::log::Level::Info, $target, $($rest)+)
    };
    ($($rest:tt)+) => {
        $crate::__log_event!($crate::log::Level::Info, ::std::module_path!(), $($rest)+)
    };
}

/// Log a debug message. Compiled out entirely in release builds — see the
/// module docs on `release_max_level_info`.
#[macro_export]
macro_rules! debug {
    (target: $target:expr, $($rest:tt)+) => {{
        if ::std::cfg!(debug_assertions) {
            $crate::__log_event!($crate::log::Level::Debug, $target, $($rest)+)
        }
    }};
    ($($rest:tt)+) => {{
        if ::std::cfg!(debug_assertions) {
            $crate::__log_event!($crate::log::Level::Debug, ::std::module_path!(), $($rest)+)
        }
    }};
}

/// Log a trace message. Compiled out entirely in release builds.
#[macro_export]
macro_rules! trace {
    (target: $target:expr, $($rest:tt)+) => {{
        if ::std::cfg!(debug_assertions) {
            $crate::__log_event!($crate::log::Level::Trace, $target, $($rest)+)
        }
    }};
    ($($rest:tt)+) => {{
        if ::std::cfg!(debug_assertions) {
            $crate::__log_event!($crate::log::Level::Trace, ::std::module_path!(), $($rest)+)
        }
    }};
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn levels_order_from_off_to_trace() {
        assert!(Level::Error < Level::Warn);
        assert!(Level::Warn < Level::Info);
        assert!(Level::Info < Level::Debug);
        assert!(Level::Debug < Level::Trace);
        assert!(Level::Off < Level::Error);
    }

    #[test]
    fn parses_a_bare_level() {
        let f = parse_env_filter(Some("debug"));
        assert_eq!(f.default, Level::Debug);
        assert!(f.directives.is_empty());
    }

    #[test]
    fn parses_per_target_directives_most_specific_first() {
        let f = parse_env_filter(Some("warn,coffeeblack_vpn=info,coffeeblack_vpn::proxy=trace"));
        assert_eq!(f.default, Level::Warn);
        assert_eq!(f.directives[0].target, "coffeeblack_vpn::proxy");
        assert_eq!(f.directives[0].level, Level::Trace);
        assert_eq!(f.directives[1].target, "coffeeblack_vpn");
    }

    #[test]
    fn a_bare_unknown_word_is_a_target_at_trace() {
        let f = parse_env_filter(Some("hyper"));
        assert_eq!(f.default, Level::Info, "default is untouched");
        assert_eq!(f.directives[0].target, "hyper");
        assert_eq!(f.directives[0].level, Level::Trace);
    }

    #[test]
    fn unparsable_directives_are_skipped_not_fatal() {
        let f = parse_env_filter(Some("coffeeblack_vpn=nonsense,info"));
        assert_eq!(f.default, Level::Info);
        assert!(f.directives.is_empty());
    }

    #[test]
    fn target_matching_respects_module_boundaries() {
        assert!(covers("hyper", "hyper"));
        assert!(covers("hyper", "hyper::client::conn"));
        assert!(!covers("hyper", "hyperactive"));
        assert!(!covers("hyper::client", "hyper"));
    }

    /// `enabled` reads the process-wide filter, so drive the resolution logic
    /// directly rather than mutating global state under a test runner that
    /// shares it.
    fn resolve(f: &Filter, level: Level, target: &str) -> bool {
        let effective = f
            .directives
            .iter()
            .find(|d| covers(&d.target, target))
            .map(|d| d.level)
            .unwrap_or(f.default);
        level != Level::Off && level <= effective
    }

    #[test]
    fn resolution_prefers_the_longest_matching_target() {
        let f = parse_env_filter(Some("error,coffeeblack_vpn=info,coffeeblack_vpn::proxy=debug"));
        assert!(resolve(&f, Level::Debug, "coffeeblack_vpn::proxy::session"));
        assert!(!resolve(&f, Level::Debug, "coffeeblack_vpn::db"));
        assert!(resolve(&f, Level::Info, "coffeeblack_vpn::db"));
        assert!(!resolve(&f, Level::Info, "hyper::client"));
        assert!(resolve(&f, Level::Error, "hyper::client"));
    }

    #[test]
    fn off_disables_everything_for_that_target() {
        let f = parse_env_filter(Some("info,noisy=off"));
        assert!(!resolve(&f, Level::Error, "noisy::inner"));
        assert!(resolve(&f, Level::Info, "quiet"));
    }

    #[test]
    fn default_is_info_when_rust_log_is_absent() {
        let f = parse_env_filter(None);
        assert_eq!(f.default, Level::Info);
        assert!(resolve(&f, Level::Info, "anything"));
        assert!(!resolve(&f, Level::Debug, "anything"));
    }

    #[test]
    fn timestamp_is_rfc3339_utc_with_microseconds() {
        let t = timestamp();
        assert_eq!(t.len(), 27, "YYYY-MM-DDTHH:MM:SS.ffffffZ, got {t}");
        assert!(t.ends_with('Z'));
        assert_eq!(&t[4..5], "-");
        assert_eq!(&t[10..11], "T");
        assert_eq!(&t[19..20], ".");
    }

    #[test]
    fn field_macro_puts_the_message_first_then_fields() {
        let mut msg = String::new();
        let pid = 42;
        let err = std::io::Error::new(std::io::ErrorKind::NotFound, "gone");
        crate::__log_fields!(msg, pid, error = %err, kind = "tor", "child failed");
        assert_eq!(msg, "child failed pid=42 error=gone kind=tor");
    }

    #[test]
    fn field_macro_handles_debug_and_shorthands() {
        let mut msg = String::new();
        let reason = "shutdown";
        let count = 3u32;
        crate::__log_fields!(msg, %reason, ?count, "stopping {} child", count);
        assert_eq!(msg, "stopping 3 child reason=shutdown count=3");
    }

    #[test]
    fn field_macro_accepts_a_bare_message() {
        let mut msg = String::new();
        crate::__log_fields!(msg, "plain message");
        assert_eq!(msg, "plain message");
        let mut msg = String::new();
        crate::__log_fields!(msg, "interpolated {}", 7);
        assert_eq!(msg, "interpolated 7");
    }
}
