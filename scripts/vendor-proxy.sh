#!/usr/bin/env bash
#
# vendor-proxy.sh — (re)vendor the in-process DPI proxy from upstream.
#
# The modules under src/proxy/ (except mod.rs and supervisor.rs, which are
# awg-easy-rs's own glue) are a near-verbatim mirror of the `src/` tree of
# wiresock/amneziawg-install's `amneziawg-proxy` crate. The only mechanical
# change is rehoming the crate paths: `crate::` -> `crate::proxy::`.
#
# This script makes upgrading to a newer upstream a single reproducible
# command, and lets CI verify the vendored tree hasn't drifted or been
# hand-edited.
#
#   ./scripts/vendor-proxy.sh sync                 # re-vendor at the pinned ref
#   ./scripts/vendor-proxy.sh sync --ref <git-ref> # upgrade to a new ref/commit/tag
#   ./scripts/vendor-proxy.sh verify               # check working tree vs the lock (no network)
#   ./scripts/vendor-proxy.sh diff                 # show what a sync would change (no writes)
#
# `sync` needs `git` + network; `verify` is offline (sha256 only).
set -euo pipefail

# --- constants ---------------------------------------------------------------
UPSTREAM_REPO="https://github.com/wiresock/amneziawg-install"
UPSTREAM_SUBDIR="amneziawg-proxy/src"
UPSTREAM_CARGO="amneziawg-proxy/Cargo.toml"
TRANSFORM='s/crate::/crate::proxy::/g'
# The vendored modules (upstream `src/*.rs` minus the binary/lib roots
# main.rs + lib.rs, which we replace with our own mod.rs).
VENDORED=(backend config errors metrics proxy quic_handshake responder session transform)
# Our own hand-written files under src/proxy/ that must NEVER be overwritten.
OURS=(mod.rs supervisor.rs)

# --- locate repo root --------------------------------------------------------
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
ROOT="$(cd -- "$SCRIPT_DIR/.." && pwd)"
PROXY_DIR="$ROOT/src/proxy"
LOCK="$PROXY_DIR/VENDOR.lock"
PATCHES="$PROXY_DIR/patches"

c_red=$'\033[31m'; c_grn=$'\033[32m'; c_ylw=$'\033[33m'; c_dim=$'\033[2m'; c_rst=$'\033[0m'
info() { printf '%s==>%s %s\n' "$c_grn" "$c_rst" "$*"; }
warn() { printf '%swarn:%s %s\n' "$c_ylw" "$c_rst" "$*" >&2; }
die()  { printf '%serror:%s %s\n' "$c_red" "$c_rst" "$*" >&2; exit 1; }

sha() { sha256sum "$1" | cut -d' ' -f1; }

need() { command -v "$1" >/dev/null 2>&1 || die "'$1' is required for this command"; }

lock_get() { # key -> value from VENDOR.lock
  [ -f "$LOCK" ] || return 1
  sed -n "s/^$1=//p" "$LOCK" | head -n1
}

# --- verify (offline): current files vs the recorded sha256s -----------------
cmd_verify() {
  [ -f "$LOCK" ] || die "no $LOCK — run '$0 sync' first"
  local ref; ref="$(lock_get ref || true)"
  info "verifying src/proxy/ against VENDOR.lock (ref ${ref:-?})"
  local bad=0 f path want got
  for f in "${VENDORED[@]}"; do
    path="$PROXY_DIR/$f.rs"
    [ -f "$path" ] || { warn "missing vendored file: $f.rs"; bad=1; continue; }
    want="$(lock_get "$f.rs" || true)"
    got="$(sha "$path")"
    if [ "$want" != "$got" ]; then
      warn "sha mismatch: $f.rs (locked ${want:0:12}… != actual ${got:0:12}…)"
      bad=1
    fi
  done
  # Verify the local patches too (grep -F exact key match — patch names carry dots).
  if [ -d "$PATCHES" ] && ls "$PATCHES"/*.patch >/dev/null 2>&1; then
    for f in "$PATCHES"/*.patch; do
      want="$(grep -F "patch/$(basename "$f")=" "$LOCK" | head -n1 | sed 's/^[^=]*=//')"
      got="$(sha "$f")"
      if [ -z "$want" ]; then warn "patch not in lock: $(basename "$f")"; bad=1; continue; fi
      if [ "$want" != "$got" ]; then warn "sha mismatch: patch $(basename "$f")"; bad=1; fi
    done
  fi
  if [ "$bad" -ne 0 ]; then
    die "vendored proxy tree has drifted from VENDOR.lock (local edits, or a sync you didn't lock). Re-run '$0 sync' or revert the edit."
  fi
  info "${c_grn}OK${c_rst} — all ${#VENDORED[@]} vendored modules + local patches match the lock"
}

# --- fetch upstream into a temp dir, return the resolved commit --------------
_fetch() { # <ref> <destdir>  -> echoes resolved commit sha on fd 3
  local ref="$1" dest="$2"
  mkdir -p "$dest"
  git -C "$dest" init -q
  git -C "$dest" remote add origin "$UPSTREAM_REPO"
  git -C "$dest" fetch -q --depth 1 origin "$ref"
  git -C "$dest" checkout -q FETCH_HEAD
  git -C "$dest" rev-parse HEAD
}

# --- materialise the transformed tree into a staging dir ---------------------
_stage() { # <upstream_src_dir> <stage_dir>
  local src="$1" stage="$2" f up
  # Guard: upstream module set must still match what we vendor, else a new
  # module would be silently dropped (compile error) — surface it loudly.
  local upstream_mods; upstream_mods="$(cd "$src" && ls *.rs 2>/dev/null | sed 's/\.rs$//' | grep -Ev '^(main|lib)$' | sort | tr '\n' ' ')"
  local ours_sorted; ours_sorted="$(printf '%s\n' "${VENDORED[@]}" | sort | tr '\n' ' ')"
  if [ "$upstream_mods" != "$ours_sorted" ]; then
    warn "upstream module set changed!"
    warn "  upstream: $upstream_mods"
    warn "  vendored: $ours_sorted"
    warn "Update VENDORED=() in this script and declare the new module in src/proxy/mod.rs."
  fi
  for f in "${VENDORED[@]}"; do
    up="$src/$f.rs"
    [ -f "$up" ] || die "upstream is missing $f.rs — did the layout change?"
    sed "$TRANSFORM" "$up" > "$stage/$f.rs"
  done
  # Re-apply our local security patches on top of the pristine upstream mirror.
  # Kept OUT of the vendored files (upstream stays byte-diffable) and re-applied
  # on every sync so the hardening survives an upgrade. A failure here means
  # upstream changed a patched region — refresh the patch rather than dropping it.
  if [ -d "$PATCHES" ]; then
    local p
    for p in "$PATCHES"/*.patch; do
      [ -e "$p" ] || continue
      if ! patch -s -p0 -d "$stage" < "$p"; then
        die "failed to apply $(basename "$p") — upstream likely changed a patched region; refresh it (see src/proxy/patches/README)."
      fi
    done
  fi
}

# --- diff (no writes): show what a sync would change -------------------------
cmd_diff() {
  need git; need patch
  local ref; ref="${1:-$(lock_get ref || echo HEAD)}"
  local tmp; tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' RETURN
  info "fetching $UPSTREAM_REPO @ $ref"
  local commit; commit="$(_fetch "$ref" "$tmp/up")"
  mkdir -p "$tmp/stage"
  _stage "$tmp/up/$UPSTREAM_SUBDIR" "$tmp/stage"
  local f changed=0
  for f in "${VENDORED[@]}"; do
    if ! diff -q "$PROXY_DIR/$f.rs" "$tmp/stage/$f.rs" >/dev/null 2>&1; then
      printf '%s~ %s.rs%s\n' "$c_ylw" "$f" "$c_rst"
      diff -u "$PROXY_DIR/$f.rs" "$tmp/stage/$f.rs" | sed '1,2d' | head -n 40 | sed "s/^/  $c_dim/;s/$/$c_rst/" || true
      changed=1
    fi
  done
  [ "$changed" -eq 0 ] && info "no changes — working tree already matches $UPSTREAM_REPO@${commit:0:12}"
  info "(diff only; run 'sync --ref $ref' to apply)"
}

# --- sync: write the transformed tree + regenerate the lock ------------------
cmd_sync() {
  need git; need sed; need patch
  local ref; ref="${1:-$(lock_get ref || die "no ref: pass --ref <git-ref> the first time")}"
  local tmp; tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' RETURN
  info "fetching $UPSTREAM_REPO @ $ref"
  local commit; commit="$(_fetch "$ref" "$tmp/up")"
  info "resolved to commit ${commit}"
  mkdir -p "$tmp/stage"
  _stage "$tmp/up/$UPSTREAM_SUBDIR" "$tmp/stage"

  # Sanity: our hand-written files must exist and are never touched.
  local o
  for o in "${OURS[@]}"; do
    [ -f "$PROXY_DIR/$o" ] || warn "expected hand-written $PROXY_DIR/$o is missing"
  done

  local f
  for f in "${VENDORED[@]}"; do
    cp "$tmp/stage/$f.rs" "$PROXY_DIR/$f.rs"
  done

  local pver; pver="$(sed -n 's/^version *= *"\(.*\)"/\1/p' "$tmp/up/$UPSTREAM_CARGO" | head -n1)"

  # Regenerate the lock.
  {
    echo "# Auto-generated by scripts/vendor-proxy.sh — do not edit by hand."
    echo "# The files below are a mirror of $UPSTREAM_REPO:$UPSTREAM_SUBDIR"
    echo "# transformed with sed '$TRANSFORM', then the local patches in"
    echo "# src/proxy/patches/ applied. Regenerate via scripts/vendor-proxy.sh."
    echo "repo=$UPSTREAM_REPO"
    echo "ref=$commit"
    echo "requested_ref=$ref"
    echo "subdir=$UPSTREAM_SUBDIR"
    echo "transform=$TRANSFORM"
    echo "proxy_version=$pver"
    echo "# sha256 of each vendored file AS WRITTEN into src/proxy/ (post-transform, post-patch):"
    for f in "${VENDORED[@]}"; do
      echo "$f.rs=$(sha "$PROXY_DIR/$f.rs")"
    done
    if [ -d "$PATCHES" ] && ls "$PATCHES"/*.patch >/dev/null 2>&1; then
      echo "# sha256 of each local security patch (applied after the transform):"
      for p in "$PATCHES"/*.patch; do
        echo "patch/$(basename "$p")=$(sha "$p")"
      done
    fi
  } > "$LOCK"

  info "vendored ${#VENDORED[@]} modules at ${commit:0:12} (amneziawg-proxy v${pver:-?})"

  # Dependency drift check — we can't safely rewrite Cargo.toml, but the
  # maintainer must reconcile any dep change by hand.
  info "upstream [dependencies] (reconcile against awg-easy-rs Cargo.toml if changed):"
  sed -n '/^\[dependencies\]/,/^\[/p' "$tmp/up/$UPSTREAM_CARGO" | sed '1d;/^\[/d;/^\s*$/d' | sed "s/^/  $c_dim/;s/$/$c_rst/"

  cat <<EOF

${c_grn}Next steps${c_rst}
  1. Review the diff:            git diff -- src/proxy/
  2. Reconcile new deps (above) into Cargo.toml if any changed.
  3. Build + test:              cargo test
  4. Re-check lint:             cargo clippy --all-targets
  5. Commit src/proxy/ + VENDOR.lock together.
EOF
}

# --- dispatch ----------------------------------------------------------------
sub="${1:-verify}"; shift || true
ref_arg=""
while [ $# -gt 0 ]; do
  case "$1" in
    --ref) ref_arg="${2:-}"; shift 2 || die "--ref needs a value";;
    --ref=*) ref_arg="${1#--ref=}"; shift;;
    *) die "unknown argument: $1";;
  esac
done

case "$sub" in
  verify) cmd_verify;;
  sync)   cmd_sync "$ref_arg";;
  diff)   cmd_diff "$ref_arg";;
  -h|--help|help)
    grep -E '^#( |$)' "$0" | sed 's/^# \{0,1\}//' | sed '/^!/d'
    ;;
  *) die "unknown subcommand '$sub' (use: sync | verify | diff | help)";;
esac
