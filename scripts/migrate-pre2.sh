#!/usr/bin/env bash
#
# migrate-pre2.sh — in-place pre-2.0 → 2.0 migrator for an AmneziaWG server .conf
#
# AmneziaWG 2.0 added the S3/S4 shuffle parameters and turned the single-value
# H1–H4 header magics into "min-max" ranges. A server config written by a
# pre-2.0 installer is missing S3/S4 and carries scalar H1–H4; the 2.0 kernel
# module + tools expect the new form. This script migrates an existing on-disk
# server config in place:
#
#   * Generates S3/S4 in [15,150] satisfying the bidirectional protocol
#     constraint  S3 + 56 != S4  AND  S4 + 56 != S3.
#   * Converts each scalar H1–H4 to a "min-max" range and, if any pair overlaps
#     (or a value is missing/invalid), regenerates all four as non-overlapping
#     ranges.
#   * Backs up the target to <conf>.bak, writes atomically (temp file + rename),
#     preserves the original mode (600/400), and rolls back from the .bak on any
#     failure.
#
# It searches /etc/coffeeblack/conf and /etc/amnezia/amneziawg by default; override the
# target with --config PATH.
#
# Usage:
#   sudo ./migrate-pre2.sh                    # find + migrate (prompts)
#   sudo ./migrate-pre2.sh --config /etc/coffeeblack/conf/cb0.conf
#   sudo ./migrate-pre2.sh --force            # no prompt (also: AUTO_INSTALL=y)
#   sudo ./migrate-pre2.sh --dry-run          # report what would change, do nothing
#   ./migrate-pre2.sh --help
#
# NOTE: after migration, existing client configs are INCOMPATIBLE and must be
# regenerated (their S3/S4/H1–H4 no longer match the server).
#
# https://github.com/coffeegrind123/coffeeblack-vpn

set -euo pipefail

# ── Colours / logging ─────────────────────────────────────────────────────────

if [[ -t 1 ]]; then
	RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
	CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'
else
	RED=''; GREEN=''; YELLOW=''; CYAN=''; BOLD=''; NC=''
fi

info()  { printf "%b[+]%b %s\n" "${GREEN}" "${NC}" "$*"; }
warn()  { printf "%b[!]%b %s\n" "${YELLOW}" "${NC}" "$*"; }
error() { printf "%b[x]%b %s\n" "${RED}" "${NC}" "$*" >&2; }
die()   { error "$*"; exit 1; }
step()  { printf "\n%b%b==> %s%b\n" "${BOLD}" "${CYAN}" "$*" "${NC}"; }

# ── Config ─────────────────────────────────────────────────────────────────────

CONFIG_OVERRIDE=""
FORCE=false
DRY_RUN=false

readonly -a SEARCH_DIRS=("/etc/coffeeblack/conf" "/etc/amnezia/amneziawg")

# Range bounds (AmneziaWG protocol domains).
readonly S_MIN=15
readonly S_MAX=150
readonly H_MIN=5
readonly H_MAX=2147483647

usage() {
	cat <<EOF
migrate-pre2.sh — in-place pre-2.0 → 2.0 migrator for an AmneziaWG server .conf

Usage:
  sudo $0 [OPTIONS]

Options:
  --config PATH   Migrate this exact server .conf (skips auto-discovery).
  --force         Do not prompt for confirmation (also honoured via AUTO_INSTALL=y).
  --dry-run       Report what would change without modifying anything.
  -h, --help      Show this help and exit.

Without --config, the script scans:
$(printf '  %s\n' "${SEARCH_DIRS[@]}")
for AmneziaWG *server* configs (an [Interface] with ListenPort and S1/S2) that
still lack S3/S4 or carry scalar H1–H4, and offers to migrate each.
EOF
}

parse_args() {
	while [[ $# -gt 0 ]]; do
		case "$1" in
			-h|--help)  usage; exit 0 ;;
			--config)   CONFIG_OVERRIDE="${2:?--config requires a path}"; shift 2 ;;
			--force)    FORCE=true; shift ;;
			--dry-run)  DRY_RUN=true; shift ;;
			*) error "Unknown option: $1"; usage; exit 1 ;;
		esac
	done
	if [[ "${AUTO_INSTALL:-}" =~ ^[Yy]$ ]]; then
		FORCE=true
	fi
}

check_root() {
	[[ "${EUID}" -eq 0 ]] || die "This migrator must be run as root (use sudo)."
}

# ── Validation helpers (ported verbatim from amneziawg-install.sh) ────────────

# Parse "min-max" or a single value into the caller's MIN/MAX vars (by name).
# Validates format and min <= max only; callers enforce domain bounds.
parseRange() {
	local input="$1" min_var="$2" max_var="$3"
	[[ -n "${input}" ]] || return 1
	if [[ ${input} =~ ^([0-9]+)-([0-9]+)$ ]]; then
		local min=$((10#${BASH_REMATCH[1]}))
		local max=$((10#${BASH_REMATCH[2]}))
		(( min > max )) && return 1
		printf -v "${min_var}" '%s' "${min}"
		printf -v "${max_var}" '%s' "${max}"
	elif [[ ${input} =~ ^[0-9]+$ ]]; then
		local val=$((10#${input}))
		printf -v "${min_var}" '%s' "${val}"
		printf -v "${max_var}" '%s' "${val}"
	else
		return 1
	fi
	return 0
}

# Return 0 (true) when the two ranges overlap, 1 when fully separated.
# Boundary-sharing counts as overlap (max1 < min2 OR max2 < min1 → no overlap).
rangesOverlap() {
	local min1=$1 max1=$2 min2=$3 max2=$4
	if (( max1 < min2 )) || (( max2 < min1 )); then
		return 1
	fi
	return 0
}

# Validate min <= max and both within [lower, upper].
validateRange() {
	local min=$1 max=$2 lower=$3 upper=$4
	(( min > max )) && return 1
	{ (( min < lower )) || (( max > upper )); } && return 1
	return 0
}

# ── S3/S4 generation ──────────────────────────────────────────────────────────

RANDOM_AWG_S3=0
RANDOM_AWG_S4=0
generateS3AndS4() {
	RANDOM_AWG_S3=$(shuf -i"${S_MIN}-${S_MAX}" -n1)
	RANDOM_AWG_S4=$(shuf -i"${S_MIN}-${S_MAX}" -n1)
}

# Generate S3/S4 satisfying the bidirectional constraint (56 = WG handshake size).
generateValidS3S4() {
	generateS3AndS4
	while (( RANDOM_AWG_S3 + 56 == RANDOM_AWG_S4 )) || (( RANDOM_AWG_S4 + 56 == RANDOM_AWG_S3 )); do
		generateS3AndS4
	done
}

# ── H1–H4 range generation (segment-based, non-overlapping) ───────────────────

RANDOM_AWG_H1_MIN=0; RANDOM_AWG_H1_MAX=0
RANDOM_AWG_H2_MIN=0; RANDOM_AWG_H2_MAX=0
RANDOM_AWG_H3_MIN=0; RANDOM_AWG_H3_MAX=0
RANDOM_AWG_H4_MIN=0; RANDOM_AWG_H4_MAX=0

generateH1AndH2AndH3AndH4Ranges() {
	local RANGE_SIZE=100000000
	local MIN_VAL=${H_MIN}
	local MAX_VAL=${H_MAX}
	local GAP=1

	local RAW_AVAILABLE=$((MAX_VAL - MIN_VAL - GAP * 3))
	local AVAILABLE_RANGE=$((RAW_AVAILABLE - RAW_AVAILABLE % 4))
	local SEGMENT_SIZE=$((AVAILABLE_RANGE / 4))

	if (( SEGMENT_SIZE <= RANGE_SIZE )); then
		# Deterministic fallback (each range RANGE_SIZE wide, separated by GAP).
		RANDOM_AWG_H1_MIN=${MIN_VAL}
		RANDOM_AWG_H1_MAX=$((MIN_VAL + RANGE_SIZE - 1))
		RANDOM_AWG_H2_MIN=$((RANDOM_AWG_H1_MAX + GAP))
		RANDOM_AWG_H2_MAX=$((RANDOM_AWG_H2_MIN + RANGE_SIZE - 1))
		RANDOM_AWG_H3_MIN=$((RANDOM_AWG_H2_MAX + GAP))
		RANDOM_AWG_H3_MAX=$((RANDOM_AWG_H3_MIN + RANGE_SIZE - 1))
		RANDOM_AWG_H4_MIN=$((RANDOM_AWG_H3_MAX + GAP))
		RANDOM_AWG_H4_MAX=$((RANDOM_AWG_H4_MIN + RANGE_SIZE - 1))
		return
	fi

	local RANDOM_OFFSET_MAX=$((SEGMENT_SIZE - RANGE_SIZE))

	local H1_START=$((MIN_VAL + $(shuf -i0-${RANDOM_OFFSET_MAX} -n1)))
	RANDOM_AWG_H1_MIN=${H1_START}
	RANDOM_AWG_H1_MAX=$((H1_START + RANGE_SIZE - 1))

	local H2_START=$((MIN_VAL + SEGMENT_SIZE + GAP + $(shuf -i0-${RANDOM_OFFSET_MAX} -n1)))
	RANDOM_AWG_H2_MIN=${H2_START}
	RANDOM_AWG_H2_MAX=$((H2_START + RANGE_SIZE - 1))

	local H3_START=$((MIN_VAL + (SEGMENT_SIZE + GAP) * 2 + $(shuf -i0-${RANDOM_OFFSET_MAX} -n1)))
	RANDOM_AWG_H3_MIN=${H3_START}
	RANDOM_AWG_H3_MAX=$((H3_START + RANGE_SIZE - 1))

	local H4_SEGMENT_START=$((MIN_VAL + (SEGMENT_SIZE + GAP) * 3))
	local H4_SEGMENT_MAX_START=$((MAX_VAL - RANGE_SIZE + 1))
	if (( H4_SEGMENT_START > H4_SEGMENT_MAX_START )); then
		H4_SEGMENT_START=${H4_SEGMENT_MAX_START}
	fi
	local H4_RANDOM_OFFSET_MAX=$((MAX_VAL - H4_SEGMENT_START - RANGE_SIZE + 1))
	(( H4_RANDOM_OFFSET_MAX < 0 )) && H4_RANDOM_OFFSET_MAX=0
	local H4_START=$((H4_SEGMENT_START + $(shuf -i0-${H4_RANDOM_OFFSET_MAX} -n1)))
	RANDOM_AWG_H4_MIN=${H4_START}
	RANDOM_AWG_H4_MAX=$((H4_START + RANGE_SIZE - 1))

	# Safety net: if any pair overlaps, fall back to the deterministic layout.
	local overlap=0
	rangesOverlap "${RANDOM_AWG_H1_MIN}" "${RANDOM_AWG_H1_MAX}" "${RANDOM_AWG_H2_MIN}" "${RANDOM_AWG_H2_MAX}" && overlap=1
	rangesOverlap "${RANDOM_AWG_H1_MIN}" "${RANDOM_AWG_H1_MAX}" "${RANDOM_AWG_H3_MIN}" "${RANDOM_AWG_H3_MAX}" && overlap=1
	rangesOverlap "${RANDOM_AWG_H1_MIN}" "${RANDOM_AWG_H1_MAX}" "${RANDOM_AWG_H4_MIN}" "${RANDOM_AWG_H4_MAX}" && overlap=1
	rangesOverlap "${RANDOM_AWG_H2_MIN}" "${RANDOM_AWG_H2_MAX}" "${RANDOM_AWG_H3_MIN}" "${RANDOM_AWG_H3_MAX}" && overlap=1
	rangesOverlap "${RANDOM_AWG_H2_MIN}" "${RANDOM_AWG_H2_MAX}" "${RANDOM_AWG_H4_MIN}" "${RANDOM_AWG_H4_MAX}" && overlap=1
	rangesOverlap "${RANDOM_AWG_H3_MIN}" "${RANDOM_AWG_H3_MAX}" "${RANDOM_AWG_H4_MIN}" "${RANDOM_AWG_H4_MAX}" && overlap=1
	if (( overlap )); then
		RANDOM_AWG_H1_MIN=${MIN_VAL}
		RANDOM_AWG_H1_MAX=$((RANDOM_AWG_H1_MIN + RANGE_SIZE - 1))
		RANDOM_AWG_H2_MIN=$((RANDOM_AWG_H1_MAX + GAP))
		RANDOM_AWG_H2_MAX=$((RANDOM_AWG_H2_MIN + RANGE_SIZE - 1))
		RANDOM_AWG_H3_MIN=$((RANDOM_AWG_H2_MAX + GAP))
		RANDOM_AWG_H3_MAX=$((RANDOM_AWG_H3_MIN + RANGE_SIZE - 1))
		RANDOM_AWG_H4_MIN=$((RANDOM_AWG_H3_MAX + GAP))
		RANDOM_AWG_H4_MAX=$((RANDOM_AWG_H4_MIN + RANGE_SIZE - 1))
	fi
}

# Convert a scalar H value in VAR_NAME to "n-n" range form when needed.
# Return: 0 converted, 1 no change (already a valid range), 2 invalid.
convertHToRangeIfNeeded() {
	local var_name=$1
	local value=${!var_name}
	[[ -z "${value}" ]] && return 1
	if [[ "${value}" =~ ^[0-9]+-[0-9]+$ ]]; then
		local rmin rmax
		if parseRange "${value}" "rmin" "rmax" && validateRange "${rmin}" "${rmax}" "${H_MIN}" "${H_MAX}"; then
			return 1
		fi
		return 2
	fi
	if [[ "${value}" =~ ^[0-9]+$ ]]; then
		local num=$((10#${value}))
		if (( num >= H_MIN )) && (( num <= H_MAX )); then
			printf -v "${var_name}" '%s' "${num}-${num}"
			return 0
		fi
	fi
	return 2
}

# ── Config-file inspection ────────────────────────────────────────────────────

# Read "KEY = value" from a .conf ([Interface] scalars). Echoes the trimmed value.
confGet() {
	local file="$1" key="$2"
	grep -E "^[[:space:]]*${key}[[:space:]]*=" "${file}" 2>/dev/null \
		| head -n1 | sed -E "s/^[[:space:]]*${key}[[:space:]]*=[[:space:]]*//" \
		| sed -E 's/[[:space:]]+$//'
}

# Return 0 if the file looks like an AmneziaWG *server* config.
isServerConfig() {
	local file="$1"
	[[ -f "${file}" && -r "${file}" ]] || return 1
	grep -qE '^\[Interface\]' "${file}" || return 1
	grep -qE '^[[:space:]]*ListenPort[[:space:]]*=' "${file}" || return 1
	grep -qE '^[[:space:]]*PrivateKey[[:space:]]*=' "${file}" || return 1
	# Must carry the AWG obfuscation params (S1/S2 or Jc) to be an AWG server.
	grep -qE '^[[:space:]]*(S1|Jc)[[:space:]]*=' "${file}" || return 1
	return 0
}

# ── Migration decision ────────────────────────────────────────────────────────
# These globals hold the resolved-target values written back to the config.
NEW_S3=""; NEW_S4=""
NEW_H1=""; NEW_H2=""; NEW_H3=""; NEW_H4=""

# Decide S3/S4 for the given file. Echoes nothing; sets NEW_S3/NEW_S4. Returns
# 0 if a change is required, 1 if the existing values are already valid.
decideS3S4() {
	local file="$1"
	local s3 s4
	s3="$(confGet "${file}" S3)"
	s4="$(confGet "${file}" S4)"

	if [[ -n "${s3}" && -n "${s4}" ]] \
		&& [[ "${s3}" =~ ^[0-9]+$ && "${s4}" =~ ^[0-9]+$ ]] \
		&& (( s3 >= S_MIN )) && (( s3 <= S_MAX )) \
		&& (( s4 >= S_MIN )) && (( s4 <= S_MAX )) \
		&& (( s3 + 56 != s4 )) && (( s4 + 56 != s3 )); then
		NEW_S3="${s3}"; NEW_S4="${s4}"
		return 1
	fi

	generateValidS3S4
	NEW_S3="${RANDOM_AWG_S3}"; NEW_S4="${RANDOM_AWG_S4}"
	return 0
}

# Decide H1–H4 for the given file. Sets NEW_H1..NEW_H4. Returns 0 if change
# required, 1 if unchanged.
decideH1H4() {
	local file="$1"
	local SERVER_AWG_H1 SERVER_AWG_H2 SERVER_AWG_H3 SERVER_AWG_H4
	SERVER_AWG_H1="$(confGet "${file}" H1)"
	SERVER_AWG_H2="$(confGet "${file}" H2)"
	SERVER_AWG_H3="$(confGet "${file}" H3)"
	SERVER_AWG_H4="$(confGet "${file}" H4)"

	local converted=0 invalid=0 rc
	local h
	for h in SERVER_AWG_H1 SERVER_AWG_H2 SERVER_AWG_H3 SERVER_AWG_H4; do
		convertHToRangeIfNeeded "${h}" && rc=0 || rc=$?
		if [[ ${rc} -eq 0 ]]; then converted=1
		elif [[ ${rc} -eq 2 ]]; then invalid=1
		fi
	done

	if [[ -z "${SERVER_AWG_H1}" || -z "${SERVER_AWG_H2}" || -z "${SERVER_AWG_H3}" || -z "${SERVER_AWG_H4}" ]]; then
		invalid=1
	fi

	# Overlap check across the (possibly converted) ranges.
	if [[ ${invalid} -eq 0 ]]; then
		local h1min h1max h2min h2max h3min h3max h4min h4max
		if parseRange "${SERVER_AWG_H1}" h1min h1max \
			&& parseRange "${SERVER_AWG_H2}" h2min h2max \
			&& parseRange "${SERVER_AWG_H3}" h3min h3max \
			&& parseRange "${SERVER_AWG_H4}" h4min h4max; then
			if rangesOverlap "${h1min}" "${h1max}" "${h2min}" "${h2max}" \
				|| rangesOverlap "${h1min}" "${h1max}" "${h3min}" "${h3max}" \
				|| rangesOverlap "${h1min}" "${h1max}" "${h4min}" "${h4max}" \
				|| rangesOverlap "${h2min}" "${h2max}" "${h3min}" "${h3max}" \
				|| rangesOverlap "${h2min}" "${h2max}" "${h4min}" "${h4max}" \
				|| rangesOverlap "${h3min}" "${h3max}" "${h4min}" "${h4max}"; then
				invalid=1
			fi
		else
			invalid=1
		fi
	fi

	if [[ ${invalid} -eq 1 ]]; then
		generateH1AndH2AndH3AndH4Ranges
		SERVER_AWG_H1="${RANDOM_AWG_H1_MIN}-${RANDOM_AWG_H1_MAX}"
		SERVER_AWG_H2="${RANDOM_AWG_H2_MIN}-${RANDOM_AWG_H2_MAX}"
		SERVER_AWG_H3="${RANDOM_AWG_H3_MIN}-${RANDOM_AWG_H3_MAX}"
		SERVER_AWG_H4="${RANDOM_AWG_H4_MIN}-${RANDOM_AWG_H4_MAX}"
		converted=1
	fi

	NEW_H1="${SERVER_AWG_H1}"; NEW_H2="${SERVER_AWG_H2}"
	NEW_H3="${SERVER_AWG_H3}"; NEW_H4="${SERVER_AWG_H4}"

	[[ ${converted} -eq 1 ]] && return 0
	return 1
}

# ── Config rewrite (atomic, on a working copy) ────────────────────────────────

# Insert-or-update "KEY = value" in the given working-copy file. When missing,
# insert after the first present anchor from the space-separated $3 list.
# Returns non-zero on failure.
upsertParam() {
	local file="$1" key="$2" value="$3"; shift 3
	local anchors=("$@")
	if grep -qE "^[[:space:]]*${key}[[:space:]]*=" "${file}"; then
		sed -i -E "s|^[[:space:]]*${key}[[:space:]]*=.*|${key} = ${value}|" "${file}" || return 1
		return 0
	fi
	local anchor
	for anchor in "${anchors[@]}"; do
		if grep -qE "^[[:space:]]*${anchor}[[:space:]]*=" "${file}"; then
			sed -i -E "/^[[:space:]]*${anchor}[[:space:]]*=.*/a ${key} = ${value}" "${file}" || return 1
			grep -qE "^[[:space:]]*${key}[[:space:]]*=" "${file}" || return 1
			return 0
		fi
	done
	return 1
}

# ── Per-file migration ────────────────────────────────────────────────────────

# migrate_one CONF — inspect, and if migration is needed, back up and rewrite.
# Returns 0 on success (migrated or already-current), non-zero on error.
migrate_one() {
	local conf="$1"

	if [[ -L "${conf}" ]]; then
		warn "Refusing to migrate a symlink: ${conf}"
		return 1
	fi
	isServerConfig "${conf}" || { warn "Not an AmneziaWG server config, skipping: ${conf}"; return 0; }

	step "Inspecting ${conf}"

	# decideS3S4 / decideH1H4 return 0 when a change is required, 1 when the
	# existing values are already valid 2.0 form.
	local s3_changed=0 h_changed=0
	if decideS3S4 "${conf}"; then s3_changed=1; fi
	if decideH1H4 "${conf}"; then h_changed=1; fi

	if [[ ${s3_changed} -eq 0 && ${h_changed} -eq 0 ]]; then
		info "Already in AmneziaWG 2.0 format; no migration needed."
		return 0
	fi

	printf "  %bPlanned changes:%b\n" "${BOLD}" "${NC}"
	[[ ${s3_changed} -eq 1 ]] && printf "    S3 = %s\n    S4 = %s\n" "${NEW_S3}" "${NEW_S4}"
	if [[ ${h_changed} -eq 1 ]]; then
		printf "    H1 = %s\n    H2 = %s\n    H3 = %s\n    H4 = %s\n" \
			"${NEW_H1}" "${NEW_H2}" "${NEW_H3}" "${NEW_H4}"
	fi

	if [[ "${DRY_RUN}" == "true" ]]; then
		warn "--dry-run: no changes written to ${conf}."
		return 0
	fi

	printf "\n"
	warn "After migration, EXISTING CLIENT CONFIGS WILL BE INCOMPATIBLE and must be regenerated."
	if [[ "${FORCE}" != "true" ]]; then
		local resp
		read -rp "Migrate ${conf} to AmneziaWG 2.0? [y/N]: " resp
		case "${resp}" in
			[Yy]) ;;
			*) info "Skipped ${conf}."; return 0 ;;
		esac
	else
		info "--force / AUTO_INSTALL: auto-confirming migration of ${conf}."
	fi

	# Capture original mode (preserve 400 vs 600; default 600 otherwise).
	local orig_mode
	if orig_mode="$(stat -c '%a' "${conf}" 2>/dev/null)"; then
		[[ "${orig_mode}" == "400" ]] || orig_mode="600"
	else
		orig_mode="600"
	fi

	# Backup.
	local bak="${conf}.bak"
	if ! cp -p "${conf}" "${bak}"; then
		die "Failed to create backup ${bak}. Aborting; ${conf} left untouched."
	fi
	info "Backed up to ${bak}"

	# Work on a temp copy in the same directory (atomic rename target).
	local dir tmp
	dir="$(dirname "${conf}")"
	if ! tmp="$(mktemp "${dir}/.cbmig.XXXXXX")"; then
		rm -f "${bak}"
		die "Failed to create temp file in ${dir}."
	fi
	# Ensure temp is cleaned up if we bail before the rename.
	trap 'rm -f "${tmp}" 2>/dev/null || true' RETURN

	if ! cp "${conf}" "${tmp}"; then
		rollback "${conf}" "${bak}" "temp copy failed"
		return 1
	fi

	# Apply S3/S4 (S3 after S2; S4 after S3 or S2).
	if [[ ${s3_changed} -eq 1 ]]; then
		upsertParam "${tmp}" S3 "${NEW_S3}" S2 || { rollback "${conf}" "${bak}" "failed to set S3"; return 1; }
		upsertParam "${tmp}" S4 "${NEW_S4}" S3 S2 || { rollback "${conf}" "${bak}" "failed to set S4"; return 1; }
	fi

	# Apply H1–H4 (insert after S4/S3/S2 in reverse so final order is H1..H4).
	if [[ ${h_changed} -eq 1 ]]; then
		upsertParam "${tmp}" H4 "${NEW_H4}" S4 S3 S2 || { rollback "${conf}" "${bak}" "failed to set H4"; return 1; }
		upsertParam "${tmp}" H3 "${NEW_H3}" S4 S3 S2 || { rollback "${conf}" "${bak}" "failed to set H3"; return 1; }
		upsertParam "${tmp}" H2 "${NEW_H2}" S4 S3 S2 || { rollback "${conf}" "${bak}" "failed to set H2"; return 1; }
		upsertParam "${tmp}" H1 "${NEW_H1}" S4 S3 S2 || { rollback "${conf}" "${bak}" "failed to set H1"; return 1; }
	fi

	# Preserve ownership from the original, set the intended mode, then atomically
	# move into place.
	chown --reference="${conf}" "${tmp}" 2>/dev/null || true
	chmod "${orig_mode}" "${tmp}" 2>/dev/null || true

	if ! mv -f "${tmp}" "${conf}"; then
		rollback "${conf}" "${bak}" "atomic rename failed"
		return 1
	fi
	trap - RETURN  # temp consumed by mv

	# Success — drop the backup.
	rm -f "${bak}"
	info "Migrated ${conf} to AmneziaWG 2.0 (mode ${orig_mode})."
	warn "Regenerate all client configs so they match the new server parameters."
	return 0
}

# rollback CONF BAK MESSAGE — restore the config from its backup and report.
rollback() {
	local conf="$1" bak="$2" msg="$3"
	error "Migration failed: ${msg}"
	info "Restoring ${conf} from ${bak}..."
	if cp -p "${bak}" "${conf}" 2>/dev/null; then
		rm -f "${bak}"
		info "Restored original ${conf}. No changes were applied."
	else
		error "Could not restore automatically. Your backup is preserved at ${bak}."
	fi
}

# ── Discovery ──────────────────────────────────────────────────────────────────

discover_configs() {
	local -a found=()
	local dir f
	for dir in "${SEARCH_DIRS[@]}"; do
		[[ -d "${dir}" ]] || continue
		# -xdev: stay on one filesystem; bounded depth.
		while IFS= read -r -d '' f; do
			isServerConfig "${f}" && found+=("${f}")
		done < <(find "${dir}" -xdev -maxdepth 2 -type f -name '*.conf' -print0 2>/dev/null)
	done
	printf '%s\n' "${found[@]}"
}

# ── Main ──────────────────────────────────────────────────────────────────────

main() {
	parse_args "$@"
	check_root

	command -v shuf >/dev/null 2>&1 || die "'shuf' (coreutils) is required but not found."

	if [[ -n "${CONFIG_OVERRIDE}" ]]; then
		[[ -f "${CONFIG_OVERRIDE}" ]] || die "Config not found: ${CONFIG_OVERRIDE}"
		migrate_one "${CONFIG_OVERRIDE}"
		return
	fi

	step "Searching for AmneziaWG server configs"
	local -a configs=()
	mapfile -t configs < <(discover_configs)

	if [[ "${#configs[@]}" -eq 0 ]]; then
		die "No AmneziaWG server configs found under: ${SEARCH_DIRS[*]}. Use --config PATH to target one explicitly."
	fi

	info "Found ${#configs[@]} candidate config(s):"
	printf '    %s\n' "${configs[@]}"

	local conf rc=0
	for conf in "${configs[@]}"; do
		migrate_one "${conf}" || rc=1
	done

	if [[ ${rc} -eq 0 ]]; then
		step "Done"
		info "All targeted configs are at AmneziaWG 2.0. Regenerate client configs and restart the service:"
		info "  sudo systemctl restart coffeeblack-vpn"
	fi
	return "${rc}"
}

main "$@"
