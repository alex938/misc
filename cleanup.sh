#!/usr/bin/env bash
#
# cleanup.sh — VM & Docker housekeeping
# https://github.com/alex938/misc
#
# Usage: sudo ./cleanup.sh [OPTIONS]
#   curl -fsSL https://raw.githubusercontent.com/alex938/misc/main/cleanup.sh \
#     | sudo bash -s -- --docker-images-all
#
# Safe by default: this reclaims caches and rebuildable data. Anything that can
# destroy data you cannot regenerate (named Docker volumes) is opt-in and needs
# an explicit confirmation.

set -euo pipefail

VERSION="2.0.0"

if [[ -z ${BASH_VERSINFO[0]:-} ]] || (( BASH_VERSINFO[0] * 100 + BASH_VERSINFO[1] < 403 )); then
  echo "cleanup.sh requires bash 4.3 or newer (found ${BASH_VERSION:-unknown})" >&2
  exit 1
fi

# ── Defaults ─────────────────────────────────────────────────────────────────
DOCKER_IMAGES_ALL=false   # remove ALL unused images, not just dangling ones
DOCKER_VOLUMES=false      # remove unused *named* volumes — destroys data
DRY_RUN=false
ASSUME_YES=false
JOURNAL_KEEP="14d"
TMP_AGE_DAYS=7
LOG_AGE_DAYS=30
LOG_FILE=""

LOCK_FILE="/var/lock/cleanup.sh.lock"

usage() {
  cat <<EOF
cleanup.sh ${VERSION} — VM & Docker housekeeping

Usage: sudo $0 [OPTIONS]

Options:
  --dry-run              Show what would be removed, change nothing
  --docker-images-all    Remove all unused images, not just dangling ones
  --docker-volumes       Remove unused named volumes (DESTROYS DATA)
  --journal-keep=AGE     Journal retention, e.g. 14d, 4w (default: ${JOURNAL_KEEP})
  --tmp-age=DAYS         Age threshold for /tmp entries (default: ${TMP_AGE_DAYS})
  --log-age=DAYS         Age threshold for rotated logs (default: ${LOG_AGE_DAYS})
  --log=FILE             Append a timestamped transcript to FILE
  -y, --yes              Do not prompt for confirmation
  -V, --version          Print version and exit
  -h, --help             Show this help and exit

Exit status: 0 on success, 1 if any cleanup step failed, 2 on usage error.
EOF
}

die() { printf 'cleanup.sh: %s\n' "$1" >&2; exit "${2:-1}"; }

# ── Argument parsing ─────────────────────────────────────────────────────────
while (( $# )); do
  case $1 in
    --docker-images-all) DOCKER_IMAGES_ALL=true ;;
    --docker-volumes)    DOCKER_VOLUMES=true ;;
    --dry-run|-n)        DRY_RUN=true ;;
    -y|--yes)            ASSUME_YES=true ;;
    --journal-keep=*)    JOURNAL_KEEP="${1#*=}" ;;
    --tmp-age=*)         TMP_AGE_DAYS="${1#*=}" ;;
    --log-age=*)         LOG_AGE_DAYS="${1#*=}" ;;
    --log=*)             LOG_FILE="${1#*=}" ;;
    -V|--version)        printf 'cleanup.sh %s\n' "$VERSION"; exit 0 ;;
    -h|--help)           usage; exit 0 ;;
    --)                  shift; break ;;
    *)                   usage >&2; die "unknown option: $1" 2 ;;
  esac
  shift
done
(( $# == 0 )) || die "unexpected argument: $1" 2

# Validate, so a typo can never be read as "delete everything".
[[ $JOURNAL_KEEP =~ ^[0-9]+(s|min|m|h|d|w|M|y)?$ ]] \
  || die "--journal-keep must look like 14d, 4w, 6M (got: ${JOURNAL_KEEP})" 2
[[ $TMP_AGE_DAYS =~ ^[0-9]+$ ]] || die "--tmp-age must be a whole number of days" 2
[[ $LOG_AGE_DAYS =~ ^[0-9]+$ ]] || die "--log-age must be a whole number of days" 2

# ── Output helpers ───────────────────────────────────────────────────────────
if [[ -t 1 && -z ${NO_COLOR:-} && ${TERM:-dumb} != dumb ]]; then
  RED=$'\033[0;31m'; YELLOW=$'\033[1;33m'; GREEN=$'\033[0;32m'
  CYAN=$'\033[0;36m'; BOLD=$'\033[1m'; RESET=$'\033[0m'
else
  RED=''; YELLOW=''; GREEN=''; CYAN=''; BOLD=''; RESET=''
fi

CURRENT_SECTION="startup"
declare -a FAILURES=()

# out <pretty> [plain] — colour to the terminal, plain text to the log file.
out() {
  printf '%s\n' "$1"
  if [[ -n $LOG_FILE ]]; then
    printf '%s %s\n' "$(date -Is)" "${2-$1}" >>"$LOG_FILE" || true
  fi
}

header() { CURRENT_SECTION="$*"; out "" ""; out "${BOLD}${CYAN}==> $*${RESET}" "==> $*"; }
info()   { out "    ${YELLOW}$*${RESET}" "    $*"; }
ok()     { out "    ${GREEN}✓ $*${RESET}" "    OK: $*"; }
warn()   { out "    ${RED}✗ $*${RESET}" "    FAIL: $*"; }
note()   { out "    $*" "    $*"; }

fail() {
  FAILURES+=("${CURRENT_SECTION}: $1")
  warn "$1"
}

# Render a command the way you would have to retype it.
quote_cmd() {
  local part out=""
  for part in "$@"; do out+="${out:+ }$(printf '%q' "$part")"; done
  printf '%s' "$out"
}

# run_cmd <cmd...> — run a step, capture output, record failure, keep going.
run_cmd() {
  local pretty; pretty=$(quote_cmd "$@")
  if $DRY_RUN; then
    out "    ${YELLOW}[dry-run]${RESET} ${pretty}" "    [dry-run] ${pretty}"
    return 0
  fi
  local output rc=0
  output=$("$@" 2>&1) || rc=$?
  if [[ -n $LOG_FILE && -n $output ]]; then
    printf '%s\n' "$output" >>"$LOG_FILE" || true
  fi
  if (( rc != 0 )); then
    fail "exit ${rc}: ${pretty}"
    [[ -n $output ]] && out "        ${output//$'\n'/$'\n'        }" ""
    return 0
  fi
  return 0
}

# safe_rm <path...> — delete via xargs so a long candidate list can't blow ARG_MAX.
safe_rm() {
  (( $# )) || return 0
  local rc=0
  printf '%s\0' "$@" | xargs -0 --no-run-if-empty rm -rf -- || rc=$?
  (( rc == 0 )) || fail "rm failed (exit ${rc})"
  return 0
}

# Human-readable size from a kilobyte count.
hr_kb() {
  awk -v k="${1:-0}" 'BEGIN {
    split("KB MB GB TB PB", u, " "); i = 1
    if (k < 0) { printf "-"; k = -k }
    while (k >= 1024 && i < 5) { k /= 1024; i++ }
    printf "%.1f%s", k, u[i]
  }'
}

du_kb() {
  (( $# )) || { printf '0'; return 0; }
  printf '%s\0' "$@" | xargs -0 --no-run-if-empty du -sk 2>/dev/null \
    | awk '{ total += $1 } END { printf "%d", total + 0 }'
}

# ── Preconditions ────────────────────────────────────────────────────────────
# A dry run only reads, so it does not need root — that makes it usable for
# checking what a real run would do before committing to sudo.
if [[ $EUID -ne 0 ]]; then
  if $DRY_RUN; then
    info "Not running as root — some paths will be unreadable and under-reported."
  else
    die "must run as root (try: sudo $0 $*)"
  fi
fi

if $DOCKER_VOLUMES && ! $DRY_RUN && ! $ASSUME_YES; then
  if [[ -t 0 ]]; then
    printf '%s' "${RED}--docker-volumes deletes unused NAMED volumes (database data lives there). Continue? [y/N] ${RESET}"
    read -r reply
    [[ $reply =~ ^[Yy]$ ]] || die "aborted"
  else
    die "--docker-volumes destroys named volume data and there is no terminal to confirm on; re-run with --yes if you mean it" 2
  fi
fi

if [[ -n $LOG_FILE ]]; then
  : >>"$LOG_FILE" || die "cannot write log file: ${LOG_FILE}"
fi

# ── Single-instance lock ─────────────────────────────────────────────────────
# Two concurrent runs would race each other's finds and produce nonsense totals.
if command -v flock >/dev/null 2>&1 && [[ $EUID -eq 0 ]]; then
  exec 9>"$LOCK_FILE" || die "cannot open lock file: ${LOCK_FILE}"
  flock -n 9 || die "another cleanup.sh is already running (lock: ${LOCK_FILE})"
fi

trap 'rc=$?; (( rc )) && printf "\n%scleanup.sh aborted at line %s (exit %s)%s\n" "$RED" "$LINENO" "$rc" "$RESET" >&2; exit $rc' ERR
trap 'printf "\n%sInterrupted — stopping.%s\n" "$YELLOW" "$RESET" >&2; exit 130' INT TERM

# ── Disk accounting ──────────────────────────────────────────────────────────
# Only local filesystems: NFS/CIFS usage moves for reasons that have nothing to
# do with us, and would make "freed" meaningless.
declare -A DISK_BEFORE=() DISK_AFTER=()

snapshot_disk() {
  local -n _snap=$1
  local _fs _type _blocks used _avail _pct target
  _snap=()
  while read -r _fs _type _blocks used _avail _pct target; do
    [[ $target == /* ]] || continue
    _snap["$target"]=$used
  done < <(df -klPT -x tmpfs -x devtmpfs -x squashfs -x overlay 2>/dev/null | tail -n +2)
}

snapshot_disk DISK_BEFORE

out "${BOLD}╔══════════════════════════════════════╗${RESET}" "cleanup.sh ${VERSION}"
out "${BOLD}║        VM Cleanup Script             ║${RESET}" ""
out "${BOLD}╚══════════════════════════════════════╝${RESET}" ""
# Written as `if` rather than `$DRY_RUN && ...`: an and-list whose left side is
# false yields exit status 1, which is a live grenade under `set -e`.
if $DRY_RUN; then out "  ${YELLOW}-- DRY RUN MODE (no changes) --${RESET}" "-- DRY RUN --"; fi
for mount in "${!DISK_BEFORE[@]}"; do
  out "  ${mount}: ${BOLD}$(hr_kb "${DISK_BEFORE[$mount]}")${RESET} used" "  ${mount}: $(hr_kb "${DISK_BEFORE[$mount]}") used"
done

# ── 1. Docker ────────────────────────────────────────────────────────────────
if command -v docker >/dev/null 2>&1; then
  header "Docker"
  if docker info >/dev/null 2>&1; then
    info "Stopped containers"
    run_cmd docker container prune -f

    info "Dangling images"
    run_cmd docker image prune -f

    if $DOCKER_IMAGES_ALL; then
      info "All unused images (--docker-images-all)"
      run_cmd docker image prune -af
    fi

    info "Build cache"
    run_cmd docker builder prune -af

    if $DOCKER_VOLUMES; then
      info "Unused named volumes (--docker-volumes)"
      run_cmd docker volume prune -af
    else
      note "Unused volumes: skipped (pass --docker-volumes; this deletes real data)"
    fi

    info "Unused networks"
    run_cmd docker network prune -f

    ok "Docker done"
  else
    note "Docker CLI present but the daemon is not responding — skipping"
  fi
fi

# ── 2. APT ───────────────────────────────────────────────────────────────────
if command -v apt-get >/dev/null 2>&1; then
  header "APT"
  export DEBIAN_FRONTEND=noninteractive

  info "Package cache (apt-get clean)"
  run_cmd apt-get clean

  info "Orphaned packages and old kernels (autoremove --purge)"
  run_cmd apt-get autoremove --purge -y

  info "Superseded .debs (autoclean)"
  run_cmd apt-get autoclean -y

  ok "APT done"
fi

# ── 3. Journal logs ──────────────────────────────────────────────────────────
if command -v journalctl >/dev/null 2>&1; then
  header "systemd journal (keeping last ${JOURNAL_KEEP})"
  run_cmd journalctl --vacuum-time="${JOURNAL_KEEP}"
  ok "Journal done"
fi

# ── 4. Temporary directories ─────────────────────────────────────────────────
# An entry is stale only when nothing inside it has changed for TMP_AGE_DAYS.
# The old -atime test was unreliable (relatime/noatime mounts barely update it)
# and judged directories by their own timestamp, so a long-lived directory full
# of live files looked disposable. Sockets and runtime dirs belonging to logins,
# X11, systemd and snap are never candidates: removing them breaks running
# services.
clean_tmpdir() {
  local dir=$1 days=$2
  [[ -d $dir ]] || return 0

  local -a keep=(
    -name '.X11-unix'   -o -name '.XIM-unix'  -o -name '.ICE-unix'
    -o -name '.font-unix' -o -name '.Test-unix' -o -name '.X*-lock'
    -o -name 'systemd-private-*' -o -name 'snap-private-tmp'
    -o -name 'snap.*'   -o -name '.snap*'     -o -name '.mount_*'
    -o -name 'ssh-*'    -o -name 'gpg-*'      -o -name 'dbus-*'
    -o -name 'pulse-*'  -o -name 'tmux-*'     -o -name '.font-cache*'
  )

  local -a candidates=() entry
  while IFS= read -r -d '' entry; do
    # Nothing modified inside the last N days? Then it is genuinely idle.
    if [[ -z $(find "$entry" -xdev -newermt "-${days} days" -print -quit 2>/dev/null) ]]; then
      candidates+=("$entry")
    fi
  done < <(find "$dir" -xdev -mindepth 1 -maxdepth 1 ! \( "${keep[@]}" \) -print0 2>/dev/null)

  if (( ${#candidates[@]} == 0 )); then
    note "${dir}: nothing older than ${days} days"
    return 0
  fi

  local size; size=$(du_kb "${candidates[@]}")
  info "${dir}: ${#candidates[@]} stale item(s), $(hr_kb "$size")"
  if $DRY_RUN; then
    printf '        %s\n' "${candidates[@]:0:20}"
    (( ${#candidates[@]} > 20 )) && note "... and $(( ${#candidates[@]} - 20 )) more"
  else
    safe_rm "${candidates[@]}"
  fi
  return 0
}

header "Temporary files (idle for ${TMP_AGE_DAYS}+ days)"
clean_tmpdir /tmp "$TMP_AGE_DAYS"
clean_tmpdir /var/tmp "$TMP_AGE_DAYS"
ok "Temp done"

# ── 5. Snap ──────────────────────────────────────────────────────────────────
if command -v snap >/dev/null 2>&1; then
  header "Snap (superseded revisions)"
  # Match the Notes column specifically. The old /disabled/ line match would
  # also fire on a snap whose name or version merely contained the word.
  mapfile -t disabled_snaps < <(
    snap list --all 2>/dev/null | awk 'NR > 1 && $NF ~ /(^|,)disabled(,|$)/ { print $1 "\t" $3 }'
  )
  if (( ${#disabled_snaps[@]} == 0 )); then
    note "No superseded revisions"
  else
    for line in "${disabled_snaps[@]}"; do
      IFS=$'\t' read -r snap_name snap_rev <<<"$line"
      [[ -n $snap_name && -n $snap_rev ]] || continue
      info "${snap_name} revision ${snap_rev}"
      run_cmd snap remove "$snap_name" --revision="$snap_rev"
    done
    ok "Snap done"
  fi
fi

# ── 6. pip cache ─────────────────────────────────────────────────────────────
# Purging as root only clears root's cache, which is rarely the one filling the
# disk, so clear each real user's cache directory too.
header "pip cache"
if command -v pip3 >/dev/null 2>&1 || command -v pip >/dev/null 2>&1; then
  pip_bin=$(command -v pip3 || command -v pip)
  run_cmd "$pip_bin" cache purge
fi
declare -a pip_caches=()
while IFS= read -r home; do
  [[ -d "${home}/.cache/pip" ]] && pip_caches+=("${home}/.cache/pip")
done < <(awk -F: '($3 >= 1000 && $3 < 65534) || $3 == 0 { print $6 }' /etc/passwd | sort -u)
if (( ${#pip_caches[@]} )); then
  info "Per-user caches: $(hr_kb "$(du_kb "${pip_caches[@]}")")"
  if $DRY_RUN; then
    printf '        %s\n' "${pip_caches[@]}"
  else
    safe_rm "${pip_caches[@]}"
  fi
fi
ok "pip cache done"

# ── 7. Thumbnail cache ───────────────────────────────────────────────────────
# Found with find rather than an unquoted glob: the old `rm -rf $THUMB_DIR`
# would have passed a literal '/home/*/.cache/thumbnails' to rm on a glob miss.
header "Thumbnail cache"
declare -a thumb_dirs=()
while IFS= read -r -d '' d; do thumb_dirs+=("$d"); done < <(
  find /home /root -mindepth 2 -maxdepth 3 -type d -name thumbnails -path '*/.cache/*' -print0 2>/dev/null
)
if (( ${#thumb_dirs[@]} == 0 )); then
  note "None found"
else
  info "${#thumb_dirs[@]} directories ($(hr_kb "$(du_kb "${thumb_dirs[@]}")"))"
  if $DRY_RUN; then
    printf '        %s\n' "${thumb_dirs[@]}"
  else
    safe_rm "${thumb_dirs[@]}"
    ok "Thumbnails done"
  fi
fi

# ── 8. Rotated logs in /var/log ──────────────────────────────────────────────
header "/var/log (rotated logs older than ${LOG_AGE_DAYS} days)"
declare -a old_logs=()
while IFS= read -r -d '' f; do old_logs+=("$f"); done < <(
  find /var/log -xdev -type f \
    \( -name '*.gz' -o -name '*.xz' -o -name '*.bz2' -o -name '*.old' \
       -o -name '*.[0-9]' -o -name '*.[0-9][0-9]' \) \
    -mtime "+${LOG_AGE_DAYS}" -print0 2>/dev/null
)
if (( ${#old_logs[@]} == 0 )); then
  note "Nothing to remove"
else
  info "${#old_logs[@]} files ($(hr_kb "$(du_kb "${old_logs[@]}")"))"
  if $DRY_RUN; then
    printf '        %s\n' "${old_logs[@]:0:20}"
    (( ${#old_logs[@]} > 20 )) && note "... and $(( ${#old_logs[@]} - 20 )) more"
  else
    safe_rm "${old_logs[@]}"
    ok "Old logs done"
  fi
fi

# ── Summary ──────────────────────────────────────────────────────────────────
snapshot_disk DISK_AFTER

total_freed=0
declare -a per_mount=()
for mount in "${!DISK_BEFORE[@]}"; do
  [[ -v DISK_AFTER["$mount"] ]] || continue   # unmounted mid-run (e.g. a snap loop)
  delta=$(( DISK_BEFORE[$mount] - DISK_AFTER[$mount] ))
  total_freed=$(( total_freed + delta ))
  (( delta >= 1024 || delta <= -1024 )) && per_mount+=("${mount}|${delta}")
done

out "" ""
out "${BOLD}${GREEN}══════════════════════════════════════${RESET}" "======================================"
if (( ${#FAILURES[@]} )); then
  out "${BOLD}  Done, with ${#FAILURES[@]} failure(s).${RESET}" "Done, with ${#FAILURES[@]} failure(s)."
else
  out "${BOLD}  Done!${RESET}" "Done."
fi

for entry in "${per_mount[@]}"; do
  mount=${entry%|*}; delta=${entry#*|}
  out "  ${mount}: ${BOLD}$(hr_kb "$delta")${RESET} freed" "  ${mount}: $(hr_kb "$delta") freed"
done

if (( total_freed > 0 )); then
  out "  ${GREEN}${BOLD}Total freed : $(hr_kb "$total_freed")${RESET}" "Total freed: $(hr_kb "$total_freed")"
else
  out "  Total freed : 0 (already clean)" "Total freed: 0"
fi

if (( ${#FAILURES[@]} )); then
  out "" ""
  out "${RED}${BOLD}  Failed steps:${RESET}" "Failed steps:"
  for f in "${FAILURES[@]}"; do
    out "    ${RED}• ${f}${RESET}" "  - ${f}"
  done
fi

if $DRY_RUN; then out "  ${YELLOW}(dry-run — no changes were made)${RESET}" "(dry-run)"; fi
out "${BOLD}${GREEN}══════════════════════════════════════${RESET}" "======================================"

# Non-zero exit so cron, CI and monitoring notice a partial failure.
(( ${#FAILURES[@]} == 0 )) || exit 1
exit 0
