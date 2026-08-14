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
# destroy data you cannot regenerate (named container volumes) is opt-in and
# needs an explicit confirmation.

set -euo pipefail

VERSION="2.1.0"

if [[ -z ${BASH_VERSINFO[0]:-} ]] || (( BASH_VERSINFO[0] * 100 + BASH_VERSINFO[1] < 403 )); then
  echo "cleanup.sh requires bash 4.3 or newer (found ${BASH_VERSION:-unknown})" >&2
  exit 1
fi

# ── Sections ─────────────────────────────────────────────────────────────────
ALL_SECTIONS=(docker podman apt journal tmp snap flatpak caches thumbnails logs coredumps trash)

# ── Defaults ─────────────────────────────────────────────────────────────────
DOCKER_IMAGES_ALL=false   # remove ALL unused images, not just dangling ones
CONTAINER_VOLUMES=false   # remove unused *named* volumes — destroys data
DEEP_CACHES=false         # also drop caches that are slow to refill
DRY_RUN=false
ASSUME_YES=false
QUIET=false
JSON=false
JOURNAL_KEEP="14d"
JOURNAL_SIZE=""
TMP_AGE_DAYS=7
LOG_AGE_DAYS=30
CORE_AGE_DAYS=7
TRASH_AGE_DAYS=30
IF_USED_ABOVE=0
LOG_FILE=""
declare -a ONLY=() SKIP=()

LOCK_FILE="/var/lock/cleanup.sh.lock"

usage() {
  cat <<EOF
cleanup.sh ${VERSION} — VM & Docker housekeeping

Usage: sudo $0 [OPTIONS]

Selection:
  --only=A,B             Run only these sections
  --skip=A,B             Run everything except these sections
  --if-used-above=PCT    Exit without doing anything unless some local
                         filesystem is at least PCT% full
  Sections: ${ALL_SECTIONS[*]}

Aggressiveness:
  --docker-images-all    Remove all unused images, not just dangling ones
  --volumes              Remove unused named volumes (DESTROYS DATA)
  --deep-caches          Also drop slow-to-refill caches (go modules, cargo
                         sources) on top of the cheap ones
  --journal-keep=AGE     Journal retention by age, e.g. 14d, 4w (default: ${JOURNAL_KEEP})
  --journal-size=SIZE    Also cap the journal by size, e.g. 500M, 2G
  --tmp-age=DAYS         Idle threshold for /tmp and /var/tmp (default: ${TMP_AGE_DAYS})
  --log-age=DAYS         Age threshold for rotated logs (default: ${LOG_AGE_DAYS})
  --core-age=DAYS        Age threshold for core dumps (default: ${CORE_AGE_DAYS})
  --trash-age=DAYS       Age threshold for user trash (default: ${TRASH_AGE_DAYS})

Output:
  --dry-run, -n          Show what would be removed, change nothing
  --quiet, -q            Only report failures
  --json                 Emit a machine-readable summary on stdout (implies -q)
  --log=FILE             Append a timestamped transcript to FILE
  -y, --yes              Do not prompt for confirmation
  -V, --version          Print version and exit
  -h, --help             Show this help and exit

Exit status: 0 on success, 1 if any cleanup step failed, 2 on usage error.
EOF
}

die() { printf 'cleanup.sh: %s\n' "$1" >&2; exit "${2:-1}"; }

is_section() {
  local candidate=$1 s
  for s in "${ALL_SECTIONS[@]}"; do
    [[ $s == "$candidate" ]] && return 0
  done
  return 1
}

parse_sections() {
  local -n _dest=$1
  local raw=$2 item
  IFS=',' read -r -a _dest <<<"$raw"
  for item in "${_dest[@]}"; do
    is_section "$item" || die "unknown section: ${item} (valid: ${ALL_SECTIONS[*]})" 2
  done
}

# ── Argument parsing ─────────────────────────────────────────────────────────
while (( $# )); do
  case $1 in
    --docker-images-all)  DOCKER_IMAGES_ALL=true ;;
    --volumes|--docker-volumes) CONTAINER_VOLUMES=true ;;
    --deep-caches)        DEEP_CACHES=true ;;
    --dry-run|-n)         DRY_RUN=true ;;
    -q|--quiet)           QUIET=true ;;
    --json)               JSON=true; QUIET=true ;;
    -y|--yes)             ASSUME_YES=true ;;
    --only=*)             parse_sections ONLY "${1#*=}" ;;
    --skip=*)             parse_sections SKIP "${1#*=}" ;;
    --if-used-above=*)    IF_USED_ABOVE="${1#*=}"; IF_USED_ABOVE="${IF_USED_ABOVE%\%}" ;;
    --journal-keep=*)     JOURNAL_KEEP="${1#*=}" ;;
    --journal-size=*)     JOURNAL_SIZE="${1#*=}" ;;
    --tmp-age=*)          TMP_AGE_DAYS="${1#*=}" ;;
    --log-age=*)          LOG_AGE_DAYS="${1#*=}" ;;
    --core-age=*)         CORE_AGE_DAYS="${1#*=}" ;;
    --trash-age=*)        TRASH_AGE_DAYS="${1#*=}" ;;
    --log=*)              LOG_FILE="${1#*=}" ;;
    -V|--version)         printf 'cleanup.sh %s\n' "$VERSION"; exit 0 ;;
    -h|--help)            usage; exit 0 ;;
    --)                   shift; break ;;
    *)                    usage >&2; die "unknown option: $1" 2 ;;
  esac
  shift
done
(( $# == 0 )) || die "unexpected argument: $1" 2

# Validate, so a typo can never be read as "delete everything".
[[ $JOURNAL_KEEP =~ ^[0-9]+(s|min|m|h|d|w|M|y)?$ ]] \
  || die "--journal-keep must look like 14d, 4w, 6M (got: ${JOURNAL_KEEP})" 2
[[ -z $JOURNAL_SIZE || $JOURNAL_SIZE =~ ^[0-9]+(K|M|G|T)?$ ]] \
  || die "--journal-size must look like 500M, 2G (got: ${JOURNAL_SIZE})" 2
for pair in "TMP_AGE_DAYS:--tmp-age" "LOG_AGE_DAYS:--log-age" \
            "CORE_AGE_DAYS:--core-age" "TRASH_AGE_DAYS:--trash-age" \
            "IF_USED_ABOVE:--if-used-above"; do
  varname=${pair%%:*}
  [[ ${!varname} =~ ^[0-9]+$ ]] || die "${pair#*:} must be a whole number (got: ${!varname})" 2
done
(( IF_USED_ABOVE <= 100 )) || die "--if-used-above must be 0-100" 2
(( ${#ONLY[@]} == 0 || ${#SKIP[@]} == 0 )) || die "--only and --skip are mutually exclusive" 2

# ── Output helpers ───────────────────────────────────────────────────────────
if [[ -t 1 && -z ${NO_COLOR:-} && ${TERM:-dumb} != dumb ]] && ! $JSON; then
  RED=$'\033[0;31m'; YELLOW=$'\033[1;33m'; GREEN=$'\033[0;32m'
  CYAN=$'\033[0;36m'; BOLD=$'\033[1m'; RESET=$'\033[0m'
else
  RED=''; YELLOW=''; GREEN=''; CYAN=''; BOLD=''; RESET=''
fi

CURRENT_SECTION="startup"
SECTION_FAIL_MARK=0
declare -a FAILURES=() SECTIONS_RUN=()

log_line() {
  [[ -n $LOG_FILE ]] || return 0
  printf '%s %s\n' "$(date -Is)" "$1" >>"$LOG_FILE" || true
}

# out <pretty> [plain] — colour to the terminal, plain text to the log file.
out() {
  $QUIET || printf '%s\n' "$1"
  log_line "${2-$1}"
}

# Failures are worth seeing even under --quiet, so they go to stderr.
err_out() {
  printf '%s\n' "$1" >&2
  log_line "${2-$1}"
}

# header <section-id> <title> — announce a section that is actually executing.
# Recorded here rather than in want() so the summary lists what ran, not what
# was merely selected on a host where the tool turned out to be absent.
header() {
  local id=$1; shift
  CURRENT_SECTION="$*"
  SECTIONS_RUN+=("$id")
  SECTION_FAIL_MARK=${#FAILURES[@]}
  out "" ""
  out "${BOLD}${CYAN}==> $*${RESET}" "==> $*"
}
info()   { out "    ${YELLOW}$*${RESET}" "    $*"; }
ok()     { out "    ${GREEN}✓ $*${RESET}" "    OK: $*"; }
note()   { out "    $*" "    $*"; }
warn()   { err_out "    ${RED}✗ $*${RESET}" "    FAIL: $*"; }

fail() {
  FAILURES+=("${CURRENT_SECTION}: $1")
  warn "$1"
}

# Close a section. A green tick directly under a red cross is a lie, so only
# claim success when nothing in this section failed.
done_section() {
  local new=$(( ${#FAILURES[@]} - SECTION_FAIL_MARK ))
  if (( new > 0 )); then
    note "${CURRENT_SECTION}: finished with ${new} failure(s)"
  else
    ok "$1"
  fi
}

# want <section> — is this section selected by --only/--skip?
want() {
  local s=$1 x
  if (( ${#ONLY[@]} )); then
    for x in "${ONLY[@]}"; do
      if [[ $x == "$s" ]]; then return 0; fi
    done
    return 1
  fi
  for x in "${SKIP[@]}"; do
    if [[ $x == "$s" ]]; then return 1; fi
  done
  return 0
}

# Render a command the way you would have to retype it.
quote_cmd() {
  local part rendered=""
  for part in "$@"; do rendered+="${rendered:+ }$(printf '%q' "$part")"; done
  printf '%s' "$rendered"
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
  [[ -n $output ]] && log_line "${output}"
  if (( rc != 0 )); then
    fail "exit ${rc}: ${pretty}"
    [[ -n $output ]] && err_out "        ${output//$'\n'/$'\n'        }" ""
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

json_escape() {
  local s=$1
  s=${s//\\/\\\\}; s=${s//\"/\\\"}
  s=${s//$'\n'/\\n}; s=${s//$'\t'/\\t}; s=${s//$'\r'/}
  printf '%s' "$s"
}

# purge_paths <label> <path...> — report, then remove (or list, under --dry-run).
purge_paths() {
  local label=$1; shift
  if (( $# == 0 )); then
    note "${label}: nothing to remove"
    return 0
  fi
  info "${label}: $# item(s), $(hr_kb "$(du_kb "$@")")"
  if $DRY_RUN; then
    # Everything user-facing goes through out(), or --quiet leaks and --json
    # emits an unparseable document.
    local path
    for path in "${@:1:15}"; do out "        ${path}" "        ${path}"; done
    (( $# > 15 )) && note "... and $(( $# - 15 )) more"
  else
    safe_rm "$@"
  fi
  return 0
}

# Every real user's home, plus root's.
home_dirs() {
  awk -F: '($3 >= 1000 && $3 < 65534) || $3 == 0 { print $6 }' /etc/passwd \
    | sort -u | while IFS= read -r h; do [[ -d $h ]] && printf '%s\n' "$h"; done
  return 0
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

if $CONTAINER_VOLUMES && ! $DRY_RUN && ! $ASSUME_YES; then
  if [[ -t 0 ]]; then
    printf '%s' "${RED}--volumes deletes unused NAMED volumes (database data lives there). Continue? [y/N] ${RESET}"
    read -r reply
    [[ $reply =~ ^[Yy]$ ]] || die "aborted"
  else
    die "--volumes destroys named volume data and there is no terminal to confirm on; re-run with --yes if you mean it" 2
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

df_local() { df -klPT -x tmpfs -x devtmpfs -x squashfs -x overlay 2>/dev/null | tail -n +2; }

snapshot_disk() {
  local -n _snap=$1
  local _fs _type _blocks used _avail _pct target
  _snap=()
  while read -r _fs _type _blocks used _avail _pct target; do
    [[ $target == /* ]] || continue
    _snap["$target"]=$used
  done < <(df_local)
}

max_used_pct() {
  df_local | awk '{ gsub(/%/, "", $6); if ($6 + 0 > m) m = $6 + 0 } END { printf "%d", m + 0 }'
}

if (( IF_USED_ABOVE > 0 )); then
  current_pct=$(max_used_pct)
  if (( current_pct < IF_USED_ABOVE )); then
    if $JSON; then
      printf '{"version":"%s","skipped":true,"reason":"max_used_pct %d < %d"}\n' \
        "$VERSION" "$current_pct" "$IF_USED_ABOVE"
    else
      out "Fullest local filesystem is at ${current_pct}%, below the ${IF_USED_ABOVE}% threshold — nothing to do." ""
    fi
    exit 0
  fi
fi

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

# ── Docker ───────────────────────────────────────────────────────────────────
if want docker && command -v docker >/dev/null 2>&1; then
  header docker "Docker"
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

    if $CONTAINER_VOLUMES; then
      info "Unused named volumes (--volumes)"
      run_cmd docker volume prune -af
    else
      note "Unused volumes: skipped (pass --volumes; this deletes real data)"
    fi

    info "Unused networks"
    run_cmd docker network prune -f

    done_section "Docker done"
  else
    note "Docker CLI present but the daemon is not responding — skipping"
  fi
fi

# ── Podman ───────────────────────────────────────────────────────────────────
if want podman && command -v podman >/dev/null 2>&1; then
  header podman "Podman"
  if $CONTAINER_VOLUMES; then
    run_cmd podman system prune -af --volumes
  else
    run_cmd podman system prune -af
  fi
  done_section "Podman done"
fi

# ── APT ──────────────────────────────────────────────────────────────────────
if want apt && command -v apt-get >/dev/null 2>&1; then
  header apt "APT"
  export DEBIAN_FRONTEND=noninteractive

  info "Package cache (apt-get clean)"
  run_cmd apt-get clean

  info "Orphaned packages and old kernels (autoremove --purge)"
  run_cmd apt-get autoremove --purge -y

  info "Superseded .debs (autoclean)"
  run_cmd apt-get autoclean -y

  done_section "APT done"
fi

# ── systemd journal ──────────────────────────────────────────────────────────
if want journal && command -v journalctl >/dev/null 2>&1; then
  header journal "systemd journal (keeping last ${JOURNAL_KEEP})"
  run_cmd journalctl --vacuum-time="${JOURNAL_KEEP}"
  if [[ -n $JOURNAL_SIZE ]]; then
    info "Capping journal at ${JOURNAL_SIZE}"
    run_cmd journalctl --vacuum-size="${JOURNAL_SIZE}"
  fi
  done_section "Journal done"
fi

# ── Temporary directories ────────────────────────────────────────────────────
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

  purge_paths "$dir" "${candidates[@]}"
}

if want tmp; then
  header tmp "Temporary files (idle for ${TMP_AGE_DAYS}+ days)"
  clean_tmpdir /tmp "$TMP_AGE_DAYS"
  clean_tmpdir /var/tmp "$TMP_AGE_DAYS"
  done_section "Temp done"
fi

# ── Snap ─────────────────────────────────────────────────────────────────────
if want snap && command -v snap >/dev/null 2>&1; then
  header snap "Snap (superseded revisions)"
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
  fi
  # snapd keeps downloaded .snap blobs here after installing them.
  if [[ -d /var/lib/snapd/cache ]]; then
    mapfile -t snap_blobs < <(find /var/lib/snapd/cache -mindepth 1 -maxdepth 1 2>/dev/null)
    purge_paths "snapd download cache" "${snap_blobs[@]}"
  fi
  done_section "Snap done"
fi

# ── Flatpak ──────────────────────────────────────────────────────────────────
if want flatpak && command -v flatpak >/dev/null 2>&1; then
  header flatpak "Flatpak (unused runtimes)"
  run_cmd flatpak uninstall --unused --assumeyes
  done_section "Flatpak done"
fi

# ── Developer and package caches ─────────────────────────────────────────────
# Purging as root only clears root's cache, which is rarely the one filling the
# disk, so walk every real user's home as well.
#
# Deliberately absent: the pnpm content-addressed store, because installed
# node_modules hardlink into it and removing it breaks working checkouts. Use
# `pnpm store prune` for that.
CHEAP_CACHES=(
  .cache/pip .cache/uv .cache/yarn .cache/go-build .cache/node-gyp
  .cache/typescript .cache/composer .npm/_cacache .cache/deno/gen
  .gradle/caches/build-cache-1 .cache/pre-commit
)
# Large and slow to refill — everything here has to be re-downloaded.
DEEP_CACHE_PATHS=(.cargo/registry/cache .cargo/registry/src .cache/huggingface)

if want caches; then
  header caches "Package and developer caches"

  if command -v pip3 >/dev/null 2>&1 || command -v pip >/dev/null 2>&1; then
    pip_bin=$(command -v pip3 || command -v pip)
    run_cmd "$pip_bin" cache purge
  fi

  declare -a cache_paths=()
  while IFS= read -r home; do
    for sub in "${CHEAP_CACHES[@]}"; do
      [[ -d "${home}/${sub}" ]] && cache_paths+=("${home}/${sub}")
    done
    if $DEEP_CACHES; then
      for sub in "${DEEP_CACHE_PATHS[@]}"; do
        [[ -d "${home}/${sub}" ]] && cache_paths+=("${home}/${sub}")
      done
    fi
  done < <(home_dirs)
  purge_paths "User caches" "${cache_paths[@]}"

  # The Go module cache is mode 0444 all the way down, so `rm -rf` is the wrong
  # tool; the toolchain has to unpick it. It also has to run as the owning user,
  # otherwise root only ever clears its own GOPATH — never the one that is
  # actually large.
  if $DEEP_CACHES && command -v go >/dev/null 2>&1; then
    while IFS= read -r home; do
      [[ -d "${home}/go/pkg/mod" ]] || continue
      owner=$(stat -c '%U' "$home" 2>/dev/null) || continue
      info "Go module cache for ${owner}"
      if [[ $EUID -eq 0 && $owner != root ]] && command -v runuser >/dev/null 2>&1; then
        run_cmd runuser -u "$owner" -- go clean -modcache
      else
        run_cmd go clean -modcache
      fi
    done < <(home_dirs)
  elif ! $DEEP_CACHES; then
    note "Go modules and cargo sources: skipped (pass --deep-caches)"
  fi

  done_section "Caches done"
fi

# ── Thumbnail cache ──────────────────────────────────────────────────────────
# Found with find rather than an unquoted glob: the old `rm -rf $THUMB_DIR`
# would have passed a literal '/home/*/.cache/thumbnails' to rm on a glob miss.
if want thumbnails; then
  header thumbnails "Thumbnail cache"
  declare -a thumb_dirs=()
  while IFS= read -r -d '' d; do thumb_dirs+=("$d"); done < <(
    find /home /root -mindepth 2 -maxdepth 3 -type d -name thumbnails -path '*/.cache/*' -print0 2>/dev/null
  )
  purge_paths "Thumbnails" "${thumb_dirs[@]}"
fi

# ── Rotated logs ─────────────────────────────────────────────────────────────
if want logs; then
  header logs "/var/log (rotated logs older than ${LOG_AGE_DAYS} days)"
  declare -a old_logs=()
  while IFS= read -r -d '' f; do old_logs+=("$f"); done < <(
    find /var/log -xdev -type f \
      \( -name '*.gz' -o -name '*.xz' -o -name '*.bz2' -o -name '*.old' \
         -o -name '*.[0-9]' -o -name '*.[0-9][0-9]' \) \
      -mtime "+${LOG_AGE_DAYS}" -print0 2>/dev/null
  )
  purge_paths "Rotated logs" "${old_logs[@]}"
fi

# ── Crash dumps ──────────────────────────────────────────────────────────────
# Core dumps are the classic silent disk filler: one crash loop in a service
# with a large heap can write gigabytes overnight.
if want coredumps; then
  header coredumps "Crash dumps older than ${CORE_AGE_DAYS} days"
  declare -a dumps=()
  for dir in /var/lib/systemd/coredump /var/crash /var/lib/apport/coredump; do
    [[ -d $dir ]] || continue
    while IFS= read -r -d '' f; do dumps+=("$f"); done < <(
      find "$dir" -xdev -mindepth 1 -maxdepth 1 -type f -mtime "+${CORE_AGE_DAYS}" -print0 2>/dev/null
    )
  done
  purge_paths "Crash dumps" "${dumps[@]}"
fi

# ── User trash ───────────────────────────────────────────────────────────────
# Files the user already chose to delete, held past the age threshold. The
# matching .trashinfo entries are aged out on the same schedule; a desktop
# environment tidies up any orphans on its own.
if want trash; then
  header trash "Trash older than ${TRASH_AGE_DAYS} days"
  declare -a trashed=()
  while IFS= read -r home; do
    for sub in files info; do
      [[ -d "${home}/.local/share/Trash/${sub}" ]] || continue
      while IFS= read -r -d '' f; do trashed+=("$f"); done < <(
        find "${home}/.local/share/Trash/${sub}" -mindepth 1 -maxdepth 1 \
          -mtime "+${TRASH_AGE_DAYS}" -print0 2>/dev/null
      )
    done
  done < <(home_dirs)
  purge_paths "Trash" "${trashed[@]}"
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

if $JSON; then
  printf '{"version":"%s","dry_run":%s,"freed_kb":%d,"sections":[' \
    "$VERSION" "$DRY_RUN" "$total_freed"
  for i in "${!SECTIONS_RUN[@]}"; do
    (( i )) && printf ','
    printf '"%s"' "$(json_escape "${SECTIONS_RUN[$i]}")"
  done
  printf '],"mounts":{'
  first=true
  for mount in "${!DISK_BEFORE[@]}"; do
    [[ -v DISK_AFTER["$mount"] ]] || continue
    $first || printf ','
    first=false
    printf '"%s":{"before_kb":%d,"after_kb":%d}' \
      "$(json_escape "$mount")" "${DISK_BEFORE[$mount]}" "${DISK_AFTER[$mount]}"
  done
  printf '},"failures":['
  for i in "${!FAILURES[@]}"; do
    (( i )) && printf ','
    printf '"%s"' "$(json_escape "${FAILURES[$i]}")"
  done
  printf ']}\n'
else
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
    err_out "${RED}${BOLD}  Failed steps:${RESET}" "Failed steps:"
    for f in "${FAILURES[@]}"; do
      err_out "    ${RED}• ${f}${RESET}" "  - ${f}"
    done
  fi

  if $DRY_RUN; then out "  ${YELLOW}(dry-run — no changes were made)${RESET}" "(dry-run)"; fi
  out "${BOLD}${GREEN}══════════════════════════════════════${RESET}" "======================================"
fi

# Non-zero exit so cron, CI and monitoring notice a partial failure.
(( ${#FAILURES[@]} == 0 )) || exit 1
exit 0
