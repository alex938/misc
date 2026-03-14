#!/usr/bin/env bash
# cleanup.sh — VM & Docker housekeeping
# Usage: sudo ./cleanup.sh [--docker-images-all] [--dry-run]

# ── Flags ────────────────────────────────────────────────────────────────────
DOCKER_IMAGES_ALL=false   # remove ALL unused images, not just dangling ones
DRY_RUN=false
JOURNAL_KEEP="14d"
TMP_AGE_DAYS=7

for arg in "$@"; do
  case $arg in
    --docker-images-all) DOCKER_IMAGES_ALL=true ;;
    --dry-run)           DRY_RUN=true ;;
    --journal-keep=*)    JOURNAL_KEEP="${arg#*=}" ;;
    --tmp-age=*)         TMP_AGE_DAYS="${arg#*=}" ;;
    -h|--help)
      echo "Usage: sudo $0 [--docker-images-all] [--dry-run] [--journal-keep=14d] [--tmp-age=7]"
      exit 0 ;;
  esac
done

# ── Colour helpers ───────────────────────────────────────────────────────────
RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

header()  { echo -e "\n${BOLD}${CYAN}==> $*${RESET}"; }
info()    { echo -e "    ${YELLOW}$*${RESET}"; }
ok()      { echo -e "    ${GREEN}✓ $*${RESET}"; }
skip()    { echo -e "    (skipped — dry run)"; }
run_cmd() { $DRY_RUN && { echo -e "    ${YELLOW}[dry-run]${RESET} $*"; skip; return; }; "$@"; }

# ── Root check ───────────────────────────────────────────────────────────────
if [[ $EUID -ne 0 ]]; then
  echo -e "${RED}Please run as root (sudo $0)${RESET}" >&2
  exit 1
fi

disk_before=$(df / --output=used -BM | tail -1 | tr -d 'M ')

echo -e "${BOLD}╔══════════════════════════════════════╗"
echo -e "║        VM Cleanup Script             ║"
echo -e "╚══════════════════════════════════════╝${RESET}"
$DRY_RUN && echo -e "${YELLOW}  -- DRY RUN MODE (no changes) --${RESET}"
echo -e "  Disk used before: ${BOLD}${disk_before}MB${RESET}"

# ── 1. Docker ────────────────────────────────────────────────────────────────
if command -v docker &>/dev/null; then
  header "Docker"

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

  info "Unused volumes"
  run_cmd docker volume prune -f

  info "Unused networks"
  run_cmd docker network prune -f

  ok "Docker done"
else
  info "Docker not found — skipping"
fi

# ── 2. APT ───────────────────────────────────────────────────────────────────
if command -v apt-get &>/dev/null; then
  header "APT"

  info "Package cache (apt clean)"
  run_cmd apt-get clean -y

  info "Orphaned packages (autoremove)"
  run_cmd apt-get autoremove -y

  info "Partial packages (autoclean)"
  run_cmd apt-get autoclean -y

  ok "APT done"
fi

# ── 3. Journal logs ──────────────────────────────────────────────────────────
if command -v journalctl &>/dev/null; then
  header "systemd journal (keeping last ${JOURNAL_KEEP})"
  run_cmd journalctl --vacuum-time="${JOURNAL_KEEP}"
  ok "Journal done"
fi

# ── 4. /tmp ──────────────────────────────────────────────────────────────────
header "/tmp (files older than ${TMP_AGE_DAYS} days)"
if $DRY_RUN; then
  find /tmp -mindepth 1 -atime "+${TMP_AGE_DAYS}" -print 2>/dev/null | head -20
  skip
else
  find /tmp -mindepth 1 -atime "+${TMP_AGE_DAYS}" -delete 2>/dev/null
  ok "/tmp done"
fi

# ── 5. Snap ──────────────────────────────────────────────────────────────────
if command -v snap &>/dev/null; then
  header "Snap (old revisions)"
  if $DRY_RUN; then
    snap list --all | awk '/disabled/ {print $1, $2, $3}'
    skip
  else
    snap list --all | awk '/disabled/ {print $1, $3}' | while read -r name rev; do
      snap remove "$name" --revision="$rev"
    done
    ok "Snap done"
  fi
fi

# ── 6. pip cache ─────────────────────────────────────────────────────────────
if command -v pip &>/dev/null; then
  header "pip cache"
  run_cmd pip cache purge
  ok "pip cache done"
fi

# ── 7. Thumbnail cache ───────────────────────────────────────────────────────
THUMB_DIR="/home/*/.cache/thumbnails"
if ls $THUMB_DIR &>/dev/null 2>&1; then
  header "Thumbnail cache"
  if $DRY_RUN; then
    du -sh $THUMB_DIR 2>/dev/null
    skip
  else
    rm -rf $THUMB_DIR
    ok "Thumbnails done"
  fi
fi

# ── 8. Old compressed logs in /var/log ───────────────────────────────────────
header "/var/log (*.gz and rotated logs older than 30 days)"
if $DRY_RUN; then
  find /var/log -type f \( -name "*.gz" -o -name "*.1" -o -name "*.old" \) \
    -mtime +30 -print 2>/dev/null
  skip
else
  find /var/log -type f \( -name "*.gz" -o -name "*.1" -o -name "*.old" \) \
    -mtime +30 -delete 2>/dev/null
  ok "Old logs done"
fi

# ── Summary ──────────────────────────────────────────────────────────────────
disk_after=$(df / --output=used -BM | tail -1 | tr -d 'M ')
freed=$(( disk_before - disk_after ))

echo -e "\n${BOLD}${GREEN}══════════════════════════════════════${RESET}"
echo -e "${BOLD}  Done!${RESET}"
echo -e "  Disk before : ${disk_before}MB"
echo -e "  Disk after  : ${disk_after}MB"
if [[ $freed -gt 0 ]]; then
  echo -e "  ${GREEN}${BOLD}Freed       : ${freed}MB${RESET}"
else
  echo -e "  Freed       : 0MB (already clean)"
fi
$DRY_RUN && echo -e "  ${YELLOW}(dry-run — no changes were made)${RESET}"
echo -e "${BOLD}${GREEN}══════════════════════════════════════${RESET}\n"
