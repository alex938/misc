#!/bin/bash
#
# Verify the backup pulled onto the standby box.
#
# Run this script from the standby box, after pull_dev1backup.sh.
#
# Two checks:
#
#   Structure. A dry run of the same rsync the pull performs, which lists
#   every file that still differs in size or mtime, plus anything the next
#   pull would delete. A clean run means the mirror matches the NAS.
#
#   Content. Size and mtime matching does not prove the bytes match, so a
#   random sample of files is compared byte for byte with sha256. A
#   different sample is drawn each run, so coverage builds up over time.
#
# Nothing is copied and nothing in /home/alex is modified. This script only
# reads, apart from its own log.
#

set -Eeuo pipefail

SOURCE="/mnt/share1/dev1backup/"
DESTINATION="/home/alex/"
LOGFILE="/home/alex/logs/backup_test.log"

SAMPLE_MAX_FILES=500

mkdir -p "$(dirname "$LOGFILE")"
exec > >(tee -a "$LOGFILE") 2>&1

fail_banner() {
    echo
    echo "============================================================"
    echo " BACKUP TEST FAILED"
    echo "============================================================"
    echo
    echo "See the output above for the failing step."
}

trap fail_banner ERR

# Must match pull_dev1backup.sh, or the dry run reports every locally
# installed cache and toolchain as a difference.
EXCLUDES=(
    --exclude 'logs/'
    --exclude '.cache/'
    --exclude '.npm/'
    --exclude '.nvm/'
    --exclude '.vscode-server/'
    --exclude '.local/share/Trash/'
    --exclude 'node_modules/'
    --exclude '__pycache__/'
    --exclude '.venv/'
    --exclude 'certs/accounts/'
)

echo "============================================================"
echo " Standby backup test - $(date)"
echo "============================================================"
echo
echo "Checking NAS mount..."

if ! mountpoint -q /mnt/share1; then
    echo
    echo "ERROR: /mnt/share1 is not mounted."
    exit 1
fi

if [[ ! -d "$SOURCE" ]]; then
    echo
    echo "ERROR: Source does not exist: $SOURCE"
    exit 1
fi

echo "OK: $SOURCE is mounted and present."

echo
echo "============================================================"
echo " CHECKING STRUCTURE"
echo "============================================================"
echo
echo "Listing anything that still differs from the NAS..."
echo

DIFFS=$(mktemp)
SAMPLE_LIST=$(mktemp)
trap 'rm -f "$DIFFS" "$SAMPLE_LIST"' EXIT

# Same flags as the pull, with -n to change nothing. --itemize-changes prints
# one line per difference and stays silent when the mirror is in sync.
rsync -rlptDn --delete --itemize-changes "${EXCLUDES[@]}" \
    "$SOURCE" "$DESTINATION" > "$DIFFS"

DIFF_COUNT=$(wc -l < "$DIFFS")

if [[ "$DIFF_COUNT" -eq 0 ]]; then
    echo "OK: no differences. The mirror matches the NAS."
else
    echo "$DIFF_COUNT difference(s) found:"
    echo
    head -50 "$DIFFS"

    if [[ "$DIFF_COUNT" -gt 50 ]]; then
        echo
        echo "...and $((DIFF_COUNT - 50)) more. Full list in $LOGFILE."
    fi

    echo
    echo "Lines starting with '*deleting' are files this box has that the"
    echo "NAS does not. Other lines are files the next pull would update."
fi

echo
echo "============================================================"
echo " CHECKING CONTENT"
echo "============================================================"
echo
echo "Selecting a random sample of up to $SAMPLE_MAX_FILES files..."

# Null separators keep filenames containing spaces or newlines intact.
# shuf does the limiting itself. Piping into 'head -z -n' instead would
# close the pipe early, kill shuf with SIGPIPE and trip pipefail.
find "$SOURCE" -type f -printf '%P\0' \
    | shuf -z -n "$SAMPLE_MAX_FILES" > "$SAMPLE_LIST"

SAMPLE_FILES=$(tr -cd '\0' < "$SAMPLE_LIST" | wc -c)

if [[ "$SAMPLE_FILES" -eq 0 ]]; then
    echo
    echo "ERROR: The NAS backup contains no files."
    exit 1
fi

echo "OK: $SAMPLE_FILES files selected."
echo
echo "Comparing sha256 of each against the local copy..."
echo

CHECKED=0
MISSING=0
MISMATCHED=0
VANISHED=0
SAMPLE_BYTES=0

while IFS= read -r -d '' REL; do
    SRC="$SOURCE$REL"
    DST="$DESTINATION$REL"

    # A file the dev1 push deleted mid-run is not a local fault.
    if [[ ! -f "$SRC" ]]; then
        VANISHED=$((VANISHED + 1))
        continue
    fi

    if [[ ! -f "$DST" ]]; then
        echo "MISSING LOCALLY: $REL"
        MISSING=$((MISSING + 1))
        continue
    fi

    SRC_SUM=$(sha256sum < "$SRC" | cut -d ' ' -f 1)
    DST_SUM=$(sha256sum < "$DST" | cut -d ' ' -f 1)

    if [[ "$SRC_SUM" != "$DST_SUM" ]]; then
        echo "CHECKSUM MISMATCH: $REL"
        MISMATCHED=$((MISMATCHED + 1))
        continue
    fi

    SAMPLE_BYTES=$((SAMPLE_BYTES + $(stat -c '%s' "$SRC")))
    CHECKED=$((CHECKED + 1))
done < "$SAMPLE_LIST"

echo
echo "============================================================"
echo " CHECKING KEY PERMISSIONS"
echo "============================================================"
echo
echo "ssh refuses to use a private key others can read, so a standby with"
echo "loose modes looks fine until the moment you need it."
echo

BAD_MODES=0

while IFS= read -r -d '' KEYFILE; do
    MODE=$(stat -c '%a' "$KEYFILE")

    if [[ "$MODE" != "600" && "$MODE" != "400" ]]; then
        echo "TOO OPEN ($MODE): $KEYFILE"
        BAD_MODES=$((BAD_MODES + 1))
    fi
done < <(grep -rlZ --include='*' -e '-----BEGIN .*PRIVATE KEY-----' \
    "$DESTINATION.ssh" "${DESTINATION}keys" 2>/dev/null || true)

if [[ "$BAD_MODES" -eq 0 ]]; then
    echo "OK: every private key found is 600 or 400."
fi

echo
echo "============================================================"

if [[ "$MISMATCHED" -ne 0 || "$MISSING" -ne 0 ]]; then
    echo " BACKUP TEST FAILED"
    echo "============================================================"
    echo
    echo "$MISMATCHED sampled file(s) did not match, $MISSING missing locally."
    exit 1
fi

if [[ "$CHECKED" -eq 0 ]]; then
    echo " BACKUP TEST FAILED"
    echo "============================================================"
    echo
    echo "No files could be verified."
    exit 1
fi

if [[ "$DIFF_COUNT" -ne 0 || "$BAD_MODES" -ne 0 ]]; then
    echo " BACKUP TEST PASSED WITH WARNINGS"
else
    echo " BACKUP TEST PASSED"
fi

echo "============================================================"
echo
echo "Sample verified:  $CHECKED files, $(numfmt --to=iec "$SAMPLE_BYTES") matched by sha256"
echo "Structure:        $DIFF_COUNT file(s) differ from the NAS"
echo "Key permissions:  $BAD_MODES key(s) too open"

if [[ "$VANISHED" -ne 0 ]]; then
    echo "Skipped:          $VANISHED file(s) vanished from the NAS mid-run"
fi

if [[ "$DIFF_COUNT" -ne 0 ]]; then
    echo
    echo "Differences are expected if dev1 has pushed since the last pull."
    echo "Run pull_dev1backup.sh and test again; if they persist, investigate."
fi

echo
