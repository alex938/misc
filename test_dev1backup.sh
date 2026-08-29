#!/bin/bash
#
# Test dev1 backup on testbox.
#
# Run this script from dev1.
#
# The testbox has the NAS mounted at /mnt/share1.
#
# Each run:
#   Indexes the backup.
#   Restores a random sample of files to a temporary directory.
#   Verifies every restored file byte for byte with sha256.
#   Deletes the temporary directory.
#
# No full copy of the backup is ever kept on the testbox. Only the sample
# needs to fit on disk, capped by SAMPLE_MAX_FILES and SAMPLE_MAX_BYTES.
#
# A different random sample is drawn each run, so coverage builds up over
# time rather than being proven in a single run.
#
# /home/alex on testbox is NEVER modified.
#

set -Eeuo pipefail

fail_banner() {
    echo
    echo "============================================================"
    echo " BACKUP TEST FAILED"
    echo "============================================================"
    echo
    echo "See the output above for the failing step."
}

trap fail_banner ERR

HOST="alex@testbox.labjunkie.org"
KEY="/home/alex/keys/super"

SSH_OPTS=(
    -i "$KEY"
    -o StrictHostKeyChecking=no
    -o UserKnownHostsFile=/dev/null
    -o LogLevel=ERROR
)

echo "============================================================"
echo " dev1 backup test"
echo "============================================================"
echo
echo "Connecting to $HOST..."
echo

ssh "${SSH_OPTS[@]}" "$HOST" 'bash -s' <<'REMOTE'

set -euo pipefail

BACKUP="/mnt/share1/dev1backup/"

#
# The test restores at most SAMPLE_MAX_FILES files and at most
# SAMPLE_MAX_BYTES of data, whichever limit is reached first.
#

SAMPLE_MAX_FILES=500
SAMPLE_MAX_BYTES=$((2 * 1024 * 1024 * 1024))

echo "Checking NAS mount..."

if ! mountpoint -q /mnt/share1; then
    echo
    echo "ERROR: /mnt/share1 is not mounted."
    exit 1
fi

echo "OK: /mnt/share1 is mounted."

echo
echo "Checking backup..."

if [[ ! -d "$BACKUP" ]]; then
    echo
    echo "ERROR: Backup directory does not exist:"
    echo "  $BACKUP"
    exit 1
fi

if [[ ! -r "$BACKUP" ]]; then
    echo
    echo "ERROR: Backup directory is not readable."
    exit 1
fi

echo "OK: Backup is accessible."

WORKDIR=$(mktemp -d /var/tmp/dev1backup-test.XXXXXX)
ALL_FILES=$(mktemp)
SAMPLE_LIST=$(mktemp)

trap 'rm -rf "$WORKDIR" "$ALL_FILES" "$SAMPLE_LIST"' EXIT

echo
echo "Indexing backup..."

#
# One walk of the backup gives the total counts and the pool to sample from.
# Null separators keep filenames containing spaces or newlines intact.
#

find "$BACKUP" -type f -printf '%s\t%P\0' > "$ALL_FILES"

TOTAL_FILES=$(tr -cd '\0' < "$ALL_FILES" | wc -c)
TOTAL_BYTES=$(awk -v RS='\0' -F'\t' '{n += $1} END {print n + 0}' "$ALL_FILES")

if [[ "$TOTAL_FILES" -eq 0 ]]; then
    echo
    echo "ERROR: Backup contains no files."
    exit 1
fi

echo "OK: $TOTAL_FILES files, $(numfmt --to=iec "$TOTAL_BYTES")."

echo
echo "Selecting random sample..."

SAMPLE_FILES=0
SAMPLE_BYTES=0

while IFS=$'\t' read -r -d '' SIZE REL; do
    if [[ "$SAMPLE_FILES" -ge "$SAMPLE_MAX_FILES" ]]; then
        break
    fi

    #
    # Skip a file that would blow the byte budget and keep looking for
    # smaller ones, but always take at least one file.
    #
    if [[ "$SAMPLE_FILES" -gt 0 && $((SAMPLE_BYTES + SIZE)) -gt "$SAMPLE_MAX_BYTES" ]]; then
        continue
    fi

    printf '%s\0' "$REL" >> "$SAMPLE_LIST"
    SAMPLE_FILES=$((SAMPLE_FILES + 1))
    SAMPLE_BYTES=$((SAMPLE_BYTES + SIZE))
done < <(shuf -z < "$ALL_FILES")

echo "OK: $SAMPLE_FILES files, $(numfmt --to=iec "$SAMPLE_BYTES") selected."

#
# Only the sample has to fit, not the whole backup.
#

NEED_KB=$(( (SAMPLE_BYTES / 1024) * 11 / 10 + 1024 ))
HAVE_KB=$(df -Pk /var/tmp | awk 'NR == 2 {print $4}')

if [[ "$HAVE_KB" -lt "$NEED_KB" ]]; then
    echo
    echo "ERROR: Not enough free space in /var/tmp for the sample."
    echo "  Need: ${NEED_KB}KB"
    echo "  Have: ${HAVE_KB}KB"
    exit 1
fi

echo
echo "============================================================"
echo " RESTORING SAMPLE"
echo "============================================================"
echo

#
# rsync exit 24 means "some source files vanished during transfer", which is
# expected against a backup a live job may still be writing to. Treat it as a
# warning; any other non-zero status is a real failure.
#

rsync \
    -rlptDvh \
    --from0 \
    --files-from="$SAMPLE_LIST" \
    "$BACKUP" \
    "$WORKDIR/" || {
    RC=$?
    if [[ $RC -ne 24 ]]; then
        exit $RC
    fi
    echo
    echo "NOTE: some files vanished during transfer (rsync exit 24), continuing."
}

echo
echo "============================================================"
echo " VERIFYING SAMPLE"
echo "============================================================"
echo
echo "Comparing sha256 of every restored file against the backup..."
echo

CHECKED=0
VANISHED=0
MISMATCHED=0

while IFS= read -r -d '' REL; do
    SRC="$BACKUP$REL"
    DST="$WORKDIR/$REL"

    #
    # A file the backup job deleted mid-run is not a restore failure.
    #
    if [[ ! -f "$SRC" ]]; then
        VANISHED=$((VANISHED + 1))
        continue
    fi

    if [[ ! -f "$DST" ]]; then
        echo "MISSING FROM RESTORE: $REL"
        MISMATCHED=$((MISMATCHED + 1))
        continue
    fi

    SRC_SUM=$(sha256sum < "$SRC" | cut -d ' ' -f 1)
    DST_SUM=$(sha256sum < "$DST" | cut -d ' ' -f 1)

    if [[ "$SRC_SUM" != "$DST_SUM" ]]; then
        echo "CHECKSUM MISMATCH: $REL"
        MISMATCHED=$((MISMATCHED + 1))
        continue
    fi

    CHECKED=$((CHECKED + 1))
done < "$SAMPLE_LIST"

if [[ "$MISMATCHED" -ne 0 ]]; then
    echo
    echo "============================================================"
    echo " BACKUP TEST FAILED"
    echo "============================================================"
    echo
    echo "$MISMATCHED of $SAMPLE_FILES sampled files did not verify."
    exit 1
fi

if [[ "$CHECKED" -eq 0 ]]; then
    echo
    echo "============================================================"
    echo " BACKUP TEST FAILED"
    echo "============================================================"
    echo
    echo "No files could be verified."
    exit 1
fi

echo
echo "============================================================"
echo " BACKUP TEST PASSED"
echo "============================================================"
echo
echo "Every sampled file restored and matched the backup by sha256."
echo
echo "Backup contents:  $TOTAL_FILES files, $(numfmt --to=iec "$TOTAL_BYTES")"
echo "Sample verified:  $CHECKED files, $(numfmt --to=iec "$SAMPLE_BYTES")"

if [[ "$VANISHED" -ne 0 ]]; then
    echo "Skipped:          $VANISHED files vanished from the backup mid-run"
fi

echo
echo "Testbox disk usage:"
df -h /var/tmp

echo
echo "Temporary restore is removed on exit."
echo

REMOTE
