#!/bin/bash
# curl -sSL https://raw.githubusercontent.com/alex938/misc/refs/heads/main/backup_dev1.sh | bash

SOURCE="/home/alex/"
DESTINATION="/mnt/share1/dev1backup/"
LOGFILE="/home/alex/logs/backup.log"

mkdir -p "$(dirname "$LOGFILE")"
exec > >(tee -a "$LOGFILE") 2>&1

# Refuse to run if the NAS is not mounted, otherwise rsync would quietly
# write the whole backup to the SD card under an empty mount point.
if ! mountpoint -q /mnt/share1; then
    echo "Backup ABORTED at $(date): /mnt/share1 is not mounted"
    exit 1
fi

mkdir -p "$DESTINATION"

# Regenerable caches and toolchains. The log directory is also excluded
# because this script appends to it while rsync is reading, which trips a
# spurious error.
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
    # root-owned 0700 certbot ACME account, unreadable as alex. Deliberately
    # not backed up: /mnt/share1 is world-readable and the account is cheap
    # to re-register.
    --exclude 'certs/accounts/'
)

# -rlptDvh is -avh without -g/-o: the NAS squashes ownership on this export,
# so attempting to preserve it just produces chgrp errors and exit code 23.
rsync -rlptDvh --delete "${EXCLUDES[@]}" "$SOURCE" "$DESTINATION"
STATUS=$?

# 23 = partial transfer, 24 = source files vanished mid-run. Both are normal
# against a live home directory and do not mean the backup was lost.
case $STATUS in
    0)
        echo "Backup completed successfully at $(date)"
        ;;
    23 | 24)
        echo "Backup completed with warnings (rsync $STATUS) at $(date)"
        ;;
    *)
        echo "Backup FAILED (rsync $STATUS) at $(date)"
        exit 1
        ;;
esac
