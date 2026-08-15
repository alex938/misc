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

# Run rsync to create a backup. The log directory is excluded because this
# script appends to it while rsync is reading, which trips a spurious error.
rsync -avh --delete --exclude 'logs/' "$SOURCE" "$DESTINATION"

if [ $? -eq 0 ]; then
    echo "Backup completed successfully at $(date)"
else
    echo "Backup FAILED at $(date)"
    exit 1
fi
