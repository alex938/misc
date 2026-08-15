#!/bin/bash
# curl -sSL https://raw.githubusercontent.com/alex938/misc/refs/heads/main/backup_dev1.sh | bash | tee -a /var/log/backup.log

SOURCE="/home/alex/"
DESTINATION="/mnt/dev1backup/"

# Run rsync to create a backup
rsync -avh --delete "$SOURCE" "$DESTINATION"

if [ $? -eq 0 ]; then
    echo "Backup completed successfully at $(date)"
else
    echo "Backup FAILED at $(date)" >&2
    exit 1
fi
