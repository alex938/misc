#!/bin/bash
# curl -sSL https://raw.githubusercontent.com/alex938/misc/refs/heads/main/pull_dev1backup.sh | bash
#
# Pull the dev1 backup from the NAS into /home/alex on the standby box, so
# this machine can be taken over as dev1 if dev1 goes down.
#
# Run this script from the standby box, periodically.
#
# backup_dev1.sh pushes /home/alex on dev1 to /mnt/share1/dev1backup/. This
# script mirrors that down to /home/alex here. /home/alex on this box is
# therefore disposable: --delete makes it match dev1, and anything created
# locally that is not in the backup is removed.

SOURCE="/mnt/share1/dev1backup/"
DESTINATION="/home/alex/"
LOGFILE="/home/alex/logs/pull_backup.log"

mkdir -p "$(dirname "$LOGFILE")"
exec > >(tee -a "$LOGFILE") 2>&1

# Refuse to run if the NAS is not mounted, otherwise the source is an empty
# directory and --delete would erase this home directory.
if ! mountpoint -q /mnt/share1; then
    echo "Pull ABORTED at $(date): /mnt/share1 is not mounted"
    exit 1
fi

if [ ! -d "$SOURCE" ]; then
    echo "Pull ABORTED at $(date): $SOURCE does not exist"
    exit 1
fi

# The mount can be present while the export is empty or half-written. Since
# --delete propagates deletions into a live home directory, an unexpectedly
# tiny source is treated as a fault rather than as a real backup.
COUNT=$(find "$SOURCE" -mindepth 1 -maxdepth 1 | wc -l)
if [ "$COUNT" -lt 5 ]; then
    echo "Pull ABORTED at $(date): $SOURCE has only $COUNT entries, looks wrong"
    exit 1
fi

# backup_dev1.sh excludes these from the push, so they are never in the
# backup. Excluding them here too stops --delete from removing this box's own
# copies: the caches and toolchains it needs to actually stand in for dev1
# are installed locally and must survive every pull.
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

# -rlptDvh is -avh without -g/-o: the NAS squashes ownership on this export,
# so ownership is not preserved and everything lands owned by the user running
# this script. Modes are preserved, which is what .ssh and keys/ depend on.
rsync -rlptDvh --delete "${EXCLUDES[@]}" "$SOURCE" "$DESTINATION"
STATUS=$?

# 23 = partial transfer, 24 = source files vanished mid-run. Both are normal
# if the dev1 push happens to be running against the NAS at the same time.
case $STATUS in
    0)
        echo "Pull completed successfully at $(date)"
        ;;
    23 | 24)
        echo "Pull completed with warnings (rsync $STATUS) at $(date)"
        ;;
    *)
        echo "Pull FAILED (rsync $STATUS) at $(date)"
        exit 1
        ;;
esac

df -h "$DESTINATION"
