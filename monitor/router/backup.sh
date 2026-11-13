#!/bin/sh
# Pull a backup of the router's JFFS partition, its USB stick (Entware, add-ons,
# Skynet, logs) and its NVRAM settings onto this machine over SSH.
# Nothing is installed or written on the router; everything streams over ssh.
#
#   /var/backups/router/<UTC timestamp>/
#     jffs.tar.gz    /jffs (custom scripts, amtm add-ons + their databases)
#     usb.tar.gz     USB stick: entware/ and skynet/ (no swap file, lost+found, DLNA db)
#     nvram.txt.gz   `nvram show` -- every setting, incl. Wi-Fi keys and passwords
#     MANIFEST       firmware, sizes, sha256
#
# Backups contain secrets: the directory is root-only (0700).
set -eu

HOST=${ROUTER_HOST:-192.168.1.1}
USER=${ROUTER_USER:-admin}
KEY=${ROUTER_KEY:-/root/.ssh/id_ed25519}
DEST=${BACKUP_DIR:-/var/backups/router}
KEEP=${BACKUP_KEEP:-14}          # newest complete backups kept
MIN_FREE_MB=${MIN_FREE_MB:-1024} # never let a backup push the disk below this

ssh_r() { ssh -i "$KEY" -o BatchMode=yes -o ConnectTimeout=15 "$USER@$HOST" "$@"; }

umask 077
mkdir -p "$DEST"
chmod 700 "$DEST"

free_mb=$(df -Pm "$DEST" | awk 'NR==2 {print $4}')
if [ "$free_mb" -lt $((MIN_FREE_MB + 100)) ]; then
    echo "only ${free_mb} MB free in $DEST -- skipping backup" >&2
    exit 1
fi

ts=$(date -u +%Y-%m-%dT%H%M%SZ)
work="$DEST/.partial-$ts"
trap 'rm -rf "$work"' EXIT
mkdir "$work"

ssh_r 'tar -czf - -C / jffs' > "$work/jffs.tar.gz"
ssh_r 'cd /tmp/mnt/entware && tar -czf - entware skynet' > "$work/usb.tar.gz"
ssh_r 'nvram show 2>/dev/null' | gzip -9 > "$work/nvram.txt.gz"

# sanity: archives readable and not suspiciously small
for f in jffs.tar.gz usb.tar.gz; do
    tar -tzf "$work/$f" > /dev/null
done
[ "$(stat -c %s "$work/usb.tar.gz")" -gt 1000000 ] || { echo "usb.tar.gz too small" >&2; exit 1; }
[ "$(gzip -dc "$work/nvram.txt.gz" | wc -l)" -gt 500 ] || { echo "nvram dump too short" >&2; exit 1; }

{
    echo "router:   $HOST ($(ssh_r 'nvram get productid; nvram get buildno; nvram get extendno' | paste -sd' '))"
    echo "taken:    $ts"
    echo "restore:  see 'Router backups' in /opt/network-ai/README.md"
    echo
    cd "$work" && sha256sum jffs.tar.gz usb.tar.gz nvram.txt.gz && du -h jffs.tar.gz usb.tar.gz nvram.txt.gz
} > "$work/MANIFEST"

mv "$work" "$DEST/$ts"
trap - EXIT

# keep the newest $KEEP complete backups
ls -1d "$DEST"/20*/ 2>/dev/null | sort | head -n -"$KEEP" | while read -r old; do
    rm -rf -- "$old"
done

echo "backup $DEST/$ts: $(du -sh "$DEST/$ts" | cut -f1); $(ls -1d "$DEST"/20*/ | wc -l) kept"
