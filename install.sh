#!/bin/sh
set -eu

BASE=/opt/proxmox-soft-backup
OLD_TEST_BASE=/opt/prmt

rm -rf "$BASE"
mkdir -p "$BASE"
cp -a psb psb.py "$BASE/"
chmod +x "$BASE/psb.py"

cat > /usr/local/sbin/psb <<'SCRIPT'
#!/bin/sh
exec python3 /opt/proxmox-soft-backup/psb.py "$@"
SCRIPT
chmod +x /usr/local/sbin/psb

# Remove only the aliases and directory created by our earlier test build.
if [ -L /usr/local/sbin/prht ]; then
    target=$(readlink /usr/local/sbin/prht || true)
    if [ "$target" = "/usr/local/sbin/prmt" ]; then
        rm -f /usr/local/sbin/prht
    fi
fi

if [ -f /usr/local/sbin/prmt ] && grep -q '/opt/prmt/prmt.py' /usr/local/sbin/prmt 2>/dev/null; then
    rm -f /usr/local/sbin/prmt
fi

if [ -d "$OLD_TEST_BASE" ] && [ -f "$OLD_TEST_BASE/prmt.py" ]; then
    rm -rf "$OLD_TEST_BASE"
fi

printf '%s\n' "Proxmox Soft Backup installed: /usr/local/sbin/psb"
printf '%s\n' "Run: psb host"
