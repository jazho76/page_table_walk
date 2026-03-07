#!/bin/bash
set -euo pipefail

SECRET_BIN="$1"
OUTPUT="$2"

TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT

mkdir -p "$TMPDIR"/{bin,dev,proc,sys}

BUSYBOX=$(which busybox)
cp "$BUSYBOX" "$TMPDIR/bin/busybox"
for cmd in sh mount umount ls cat echo sleep kill; do
    ln -sf busybox "$TMPDIR/bin/$cmd"
done

cp "$SECRET_BIN" "$TMPDIR/bin/secret"

cat > "$TMPDIR/init" << 'EOF'
#!/bin/sh
export PATH=/bin
mount -t proc proc /proc
mount -t sysfs sys /sys
mount -t devtmpfs dev /dev

echo ""
echo "=== Page Walk Challenge ==="
echo ""
echo "Run in another terminal:"
echo "  gdb -ex 'target remote :1234'"
echo ""

exec /bin/secret
EOF
chmod +x "$TMPDIR/init"

(cd "$TMPDIR" && find . | cpio -o -H newc 2>/dev/null | gzip) > "$OUTPUT"
