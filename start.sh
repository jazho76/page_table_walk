#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
KERNEL="${SCRIPT_DIR}/kernel/vmlinuz"
INITRAMFS="${SCRIPT_DIR}/initramfs.cpio.gz"

if [ ! -f "$INITRAMFS" ]; then
    echo "Error: initramfs not found. Run 'make' first."
    exit 1
fi

if [ ! -f "$KERNEL" ]; then
    echo "Error: kernel not found at $KERNEL"
    exit 1
fi

echo "Booting QEMU..."
echo "  Kernel:    $KERNEL"
echo "  Initramfs: $INITRAMFS"
echo "  GDB port:  localhost:1234"
echo ""

qemu-system-x86_64 \
    -kernel "$KERNEL" \
    -initrd "$INITRAMFS" \
    -append "console=ttyS0 nokaslr" \
    -nographic \
    -echr 0x11 \
    -m 256M \
    -s \
    -no-reboot
