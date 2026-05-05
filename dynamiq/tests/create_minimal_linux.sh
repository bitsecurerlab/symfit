#!/usr/bin/env bash
# Create a tiny BusyBox initramfs for qemu-system live tests.
#
# Usage:
#   dynamiq/tests/create_minimal_linux.sh [output-dir]
#
# The default output directory is dynamiq/tests/fixtures, matching the live
# test cache. Override with DYNAMIQ_TEST_FIXTURE_DIR or the positional arg.

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUTPUT_DIR="${1:-${DYNAMIQ_TEST_FIXTURE_DIR:-"$SCRIPT_DIR/fixtures"}}"
OUTPUT_PATH="$OUTPUT_DIR/initramfs.cpio.gz"

usage() {
    sed -n '2,9p' "$0" | sed 's/^# \{0,1\}//'
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
    usage
    exit 0
fi

require_cmd() {
    if ! command -v "$1" >/dev/null 2>&1; then
        echo "ERROR: required command not found: $1" >&2
        exit 1
    fi
}

require_cmd busybox
require_cmd cpio
require_cmd gzip
require_cmd find

mkdir -p "$OUTPUT_DIR"

# Create a temporary working directory
WORK_DIR=$(mktemp -d)
cleanup() {
    rm -rf "$WORK_DIR"
}
trap cleanup EXIT

echo "Creating minimal Linux initramfs in $WORK_DIR..."

# Create directory structure
mkdir -p \
    "$WORK_DIR/rootfs/bin" \
    "$WORK_DIR/rootfs/sbin" \
    "$WORK_DIR/rootfs/etc" \
    "$WORK_DIR/rootfs/proc" \
    "$WORK_DIR/rootfs/sys" \
    "$WORK_DIR/rootfs/dev" \
    "$WORK_DIR/rootfs/tmp" \
    "$WORK_DIR/rootfs/lib"

# Copy busybox
BUSYBOX_PATH="$(command -v busybox)"
cp "$BUSYBOX_PATH" "$WORK_DIR/rootfs/bin/"

# Create symlinks for common commands.
(
    cd "$WORK_DIR/rootfs/bin"
    for cmd in sh ls cat echo mount umount ps kill reboot poweroff sleep; do
        ln -sf busybox "$cmd"
    done
)

# Create init script
cat > "$WORK_DIR/rootfs/init" <<'EOF'
#!/bin/sh
echo "DYNAMIQ_SYSTEM_VM_OK"
echo "Minimal Linux system booted successfully"
mount -t proc proc /proc
mount -t sysfs sysfs /sys
echo "System ready"
while true; do
    echo "Waiting for commands..."
    sleep 1
done
EOF
chmod +x "$WORK_DIR/rootfs/init"

# Create /dev nodes when permitted. The boot still works in many setups if the
# host cannot create device nodes, but warn so the caller knows what happened.
if ! mknod "$WORK_DIR/rootfs/dev/console" c 5 1 2>/dev/null; then
    echo "WARN: could not create /dev/console; rerun with suitable privileges if the guest has no console" >&2
fi
if ! mknod "$WORK_DIR/rootfs/dev/null" c 1 3 2>/dev/null; then
    echo "WARN: could not create /dev/null; rerun with suitable privileges if needed" >&2
fi

# Create initramfs image
(
    cd "$WORK_DIR/rootfs"
    find . -print | cpio -o -H newc 2>/dev/null | gzip -9 > "$WORK_DIR/initramfs.cpio.gz"
)

cp "$WORK_DIR/initramfs.cpio.gz" "$OUTPUT_PATH"

echo "Created initramfs: $OUTPUT_PATH"
echo ""
echo "To use with symfit-system-x86_64:"
echo "  1. Need a Linux kernel (bzImage)"
echo "  2. Command: symfit-system-x86_64 -machine pc -kernel bzImage -initrd '$OUTPUT_PATH' -append 'console=ttyS0' -serial stdio"
echo ""
echo "For the Alpine ISO live test, use test_linux_system.py; it downloads its ISO automatically."
