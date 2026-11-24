#!/bin/sh
# Rebuilds the Btrfs fixtures. Needs root, btrfs-progs, python3, zstd and a kernel
# that mounts Btrfs (WSL2 does):
#   wsl.exe -d kali-linux -u root -- sh make_fixtures.sh <out dir>
# mkfs.btrfs refuses images under about 109 MiB, so the images are that big and
# mostly zeros; pack.py stores only the non-zero chunks.
#   main: crc32c, 16 KiB nodes, default (DUP metadata) profiles, content written
#         under compress-force=zstd, zlib and lzo and then uncompressed.
#   tiny: xxhash64 checksums, 4 KiB nodes, no-holes off, a little content.
set -e
here=$(cd "$(dirname "$0")" && pwd)
out=${1:-$here}
work=$(mktemp -d)
mkdir -p "$work/mnt"
modprobe btrfs 2>/dev/null || true

phase() { # image, mount options, phase name
    mount -o "$2" -t btrfs "$1" "$work/mnt"
    python3 "$here/populate.py" "$work/mnt" "$3"
    sync
    umount "$work/mnt"
}
finish() { # name
    python3 "$here/pack.py" "$work/$1.img" "$work/$1.pack"
    zstd -19 --long=27 -q -f "$work/$1.pack" -o "$out/$1.pack.zst"
}

img="$work/main.img"
truncate -s 109m "$img"
mkfs.btrfs -f -L atlas "$img" > /dev/null
phase "$img" loop,compress-force=zstd zstd
phase "$img" loop,compress-force=zlib zlib
phase "$img" loop,compress-force=lzo lzo
phase "$img" loop,compress=no plain
finish main

img="$work/tiny.img"
truncate -s 109m "$img"
mkfs.btrfs -f -L tiny --csum xxhash -n 4096 -O ^no-holes "$img" > /dev/null
phase "$img" loop tiny
finish tiny
[ -n "$KEEP" ] || rm -rf "$work"; echo "$work"
