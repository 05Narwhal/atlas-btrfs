# Fills a mounted Btrfs with the tree the btrfs tests expect. Run by make_fixtures.sh,
# once per mount phase; the content is written deterministically so the tests can
# regenerate it (text() and rand() have twins in test_image.rs).
# Usage: populate.py <mount point> <phase>
import os
import sys

root, phase = sys.argv[1], sys.argv[2]
T = 1_700_000_000

def text(n, seed):
    """Lines that repeat every 257 lines: compressible, and not one long run."""
    out = bytearray()
    i = 0
    while len(out) < n:
        out += b"line %05d seed %d alpha bravo charlie\n" % ((i * i * seed) % 257, seed)
        i += 1
    return bytes(out[:n])


def rand(n, seed):
    out = bytearray()
    state = (seed * 2654435761 + 1) & 0xFFFFFFFF
    while len(out) < n:
        state ^= (state << 13) & 0xFFFFFFFF
        state ^= state >> 17
        state ^= (state << 5) & 0xFFFFFFFF
        out.append(state & 0xFF)
    return bytes(out)


def pat(n, seed):
    return bytes(((i * 31 + seed) & 0xFF) for i in range(n))


def put(path, data, ns=0):
    full = os.path.join(root, path)
    os.makedirs(os.path.dirname(full), exist_ok=True)
    with open(full, "wb") as f:
        f.write(data)
    t = T * 1_000_000_000 + ns
    os.utime(full, ns=(t, t))


if phase in ("zstd", "zlib", "lzo"):
    seed = {"zstd": 1, "zlib": 2, "lzo": 3}[phase]
    put(f"comp/{phase}.txt", text(140_000, seed))
    put(f"comp/inline-{phase}.txt", text(1_800, seed + 10))
    if phase == "zstd":
        put("comp/rand.bin", rand(3_000, seed))
elif phase == "plain":
    put("hello.txt", b"hello btrfs\n", 123_456_789)
    put("empty", b"")
    put("big.bin", text(100_000, 7))
    put("unicode/héllo wörld.txt", b"unicode")
    put("deep/1/2/3/4/5/6/7/8/9/file.txt", b"deep")
    put("longname/" + "L" * 255, b"long name")
    os.link(os.path.join(root, "hello.txt"), os.path.join(root, "hello-link.txt"))
    os.makedirs(os.path.join(root, "links"))
    os.symlink("../hello.txt", os.path.join(root, "links/short"))
    os.symlink("../sub", os.path.join(root, "links/subdir"))
    os.symlink("nowhere/at/all", os.path.join(root, "links/dangling"))
    os.symlink("/".join(["abcdefgh"] * 44), os.path.join(root, "links/long"))
    os.makedirs(os.path.join(root, "many"))
    for i in range(250):
        os.link(os.path.join(root, "hello.txt"), os.path.join(root, f"many/entry-{i:04d}"))
    # A subvolume with a file in it.
    os.system(f"btrfs subvolume create '{os.path.join(root, 'sub')}' > /dev/null")
    put("sub/inside.txt", b"inside the subvolume")
    # Holes, preallocation, a file bigger than 4 GiB that is nearly all hole.
    with open(os.path.join(root, "holes.bin"), "wb") as f:
        for i in range(0, 64, 8):
            f.seek(i * 4096)
            f.write(pat(4096, i))
    fd = os.open(os.path.join(root, "prealloc.bin"), os.O_CREAT | os.O_RDWR)
    os.posix_fallocate(fd, 0, 65536)
    os.pwrite(fd, pat(4096, 9), 0)
    os.close(fd)
    fd = os.open(os.path.join(root, "huge-sparse.bin"), os.O_CREAT | os.O_RDWR)
    os.ftruncate(fd, 5 * 2**30)
    os.pwrite(fd, pat(4096, 5), 5 * 2**30 - 4096)
    os.close(fd)
elif phase == "tiny":
    put("hello.txt", b"hello btrfs\n", 123_456_789)
    put("text.txt", text(10_000, 11))
    os.symlink("hello.txt", os.path.join(root, "link"))
    # A hole in the middle (explicit hole extents without the no-holes feature).
    with open(os.path.join(root, "holes.bin"), "wb") as f:
        f.write(pat(4096, 1))
        f.seek(5 * 4096)
        f.write(pat(4096, 2))
