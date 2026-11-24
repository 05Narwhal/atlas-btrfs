// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Julian A. Loy.

use std::collections::BTreeSet;

use super::synth::{self, Volume};
use super::test_image::{MTIME, Patched, load, pat, rand, text};
use super::*;
use atlas_fs_core::fs::Timestamp;

fn mounted(name: &str) -> Btrfs {
    mount(load(name)).unwrap_or_else(|e| panic!("{name}: {e}"))
}

type Listed = Vec<(String, NodeId, NodeKind, Option<u64>, EntryFlags)>;

fn list(fs: &Btrfs, dir: NodeId) -> Listed {
    let mut stream = fs.read_dir(dir).unwrap();
    let mut batch = DirBatch::default();
    let mut out = Vec::new();
    loop {
        batch.clear();
        let progress = stream.next_batch(&mut batch, 7).unwrap();
        out.extend(
            batch
                .iter()
                .map(|e| (e.name.to_owned(), e.node, e.kind, e.size, e.flags)),
        );
        if progress == DirProgress::Done {
            return out;
        }
    }
}

fn names(fs: &Btrfs, dir: NodeId) -> BTreeSet<String> {
    list(fs, dir).into_iter().map(|e| e.0).collect()
}

fn walk_to(fs: &Btrfs, path: &str) -> NodeId {
    let mut node = fs.root();
    for part in path.split('/') {
        node = fs
            .lookup(node, part)
            .unwrap()
            .unwrap_or_else(|| panic!("{path}: no {part}"));
    }
    node
}

fn read_all(fs: &Btrfs, path: &str) -> Vec<u8> {
    let source = fs.open(walk_to(fs, path), Stream::Data).unwrap();
    let mut buf = vec![0u8; usize::try_from(source.len()).unwrap()];
    source.read_at(0, &mut buf).unwrap();
    buf
}

/// The compression type of every extent record of the file at `path`.
fn compressions(fs: &Btrfs, path: &str) -> Vec<u8> {
    let loc = fs.inner.unpack(walk_to(fs, path)).unwrap();
    let root = fs.inner.subvol(loc.root).unwrap().unwrap();
    let mut out = Vec::new();
    let mut cursor = fs
        .inner
        .trees
        .seek_ge(root, Key::new(loc.ino, tree::EXTENT_DATA, 0))
        .unwrap();
    while let Some(c) = cursor.as_mut() {
        let (key, data) = c.item().unwrap();
        if key.objectid != loc.ino || key.ty != tree::EXTENT_DATA {
            break;
        }
        out.push(data[16]);
        if !c.next().unwrap() {
            break;
        }
    }
    out
}

#[test]
fn real_volume_lists_and_reads_plain_files() {
    let fs = mounted("main");
    let info = fs.info();
    assert_eq!(info.name, "atlas");
    assert_eq!(info.format, Some("Btrfs"));
    assert_eq!(info.total_bytes, Some(114_294_784));
    assert!(fs.identity().is_some());
    assert_eq!(fs.checksum_kind(), ChecksumKind::Crc32c);
    assert!(fs.checksums_verified());
    assert_eq!(fs.root(), NodeId(256));

    let root = list(&fs, fs.root());
    let by_name = |n: &str| {
        root.iter()
            .find(|e| e.0 == n)
            .unwrap_or_else(|| panic!("{n}"))
    };
    assert_eq!(by_name("hello.txt").2, NodeKind::File);
    assert_eq!(by_name("hello.txt").3, Some(12));
    assert_eq!(by_name("comp").2, NodeKind::Directory);
    assert_eq!(by_name("comp").3, None);
    assert_eq!(by_name("empty").3, Some(0));
    assert_eq!(by_name("sub").2, NodeKind::Directory);
    assert_eq!(root.len(), 14, "{:?}", names(&fs, fs.root()));

    let hello = walk_to(&fs, "hello.txt");
    assert_eq!(read_all(&fs, "hello.txt"), b"hello btrfs\n");
    assert_eq!(walk_to(&fs, "hello-link.txt"), hello);
    // hello.txt, hello-link.txt and 250 entries of many/.
    assert_eq!(fs.link_count(hello).unwrap(), 252);
    let meta = fs.metadata(hello).unwrap();
    assert_eq!(
        meta.modified,
        Some(Timestamp::from_unix(MTIME, 123_456_789))
    );
    assert_eq!(meta.size, Some(12));
    assert!(meta.created.is_some());
    assert!(meta.owner.is_some_and(|o| o.mode & 0o170_000 == 0o100_000));

    assert_eq!(read_all(&fs, "big.bin"), text(100_000, 7));
    assert_eq!(read_all(&fs, "unicode/héllo wörld.txt"), b"unicode");
    assert_eq!(read_all(&fs, "deep/1/2/3/4/5/6/7/8/9/file.txt"), b"deep");
    assert_eq!(read_all(&fs, "empty"), b"");
    let long = "L".repeat(255);
    assert_eq!(
        names(&fs, walk_to(&fs, "longname")),
        BTreeSet::from([long.clone()])
    );
    assert_eq!(read_all(&fs, &format!("longname/{long}")), b"long name");

    assert!(matches!(
        fs.open(hello, Stream::Resource),
        Err(Error::NoSuchStream { .. })
    ));
    assert!(matches!(
        fs.open(fs.root(), Stream::Data),
        Err(Error::IsADirectory { .. })
    ));
    assert!(matches!(
        fs.metadata(NodeId(u64::MAX)),
        Err(Error::NotFound { .. })
    ));
    assert!(matches!(
        fs.metadata(NodeId(0)),
        Err(Error::NotFound { .. })
    ));
    assert_eq!(fs.lookup(fs.root(), "nope").unwrap(), None);
    assert!(matches!(
        fs.lookup(hello, "x"),
        Err(Error::NotADirectory { .. })
    ));
}

#[test]
fn every_compression_decodes() {
    let fs = mounted("main");
    for (algorithm, code, seed) in [("zstd", 3u8, 1u64), ("zlib", 1, 2), ("lzo", 2, 3)] {
        let big = format!("comp/{algorithm}.txt");
        // 140000 bytes: two extents (128 KiB, then the rest), both compressed.
        assert_eq!(compressions(&fs, &big), vec![code, code], "{algorithm}");
        assert_eq!(read_all(&fs, &big), text(140_000, seed), "{algorithm}");
        let runs = fs.extents(walk_to(&fs, &big), Stream::Data).unwrap();
        assert!(!runs.is_empty());
        assert!(runs.iter().map(|r| r.len).sum::<u64>() < 140_000);

        // A small file compressed inside its tree item.
        let small = format!("comp/inline-{algorithm}.txt");
        assert_eq!(compressions(&fs, &small), vec![code], "{algorithm}");
        assert_eq!(read_all(&fs, &small), text(1_800, seed + 10), "{algorithm}");
        assert!(
            fs.extents(walk_to(&fs, &small), Stream::Data)
                .unwrap()
                .is_empty()
        );

        // A read that starts and ends inside different extents.
        let source = fs.open(walk_to(&fs, &big), Stream::Data).unwrap();
        let mut across = vec![0u8; 10_000];
        source.read_at(125_000, &mut across).unwrap();
        assert_eq!(across, text(140_000, seed)[125_000..135_000], "{algorithm}");
    }
    // Data that does not compress is stored as it is.
    assert_eq!(compressions(&fs, "comp/rand.bin"), vec![0]);
    assert_eq!(read_all(&fs, "comp/rand.bin"), rand(3_000, 1));
}

#[test]
fn links_subvolumes_and_big_directories() {
    let fs = mounted("main");
    let target = |path: &str| {
        let meta = fs.metadata(walk_to(&fs, path)).unwrap();
        assert_eq!(meta.kind, NodeKind::Symlink, "{path}");
        meta.link_target.unwrap()
    };
    assert_eq!(target("links/short"), "../hello.txt");
    assert_eq!(target("links/subdir"), "../sub");
    assert_eq!(target("links/dangling"), "nowhere/at/all");
    let long = ["abcdefgh"; 44].join("/");
    assert_eq!(target("links/long"), long);
    assert_eq!(read_all(&fs, "links/long"), long.as_bytes());
    assert_eq!(read_all(&fs, "links/short"), b"../hello.txt");

    let links = list(&fs, walk_to(&fs, "links"));
    let flag = |n: &str| links.iter().find(|e| e.0 == n).unwrap().4;
    // A link to a folder in another subvolume.
    assert!(flag("subdir").contains(EntryFlags::LINKS_TO_DIRECTORY));
    assert!(!flag("short").contains(EntryFlags::LINKS_TO_DIRECTORY));
    assert!(!flag("dangling").contains(EntryFlags::LINKS_TO_DIRECTORY));
    let subdir = walk_to(&fs, "links/subdir");
    assert!(
        fs.metadata(subdir)
            .unwrap()
            .flags
            .contains(EntryFlags::LINKS_TO_DIRECTORY)
    );
    assert_eq!(
        names(&fs, subdir),
        BTreeSet::from(["inside.txt".to_owned()])
    );
    assert!(matches!(
        fs.read_dir(walk_to(&fs, "links/dangling")),
        Err(Error::NotADirectory { .. })
    ));

    // The subvolume is a folder with its own tree and node ids.
    let sub = walk_to(&fs, "sub");
    assert_eq!(sub, NodeId((256 << 40) | 256));
    assert_eq!(fs.metadata(sub).unwrap().kind, NodeKind::Directory);
    assert_eq!(read_all(&fs, "sub/inside.txt"), b"inside the subvolume");
    assert_eq!(walk_to(&fs, "sub/inside.txt").0 >> 40, 256);

    // 250 names, listed in batches of 7, found by hash.
    let many: BTreeSet<String> = (0..250).map(|i| format!("entry-{i:04}")).collect();
    let many_dir = walk_to(&fs, "many");
    let listed = list(&fs, many_dir);
    assert_eq!(listed.len(), 250);
    assert_eq!(
        listed.iter().map(|e| e.0.clone()).collect::<BTreeSet<_>>(),
        many
    );
    // In index order: the order the names were created in.
    assert_eq!(listed[0].0, "entry-0000");
    assert_eq!(listed[249].0, "entry-0249");
    assert!(fs.lookup(many_dir, "entry-0249").unwrap().is_some());
    assert!(fs.lookup(many_dir, "entry-0250").unwrap().is_none());
    assert!(listed.iter().all(|e| e.1 == walk_to(&fs, "hello.txt")));
}

#[test]
fn holes_preallocation_and_huge_sparse_files() {
    let fs = mounted("main");
    let holes = read_all(&fs, "holes.bin");
    assert_eq!(holes.len(), 57 * 4096);
    for block in 0..57usize {
        let got = &holes[block * 4096..(block + 1) * 4096];
        if block % 8 == 0 {
            assert_eq!(got, pat(4096, block as u8), "block {block}");
        } else {
            assert!(got.iter().all(|&b| b == 0), "block {block}");
        }
    }
    // Preallocated: the first block written, the rest reads as zeros but
    // still holds disk space.
    let prealloc = read_all(&fs, "prealloc.bin");
    assert_eq!(prealloc.len(), 65_536);
    assert_eq!(prealloc[..4096], pat(4096, 9)[..]);
    assert!(prealloc[4096..].iter().all(|&b| b == 0));
    let on_disk: u64 = fs
        .extents(walk_to(&fs, "prealloc.bin"), Stream::Data)
        .unwrap()
        .iter()
        .map(|e| e.len)
        .sum();
    assert_eq!(on_disk, 65_536);

    // 5 GiB, nearly all hole.
    let huge = fs
        .open(walk_to(&fs, "huge-sparse.bin"), Stream::Data)
        .unwrap();
    let five_gib = 5u64 << 30;
    assert_eq!(huge.len(), five_gib);
    let mut tail = vec![0u8; 8192];
    huge.read_at(five_gib - 8192, &mut tail).unwrap();
    assert!(tail[..4096].iter().all(|&b| b == 0));
    assert_eq!(tail[4096..], pat(4096, 5)[..]);
    let mut head = vec![1u8; 4096];
    huge.read_at(4 << 30, &mut head).unwrap();
    assert!(head.iter().all(|&b| b == 0));
    assert!(huge.read_at(five_gib - 1, &mut [0u8; 2]).is_err());
}

#[test]
fn xxhash_volume_mounts_with_blocks_unverified() {
    let fs = mounted("tiny");
    assert_eq!(fs.info().name, "tiny");
    assert_eq!(fs.checksum_kind(), ChecksumKind::XxHash64);
    assert!(!fs.checksums_verified());
    assert_eq!(read_all(&fs, "hello.txt"), b"hello btrfs\n");
    assert_eq!(read_all(&fs, "text.txt"), text(10_000, 11));
    assert_eq!(
        fs.metadata(walk_to(&fs, "link"))
            .unwrap()
            .link_target
            .as_deref(),
        Some("hello.txt")
    );
    // Written with explicit hole extents (no-holes is off).
    let holes = read_all(&fs, "holes.bin");
    assert_eq!(holes.len(), 6 * 4096);
    assert_eq!(holes[..4096], pat(4096, 1)[..]);
    assert!(holes[4096..5 * 4096].iter().all(|&b| b == 0));
    assert_eq!(holes[5 * 4096..], pat(4096, 2)[..]);
    let runs = fs.extents(walk_to(&fs, "holes.bin"), Stream::Data).unwrap();
    assert_eq!(runs.iter().map(|r| r.len).sum::<u64>(), 2 * 4096);
}

fn mount_bytes(bytes: Vec<u8>) -> Result<Btrfs> {
    mount(Arc::new(MemSource::new(bytes)))
}

fn message(result: Result<Btrfs>) -> String {
    match result {
        Ok(_) => panic!("expected an error"),
        Err(e) => e.to_string(),
    }
}

#[test]
fn synthetic_volume_mounts_and_reads() {
    let fs = mount_bytes(Volume::new().image()).unwrap();
    assert_eq!(fs.info().name, "synth");
    assert_eq!(
        names(&fs, fs.root()),
        BTreeSet::from(["hello.txt", "data.bin", "lzo.bin"].map(String::from))
    );
    assert_eq!(read_all(&fs, "hello.txt"), b"hello");
    assert_eq!(read_all(&fs, "lzo.bin"), b"hello");
    let data = read_all(&fs, "data.bin");
    assert_eq!(data.len(), 4096);
    assert_eq!(data[251], 0);
    assert_eq!(data[250], 250);
}

#[test]
fn the_default_subvolume_is_the_one_the_root_tree_names() {
    let mut volume = Volume::new();
    volume.other_default = true;
    let fs = mount_bytes(volume.image()).unwrap();
    assert_eq!(fs.inner.default_root, 256);
    assert_eq!(fs.root(), NodeId(256));
    assert_eq!(
        names(&fs, fs.root()),
        BTreeSet::from(["other.txt".to_owned()])
    );
    assert_eq!(read_all(&fs, "other.txt"), b"other");
    // Subvolume 5 is no longer the default, so it takes a packed id.
    let loc = Loc { root: 5, ino: 256 };
    assert_eq!(fs.inner.pack(loc), Some(NodeId((5 << 40) | 256)));
    assert_eq!(
        names(&fs, NodeId((5 << 40) | 256)).len(),
        3,
        "the old default subvolume still lists"
    );
}

#[test]
fn hostile_superblocks_are_refused() {
    let good = Volume::new().image();
    // Cut short: no complete superblock.
    assert!(mount_bytes(good[..synth::SB_AT + 100].to_vec()).is_err());
    assert!(mount_bytes(Vec::new()).is_err());
    assert!(mount_bytes(vec![0u8; 1 << 20]).is_err());

    // A flipped byte without a new checksum.
    let mut bad = good.clone();
    bad[synth::SB_AT + 0x130] ^= 1;
    assert!(message(mount_bytes(bad)).contains("checksum"));

    // Each field that must stay inside its limits, with a valid checksum.
    let fields: &[(usize, &[u8], &str)] = &[
        (0x88, &2u64.to_le_bytes(), "device"),
        (0x90, &3000u32.to_le_bytes(), "sectorsize"),
        (0x94, &(1u32 << 20).to_le_bytes(), "nodesize"),
        (0x94, &2048u32.to_le_bytes(), "nodesize"),
        (0x50, &0u64.to_le_bytes(), "root"),
        (0x58, &123u64.to_le_bytes(), "chunk_root"),
        (0xA0, &5000u32.to_le_bytes(), "sys_chunk_array_size"),
        (0xC6, &[9u8], "root_level"),
        (0xC4, &9u16.to_le_bytes(), "csum_type"),
        (0xBC, &(1u64 << 30).to_le_bytes(), "incompatible"),
        (0x30, &1u64.to_le_bytes(), "bytenr"),
    ];
    for (at, bytes, what) in fields {
        let mut img = good.clone();
        img[synth::SB_AT + at..synth::SB_AT + at + bytes.len()].copy_from_slice(bytes);
        synth::reseal_sb(&mut img);
        let msg = message(mount_bytes(img));
        assert!(msg.contains(what), "{what}: {msg}");
    }

    // A bootstrap array that lies: too short for its chunk, an entry that
    // is not a chunk, a chunk of no length, two chunks that overlap.
    let array_at = synth::SB_AT + 0x32B;
    for case in 0..4 {
        let mut img = good.clone();
        match case {
            0 => {
                img[synth::SB_AT + 0xA0..synth::SB_AT + 0xA4].copy_from_slice(&40u32.to_le_bytes())
            }
            1 => img[array_at + 8] = 1,
            2 => img[array_at + 17..array_at + 25].copy_from_slice(&0u64.to_le_bytes()),
            _ => {
                let one =
                    synth::array_entry(synth::LOGICAL + 0x1000, &synth::chunk_item(0x4000, 1, 0));
                let at = 17 + 80;
                img[array_at + at..array_at + at + one.len()].copy_from_slice(&one);
                let size = u32::try_from(at + one.len()).unwrap();
                img[synth::SB_AT + 0xA0..synth::SB_AT + 0xA4].copy_from_slice(&size.to_le_bytes());
            }
        }
        synth::reseal_sb(&mut img);
        assert!(mount_bytes(img).is_err(), "case {case}");
    }
    // The striped profiles are named, not misread.
    let mut raid0 = Volume::new();
    raid0.chunk_flags = 1 | 8;
    assert!(message(mount_bytes(raid0.image())).contains("RAID0"));
}

#[test]
fn hostile_trees_fail_without_hanging() {
    let good = Volume::new().image();
    let fs_at = synth::phys(synth::FS_TREE);
    let root_at = synth::phys(synth::ROOT_TREE);

    // A block that points at itself: the child must be one level lower, so
    // the walk ends with an error.
    let mut img = good.clone();
    let looped = synth::internal(synth::FS_TREE, 1, &[(Key::new(0, 0, 0), synth::FS_TREE)]);
    img[fs_at..fs_at + synth::NODE].copy_from_slice(&looped);
    // The root item says the tree is one level deep.
    img[root_at + synth::NODE - 439 + 238] = 1;
    synth::reseal(&mut img, synth::ROOT_TREE);
    assert!(mount_bytes(img.clone()).is_err());
    // And a child that is one level too high.
    img[root_at + synth::NODE - 439 + 238] = 2;
    synth::reseal(&mut img, synth::ROOT_TREE);
    assert!(mount_bytes(img).is_err());

    // An item count that cannot fit in the block.
    let mut img = good.clone();
    img[fs_at + 0x60..fs_at + 0x64].copy_from_slice(&0x00FF_FFFFu32.to_le_bytes());
    synth::reseal(&mut img, synth::FS_TREE);
    assert!(mount_bytes(img).is_err());

    // An item whose data lies outside the block, and one that overlaps the
    // item headers.
    for offset in [u32::MAX, 0xFFF0, 4] {
        let mut img = good.clone();
        img[fs_at + 101 + 17..fs_at + 101 + 21].copy_from_slice(&offset.to_le_bytes());
        synth::reseal(&mut img, synth::FS_TREE);
        assert!(mount_bytes(img).is_err(), "offset {offset}");
    }

    // Keys out of order.
    let mut volume = Volume::new();
    volume.fs_items.reverse();
    let mut img = good.clone();
    let unsorted = synth::leaf(synth::FS_TREE, &volume.fs_items);
    img[fs_at..fs_at + synth::NODE].copy_from_slice(&unsorted);
    assert!(mount_bytes(img).is_err());

    // A block that is valid but sits at the wrong address, or belongs to
    // another volume.
    let mut img = good.clone();
    img[fs_at + 0x30..fs_at + 0x38].copy_from_slice(&(synth::FS_TREE + 0x1000).to_le_bytes());
    synth::reseal(&mut img, synth::FS_TREE);
    assert!(mount_bytes(img).is_err());
    let mut img = good.clone();
    img[fs_at + 0x20] ^= 0xFF;
    synth::reseal(&mut img, synth::FS_TREE);
    assert!(mount_bytes(img).is_err());

    // A pointer past the chunk, into the gap, or unaligned.
    for ptr in [
        synth::LOGICAL + synth::CHUNK_LEN,
        1,
        synth::FS_TREE + 7,
        u64::MAX,
    ] {
        let mut img = good.clone();
        let internal = synth::internal(synth::FS_TREE, 1, &[(Key::new(0, 0, 0), ptr)]);
        img[fs_at..fs_at + synth::NODE].copy_from_slice(&internal);
        img[root_at + synth::NODE - 439 + 238] = 1;
        synth::reseal(&mut img, synth::ROOT_TREE);
        assert!(mount_bytes(img).is_err(), "pointer {ptr:#x}");
    }
}

/// A volume whose `data.bin` has the extent `record`.
fn with_extent(record: Vec<u8>, size: u64) -> Btrfs {
    let mut volume = Volume::new();
    for (key, data) in &mut volume.fs_items {
        if *key == Key::new(258, tree::EXTENT_DATA, 0) {
            *data = record.clone();
        }
        if *key == Key::new(258, tree::INODE_ITEM, 0) {
            *data = synth::inode_item(0o100_644, size, 1);
        }
    }
    mount_bytes(volume.image()).unwrap()
}

#[test]
fn hostile_extents_fail_at_the_read() {
    use synth::{DATA, regular_extent};
    let read = |fs: &Btrfs| {
        let source = fs.open(walk_to(fs, "data.bin"), Stream::Data).unwrap();
        let mut buf = vec![0u8; usize::try_from(source.len().min(8192)).unwrap()];
        source.read_at(0, &mut buf).map(|()| buf)
    };

    // The plain extent is fine.
    assert!(
        read(&with_extent(
            regular_extent(0, 4096, DATA, 4096, 0, 4096),
            4096
        ))
        .is_ok()
    );
    // Longer than the space it claims, and than the volume.
    for (disk_num, num) in [(4096, 8192), (4096, u64::MAX)] {
        let fs = with_extent(regular_extent(0, num, DATA, disk_num, 0, num), 4096);
        assert!(read(&fs).is_err(), "{disk_num} {num}");
        assert!(fs.extents(walk_to(&fs, "data.bin"), Stream::Data).is_err());
    }
    // An extent that claims more than the volume holds: the part that is
    // there reads, the run does not map.
    let huge = u64::MAX / 2;
    let fs = with_extent(regular_extent(0, huge, DATA, huge, 0, huge), 4096);
    assert!(read(&fs).is_ok());
    assert!(fs.extents(walk_to(&fs, "data.bin"), Stream::Data).is_err());
    // An address in no chunk.
    let fs = with_extent(regular_extent(0, 4096, 0x40_0000, 4096, 0, 4096), 4096);
    assert!(read(&fs).is_err());
    // An offset that overflows with the length.
    let fs = with_extent(regular_extent(0, 4096, DATA, 4096, u64::MAX - 5, 100), 4096);
    assert!(read(&fs).is_err());
    // Zero length.
    let fs = with_extent(regular_extent(0, 0, DATA, 4096, 0, 0), 4096);
    assert!(read(&fs).is_err());
    // A decoded size past the 128 KiB rule, an encoded one far past it,
    // encryption, an unknown compression, an unknown type.
    let fs = with_extent(regular_extent(1, 1 << 30, DATA, 4096, 0, 4096), 4096);
    assert!(read(&fs).is_err());
    let fs = with_extent(regular_extent(1, 1 << 17, DATA, 1 << 30, 0, 4096), 4096);
    assert!(read(&fs).is_err());
    let mut record = regular_extent(0, 4096, DATA, 4096, 0, 4096);
    record[17] = 1;
    assert!(read(&with_extent(record, 4096)).is_err());
    assert!(
        read(&with_extent(
            regular_extent(9, 4096, DATA, 4096, 0, 4096),
            4096
        ))
        .is_err()
    );
    let mut record = regular_extent(0, 4096, DATA, 4096, 0, 4096);
    record[20] = 77;
    assert!(read(&with_extent(record, 4096)).is_err());
    // Too short to be an extent at all.
    assert!(read(&with_extent(vec![0u8; 18], 4096)).is_err());
    // Compressed data that is not: every codec, junk and a lying length.
    for (code, junk) in [
        (1u8, vec![0x78u8, 0x9C, 0xFF, 0xFF, 0xFF, 0xFF, 1, 2, 3]),
        (3, vec![0x28, 0xB5, 0x2F, 0xFD, 1, 2, 3, 4, 5, 6]),
        (2, vec![0xFF; 64]),
        (2, vec![200, 0, 0, 0, 4, 0, 0, 0, 1, 2, 3, 4]),
        (2, vec![12, 0, 0, 0, 250, 0, 0, 0, 22, 1, 2, 3]),
        (2, vec![12, 0, 0, 0, 8, 0, 0, 0, 64, 255, 17, 0]),
        (2, vec![0, 0, 0, 0]),
    ] {
        let mut volume = Volume::new();
        volume.data[0].1 = junk;
        for (key, data) in &mut volume.fs_items {
            if *key == Key::new(258, tree::EXTENT_DATA, 0) {
                *data = regular_extent(code, 4096, DATA, 4096, 0, 4096);
            }
        }
        let fs = mount_bytes(volume.image()).unwrap();
        assert!(read(&fs).is_err(), "codec {code}");
    }
    // A hole file the size of the world reads as zeros without allocating.
    let fs = with_extent(regular_extent(0, 4096, 0, 0, 0, 4096), 1 << 62);
    let source = fs.open(walk_to(&fs, "data.bin"), Stream::Data).unwrap();
    let mut buf = vec![7u8; 100];
    source.read_at((1 << 62) - 100, &mut buf).unwrap();
    assert!(buf.iter().all(|&b| b == 0));
}

/// Lists, looks up, describes and reads what it can of `fs`, within bounds.
fn exercise(fs: &Btrfs) {
    let mut budget = 300usize;
    let mut stack = vec![(fs.root(), 0usize)];
    let mut buf = vec![0u8; 8192];
    while let Some((dir, depth)) = stack.pop() {
        let Ok(mut stream) = fs.read_dir(dir) else {
            continue;
        };
        let mut batch = DirBatch::default();
        loop {
            batch.clear();
            let progress = stream.next_batch(&mut batch, 64);
            for entry in batch.iter() {
                if budget == 0 {
                    return;
                }
                budget -= 1;
                let _ = fs.lookup(dir, entry.name);
                let _ = fs.metadata(entry.node);
                let _ = fs.extents(entry.node, Stream::Data);
                if let Ok(source) = fs.open(entry.node, Stream::Data) {
                    let n = usize::try_from(source.len()).unwrap_or(0).min(buf.len());
                    let _ = source.read_at(0, &mut buf[..n]);
                    let _ = source.read_at(source.len().saturating_sub(8), &mut buf[..8.min(n)]);
                }
                if entry.is_browsable() && depth < 4 {
                    stack.push((entry.node, depth + 1));
                }
            }
            match progress {
                Ok(DirProgress::More) => {}
                Ok(DirProgress::Done) | Err(_) => break,
            }
        }
    }
}

/// A small deterministic generator: the cases are the same every run.
fn generator() -> impl FnMut() -> u64 {
    let mut state = 0x9E37_79B9_7F4A_7C15u64;
    move || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    }
}

#[test]
fn damaged_synthetic_volumes_fail_without_panicking() {
    let good = Volume::new().image();
    let mut next = generator();
    let blocks = [synth::CHUNK_TREE, synth::ROOT_TREE, synth::FS_TREE];
    let mut mounted_ok = 0;
    for _ in 0..400 {
        let mut img = good.clone();
        for _ in 0..=(next() % 3) {
            let block = blocks[(next() % 3) as usize];
            // Damage the used part of a block, then make its checksum
            // match, so the structure checks have to catch it.
            let at = synth::phys(block) + (next() % synth::NODE as u64) as usize;
            img[at] ^= (next() % 255) as u8 + 1;
        }
        for block in blocks {
            synth::reseal(&mut img, block);
        }
        if let Ok(fs) = mount_bytes(img) {
            mounted_ok += 1;
            exercise(&fs);
        }
    }
    assert!(mounted_ok > 0);
    // Every cut of the image.
    for cut in (0..good.len()).step_by(997) {
        let _ = mount_bytes(good[..cut].to_vec());
    }
    // And damage to the very first bytes of the superblock.
    for at in 0..0x400usize {
        let mut img = good.clone();
        img[synth::SB_AT + at] ^= 0xFF;
        synth::reseal_sb(&mut img);
        let _ = mount_bytes(img);
    }
}

#[test]
fn damaged_real_volumes_fail_without_panicking() {
    let mut next = generator();
    let mut mounted_ok = 0;
    // The xxhash volume is not checksummed here, so the damage reaches the
    // parsers; the crc32c volume's damage mostly stops at the checksum.
    for (name, cases) in [("tiny", 200), ("main", 40)] {
        let base = load(name);
        let spans = base.spans();
        let total: usize = spans.iter().map(|s| s.1).sum();
        for case in 0..cases {
            let mut patches = Vec::new();
            for _ in 0..=(next() % 4) {
                let mut pick = (next() % total as u64) as usize;
                for &(offset, len) in &spans {
                    if pick < len {
                        patches.push((offset + pick as u64, (next() % 255) as u8 + 1));
                        break;
                    }
                    pick -= len;
                }
            }
            // Every tenth case also cuts the image short.
            let len = if case % 10 == 9 {
                next() % base.len()
            } else {
                base.len()
            };
            let source = Arc::new(Patched {
                base: base.clone(),
                patches,
                len,
            });
            if let Ok(fs) = mount(source) {
                mounted_ok += 1;
                exercise(&fs);
            }
        }
    }
    assert!(mounted_ok > 0);
    // A damaged primary superblock falls back to the copy at 64 MiB.
    let source = Arc::new(Patched {
        base: load("main"),
        patches: vec![(0x1_0100, 0xFF)],
        len: load("main").len(),
    });
    assert!(mount(source).is_ok());
    // Without that copy the volume is refused.
    let source = Arc::new(Patched {
        base: load("main"),
        patches: vec![(0x1_0100, 0xFF)],
        len: 40 << 20,
    });
    assert!(mount(source).is_err());
}
