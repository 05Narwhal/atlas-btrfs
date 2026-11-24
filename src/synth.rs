// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Julian A. Loy.

//! A builder for tiny Btrfs volumes made byte by byte, so the tests can damage
//! one structure at a time and the fuzz seeds fit in the first mebibyte (a
//! real image keeps its trees megabytes in). One chunk maps logical
//! `LOGICAL..` onto device bytes `PHYS..`; every block is 4 KiB.

use super::crc::{crc32c, name_hash};
use super::tree::{CHUNK_ITEM, DIR_INDEX, DIR_ITEM, EXTENT_DATA, INODE_ITEM, Key, ROOT_ITEM};

pub(super) const NODE: usize = 4096;
pub(super) const LOGICAL: u64 = 0x100_0000;
pub(super) const PHYS: u64 = 0x2_0000;
pub(super) const CHUNK_LEN: u64 = 0xC_0000;
pub(super) const SB_AT: usize = 0x1_0000;
pub(super) const FSID: [u8; 16] = *b"synthetic fsid!!";

/// Logical addresses of the blocks.
pub(super) const CHUNK_TREE: u64 = LOGICAL;
pub(super) const ROOT_TREE: u64 = LOGICAL + 0x1000;
pub(super) const FS_TREE: u64 = LOGICAL + 0x2000;
pub(super) const OTHER_TREE: u64 = LOGICAL + 0x3000;
pub(super) const DATA: u64 = LOGICAL + 0x1_0000;

pub(super) fn phys(logical: u64) -> usize {
    usize::try_from(logical - LOGICAL + PHYS).unwrap()
}

fn put(buf: &mut [u8], at: usize, bytes: &[u8]) {
    buf[at..at + bytes.len()].copy_from_slice(bytes);
}

pub(super) fn key_bytes(key: Key) -> [u8; 17] {
    let mut k = [0u8; 17];
    k[..8].copy_from_slice(&key.objectid.to_le_bytes());
    k[8] = key.ty;
    k[9..].copy_from_slice(&key.offset.to_le_bytes());
    k
}

/// Writes the checksum of a block (bytes 0x20 on).
pub(super) fn seal(block: &mut [u8]) {
    let crc = crc32c(&block[0x20..]);
    block[..4].copy_from_slice(&crc.to_le_bytes());
}

fn header(logical: u64, level: u8, nritems: u32) -> Vec<u8> {
    let mut b = vec![0u8; NODE];
    put(&mut b, 0x20, &FSID);
    put(&mut b, 0x30, &logical.to_le_bytes());
    put(&mut b, 0x60, &nritems.to_le_bytes());
    b[0x64] = level;
    b
}

/// A leaf block holding `items`, data packed from the end.
pub(super) fn leaf(logical: u64, items: &[(Key, Vec<u8>)]) -> Vec<u8> {
    let mut b = header(logical, 0, u32::try_from(items.len()).unwrap());
    let mut end = NODE - 101;
    for (i, (key, data)) in items.iter().enumerate() {
        end -= data.len();
        let at = 101 + i * 25;
        put(&mut b, at, &key_bytes(*key));
        put(&mut b, at + 17, &u32::try_from(end).unwrap().to_le_bytes());
        put(
            &mut b,
            at + 21,
            &u32::try_from(data.len()).unwrap().to_le_bytes(),
        );
        put(&mut b, 101 + end, data);
    }
    seal(&mut b);
    b
}

/// An internal block whose children are at `children` (key, address).
pub(super) fn internal(logical: u64, level: u8, children: &[(Key, u64)]) -> Vec<u8> {
    let mut b = header(logical, level, u32::try_from(children.len()).unwrap());
    for (i, (key, child)) in children.iter().enumerate() {
        let at = 101 + i * 33;
        put(&mut b, at, &key_bytes(*key));
        put(&mut b, at + 17, &child.to_le_bytes());
    }
    seal(&mut b);
    b
}

/// A `btrfs_chunk` with one stripe on device 1.
pub(super) fn chunk_item(len: u64, flags: u64, physical: u64) -> Vec<u8> {
    let mut c = vec![0u8; 48 + 32];
    put(&mut c, 0, &len.to_le_bytes());
    put(&mut c, 8, &2u64.to_le_bytes());
    put(&mut c, 16, &65536u64.to_le_bytes());
    put(&mut c, 24, &flags.to_le_bytes());
    put(&mut c, 44, &1u16.to_le_bytes());
    put(&mut c, 48, &1u64.to_le_bytes());
    put(&mut c, 56, &physical.to_le_bytes());
    c
}

/// The bootstrap array entry for a chunk.
pub(super) fn array_entry(logical: u64, chunk: &[u8]) -> Vec<u8> {
    let mut e = key_bytes(Key::new(256, CHUNK_ITEM, logical)).to_vec();
    e.extend_from_slice(chunk);
    e
}

pub(super) fn inode_item(mode: u32, size: u64, nlink: u32) -> Vec<u8> {
    let mut i = vec![0u8; 160];
    put(&mut i, 16, &size.to_le_bytes());
    put(&mut i, 40, &nlink.to_le_bytes());
    put(&mut i, 52, &mode.to_le_bytes());
    // mtime: 1_700_000_000 s, 5 ns.
    put(&mut i, 136, &1_700_000_000u64.to_le_bytes());
    put(&mut i, 144, &5u32.to_le_bytes());
    i
}

pub(super) fn dir_item(name: &[u8], location: Key, ftype: u8) -> Vec<u8> {
    let mut d = vec![0u8; 30];
    put(&mut d, 0, &key_bytes(location));
    put(
        &mut d,
        27,
        &u16::try_from(name.len()).unwrap().to_le_bytes(),
    );
    d[29] = ftype;
    d.extend_from_slice(name);
    d
}

pub(super) fn inline_extent(compression: u8, ram_bytes: u64, payload: &[u8]) -> Vec<u8> {
    let mut e = vec![0u8; 21];
    put(&mut e, 8, &ram_bytes.to_le_bytes());
    e[16] = compression;
    e[20] = 0;
    e.extend_from_slice(payload);
    e
}

pub(super) fn regular_extent(
    compression: u8,
    ram_bytes: u64,
    disk_bytenr: u64,
    disk_num_bytes: u64,
    offset: u64,
    num_bytes: u64,
) -> Vec<u8> {
    let mut e = vec![0u8; 53];
    put(&mut e, 8, &ram_bytes.to_le_bytes());
    e[16] = compression;
    e[20] = 1;
    put(&mut e, 21, &disk_bytenr.to_le_bytes());
    put(&mut e, 29, &disk_num_bytes.to_le_bytes());
    put(&mut e, 37, &offset.to_le_bytes());
    put(&mut e, 45, &num_bytes.to_le_bytes());
    e
}

/// The three items a file in the top folder needs.
pub(super) fn file_entry(name: &[u8], ino: u64, index: u64) -> Vec<(Key, Vec<u8>)> {
    let target = Key::new(ino, INODE_ITEM, 0);
    vec![
        (
            Key::new(256, DIR_ITEM, u64::from(name_hash(name))),
            dir_item(name, target, 1),
        ),
        (Key::new(256, DIR_INDEX, index), dir_item(name, target, 1)),
    ]
}

/// A tiny volume under construction.
pub(super) struct Volume {
    /// Items of the file tree; kept sorted by `image`.
    pub fs_items: Vec<(Key, Vec<u8>)>,
    /// Bytes at logical addresses.
    pub data: Vec<(u64, Vec<u8>)>,
    pub chunk_flags: u64,
    /// Make subvolume 256 the default one (the root tree's `default` entry),
    /// with a single file `other.txt` in it.
    pub other_default: bool,
}

impl Volume {
    /// A top folder with `hello.txt` (inline), `data.bin` (4096 bytes of
    /// pattern) and `lzo.bin` ("hello" in a compressed LZO extent).
    pub fn new() -> Self {
        let mut fs_items = vec![(Key::new(256, INODE_ITEM, 0), inode_item(0o040_755, 0, 1))];
        fs_items.extend(file_entry(b"hello.txt", 257, 2));
        fs_items.extend(file_entry(b"data.bin", 258, 3));
        fs_items.extend(file_entry(b"lzo.bin", 259, 4));
        fs_items.push((Key::new(257, INODE_ITEM, 0), inode_item(0o100_644, 5, 1)));
        fs_items.push((Key::new(257, EXTENT_DATA, 0), inline_extent(0, 5, b"hello")));
        fs_items.push((Key::new(258, INODE_ITEM, 0), inode_item(0o100_644, 4096, 1)));
        fs_items.push((
            Key::new(258, EXTENT_DATA, 0),
            regular_extent(0, 4096, DATA, 4096, 0, 4096),
        ));
        fs_items.push((Key::new(259, INODE_ITEM, 0), inode_item(0o100_644, 5, 1)));
        fs_items.push((
            Key::new(259, EXTENT_DATA, 0),
            regular_extent(2, 5, DATA + 0x1000, 4096, 0, 5),
        ));
        let pattern: Vec<u8> = (0..4096u32).map(|i| (i % 251) as u8).collect();
        let mut lzo = Vec::new();
        let stream: &[u8] = &[22, b'h', b'e', b'l', b'l', b'o', 17, 0, 0];
        lzo.extend_from_slice(&u32::try_from(8 + stream.len()).unwrap().to_le_bytes());
        lzo.extend_from_slice(&u32::try_from(stream.len()).unwrap().to_le_bytes());
        lzo.extend_from_slice(stream);
        Self {
            fs_items,
            data: vec![(DATA, pattern), (DATA + 0x1000, lzo)],
            chunk_flags: 1 | 2 | 4,
            other_default: false,
        }
    }

    /// The bytes of the device.
    pub fn image(mut self) -> Vec<u8> {
        self.fs_items.sort_by_key(|(k, _)| *k);
        let total = usize::try_from(PHYS + CHUNK_LEN).unwrap();
        let mut img = vec![0u8; total];
        let chunk = chunk_item(CHUNK_LEN, self.chunk_flags, PHYS);
        let mut root_item = vec![0u8; 439];
        put(&mut root_item, 168, &256u64.to_le_bytes());
        put(&mut root_item, 176, &FS_TREE.to_le_bytes());
        let mut root_items = vec![(Key::new(5, ROOT_ITEM, 0), root_item.clone())];
        let mut other_block = Vec::new();
        if self.other_default {
            let mut other_root = root_item;
            put(&mut other_root, 176, &OTHER_TREE.to_le_bytes());
            root_items.push((
                Key::new(6, DIR_ITEM, u64::from(name_hash(b"default"))),
                dir_item(b"default", Key::new(256, ROOT_ITEM, u64::MAX), 2),
            ));
            root_items.push((Key::new(256, ROOT_ITEM, 0), other_root));
            let mut items = vec![(Key::new(256, INODE_ITEM, 0), inode_item(0o040_755, 0, 1))];
            items.extend(file_entry(b"other.txt", 257, 2));
            items.push((Key::new(257, INODE_ITEM, 0), inode_item(0o100_644, 5, 1)));
            items.push((Key::new(257, EXTENT_DATA, 0), inline_extent(0, 5, b"other")));
            other_block = leaf(OTHER_TREE, &items);
        }
        let mut blocks = vec![
            (
                CHUNK_TREE,
                leaf(
                    CHUNK_TREE,
                    &[(Key::new(256, CHUNK_ITEM, LOGICAL), chunk.clone())],
                ),
            ),
            (ROOT_TREE, leaf(ROOT_TREE, &root_items)),
            (FS_TREE, leaf(FS_TREE, &self.fs_items)),
        ];
        if self.other_default {
            blocks.push((OTHER_TREE, other_block));
        }
        for (logical, block) in blocks {
            let at = phys(logical);
            put(&mut img, at, &block);
        }
        for (logical, bytes) in &self.data {
            put(&mut img, phys(*logical), bytes);
        }
        let array = array_entry(LOGICAL, &chunk);
        let mut sb = vec![0u8; 4096];
        put(&mut sb, 0x20, &FSID);
        put(&mut sb, 0x30, &(SB_AT as u64).to_le_bytes());
        put(&mut sb, 0x40, b"_BHRfS_M");
        put(&mut sb, 0x48, &7u64.to_le_bytes());
        put(&mut sb, 0x50, &ROOT_TREE.to_le_bytes());
        put(&mut sb, 0x58, &CHUNK_TREE.to_le_bytes());
        put(&mut sb, 0x70, &(PHYS + CHUNK_LEN).to_le_bytes());
        put(&mut sb, 0x78, &0x4000u64.to_le_bytes());
        put(&mut sb, 0x80, &6u64.to_le_bytes());
        put(&mut sb, 0x88, &1u64.to_le_bytes());
        put(&mut sb, 0x90, &4096u32.to_le_bytes());
        put(&mut sb, 0x94, &4096u32.to_le_bytes());
        put(&mut sb, 0x98, &4096u32.to_le_bytes());
        put(&mut sb, 0x9C, &4096u32.to_le_bytes());
        put(
            &mut sb,
            0xA0,
            &u32::try_from(array.len()).unwrap().to_le_bytes(),
        );
        put(&mut sb, 0xC9, &1u64.to_le_bytes());
        put(&mut sb, 0x12B, b"synth");
        put(&mut sb, 0x32B, &array);
        seal(&mut sb);
        put(&mut img, SB_AT, &sb);
        img
    }
}

/// Recomputes the superblock checksum after a test changed a field.
pub(super) fn reseal_sb(img: &mut [u8]) {
    seal(&mut img[SB_AT..SB_AT + 4096]);
}

/// Recomputes the checksum of the block at `logical`.
pub(super) fn reseal(img: &mut [u8], logical: u64) {
    let at = phys(logical);
    seal(&mut img[at..at + NODE]);
}
