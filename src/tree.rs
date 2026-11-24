// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Julian A. Loy.

//! Btrfs B-trees: node reading and checking, and a cursor that walks the
//! items of a tree in key order.
//!
//! Every node is checked when it is read (address, owner, checksum, level,
//! item counts and bounds, key order), so the accessors can rely on the
//! shape. A child must be exactly one level below its parent, which bounds
//! the depth at 8 and rules out loops; keys must strictly increase as a
//! cursor moves, which bounds a walk by what the volume holds.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use super::bytes::{le32, le64, slice, u8_at, uuid_at};
use super::chunk::ChunkMap;
use super::crc::crc32c;
use super::sb::{ChecksumKind, Superblock, TreeRoot};
use super::{bad_crc, invalid, limit, other, out_of_range};
use atlas_fs_core::error::{CorruptKind, Corruption, Location, Result};
use atlas_fs_core::io::block::BlockSource;

pub(super) const INODE_ITEM: u8 = 1;
pub(super) const INODE_REF: u8 = 12;
pub(super) const DIR_ITEM: u8 = 84;
pub(super) const DIR_INDEX: u8 = 96;
pub(super) const EXTENT_DATA: u8 = 108;
pub(super) const ROOT_ITEM: u8 = 132;
pub(super) const CHUNK_ITEM: u8 = 228;

const HEADER: usize = 101;
const ITEM: usize = 25;
const PTR: usize = 33;
const MAX_LEVEL: u8 = 7;
/// How many bytes of nodes the cache keeps before it starts over.
const CACHE_BYTES: usize = 16 << 20;

/// A tree key: ordered by object id, then type, then offset.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct Key {
    pub objectid: u64,
    pub ty: u8,
    pub offset: u64,
}

impl Key {
    pub const fn new(objectid: u64, ty: u8, offset: u64) -> Self {
        Self {
            objectid,
            ty,
            offset,
        }
    }

    pub fn parse(buf: &[u8], at: usize) -> Result<Self> {
        Ok(Self {
            objectid: le64(buf, at)?,
            ty: u8_at(buf, at.saturating_add(8))?,
            offset: le64(buf, at.saturating_add(9))?,
        })
    }
}

/// One checked tree block.
#[derive(Debug)]
pub(super) struct Node {
    buf: Vec<u8>,
    level: u8,
    nritems: usize,
}

impl Node {
    fn parse(buf: Vec<u8>, bytenr: u64, sb: &Superblock, verify: bool) -> Result<Self> {
        let node_size = buf.len();
        if verify && le32(&buf, 0)? != crc32c(slice(&buf, 0x20, node_size.saturating_sub(0x20))?) {
            return Err(bad_crc("tree block", bytenr));
        }
        if uuid_at(&buf, 0x20)? != sb.header_fsid {
            return Err(other("a tree block belongs to another volume"));
        }
        let at = le64(&buf, 0x30)?;
        if at != bytenr {
            return Err(invalid("tree block bytenr", at));
        }
        let level = u8_at(&buf, 0x64)?;
        if level > MAX_LEVEL {
            return Err(invalid("tree block level", u64::from(level)));
        }
        let nritems = usize::try_from(le32(&buf, 0x60)?).map_err(|_| other("item count"))?;
        let entry = if level == 0 { ITEM } else { PTR };
        let room = node_size
            .saturating_sub(HEADER)
            .checked_div(entry)
            .unwrap_or(0);
        if nritems > room {
            return Err(out_of_range(
                "tree block nritems",
                u64::try_from(nritems).unwrap_or(u64::MAX),
                "items that fit",
                u64::try_from(room).unwrap_or(u64::MAX),
            ));
        }
        let node = Self {
            buf,
            level,
            nritems,
        };
        node.check_items()?;
        Ok(node)
    }

    fn check_items(&self) -> Result<()> {
        let body = self.buf.len().saturating_sub(HEADER);
        // The data of a leaf lies after its item headers.
        let items_end = self.nritems.saturating_mul(ITEM);
        let mut prev: Option<Key> = None;
        for i in 0..self.nritems {
            let key = self.key(i)?;
            if prev.is_some_and(|p| p >= key) {
                return Err(other("tree block keys are not in order"));
            }
            prev = Some(key);
            if self.level == 0 {
                let at = self.entry_at(i)?;
                let off = usize::try_from(le32(&self.buf, at.saturating_add(17))?)
                    .map_err(|_| other("item offset"))?;
                let size = usize::try_from(le32(&self.buf, at.saturating_add(21))?)
                    .map_err(|_| other("item size"))?;
                let end = off
                    .checked_add(size)
                    .ok_or_else(|| other("item end overflows"))?;
                if end > body || off < items_end {
                    return Err(out_of_range(
                        "leaf item end",
                        u64::try_from(end).unwrap_or(u64::MAX),
                        "leaf data",
                        u64::try_from(body).unwrap_or(u64::MAX),
                    ));
                }
            }
        }
        Ok(())
    }

    /// Offset in the block of entry `i`.
    fn entry_at(&self, i: usize) -> Result<usize> {
        let entry = if self.level == 0 { ITEM } else { PTR };
        i.checked_mul(entry)
            .and_then(|n| n.checked_add(HEADER))
            .ok_or_else(|| other("item index overflows"))
    }

    pub fn is_leaf(&self) -> bool {
        self.level == 0
    }

    pub fn len(&self) -> usize {
        self.nritems
    }

    /// The key of item (or child pointer) `i`.
    pub fn key(&self, i: usize) -> Result<Key> {
        if i >= self.nritems {
            return Err(other("item index is past the end of the block"));
        }
        Key::parse(&self.buf, self.entry_at(i)?)
    }

    /// Leaf item `i`: its key and its data.
    pub fn item(&self, i: usize) -> Result<(Key, &[u8])> {
        if i >= self.nritems || self.level != 0 {
            return Err(other("item index is past the end of the block"));
        }
        let at = self.entry_at(i)?;
        let key = Key::parse(&self.buf, at)?;
        let off = usize::try_from(le32(&self.buf, at.saturating_add(17))?)
            .map_err(|_| other("item offset"))?;
        let size = usize::try_from(le32(&self.buf, at.saturating_add(21))?)
            .map_err(|_| other("item size"))?;
        let data = slice(&self.buf, HEADER.saturating_add(off), size)?;
        Ok((key, data))
    }

    /// The logical address of child `i` of an internal node.
    fn child(&self, i: usize) -> Result<u64> {
        if i >= self.nritems || self.level == 0 {
            return Err(other("child index is past the end of the block"));
        }
        le64(&self.buf, self.entry_at(i)?.saturating_add(17))
    }

    /// The first index whose key is at least `key` (or greater than it, when
    /// `after`). `len()` when there is none.
    fn search(&self, key: &Key, after: bool) -> Result<usize> {
        let (mut lo, mut hi) = (0usize, self.nritems);
        while lo < hi {
            let mid = lo.saturating_add(hi.saturating_sub(lo) / 2);
            let k = self.key(mid)?;
            if k < *key || (after && k == *key) {
                lo = mid.saturating_add(1);
            } else {
                hi = mid;
            }
        }
        Ok(lo)
    }
}

struct Cache {
    map: HashMap<u64, Arc<Node>>,
    bytes: usize,
}

/// Everything needed to read tree blocks of one volume.
pub(super) struct Trees {
    source: Arc<dyn BlockSource>,
    chunks: ChunkMap,
    sb: Superblock,
    verify: bool,
    cache: Mutex<Cache>,
}

impl Trees {
    pub fn new(source: Arc<dyn BlockSource>, sb: Superblock, chunks: ChunkMap) -> Self {
        let verify = sb.csum == ChecksumKind::Crc32c;
        Self {
            source,
            chunks,
            sb,
            verify,
            cache: Mutex::new(Cache {
                map: HashMap::new(),
                bytes: 0,
            }),
        }
    }

    pub fn chunks(&self) -> &ChunkMap {
        &self.chunks
    }

    pub fn superblock(&self) -> &Superblock {
        &self.sb
    }

    /// True when block checksums are verified (crc32c volumes).
    pub fn verifies(&self) -> bool {
        self.verify
    }

    /// Reads `buf.len()` bytes at the logical address `logical`, which must
    /// lie inside one chunk.
    pub fn read_logical(&self, logical: u64, buf: &mut [u8]) -> Result<()> {
        let want = u64::try_from(buf.len()).map_err(|_| other("read length"))?;
        let (physical, room) = self.chunks.map(logical)?;
        if want > room {
            return Err(out_of_range("read length", want, "chunk end", room));
        }
        self.source.read_at(physical, buf)
    }

    /// The tree block at `bytenr`, which must be `level` levels above the
    /// leaves.
    pub fn read_node(&self, bytenr: u64, level: u8) -> Result<Arc<Node>> {
        let cached = self
            .cache
            .lock()
            .ok()
            .and_then(|c| c.map.get(&bytenr).cloned());
        let node = match cached {
            Some(node) => node,
            None => {
                let sector = u64::from(self.sb.sector_size);
                if bytenr.checked_rem(sector) != Some(0) {
                    return Err(invalid("tree block address", bytenr));
                }
                let size = usize::try_from(self.sb.node_size).map_err(|_| other("node size"))?;
                let mut buf = vec![0u8; size];
                self.read_logical(bytenr, &mut buf)?;
                let node = Arc::new(Node::parse(buf, bytenr, &self.sb, self.verify)?);
                if let Ok(mut cache) = self.cache.lock() {
                    if cache.bytes.saturating_add(size) > CACHE_BYTES {
                        cache.map.clear();
                        cache.bytes = 0;
                    }
                    cache.map.insert(bytenr, Arc::clone(&node));
                    cache.bytes = cache.bytes.saturating_add(size);
                }
                node
            }
        };
        if node.level != level {
            return Err(Corruption::new(
                super::STRUCTURE,
                Location::Object(bytenr),
                CorruptKind::InvalidValue {
                    field: "tree block level",
                    value: u64::from(node.level),
                },
            )
            .into());
        }
        Ok(node)
    }

    /// Walks from the root to the leaf where `key` belongs. The leaf's index
    /// is the first item at or after `key` (one past the end when none).
    fn descend(&self, root: TreeRoot, key: &Key) -> Result<Vec<(Arc<Node>, usize)>> {
        let mut path = Vec::with_capacity(8);
        let mut node = self.read_node(root.bytenr, root.level)?;
        loop {
            if node.is_leaf() {
                let at = node.search(key, false)?;
                path.push((node, at));
                return Ok(path);
            }
            if node.len() == 0 {
                return Err(other("an internal tree block has no children"));
            }
            // The last child whose first key is at most `key`.
            let at = node.search(key, true)?.saturating_sub(1);
            let child = self.child_of(&node, at)?;
            path.push((node, at));
            node = child;
        }
    }

    /// Child `at` of `node`, checked to be one level down and not empty.
    fn child_of(&self, node: &Node, at: usize) -> Result<Arc<Node>> {
        let below = node
            .level
            .checked_sub(1)
            .ok_or_else(|| other("a leaf has no children"))?;
        let child = self.read_node(node.child(at)?, below)?;
        if child.len() == 0 {
            return Err(other("a tree block below the root is empty"));
        }
        Ok(child)
    }

    /// A cursor on the first item at or after `key`.
    pub fn seek_ge(&self, root: TreeRoot, key: Key) -> Result<Option<Cursor<'_>>> {
        let path = self.descend(root, &key)?;
        let mut cursor = Cursor { trees: self, path };
        if cursor.at_end() {
            // Everything in this leaf is before `key`: the next leaf holds
            // the answer, if any.
            if !cursor.step_next()? {
                return Ok(None);
            }
        }
        Ok(Some(cursor))
    }

    /// A cursor on the last item at or before `key`.
    pub fn seek_le(&self, root: TreeRoot, key: Key) -> Result<Option<Cursor<'_>>> {
        let path = self.descend(root, &key)?;
        let mut cursor = Cursor { trees: self, path };
        let exact = !cursor.at_end() && cursor.key()? == key;
        if !exact && !cursor.step_prev()? {
            return Ok(None);
        }
        Ok(Some(cursor))
    }

    /// A cursor on the item with exactly `key`.
    pub fn find(&self, root: TreeRoot, key: Key) -> Result<Option<Cursor<'_>>> {
        match self.seek_ge(root, key)? {
            Some(c) if c.key()? == key => Ok(Some(c)),
            _ => Ok(None),
        }
    }
}

fn loops() -> atlas_fs_core::error::Error {
    Corruption::new(
        super::STRUCTURE,
        Location::Unspecified,
        CorruptKind::Loop { what: "tree keys" },
    )
    .into()
}

/// A position on one item of a tree.
pub(super) struct Cursor<'a> {
    trees: &'a Trees,
    /// From the root down; the last entry is the leaf and the item index in it.
    path: Vec<(Arc<Node>, usize)>,
}

impl Cursor<'_> {
    fn at_end(&self) -> bool {
        self.path.last().is_none_or(|(leaf, at)| *at >= leaf.len())
    }

    pub fn key(&self) -> Result<Key> {
        self.item().map(|(k, _)| k)
    }

    /// The item under the cursor.
    pub fn item(&self) -> Result<(Key, &[u8])> {
        let (leaf, at) = self
            .path
            .last()
            .ok_or_else(|| other("a cursor has no leaf"))?;
        leaf.item(*at)
    }

    /// Moves to the next item. `false` after the last one.
    pub fn next(&mut self) -> Result<bool> {
        let before = self.key().ok();
        if !self.step_next()? {
            return Ok(false);
        }
        let now = self.key()?;
        if before.is_some_and(|old| now <= old) {
            return Err(loops());
        }
        Ok(true)
    }

    /// Advances to the following item, across leaves if need be. A path
    /// that sits past the end of its leaf moves to the first item of the
    /// next leaf.
    fn step_next(&mut self) -> Result<bool> {
        if let Some((leaf, at)) = self.path.last_mut()
            && at.saturating_add(1) < leaf.len()
        {
            *at = at.saturating_add(1);
            return Ok(true);
        }
        // Up to the first ancestor with a next child, then down its left edge.
        self.path.pop();
        while let Some((node, at)) = self.path.last_mut() {
            if at.saturating_add(1) < node.len() {
                *at = at.saturating_add(1);
                let (node, at) = (Arc::clone(node), *at);
                self.descend_edge(&node, at, false)?;
                return Ok(true);
            }
            self.path.pop();
        }
        Ok(false)
    }

    /// Steps back to the preceding item, across leaves if need be.
    fn step_prev(&mut self) -> Result<bool> {
        if let Some((leaf, at)) = self.path.last_mut()
            && *at > 0
        {
            // A position one past the end lands on the last item.
            *at = at.saturating_sub(1).min(leaf.len().saturating_sub(1));
            return Ok(true);
        }
        self.path.pop();
        while let Some((node, at)) = self.path.last_mut() {
            if *at > 0 {
                *at = at.saturating_sub(1);
                let (node, at) = (Arc::clone(node), *at);
                self.descend_edge(&node, at, true)?;
                return Ok(true);
            }
            self.path.pop();
        }
        Ok(false)
    }

    /// From child `at` of `node` down to a leaf, along the left edge (or the
    /// right, when `last`), extending the path.
    fn descend_edge(&mut self, node: &Arc<Node>, at: usize, last: bool) -> Result<()> {
        let mut child = self.trees.child_of(node, at)?;
        loop {
            let index = if last {
                child.len().saturating_sub(1)
            } else {
                0
            };
            self.path.push((Arc::clone(&child), index));
            if child.is_leaf() {
                return Ok(());
            }
            if self.path.len() > usize::from(MAX_LEVEL).saturating_add(1) {
                return Err(limit("tree depth", u64::from(MAX_LEVEL)));
            }
            child = self.trees.child_of(&child, index)?;
        }
    }
}
