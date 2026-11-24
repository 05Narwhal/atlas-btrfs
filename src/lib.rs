// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Julian A. Loy.

//! Btrfs, read-only: one device, the chunk map from the superblock's
//! bootstrap array and the chunk tree, the default subvolume (the one the
//! `default` entry of the root tree names), subvolumes as folders, inline,
//! regular, preallocated and sparse extents, and zlib, LZO and zstd
//! compression.
//!
//! A node id packs the subvolume and the inode: the low 40 bits are the
//! inode number, the bits above are the subvolume's id, or 0 for the default
//! subvolume. So in the default subvolume a node id is the inode number
//! itself. A subvolume with an id of 2^24 or more (not reachable in practice)
//! is left out of listings. Metadata is checked before use: every length,
//! offset and count, the checksum of every tree block (crc32c volumes), and
//! the address and owner each block records. The log tree is never replayed,
//! so a volume that was not unmounted cleanly may show the state before its
//! last changes.
//!
//! Not supported: more than one device, RAID0, RAID5, RAID6 and RAID10
//! profiles, encryption, send streams, quotas (qgroups), the free-space tree
//! (so no shading on the disk strip), extended attributes, log tree replay,
//! zoned devices, and verifying checksums other than crc32c (xxhash64,
//! sha256 and blake2b volumes mount with their blocks unverified; see
//! [`Btrfs::checksums_verified`]). File data is never checked against the
//! checksum tree.
//!
//! ```no_run
//! use std::path::Path;
//! use std::sync::Arc;
//!
//! use atlas_fs_core::fs::{DirBatch, DirProgress, FileSystem};
//! use atlas_fs_core::io::file::FileSource;
//!
//! # fn main() -> Result<(), atlas_fs_core::error::Error> {
//! let source = Arc::new(FileSource::open(Path::new("volume.img"))?);
//! let volume = atlas_btrfs::mount(source)?;
//! println!("{}", volume.info().name);
//!
//! let mut stream = volume.read_dir(volume.root())?;
//! let mut batch = DirBatch::new();
//! while stream.next_batch(&mut batch, 256)? == DirProgress::More {}
//! for entry in batch.iter() {
//!     println!("{}", entry.name);
//! }
//! # Ok(())
//! # }
//! ```

#![forbid(unsafe_code)]
// On-disk bytes are hostile. These lints make the usual ways of trusting
// them (unchecked indexing, arithmetic and casts, panicking shortcuts) fail
// the clippy gate. Unit tests and the test fixtures are exempt.
#![warn(
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::unimplemented,
    clippy::unreachable,
    clippy::unwrap_used
)]
#![cfg_attr(
    any(test, feature = "test-util"),
    allow(
        clippy::arithmetic_side_effects,
        clippy::cast_possible_truncation,
        clippy::cast_possible_wrap,
        clippy::cast_sign_loss,
        clippy::expect_used,
        clippy::indexing_slicing,
        clippy::panic,
        clippy::unwrap_used
    )
)]

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use atlas_fs_core::error::{CorruptKind, Corruption, Error, Location, Result};
use atlas_fs_core::fs::{
    DirBatch, DirEntry, DirProgress, DirStream, EntryFlags, Extent, FileSystem, Metadata, NodeId,
    NodeKind, Owner, Stream, VolumeIdentity, VolumeInfo,
};
use atlas_fs_core::io::block::{BlockSource, MemSource, check_range};

mod bytes;
mod chunk;
mod crc;
mod extent;
mod inode;
mod lzo;
mod sb;
mod tree;

// Seed inputs for the fuzz targets; `volumes()` is shared with Disk Atlas, which adds the probe heads.
#[cfg(any(test, feature = "test-util"))]
#[doc(hidden)]
pub mod fuzz_seeds;
#[cfg(any(test, feature = "test-util"))]
#[allow(dead_code)]
mod synth;
#[cfg(any(test, feature = "test-util"))]
#[doc(hidden)]
#[allow(dead_code, missing_docs)]
pub mod test_image;
#[cfg(test)]
mod tests;

use chunk::ChunkMap;
use inode::{FIRST_INO, Inode, dir_recs};
pub use sb::ChecksumKind;
use sb::{SB_OFFSETS, SB_SIZE, Superblock, TreeRoot};
use tree::{CHUNK_ITEM, DIR_INDEX, DIR_ITEM, INODE_ITEM, Key, ROOT_ITEM, Trees};

const STRUCTURE: &str = "Btrfs structure";
/// The subvolume a volume starts in when its root tree names no other.
const FS_TREE: u64 = 5;
/// Subvolume roots remembered.
const MAX_SUBVOLS: usize = 4096;
/// Symbolic links remembered with the folder they were found in.
const MAX_PARENTS: usize = 65_536;
/// Path components, and links followed, when a link's target is resolved.
const MAX_COMPONENTS: u32 = 256;
const MAX_HOPS: u32 = 8;
/// A node id keeps the inode number in its low bits and the subvolume above.
const INO_BITS: u32 = 40;
const INO_MASK: u64 = (1 << INO_BITS) - 1;
const MAX_ENCODED_ROOT: u64 = (1 << 24) - 1;

pub(crate) fn other(what: &'static str) -> Error {
    Corruption::new(STRUCTURE, Location::Unspecified, CorruptKind::Other(what)).into()
}

pub(crate) fn invalid(field: &'static str, value: u64) -> Error {
    Corruption::new(
        STRUCTURE,
        Location::Unspecified,
        CorruptKind::InvalidValue { field, value },
    )
    .into()
}

pub(crate) fn out_of_range(
    field: &'static str,
    value: u64,
    limit_name: &'static str,
    limit: u64,
) -> Error {
    Corruption::new(
        STRUCTURE,
        Location::Unspecified,
        CorruptKind::OutOfRange {
            field,
            value,
            limit_name,
            limit,
        },
    )
    .into()
}

pub(crate) fn limit(what: &'static str, limit: u64) -> Error {
    Corruption::new(
        STRUCTURE,
        Location::Unspecified,
        CorruptKind::LimitExceeded { what, limit },
    )
    .into()
}

/// A checksum that does not match; `at` is a byte or logical address.
pub(crate) fn bad_crc(structure: &'static str, at: u64) -> Error {
    Corruption::new(
        structure,
        Location::Object(at),
        CorruptKind::Other("checksum mismatch"),
    )
    .into()
}

pub(crate) fn unsupported(what: impl Into<std::borrow::Cow<'static, str>>) -> Error {
    Error::unsupported(what)
}

/// A file or folder: its subvolume's id and its inode number.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Loc {
    root: u64,
    ino: u64,
}

/// What every handle, folder stream and open file shares.
struct Inner {
    trees: Trees,
    root_tree: TreeRoot,
    /// The subvolume the volume opens in, and its top folder's inode.
    default_root: u64,
    root_ino: u64,
    subvols: Mutex<HashMap<u64, TreeRoot>>,
    decoded: extent::DecodeCache,
    /// Where symbolic links were found, so a link to a folder can be followed
    /// from the folder it sits in.
    parents: Mutex<HashMap<u64, u64>>,
}

/// A mounted Btrfs volume.
pub struct Btrfs {
    inner: Arc<Inner>,
    info: VolumeInfo,
    identity: VolumeIdentity,
    csum: ChecksumKind,
}

const fn assert_send_sync<T: Send + Sync>() {}
const _: () = assert_send_sync::<Btrfs>();

fn read_superblock(source: &dyn BlockSource) -> Result<Superblock> {
    let len = source.len();
    let mut first_err = None;
    for &at in &SB_OFFSETS {
        let size = u64::try_from(SB_SIZE).unwrap_or(4096);
        if at.checked_add(size).is_none_or(|end| end > len) {
            continue;
        }
        let mut buf = vec![0u8; SB_SIZE];
        match source
            .read_at(at, &mut buf)
            .and_then(|()| Superblock::parse(&buf, at))
        {
            Ok(sb) => return Ok(sb),
            Err(e) => {
                first_err.get_or_insert(e);
            }
        }
    }
    Err(first_err.unwrap_or_else(|| {
        Corruption::new(
            STRUCTURE,
            Location::Unspecified,
            CorruptKind::Truncated {
                needed: SB_OFFSETS[0].saturating_add(4096),
                available: len,
            },
        )
        .into()
    }))
}

/// Mounts the volume in `source`.
pub fn mount(source: Arc<dyn BlockSource>) -> Result<Btrfs> {
    let sb = read_superblock(&*source)?;
    let bootstrap = ChunkMap::from_bootstrap(&sb.sys_chunk_array, sb.devid)?;
    // The chunk tree is addressed through the bootstrap chunks; the map for
    // everything else is what that tree lists.
    let mut chunks = bootstrap.clone();
    {
        let boot = Trees::new(Arc::clone(&source), sb.clone(), bootstrap);
        let mut cursor = boot.seek_ge(sb.chunk_root, Key::new(0, 0, 0))?;
        while let Some(c) = cursor.as_mut() {
            let (key, data) = c.item()?;
            if key.ty == CHUNK_ITEM && key.objectid == 256 {
                chunks.add(key.offset, data, sb.devid)?;
            }
            if !c.next()? {
                break;
            }
        }
    }
    let trees = Trees::new(Arc::clone(&source), sb.clone(), chunks);
    let root_tree = sb.root;
    let mut inner = Inner {
        trees,
        root_tree,
        default_root: FS_TREE,
        root_ino: FIRST_INO,
        subvols: Mutex::new(HashMap::new()),
        decoded: Mutex::new(Vec::new()),
        parents: Mutex::new(HashMap::new()),
    };
    // The default subvolume: the root tree's `default` directory entry.
    if let Some(root) = inner.default_subvolume(sb.root_dir_objectid)?
        && inner.subvol(root)?.is_some()
    {
        inner.default_root = root;
    }
    let tree = inner
        .subvol(inner.default_root)?
        .ok_or_else(|| other("the default subvolume has no root item"))?;
    let top = inner.load_inode(tree, FIRST_INO, FIRST_INO)?;
    if !top.is_dir() {
        return Err(invalid("subvolume top folder", FIRST_INO));
    }
    inner.root_ino = FIRST_INO;

    let name = String::from_utf8_lossy(&sb.label).into_owned();
    let mut info = VolumeInfo::new(if name.is_empty() {
        "Btrfs volume".to_owned()
    } else {
        name
    });
    info.format = Some("Btrfs");
    info.total_bytes = Some(sb.total_bytes);
    info.free_bytes = Some(sb.total_bytes.saturating_sub(sb.bytes_used));
    let mut change = [0u8; 16];
    change[..8].copy_from_slice(&sb.generation.to_be_bytes());
    change[8..].copy_from_slice(&sb.bytes_used.to_be_bytes());
    Ok(Btrfs {
        inner: Arc::new(inner),
        info,
        identity: VolumeIdentity {
            id: sb.fsid,
            change,
        },
        csum: sb.csum,
    })
}

fn lossy(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

fn kind_of_ftype(ftype: u8) -> NodeKind {
    match ftype {
        1 => NodeKind::File,
        2 => NodeKind::Directory,
        7 => NodeKind::Symlink,
        _ => NodeKind::Other,
    }
}

/// The parts of a path, last first, without empty parts and `.`.
fn components(path: &[u8]) -> Vec<Vec<u8>> {
    let mut parts: Vec<Vec<u8>> = path
        .split(|&b| b == b'/')
        .filter(|p| !p.is_empty() && *p != b".")
        .map(<[u8]>::to_vec)
        .collect();
    parts.reverse();
    parts
}

impl Inner {
    /// The id of the subvolume the root tree's `default` entry names.
    fn default_subvolume(&self, dir_objectid: u64) -> Result<Option<u64>> {
        let key = Key::new(
            dir_objectid,
            DIR_ITEM,
            u64::from(crc::name_hash(b"default")),
        );
        let Some(cursor) = self.trees.find(self.root_tree, key)? else {
            return Ok(None);
        };
        for rec in dir_recs(cursor.item()?.1) {
            let rec = rec?;
            if rec.name == b"default" && rec.location.ty == ROOT_ITEM {
                return Ok(Some(rec.location.objectid));
            }
        }
        Ok(None)
    }

    /// The node id of `loc`, when it can be packed into one.
    fn pack(&self, loc: Loc) -> Option<NodeId> {
        if loc.ino == 0 || loc.ino > INO_MASK {
            return None;
        }
        let enc = if loc.root == self.default_root {
            0
        } else if loc.root == 0 || loc.root > MAX_ENCODED_ROOT {
            return None;
        } else {
            loc.root
        };
        Some(NodeId(enc.checked_shl(INO_BITS)? | loc.ino))
    }

    /// The subvolume and inode a node id names.
    fn unpack(&self, node: NodeId) -> Result<Loc> {
        let ino = node.0 & INO_MASK;
        let enc = node.0.checked_shr(INO_BITS).unwrap_or(0);
        if ino == 0 {
            return Err(Error::NotFound { node: node.0 });
        }
        Ok(Loc {
            root: if enc == 0 { self.default_root } else { enc },
            ino,
        })
    }

    /// The inode of a node a caller named.
    fn node_inode(&self, node: NodeId) -> Result<(Loc, TreeRoot, Inode)> {
        let loc = self.unpack(node)?;
        let root = self.subvol_of(loc.root, node.0)?;
        let inode = self.load_inode(root, loc.ino, node.0)?;
        Ok((loc, root, inode))
    }

    fn remember(&self, link: u64, parent: u64) {
        if let Ok(mut map) = self.parents.lock()
            && (map.len() < MAX_PARENTS || map.contains_key(&link))
        {
            map.insert(link, parent);
        }
    }

    fn parent_of(&self, link: u64) -> Option<u64> {
        self.parents.lock().ok()?.get(&link).copied()
    }

    /// Where a directory entry points: `None` for entries that are neither
    /// an inode nor a subvolume.
    fn loc_of(&self, rootid: u64, location: Key) -> Option<Loc> {
        match location.ty {
            INODE_ITEM => Some(Loc {
                root: rootid,
                ino: location.objectid,
            }),
            ROOT_ITEM => Some(Loc {
                root: location.objectid,
                ino: FIRST_INO,
            }),
            _ => None,
        }
    }

    /// The entry called `name` in the folder `dir`. `.` is the folder itself
    /// and `..` the folder that holds it.
    fn find(&self, dir: Loc, name: &[u8]) -> Result<Option<Loc>> {
        if name == b"." {
            return Ok(Some(dir));
        }
        let root = self.subvol_of(dir.root, dir.ino)?;
        if name == b".." {
            let parent = self.parent_ino(root, dir.ino)?.unwrap_or(dir.ino);
            return Ok(Some(Loc {
                root: dir.root,
                ino: parent,
            }));
        }
        Ok(self
            .find_name(root, dir.ino, name)?
            .and_then(|(location, _)| self.loc_of(dir.root, location)))
    }

    /// The target of the symbolic link `ino`.
    fn read_link(&self, root: TreeRoot, ino: u64, inode: &Inode) -> Result<Vec<u8>> {
        if inode.size > extent::MAX_LINK {
            return Err(out_of_range(
                "symbolic link size",
                inode.size,
                "limit",
                extent::MAX_LINK,
            ));
        }
        let len = usize::try_from(inode.size).map_err(|_| other("link size"))?;
        let mut buf = vec![0u8; len];
        self.read_file(root, ino, 0, &mut buf)?;
        Ok(buf)
    }

    /// Follows `target` from the folder `start`. `None` when something on the
    /// way does not exist or the path is too long or links too deep.
    fn resolve(&self, start: Loc, target: &[u8]) -> Result<Option<Loc>> {
        let top = Loc {
            root: self.default_root,
            ino: self.root_ino,
        };
        let mut cur = if target.first() == Some(&b'/') {
            top
        } else {
            start
        };
        let mut work: Vec<Vec<u8>> = components(target);
        let mut budget = MAX_COMPONENTS;
        let mut hops = 0u32;
        while let Some(part) = work.pop() {
            budget = match budget.checked_sub(1) {
                Some(b) => b,
                None => return Ok(None),
            };
            let Some(next) = self.find(cur, &part)? else {
                return Ok(None);
            };
            let root = self.subvol_of(next.root, next.ino)?;
            let inode = self.load_inode(root, next.ino, next.ino)?;
            if inode.is_symlink() {
                hops = hops.saturating_add(1);
                if hops > MAX_HOPS {
                    return Ok(None);
                }
                let link = self.read_link(root, next.ino, &inode)?;
                if link.first() == Some(&b'/') {
                    cur = top;
                }
                work.extend(components(&link));
            } else {
                cur = next;
            }
        }
        Ok(Some(cur))
    }

    /// True when the symbolic link `ino` (found in the folder `parent`) leads
    /// to a folder.
    fn links_to_dir(&self, parent: Loc, root: TreeRoot, ino: u64, inode: &Inode) -> bool {
        let Ok(target) = self.read_link(root, ino, inode) else {
            return false;
        };
        match self.resolve(parent, &target) {
            Ok(Some(loc)) => self
                .subvol(loc.root)
                .ok()
                .flatten()
                .and_then(|r| self.load_inode(r, loc.ino, loc.ino).ok())
                .is_some_and(|i| i.is_dir()),
            _ => false,
        }
    }
}

impl Btrfs {
    /// The number of names that lead to `node`.
    pub fn link_count(&self, node: NodeId) -> Result<u32> {
        Ok(self.inner.node_inode(node)?.2.nlink)
    }

    /// The checksum the volume uses for its metadata.
    pub fn checksum_kind(&self) -> ChecksumKind {
        self.csum
    }

    /// True when tree block checksums are verified: only crc32c volumes are.
    /// The others mount, with their blocks taken on trust.
    pub fn checksums_verified(&self) -> bool {
        self.inner.trees.verifies()
    }
}

/// A folder listing.
struct BtrfsDir {
    inner: Arc<Inner>,
    root: TreeRoot,
    /// The folder, and the index to resume at.
    dir: Loc,
    next_index: u64,
    done: bool,
}

impl BtrfsDir {
    /// What a listing reports about the entry `loc`.
    fn entry_info(
        &self,
        loc: Loc,
        ftype: u8,
    ) -> (
        NodeKind,
        Option<u64>,
        Option<atlas_fs_core::fs::Timestamp>,
        EntryFlags,
    ) {
        let Ok(inode) = self.inner.load_inode(self.root, loc.ino, loc.ino) else {
            return (kind_of_ftype(ftype), None, None, EntryFlags::EMPTY);
        };
        let kind = inode.kind();
        let mut flags = EntryFlags::EMPTY;
        if kind == NodeKind::Symlink
            && let Some(node) = self.inner.pack(loc)
        {
            if let Some(parent) = self.inner.pack(self.dir) {
                self.inner.remember(node.0, parent.0);
            }
            if self
                .inner
                .links_to_dir(self.dir, self.root, loc.ino, &inode)
            {
                flags = flags.with(EntryFlags::LINKS_TO_DIRECTORY);
            }
        }
        (
            kind,
            (kind != NodeKind::Directory).then_some(inode.size),
            Some(inode.mtime),
            flags,
        )
    }
}

impl DirStream for BtrfsDir {
    fn next_batch(&mut self, out: &mut DirBatch, max: usize) -> Result<DirProgress> {
        if self.done {
            return Ok(DirProgress::Done);
        }
        let result = self.fill(out, max);
        if !matches!(result, Ok(DirProgress::More)) {
            self.done = true;
        }
        result
    }
}

impl BtrfsDir {
    fn fill(&mut self, out: &mut DirBatch, max: usize) -> Result<DirProgress> {
        let inner = Arc::clone(&self.inner);
        let key = Key::new(self.dir.ino, DIR_INDEX, self.next_index);
        let Some(mut cursor) = inner.trees.seek_ge(self.root, key)? else {
            return Ok(DirProgress::Done);
        };
        let mut added = 0usize;
        loop {
            let (key, data) = cursor.item()?;
            if key.objectid != self.dir.ino || key.ty != DIR_INDEX {
                return Ok(DirProgress::Done);
            }
            for rec in dir_recs(data) {
                let rec = rec?;
                let Some(loc) = inner.loc_of(self.dir.root, rec.location) else {
                    continue;
                };
                let Some(node) = inner.pack(loc) else {
                    continue;
                };
                let shown = String::from_utf8_lossy(rec.name);
                if rec.location.ty == ROOT_ITEM {
                    // A subvolume shows as a folder; its details are in its
                    // own tree.
                    out.push(DirEntry {
                        node,
                        name: &shown,
                        kind: NodeKind::Directory,
                        size: None,
                        resource_size: None,
                        modified: None,
                        flags: EntryFlags::EMPTY,
                    });
                } else {
                    let (kind, size, modified, flags) = self.entry_info(loc, rec.ftype);
                    out.push(DirEntry {
                        node,
                        name: &shown,
                        kind,
                        size,
                        resource_size: None,
                        modified,
                        flags,
                    });
                }
                added = added.saturating_add(1);
            }
            let Some(next) = key.offset.checked_add(1) else {
                return Ok(DirProgress::Done);
            };
            self.next_index = next;
            if added >= max {
                return Ok(DirProgress::More);
            }
            if !cursor.next()? {
                return Ok(DirProgress::Done);
            }
        }
    }
}

/// The data of one regular file.
struct BtrfsFile {
    inner: Arc<Inner>,
    root: TreeRoot,
    ino: u64,
    len: u64,
}

impl BlockSource for BtrfsFile {
    fn len(&self) -> u64 {
        self.len
    }

    fn sector_size(&self) -> u32 {
        512
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<()> {
        check_range(offset, buf.len(), self.len)?;
        self.inner.read_file(self.root, self.ino, offset, buf)
    }
}

impl FileSystem for Btrfs {
    fn info(&self) -> VolumeInfo {
        self.info.clone()
    }

    fn root(&self) -> NodeId {
        self.inner
            .pack(Loc {
                root: self.inner.default_root,
                ino: self.inner.root_ino,
            })
            .unwrap_or(NodeId(self.inner.root_ino))
    }

    fn metadata(&self, node: NodeId) -> Result<Metadata> {
        let (loc, root, inode) = self.inner.node_inode(node)?;
        let kind = inode.kind();
        let mut flags = EntryFlags::EMPTY;
        let mut link_target = None;
        if kind == NodeKind::Symlink
            && let Ok(target) = self.inner.read_link(root, loc.ino, &inode)
        {
            // A relative link can be followed only from the folder it was
            // listed in.
            let start = match self.inner.parent_of(node.0) {
                Some(parent) => self.inner.unpack(NodeId(parent)).ok(),
                None => (target.first() == Some(&b'/')).then_some(Loc {
                    root: self.inner.default_root,
                    ino: self.inner.root_ino,
                }),
            };
            if let Some(start) = start
                && self.inner.links_to_dir(start, root, loc.ino, &inode)
            {
                flags = flags.with(EntryFlags::LINKS_TO_DIRECTORY);
            }
            link_target = Some(lossy(&target));
        }
        Ok(Metadata {
            node,
            kind,
            size: (kind != NodeKind::Directory).then_some(inode.size),
            resource_size: None,
            created: inode.otime,
            modified: Some(inode.mtime),
            accessed: Some(inode.atime),
            flags,
            link_target,
            finder_codes: None,
            owner: Some(Owner {
                user: inode.uid,
                group: inode.gid,
                mode: u16::try_from(inode.mode & 0xFFFF).unwrap_or(0),
            }),
            attributes: None,
            finder_info: None,
        })
    }

    fn lookup(&self, dir: NodeId, name: &str) -> Result<Option<NodeId>> {
        let name = name.as_bytes();
        if name.is_empty() || name == b"." || name == b".." || name.contains(&b'/') {
            return Ok(None);
        }
        let (loc, _, inode) = self.inner.node_inode(dir)?;
        if !inode.is_dir() {
            return Err(Error::NotADirectory { node: dir.0 });
        }
        let Some(found) = self.inner.find(loc, name)? else {
            return Ok(None);
        };
        let Some(node) = self.inner.pack(found) else {
            return Ok(None);
        };
        if let Ok(root) = self.inner.subvol_of(found.root, node.0)
            && self
                .inner
                .load_inode(root, found.ino, node.0)
                .is_ok_and(|i| i.is_symlink())
        {
            self.inner.remember(node.0, dir.0);
        }
        Ok(Some(node))
    }

    fn read_dir(&self, dir: NodeId) -> Result<Box<dyn DirStream>> {
        let (mut loc, mut root, mut inode) = self.inner.node_inode(dir)?;
        if inode.is_symlink() {
            let target = self.inner.read_link(root, loc.ino, &inode)?;
            let start = self
                .inner
                .parent_of(dir.0)
                .and_then(|p| self.inner.unpack(NodeId(p)).ok())
                .unwrap_or(Loc {
                    root: self.inner.default_root,
                    ino: self.inner.root_ino,
                });
            let Some(found) = self.inner.resolve(start, &target)? else {
                return Err(Error::NotADirectory { node: dir.0 });
            };
            loc = found;
            root = self.inner.subvol_of(loc.root, dir.0)?;
            inode = self.inner.load_inode(root, loc.ino, dir.0)?;
        }
        if !inode.is_dir() {
            return Err(Error::NotADirectory { node: dir.0 });
        }
        Ok(Box::new(BtrfsDir {
            inner: Arc::clone(&self.inner),
            root,
            dir: loc,
            next_index: 0,
            done: false,
        }))
    }

    fn extents(&self, node: NodeId, stream: Stream) -> Result<Vec<Extent>> {
        if !matches!(stream, Stream::Data) {
            return Err(Error::NoSuchStream { node: node.0 });
        }
        let (loc, root, inode) = self.inner.node_inode(node)?;
        match inode.kind() {
            NodeKind::Directory => Err(Error::IsADirectory { node: node.0 }),
            NodeKind::File | NodeKind::Symlink => self.inner.file_runs(root, loc.ino),
            _ => Err(Error::NoSuchStream { node: node.0 }),
        }
    }

    fn open(&self, node: NodeId, stream: Stream) -> Result<Arc<dyn BlockSource>> {
        if !matches!(stream, Stream::Data) {
            return Err(Error::NoSuchStream { node: node.0 });
        }
        let (loc, root, inode) = self.inner.node_inode(node)?;
        match inode.kind() {
            NodeKind::Directory => Err(Error::IsADirectory { node: node.0 }),
            NodeKind::Symlink => Ok(Arc::new(MemSource::new(
                self.inner.read_link(root, loc.ino, &inode)?,
            ))),
            NodeKind::File => Ok(Arc::new(BtrfsFile {
                inner: Arc::clone(&self.inner),
                root,
                ino: loc.ino,
                len: inode.size,
            })),
            _ => Err(Error::NoSuchStream { node: node.0 }),
        }
    }

    fn identity(&self) -> Option<VolumeIdentity> {
        Some(self.identity)
    }
}
