// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Julian A. Loy.

//! Inode items, directory items, and the lookups on them: the part of the
//! reader that turns names into inodes inside one subvolume.

use super::bytes::{le16, le32, le64, slice, u8_at};
use super::crc::name_hash;
use super::sb::TreeRoot;
use super::tree::{DIR_ITEM, INODE_ITEM, INODE_REF, Key, ROOT_ITEM};
use super::{Inner, other, out_of_range};
use atlas_fs_core::error::{Error, Result};
use atlas_fs_core::fs::{NodeKind, Timestamp};

/// The inode number of every subvolume's top folder.
pub(super) const FIRST_INO: u64 = 256;

const INODE_LEN: usize = 160;
const S_IFMT: u32 = 0o170_000;
const S_IFREG: u32 = 0o100_000;
const S_IFDIR: u32 = 0o040_000;
const S_IFLNK: u32 = 0o120_000;

/// The fields of an `INODE_ITEM` the reader shows.
#[derive(Debug, Clone)]
pub(super) struct Inode {
    pub size: u64,
    pub nlink: u32,
    pub uid: u32,
    pub gid: u32,
    pub mode: u32,
    pub atime: Timestamp,
    pub mtime: Timestamp,
    /// The creation time; absent when the item records none.
    pub otime: Option<Timestamp>,
}

fn timestamp(buf: &[u8], at: usize) -> Result<Timestamp> {
    let sec = i64::from_le_bytes(le64(buf, at)?.to_le_bytes());
    let nsec = le32(buf, at.saturating_add(8))?.min(999_999_999);
    Ok(Timestamp::from_unix(sec, nsec))
}

impl Inode {
    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.len() < INODE_LEN {
            return Err(out_of_range(
                "inode item size",
                u64::try_from(data.len()).unwrap_or(u64::MAX),
                "inode item",
                INODE_LEN as u64,
            ));
        }
        let (osec, onsec) = (le64(data, 148)?, le32(data, 156)?);
        Ok(Self {
            size: le64(data, 16)?,
            nlink: le32(data, 40)?,
            uid: le32(data, 44)?,
            gid: le32(data, 48)?,
            mode: le32(data, 52)?,
            atime: timestamp(data, 112)?,
            mtime: timestamp(data, 136)?,
            otime: (osec != 0 || onsec != 0)
                .then(|| timestamp(data, 148))
                .transpose()?,
        })
    }

    pub fn kind(&self) -> NodeKind {
        match self.mode & S_IFMT {
            S_IFREG => NodeKind::File,
            S_IFDIR => NodeKind::Directory,
            S_IFLNK => NodeKind::Symlink,
            _ => NodeKind::Other,
        }
    }

    pub fn is_dir(&self) -> bool {
        self.mode & S_IFMT == S_IFDIR
    }

    pub fn is_symlink(&self) -> bool {
        self.mode & S_IFMT == S_IFLNK
    }
}

/// One entry of a directory item.
#[derive(Debug, Clone, Copy)]
pub(super) struct DirRec<'a> {
    /// What the entry points at: an inode, or a subvolume's root item.
    pub location: Key,
    /// The file type byte (1 file, 2 folder, 7 link, ...).
    pub ftype: u8,
    pub name: &'a [u8],
}

/// The entries of one `DIR_ITEM` or `DIR_INDEX` item. A name hash that
/// collides puts several entries in one item.
pub(super) struct DirRecs<'a> {
    data: &'a [u8],
}

pub(super) fn dir_recs(data: &[u8]) -> DirRecs<'_> {
    DirRecs { data }
}

impl<'a> Iterator for DirRecs<'a> {
    type Item = Result<DirRec<'a>>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.data.is_empty() {
            return None;
        }
        let parsed = (|| {
            let location = Key::parse(self.data, 0)?;
            let data_len = usize::from(le16(self.data, 25)?);
            let name_len = usize::from(le16(self.data, 27)?);
            let ftype = u8_at(self.data, 29)?;
            if name_len == 0 || name_len > 255 {
                return Err(other("a directory entry's name length is not valid"));
            }
            let name = slice(self.data, 30, name_len)?;
            let total = name_len
                .checked_add(data_len)
                .and_then(|n| n.checked_add(30))
                .ok_or_else(|| other("a directory entry overflows"))?;
            let rest = self
                .data
                .get(total..)
                .ok_or_else(|| other("a directory entry is cut short"))?;
            Ok((
                DirRec {
                    location,
                    ftype,
                    name,
                },
                rest,
            ))
        })();
        match parsed {
            Ok((rec, rest)) => {
                self.data = rest;
                Some(Ok(rec))
            }
            Err(e) => {
                // One error ends the item.
                self.data = &[];
                Some(Err(e))
            }
        }
    }
}

impl Inner {
    /// Where subvolume `rootid` has its tree, or `None` when the root tree
    /// has no such subvolume.
    pub(super) fn subvol(&self, rootid: u64) -> Result<Option<TreeRoot>> {
        if let Ok(cache) = self.subvols.lock()
            && let Some(root) = cache.get(&rootid)
        {
            return Ok(Some(*root));
        }
        let Some(cursor) = self
            .trees
            .seek_ge(self.root_tree, Key::new(rootid, ROOT_ITEM, 0))?
        else {
            return Ok(None);
        };
        let (key, data) = cursor.item()?;
        if key.objectid != rootid || key.ty != ROOT_ITEM {
            return Ok(None);
        }
        // The root item: an inode item, then generation, root_dirid, bytenr
        // at 176, ... and the level at 238.
        let bytenr = le64(data, 176)?;
        let level = u8_at(data, 238)?;
        if bytenr == 0 || level > 7 {
            return Err(other("a subvolume's root item is not valid"));
        }
        let root = TreeRoot { bytenr, level };
        if let Ok(mut cache) = self.subvols.lock()
            && (cache.len() < super::MAX_SUBVOLS || cache.contains_key(&rootid))
        {
            cache.insert(rootid, root);
        }
        Ok(Some(root))
    }

    /// The tree of subvolume `rootid`, or `NotFound` for the node `node`.
    pub(super) fn subvol_of(&self, rootid: u64, node: u64) -> Result<TreeRoot> {
        self.subvol(rootid)?.ok_or(Error::NotFound { node })
    }

    /// The inode `ino` of the tree `root`.
    pub(super) fn load_inode(&self, root: TreeRoot, ino: u64, node: u64) -> Result<Inode> {
        match self.trees.find(root, Key::new(ino, INODE_ITEM, 0))? {
            Some(cursor) => Inode::parse(cursor.item()?.1),
            None => Err(Error::NotFound { node }),
        }
    }

    /// The entry called `name` in folder `dir` of the tree `root`: where it
    /// points and its file type.
    pub(super) fn find_name(
        &self,
        root: TreeRoot,
        dir: u64,
        name: &[u8],
    ) -> Result<Option<(Key, u8)>> {
        let key = Key::new(dir, DIR_ITEM, u64::from(name_hash(name)));
        let Some(cursor) = self.trees.find(root, key)? else {
            return Ok(None);
        };
        for rec in dir_recs(cursor.item()?.1) {
            let rec = rec?;
            if rec.name == name {
                return Ok(Some((rec.location, rec.ftype)));
            }
        }
        Ok(None)
    }

    /// The folder that holds `ino`, from its first `INODE_REF`. `None` for a
    /// subvolume's top folder.
    pub(super) fn parent_ino(&self, root: TreeRoot, ino: u64) -> Result<Option<u64>> {
        let Some(cursor) = self.trees.seek_ge(root, Key::new(ino, INODE_REF, 0))? else {
            return Ok(None);
        };
        let key = cursor.key()?;
        Ok((key.objectid == ino && key.ty == INODE_REF).then_some(key.offset))
    }
}
