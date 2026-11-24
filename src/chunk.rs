// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Julian A. Loy.

//! The chunk map: where a logical address (what every pointer in a Btrfs
//! tree holds) lives on the one device. Built from the superblock's bootstrap
//! array and then the chunk tree.

use super::bytes::{le16, le64};
use super::{invalid, limit, other, out_of_range, unsupported};
use atlas_fs_core::error::Result;

/// Bytes of a `btrfs_chunk` before its stripes, and of one stripe.
pub(super) const CHUNK_HEADER: usize = 48;
pub(super) const STRIPE_LEN: usize = 32;

const TYPE_RAID0: u64 = 1 << 3;
const TYPE_RAID10: u64 = 1 << 6;
const TYPE_RAID5: u64 = 1 << 7;
const TYPE_RAID6: u64 = 1 << 8;
/// Profiles that spread one chunk's bytes over several devices.
const STRIPED: u64 = TYPE_RAID0 | TYPE_RAID10 | TYPE_RAID5 | TYPE_RAID6;

/// The most chunks a volume may have (a 1 GiB chunk each: 1 PiB).
const MAX_CHUNKS: usize = 1 << 20;
/// The most stripes a chunk item may list.
const MAX_STRIPES: u16 = 256;

#[derive(Debug, Clone, Copy)]
struct Chunk {
    start: u64,
    len: u64,
    /// Byte offset of this chunk's data on the device.
    physical: u64,
}

/// Logical-to-physical address translation, sorted by logical start.
#[derive(Debug, Default, Clone)]
pub(super) struct ChunkMap {
    chunks: Vec<Chunk>,
}

impl ChunkMap {
    /// Adds the chunk item `data` (the value of the key `(256, CHUNK_ITEM,
    /// logical)`) for a volume whose one device has id `devid`.
    pub fn add(&mut self, logical: u64, data: &[u8], devid: u64) -> Result<()> {
        let len = le64(data, 0)?;
        let flags = le64(data, 24)?;
        let num_stripes = le16(data, 44)?;
        if len == 0 {
            return Err(invalid("chunk length", 0));
        }
        if num_stripes == 0 || num_stripes > MAX_STRIPES {
            return Err(invalid("chunk num_stripes", u64::from(num_stripes)));
        }
        if flags & STRIPED != 0 {
            return Err(unsupported(
                "Btrfs RAID0, RAID5, RAID6 and RAID10 profiles (the data is spread over several devices)",
            ));
        }
        let need = usize::from(num_stripes)
            .checked_mul(STRIPE_LEN)
            .and_then(|n| n.checked_add(CHUNK_HEADER))
            .ok_or_else(|| other("chunk size overflows"))?;
        if data.len() < need {
            return Err(out_of_range(
                "chunk item size",
                u64::try_from(data.len()).unwrap_or(u64::MAX),
                "stripes",
                u64::try_from(need).unwrap_or(u64::MAX),
            ));
        }
        logical
            .checked_add(len)
            .ok_or_else(|| other("chunk end overflows"))?;
        // The first stripe on this device holds the data (DUP and RAID1
        // keep identical copies).
        let mut physical = None;
        for i in 0..usize::from(num_stripes) {
            let at = i
                .checked_mul(STRIPE_LEN)
                .and_then(|n| n.checked_add(CHUNK_HEADER))
                .ok_or_else(|| other("chunk size overflows"))?;
            if le64(data, at)? == devid {
                physical = Some(le64(data, at.saturating_add(8))?);
                break;
            }
        }
        let physical =
            physical.ok_or_else(|| other("chunk has no stripe on the volume's device"))?;
        physical
            .checked_add(len)
            .ok_or_else(|| other("chunk end overflows"))?;
        self.insert(Chunk {
            start: logical,
            len,
            physical,
        })
    }

    fn insert(&mut self, chunk: Chunk) -> Result<()> {
        let at = self.chunks.partition_point(|c| c.start < chunk.start);
        if let Some(same) = self.chunks.get(at).filter(|c| c.start == chunk.start) {
            // The system chunk is in both the bootstrap array and the chunk
            // tree; the two must agree.
            return if same.len == chunk.len && same.physical == chunk.physical {
                Ok(())
            } else {
                Err(other("two chunk items disagree about one chunk"))
            };
        }
        let end = chunk.start.saturating_add(chunk.len);
        if self.chunks.get(at).is_some_and(|next| next.start < end) {
            return Err(other("chunks overlap"));
        }
        if let Some(prev) = at.checked_sub(1).and_then(|p| self.chunks.get(p))
            && prev.start.saturating_add(prev.len) > chunk.start
        {
            return Err(other("chunks overlap"));
        }
        if self.chunks.len() >= MAX_CHUNKS {
            return Err(limit("chunks", MAX_CHUNKS as u64));
        }
        self.chunks.insert(at, chunk);
        Ok(())
    }

    /// The device offset of `logical`, and how many bytes from there to the
    /// end of the chunk.
    pub fn map(&self, logical: u64) -> Result<(u64, u64)> {
        let after = self.chunks.partition_point(|c| c.start <= logical);
        let chunk = after
            .checked_sub(1)
            .and_then(|i| self.chunks.get(i))
            .ok_or_else(|| out_of_range("logical address", logical, "first chunk", 0))?;
        let within = logical.saturating_sub(chunk.start);
        if within >= chunk.len {
            return Err(out_of_range(
                "logical address",
                logical,
                "chunk end",
                chunk.start.saturating_add(chunk.len),
            ));
        }
        Ok((
            chunk.physical.saturating_add(within),
            chunk.len.saturating_sub(within),
        ))
    }

    /// Parses the bootstrap array of the superblock: pairs of a disk key and
    /// a chunk item.
    pub fn from_bootstrap(array: &[u8], devid: u64) -> Result<Self> {
        let mut map = Self::default();
        let mut at = 0usize;
        while at < array.len() {
            // The disk key: objectid, type, offset.
            let objectid = le64(array, at)?;
            let ty = *array
                .get(at.saturating_add(8))
                .ok_or_else(|| other("bootstrap array is cut short"))?;
            let logical = le64(array, at.saturating_add(9))?;
            if objectid != 256 || ty != super::tree::CHUNK_ITEM {
                return Err(invalid("sys_chunk_array key", objectid));
            }
            let item = at.saturating_add(17);
            let rest = array
                .get(item..)
                .ok_or_else(|| other("bootstrap array is cut short"))?;
            let stripes = usize::from(le16(rest, 44)?);
            let size = stripes
                .checked_mul(STRIPE_LEN)
                .and_then(|n| n.checked_add(CHUNK_HEADER))
                .ok_or_else(|| other("chunk size overflows"))?;
            let data = rest
                .get(..size)
                .ok_or_else(|| other("bootstrap array is cut short"))?;
            map.add(logical, data, devid)?;
            at = item
                .checked_add(size)
                .ok_or_else(|| other("bootstrap array overflows"))?;
        }
        Ok(map)
    }
}
