// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Julian A. Loy.

//! The superblock: three copies (64 KiB, 64 MiB, 256 GiB), each 4 KiB. Every
//! number read from it is checked here, so the rest of the reader can rely on
//! the geometry.

use super::bytes::{le16, le32, le64, slice, u8_at, uuid_at};
use super::crc::crc32c;
use super::{bad_crc, invalid, other, out_of_range, unsupported};
use atlas_fs_core::error::Result;

pub(super) const SB_SIZE: usize = 4096;
/// Byte offsets of the superblock copies.
pub(super) const SB_OFFSETS: [u64; 3] = [64 << 10, 64 << 20, 256 << 30];
/// "_BHRfS_M".
pub(super) const MAGIC: u64 = 0x4D5F_5366_5248_425F;

const ARRAY_MAX: usize = 2048;
const MAX_LEVEL: u8 = 7;

const INCOMPAT_METADATA_UUID: u64 = 1 << 10;
/// What this reader understands. Anything else (zoned devices, the RAID
/// stripe tree, extent tree v2) changes where things are.
const INCOMPAT_KNOWN: u64 = 1 // mixed backrefs
    | 1 << 1 // default subvolume
    | 1 << 2 // mixed groups
    | 1 << 3 // lzo
    | 1 << 4 // zstd
    | 1 << 5 // big metadata
    | 1 << 6 // extended iref
    | 1 << 7 // raid56 (its chunks are refused one by one)
    | 1 << 8 // skinny metadata
    | 1 << 9 // no holes
    | INCOMPAT_METADATA_UUID
    | 1 << 11 // raid1c3 and raid1c4
    | 1 << 16; // simple quota

/// The checksum a volume uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChecksumKind {
    Crc32c,
    XxHash64,
    Sha256,
    Blake2b,
}

impl ChecksumKind {
    pub fn name(self) -> &'static str {
        match self {
            Self::Crc32c => "crc32c",
            Self::XxHash64 => "xxhash64",
            Self::Sha256 => "sha256",
            Self::Blake2b => "blake2b",
        }
    }
}

/// Where a tree starts.
#[derive(Debug, Clone, Copy)]
pub(super) struct TreeRoot {
    pub bytenr: u64,
    pub level: u8,
}

#[derive(Debug, Clone)]
pub(super) struct Superblock {
    pub fsid: [u8; 16],
    /// The id node headers carry: `metadata_uuid` when that feature is on.
    pub header_fsid: [u8; 16],
    pub generation: u64,
    pub root: TreeRoot,
    pub chunk_root: TreeRoot,
    pub total_bytes: u64,
    pub bytes_used: u64,
    pub root_dir_objectid: u64,
    pub sector_size: u32,
    pub node_size: u32,
    pub csum: ChecksumKind,
    pub devid: u64,
    pub label: Vec<u8>,
    pub sys_chunk_array: Vec<u8>,
}

fn pow2_between(field: &'static str, value: u32, lo: u32, hi: u32) -> Result<()> {
    if value.is_power_of_two() && (lo..=hi).contains(&value) {
        Ok(())
    } else {
        Err(invalid(field, u64::from(value)))
    }
}

fn level(field: &'static str, buf: &[u8], at: usize) -> Result<u8> {
    let l = u8_at(buf, at)?;
    if l > MAX_LEVEL {
        return Err(invalid(field, u64::from(l)));
    }
    Ok(l)
}

impl Superblock {
    /// Parses the 4 KiB at `buf`, a copy that was read from byte `at`.
    pub fn parse(buf: &[u8], at: u64) -> Result<Self> {
        let buf = slice(buf, 0, SB_SIZE)?;
        let magic = le64(buf, 0x40)?;
        if magic != MAGIC {
            return Err(atlas_fs_core::error::Corruption::new(
                super::STRUCTURE,
                atlas_fs_core::error::Location::Unspecified,
                atlas_fs_core::error::CorruptKind::BadSignature {
                    expected: MAGIC,
                    found: magic,
                },
            )
            .into());
        }
        let csum = match le16(buf, 0xC4)? {
            0 => ChecksumKind::Crc32c,
            1 => ChecksumKind::XxHash64,
            2 => ChecksumKind::Sha256,
            3 => ChecksumKind::Blake2b,
            other => return Err(invalid("csum_type", u64::from(other))),
        };
        if csum == ChecksumKind::Crc32c
            && le32(buf, 0)? != crc32c(slice(buf, 0x20, SB_SIZE.saturating_sub(0x20))?)
        {
            return Err(bad_crc("superblock", at));
        }
        let bytenr = le64(buf, 0x30)?;
        if bytenr != at {
            return Err(invalid("sb bytenr", bytenr));
        }
        let sector_size = le32(buf, 0x90)?;
        let node_size = le32(buf, 0x94)?;
        pow2_between("sectorsize", sector_size, 512, 65536)?;
        pow2_between("nodesize", node_size, sector_size.max(1024), 65536)?;
        let num_devices = le64(buf, 0x88)?;
        if num_devices != 1 {
            return Err(unsupported(format!(
                "Btrfs volumes that span several devices ({num_devices} devices); open them together in another tool"
            )));
        }
        let incompat = le64(buf, 0xBC)?;
        if incompat & !INCOMPAT_KNOWN != 0 {
            return Err(unsupported(format!(
                "Btrfs incompatible features {:#x}",
                incompat & !INCOMPAT_KNOWN
            )));
        }
        let array_size = usize::try_from(le32(buf, 0xA0)?).map_err(|_| other("array size"))?;
        if array_size > ARRAY_MAX {
            return Err(out_of_range(
                "sys_chunk_array_size",
                array_size as u64,
                "array",
                ARRAY_MAX as u64,
            ));
        }
        let fsid = uuid_at(buf, 0x20)?;
        let metadata_uuid = uuid_at(buf, 0x23B)?;
        let header_fsid = if incompat & INCOMPAT_METADATA_UUID != 0 && metadata_uuid != [0; 16] {
            metadata_uuid
        } else {
            fsid
        };
        let root = le64(buf, 0x50)?;
        let chunk_root = le64(buf, 0x58)?;
        for (field, value) in [("root", root), ("chunk_root", chunk_root)] {
            if value == 0 || value.checked_rem(u64::from(sector_size)) != Some(0) {
                return Err(invalid(field, value));
            }
        }
        let label_raw = slice(buf, 0x12B, 256)?;
        let label_len = label_raw.iter().position(|&b| b == 0).unwrap_or(256);
        Ok(Self {
            fsid,
            header_fsid,
            generation: le64(buf, 0x48)?,
            root: TreeRoot {
                bytenr: root,
                level: level("root_level", buf, 0xC6)?,
            },
            chunk_root: TreeRoot {
                bytenr: chunk_root,
                level: level("chunk_root_level", buf, 0xC7)?,
            },
            total_bytes: le64(buf, 0x70)?,
            bytes_used: le64(buf, 0x78)?,
            root_dir_objectid: le64(buf, 0x80)?,
            sector_size,
            node_size,
            csum,
            devid: le64(buf, 0xC9)?,
            label: label_raw.get(..label_len).unwrap_or(&[]).to_vec(),
            sys_chunk_array: slice(buf, 0x32B, array_size)?.to_vec(),
        })
    }
}
