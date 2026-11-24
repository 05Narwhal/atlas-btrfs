// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Julian A. Loy.

//! File data: `EXTENT_DATA` items (inline, regular, preallocated, holes), and
//! the zlib, LZO and zstd decoders that undo transparent compression.
//!
//! A file's extents are looked up in the tree for each read, so a file with
//! millions of extents costs memory only for the extent being read.

use std::io::Read;
use std::sync::Arc;

use super::bytes::{le32, le64, u8_at};
use super::lzo;
use super::sb::TreeRoot;
use super::tree::{EXTENT_DATA, Key};
use super::{Inner, invalid, limit, other, out_of_range, unsupported};
use atlas_fs_core::error::Result;
use atlas_fs_core::fs::Extent;

/// The most a compressed extent decodes to (the kernel's rule).
const MAX_DECODED: u64 = 128 << 10;
/// The most compressed bytes of one extent (the encoding can expand data a
/// little; the sector rounding adds up to one sector).
const MAX_ENCODED: u64 = 2 * MAX_DECODED;
/// Decoded extents kept for the next read.
const DECODE_CACHE: usize = 4;
/// Extents one `extents` call reports before it gives up.
const MAX_EXTENTS: usize = 1 << 22;
/// Longest symbolic link target read.
pub(super) const MAX_LINK: u64 = 64 << 10;

/// The largest zstd window (2^17 bytes) Btrfs compresses with.
const ZSTD_WINDOW_LOG: u32 = 17;

const COMPRESS_NONE: u8 = 0;
const COMPRESS_ZLIB: u8 = 1;
const COMPRESS_LZO: u8 = 2;
const COMPRESS_ZSTD: u8 = 3;

#[derive(Debug)]
pub(super) enum Body {
    /// The data is in the item itself (after the 21-byte header).
    Inline(Vec<u8>),
    /// `num_bytes` of the extent at `disk_bytenr`, starting `offset` bytes
    /// into it (into its decoded form, when compressed).
    Regular {
        disk_bytenr: u64,
        disk_num_bytes: u64,
        offset: u64,
        num_bytes: u64,
    },
    /// Allocated and never written: reads as zeros.
    Prealloc {
        disk_bytenr: u64,
        disk_num_bytes: u64,
        offset: u64,
        num_bytes: u64,
    },
}

/// One `EXTENT_DATA` item.
#[derive(Debug)]
pub(super) struct FileExtent {
    /// The file offset the extent starts at.
    pub start: u64,
    /// How many file bytes it covers.
    pub len: u64,
    pub compression: u8,
    pub ram_bytes: u64,
    pub body: Body,
}

impl FileExtent {
    pub fn end(&self) -> Result<u64> {
        self.start
            .checked_add(self.len)
            .ok_or_else(|| other("an extent ends past the largest file offset"))
    }

    pub fn parse(key: Key, data: &[u8]) -> Result<Self> {
        let ram_bytes = le64(data, 8)?;
        let compression = u8_at(data, 16)?;
        if u8_at(data, 17)? != 0 || le32(data, 18).map(|v| v & 0xFFFF)? != 0 {
            return Err(unsupported("encrypted or specially encoded Btrfs extents"));
        }
        if compression > COMPRESS_ZSTD {
            return Err(unsupported(format!("Btrfs compression type {compression}")));
        }
        if compression != COMPRESS_NONE && ram_bytes > MAX_DECODED {
            return Err(out_of_range(
                "extent ram_bytes",
                ram_bytes,
                "decoded extent",
                MAX_DECODED,
            ));
        }
        let ty = u8_at(data, 20)?;
        if ty == 0 {
            let payload = data.get(21..).ok_or_else(|| other("inline extent"))?;
            let len = if compression == COMPRESS_NONE {
                u64::try_from(payload.len()).unwrap_or(u64::MAX)
            } else {
                ram_bytes
            };
            return Ok(Self {
                start: key.offset,
                len,
                compression,
                ram_bytes,
                body: Body::Inline(payload.to_vec()),
            });
        }
        let disk_bytenr = le64(data, 21)?;
        let disk_num_bytes = le64(data, 29)?;
        let offset = le64(data, 37)?;
        let num_bytes = le64(data, 45)?;
        if num_bytes == 0 {
            return Err(invalid("extent num_bytes", 0));
        }
        let within = offset
            .checked_add(num_bytes)
            .ok_or_else(|| other("extent range overflows"))?;
        let limit_bytes = if compression == COMPRESS_NONE {
            disk_num_bytes
        } else {
            ram_bytes
        };
        if disk_bytenr != 0 && ty == 1 && within > limit_bytes {
            return Err(out_of_range(
                "extent range",
                within,
                "extent size",
                limit_bytes,
            ));
        }
        if compression != COMPRESS_NONE && ty == 1 && disk_num_bytes > MAX_ENCODED {
            return Err(out_of_range(
                "compressed extent size",
                disk_num_bytes,
                "limit",
                MAX_ENCODED,
            ));
        }
        let body = match ty {
            1 => Body::Regular {
                disk_bytenr,
                disk_num_bytes,
                offset,
                num_bytes,
            },
            2 => Body::Prealloc {
                disk_bytenr,
                disk_num_bytes,
                offset,
                num_bytes,
            },
            other_ty => return Err(invalid("extent type", u64::from(other_ty))),
        };
        let extent = Self {
            start: key.offset,
            len: num_bytes,
            compression,
            ram_bytes,
            body,
        };
        extent.end()?;
        Ok(extent)
    }
}

/// What lies at a file offset.
enum Spot {
    Extent(FileExtent),
    /// No extent: zeros up to this file offset.
    Hole(u64),
}

/// A decoded extent kept for the next read.
pub(super) struct Decoded {
    bytenr: u64,
    size: u64,
    compression: u8,
    data: Arc<Vec<u8>>,
}

pub(super) type DecodeCache = std::sync::Mutex<Vec<Decoded>>;

impl Inner {
    fn extent_at(&self, root: TreeRoot, ino: u64, pos: u64) -> Result<Spot> {
        if let Some(cursor) = self.trees.seek_le(root, Key::new(ino, EXTENT_DATA, pos))? {
            let (key, data) = cursor.item()?;
            if key.objectid == ino && key.ty == EXTENT_DATA {
                let extent = FileExtent::parse(key, data)?;
                if pos < extent.end()? {
                    return Ok(Spot::Extent(extent));
                }
            }
        }
        let until = match self.trees.seek_ge(root, Key::new(ino, EXTENT_DATA, pos))? {
            Some(cursor) => {
                let key = cursor.key()?;
                if key.objectid == ino && key.ty == EXTENT_DATA {
                    key.offset
                } else {
                    u64::MAX
                }
            }
            None => u64::MAX,
        };
        if until <= pos {
            return Err(other("an extent overlaps the one before it"));
        }
        Ok(Spot::Hole(until))
    }

    /// Reads `buf.len()` bytes of file `ino` at `offset`. The caller has
    /// checked the range against the file size.
    pub(super) fn read_file(
        &self,
        root: TreeRoot,
        ino: u64,
        offset: u64,
        buf: &mut [u8],
    ) -> Result<()> {
        let want = u64::try_from(buf.len()).map_err(|_| other("read length"))?;
        let end = offset
            .checked_add(want)
            .ok_or_else(|| other("read range overflows"))?;
        let mut pos = offset;
        let mut done = 0usize;
        while pos < end {
            let (until, extent) = match self.extent_at(root, ino, pos)? {
                Spot::Hole(until) => (until, None),
                Spot::Extent(e) => (e.end()?, Some(e)),
            };
            let stop = end.min(until);
            let n = usize::try_from(stop.saturating_sub(pos)).map_err(|_| other("read length"))?;
            let dst = buf
                .get_mut(done..done.saturating_add(n))
                .ok_or_else(|| other("read range"))?;
            match &extent {
                None => dst.fill(0),
                Some(e) => self.copy_extent(e, pos, dst)?,
            }
            pos = stop;
            done = done.saturating_add(n);
        }
        Ok(())
    }

    /// Fills `dst` with the bytes of `extent` from file offset `pos`.
    fn copy_extent(&self, extent: &FileExtent, pos: u64, dst: &mut [u8]) -> Result<()> {
        let into = pos.saturating_sub(extent.start);
        match &extent.body {
            Body::Prealloc { .. } => dst.fill(0),
            Body::Inline(payload) => {
                let decoded = self.decode(extent.compression, payload, extent.ram_bytes)?;
                copy_padded(&decoded, into, dst)?;
            }
            Body::Regular {
                disk_bytenr,
                disk_num_bytes,
                offset,
                ..
            } => {
                if *disk_bytenr == 0 {
                    dst.fill(0);
                } else if extent.compression == COMPRESS_NONE {
                    let at = disk_bytenr
                        .checked_add(*offset)
                        .and_then(|a| a.checked_add(into))
                        .ok_or_else(|| other("extent address overflows"))?;
                    self.trees.read_logical(at, dst)?;
                } else {
                    let decoded = self.decoded_extent(*disk_bytenr, *disk_num_bytes, extent)?;
                    let from = offset
                        .checked_add(into)
                        .ok_or_else(|| other("extent offset overflows"))?;
                    copy_padded(&decoded, from, dst)?;
                }
            }
        }
        Ok(())
    }

    /// The decoded form of the compressed extent at `bytenr`, from the cache
    /// or read and decoded now.
    fn decoded_extent(&self, bytenr: u64, size: u64, extent: &FileExtent) -> Result<Arc<Vec<u8>>> {
        let compression = extent.compression;
        if let Ok(cache) = self.decoded.lock()
            && let Some(hit) = cache
                .iter()
                .find(|d| d.bytenr == bytenr && d.size == size && d.compression == compression)
        {
            return Ok(Arc::clone(&hit.data));
        }
        let mut raw = vec![0u8; usize::try_from(size).map_err(|_| other("extent size"))?];
        self.trees.read_logical(bytenr, &mut raw)?;
        let data = Arc::new(self.decode(compression, &raw, extent.ram_bytes)?);
        if let Ok(mut cache) = self.decoded.lock() {
            if cache.len() >= DECODE_CACHE {
                cache.remove(0);
            }
            cache.push(Decoded {
                bytenr,
                size,
                compression,
                data: Arc::clone(&data),
            });
        }
        Ok(data)
    }

    /// Decodes `raw` (compressed with `compression`) to at most `ram_bytes`.
    fn decode(&self, compression: u8, raw: &[u8], ram_bytes: u64) -> Result<Vec<u8>> {
        let max = usize::try_from(match compression {
            COMPRESS_NONE => u64::try_from(raw.len()).unwrap_or(u64::MAX),
            _ => ram_bytes.min(MAX_DECODED),
        })
        .map_err(|_| other("extent size"))?;
        match compression {
            COMPRESS_NONE => Ok(raw.to_vec()),
            COMPRESS_ZLIB => miniz_oxide::inflate::decompress_to_vec_zlib_with_limit(raw, max)
                .map_err(|_| other("zlib data is damaged")),
            COMPRESS_ZSTD => {
                let mut decoder = zstd::stream::read::Decoder::new(raw)
                    .map_err(|_| other("zstd data is damaged"))?
                    .single_frame();
                // Btrfs never writes a window above 128 KiB; a frame that asks
                // for more would only make the decoder allocate it.
                decoder
                    .window_log_max(ZSTD_WINDOW_LOG)
                    .map_err(|_| other("zstd data is damaged"))?;
                let mut out = Vec::new();
                (&mut decoder)
                    .take(u64::try_from(max).unwrap_or(u64::MAX).saturating_add(1))
                    .read_to_end(&mut out)
                    .map_err(|_| other("zstd data is damaged"))?;
                if out.len() > max {
                    return Err(limit("decoded zstd extent", max as u64));
                }
                Ok(out)
            }
            COMPRESS_LZO => self.decode_lzo(raw, max),
            other_kind => Err(unsupported(format!("Btrfs compression type {other_kind}"))),
        }
    }

    /// Btrfs's LZO framing: the total length (4 bytes), then segments of a
    /// length (4 bytes) and an LZO1X stream, none of whose headers straddles
    /// a sector boundary.
    fn decode_lzo(&self, raw: &[u8], max: usize) -> Result<Vec<u8>> {
        let total = usize::try_from(le32(raw, 0)?).map_err(|_| other("LZO length"))?;
        let data = raw
            .get(..total)
            .filter(|_| total >= 4)
            .ok_or_else(|| other("LZO data is damaged"))?;
        let sector = usize::try_from(self.trees.superblock().sector_size)
            .map_err(|_| other("sector size"))?;
        let mut out = Vec::new();
        let mut pos = 4usize;
        while pos < total {
            let room = sector.saturating_sub(pos.checked_rem(sector).unwrap_or(0));
            if room < 4 {
                pos = pos.saturating_add(room);
                continue;
            }
            let seg = usize::try_from(le32(data, pos)?).map_err(|_| other("LZO length"))?;
            let from = pos.saturating_add(4);
            let to = from
                .checked_add(seg)
                .filter(|&e| e <= total)
                .ok_or_else(|| other("LZO data is damaged"))?;
            let stream = data.get(from..to).ok_or_else(|| other("LZO data"))?;
            lzo::decompress(stream, &mut out, max)?;
            pos = to;
        }
        Ok(out)
    }

    /// The physical runs that hold the data of file `ino`, in file order,
    /// with neighbours merged. Compressed extents report the compressed
    /// bytes. Inline data is in the tree, so it adds none.
    pub(super) fn file_runs(&self, root: TreeRoot, ino: u64) -> Result<Vec<Extent>> {
        let mut out: Vec<Extent> = Vec::new();
        let Some(mut cursor) = self.trees.seek_ge(root, Key::new(ino, EXTENT_DATA, 0))? else {
            return Ok(out);
        };
        loop {
            let (key, data) = cursor.item()?;
            if key.objectid != ino || key.ty != EXTENT_DATA {
                break;
            }
            let extent = FileExtent::parse(key, data)?;
            let run = match &extent.body {
                Body::Regular {
                    disk_bytenr,
                    disk_num_bytes,
                    offset,
                    num_bytes,
                }
                | Body::Prealloc {
                    disk_bytenr,
                    disk_num_bytes,
                    offset,
                    num_bytes,
                } if *disk_bytenr != 0 => {
                    if extent.compression == COMPRESS_NONE {
                        Some((disk_bytenr.saturating_add(*offset), *num_bytes))
                    } else {
                        Some((*disk_bytenr, *disk_num_bytes))
                    }
                }
                _ => None,
            };
            if let Some((logical, len)) = run
                && len > 0
            {
                let (physical, room) = self.trees.chunks().map(logical)?;
                if len > room {
                    return Err(out_of_range("extent length", len, "chunk end", room));
                }
                match out.last_mut() {
                    // Another reference to the same bytes.
                    Some(last) if last.offset == physical && last.len == len => {}
                    Some(last) if last.offset.checked_add(last.len) == Some(physical) => {
                        last.len = last.len.saturating_add(len);
                    }
                    _ => {
                        if out.len() >= MAX_EXTENTS {
                            return Err(limit("extents", MAX_EXTENTS as u64));
                        }
                        out.push(Extent {
                            offset: physical,
                            len,
                        });
                    }
                }
            }
            if !cursor.next()? {
                break;
            }
        }
        Ok(out)
    }
}

/// Copies from `src` starting at `from` into `dst`, zero-filling what `src`
/// does not have (a decoded extent can be shorter than it claims).
fn copy_padded(src: &[u8], from: u64, dst: &mut [u8]) -> Result<()> {
    let from = usize::try_from(from).unwrap_or(usize::MAX);
    let have = src.get(from..).unwrap_or(&[]);
    let n = have.len().min(dst.len());
    let (head, tail) = dst.split_at_mut(n);
    head.copy_from_slice(have.get(..n).ok_or_else(|| other("extent bytes"))?);
    tail.fill(0);
    Ok(())
}
