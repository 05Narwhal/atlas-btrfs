// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Julian A. Loy.

//! The Btrfs images the tests read. `fixtures/make_fixtures.sh` makes them
//! with `mkfs.btrfs` (109 MiB, the smallest mkfs accepts, nearly all zeros);
//! `pack.py` keeps the non-zero runs and zstd compresses the result. Loading
//! one gives a [`Sparse`] source that answers zeros for the gaps.

use std::sync::{Arc, OnceLock};

use atlas_fs_core::error::Result;
use atlas_fs_core::io::block::{BlockSource, check_range};

/// Modification time of the files the fixtures hold, in Unix seconds.
pub const MTIME: i64 = 1_700_000_000;

/// The fixtures: crc32c with every kind of content, and xxhash64 with 4 KiB
/// nodes and explicit holes.
pub const NAMES: [&str; 2] = ["main", "tiny"];

/// A byte pattern the fixtures hold: `populate.py`'s `pat`.
pub fn pat(n: usize, seed: u8) -> Vec<u8> {
    (0..n)
        .map(|i| (i as u8).wrapping_mul(31).wrapping_add(seed))
        .collect()
}

/// Lines that repeat every 257: `populate.py`'s `text`.
pub fn text(n: usize, seed: u64) -> Vec<u8> {
    let mut out = Vec::new();
    let mut i = 0u64;
    while out.len() < n {
        out.extend_from_slice(
            format!(
                "line {:05} seed {} alpha bravo charlie
",
                (i * i * seed) % 257,
                seed
            )
            .as_bytes(),
        );
        i += 1;
    }
    out.truncate(n);
    out
}

/// Bytes that do not compress: `populate.py`'s `rand`.
pub fn rand(n: usize, seed: u64) -> Vec<u8> {
    let mut state = (seed * 2_654_435_761 + 1) & 0xFFFF_FFFF;
    let mut out = Vec::new();
    while out.len() < n {
        state ^= (state << 13) & 0xFFFF_FFFF;
        state ^= state >> 17;
        state ^= (state << 5) & 0xFFFF_FFFF;
        out.push((state & 0xFF) as u8);
    }
    out
}

/// A large image kept as its non-zero runs.
pub struct Sparse {
    len: u64,
    /// (offset, bytes), sorted by offset, not overlapping.
    runs: Vec<(u64, Vec<u8>)>,
}

impl Sparse {
    fn parse(pack: &[u8]) -> Self {
        let len = u64::from_le_bytes(pack[..8].try_into().unwrap());
        let mut runs = Vec::new();
        let mut at = 8;
        while at < pack.len() {
            let offset = u64::from_le_bytes(pack[at..at + 8].try_into().unwrap());
            let n = u32::from_le_bytes(pack[at + 8..at + 12].try_into().unwrap()) as usize;
            runs.push((offset, pack[at + 12..at + 12 + n].to_vec()));
            at += 12 + n;
        }
        Self { len, runs }
    }

    /// The first `n` bytes (or all of them, when the image is shorter).
    pub fn head(&self, n: usize) -> Vec<u8> {
        let n = n.min(usize::try_from(self.len).unwrap_or(usize::MAX));
        let mut out = vec![0u8; n];
        self.read_at(0, &mut out).unwrap();
        out
    }

    /// Where the non-zero runs are: (offset, length).
    pub fn spans(&self) -> Vec<(u64, usize)> {
        self.runs.iter().map(|(o, b)| (*o, b.len())).collect()
    }
}

impl BlockSource for Sparse {
    fn len(&self) -> u64 {
        self.len
    }

    fn sector_size(&self) -> u32 {
        512
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<()> {
        check_range(offset, buf.len(), self.len)?;
        buf.fill(0);
        let end = offset + buf.len() as u64;
        let first = self
            .runs
            .partition_point(|(o, b)| *o + b.len() as u64 <= offset);
        for (o, bytes) in &self.runs[first..] {
            if *o >= end {
                break;
            }
            let from = offset.max(*o);
            let to = end.min(*o + bytes.len() as u64);
            buf[(from - offset) as usize..(to - offset) as usize]
                .copy_from_slice(&bytes[(from - *o) as usize..(to - *o) as usize]);
        }
        Ok(())
    }
}

/// An image with a few bytes changed, and optionally cut short.
pub struct Patched {
    pub base: Arc<Sparse>,
    pub patches: Vec<(u64, u8)>,
    pub len: u64,
}

impl BlockSource for Patched {
    fn len(&self) -> u64 {
        self.len
    }

    fn sector_size(&self) -> u32 {
        512
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<()> {
        check_range(offset, buf.len(), self.len)?;
        self.base.read_at(offset, buf)?;
        for &(at, xor) in &self.patches {
            if at >= offset && at - offset < buf.len() as u64 {
                buf[(at - offset) as usize] ^= xor;
            }
        }
        Ok(())
    }
}

fn load_packed(compressed: &[u8]) -> Arc<Sparse> {
    let pack = zstd::stream::decode_all(compressed).expect("decompress the fixture");
    Arc::new(Sparse::parse(&pack))
}

/// The fixture `name` (one of [`NAMES`]).
pub fn load(name: &str) -> Arc<Sparse> {
    static CACHE: [OnceLock<Arc<Sparse>>; 2] = [OnceLock::new(), OnceLock::new()];
    let index = NAMES
        .iter()
        .position(|n| *n == name)
        .expect("a fixture name");
    CACHE[index]
        .get_or_init(|| match index {
            0 => load_packed(include_bytes!("fixtures/main.pack.zst")),
            _ => load_packed(include_bytes!("fixtures/tiny.pack.zst")),
        })
        .clone()
}
