// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Julian A. Loy.

//! LZO1X decompression, written for Btrfs: bounded in output, checked on every
//! input read and back reference, no panics. The instruction set is the one in
//! the kernel's `Documentation/staging/lzo.rst`.

use super::other;
use atlas_fs_core::error::Result;

const DAMAGED: &str = "LZO data is damaged";

struct Input<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Input<'a> {
    fn byte(&mut self) -> Result<u8> {
        let b = self
            .buf
            .get(self.pos)
            .copied()
            .ok_or_else(|| other(DAMAGED))?;
        self.pos = self.pos.saturating_add(1);
        Ok(b)
    }

    fn le16(&mut self) -> Result<usize> {
        let lo = usize::from(self.byte()?);
        let hi = usize::from(self.byte()?);
        Ok(lo | (hi << 8))
    }

    /// `base`, plus 255 for every zero byte, plus the first non-zero byte.
    fn extended(&mut self, base: usize) -> Result<usize> {
        let mut total = base;
        loop {
            let b = self.byte()?;
            if b == 0 {
                total = total.checked_add(255).ok_or_else(|| other(DAMAGED))?;
            } else {
                return total
                    .checked_add(usize::from(b))
                    .ok_or_else(|| other(DAMAGED));
            }
        }
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self.pos.checked_add(n).ok_or_else(|| other(DAMAGED))?;
        let s = self.buf.get(self.pos..end).ok_or_else(|| other(DAMAGED))?;
        self.pos = end;
        Ok(s)
    }
}

fn literals(input: &mut Input<'_>, out: &mut Vec<u8>, n: usize, limit: usize) -> Result<()> {
    if out.len().checked_add(n).is_none_or(|end| end > limit) {
        return Err(other(DAMAGED));
    }
    out.extend_from_slice(input.take(n)?);
    Ok(())
}

/// Appends the decompressed form of `input` (one LZO1X stream) to `out`. The
/// stream's back references reach only into what this call appended, and
/// `out` never grows past `limit` bytes in all. A stream that ends at an
/// instruction boundary without the end marker is accepted.
pub(super) fn decompress(input: &[u8], out: &mut Vec<u8>, limit: usize) -> Result<()> {
    let base = out.len();
    let mut inp = Input { buf: input, pos: 0 };
    // How many literals the last instruction copied: 0 to 3, or 4 for a run
    // of four or more.
    let mut state: usize = 0;
    if let Some(&first) = input.first()
        && first > 17
    {
        inp.pos = 1;
        let n = usize::from(first).saturating_sub(17);
        literals(&mut inp, out, n, limit)?;
        state = n.min(4);
    }
    while inp.pos < input.len() {
        let t = inp.byte()?;
        let (len, dist, trailing);
        if t < 16 {
            if state == 0 {
                let n = if t == 0 {
                    inp.extended(15)?
                } else {
                    usize::from(t)
                };
                literals(&mut inp, out, n.saturating_add(3), limit)?;
                state = 4;
                continue;
            }
            let h = usize::from(inp.byte()?);
            let d = usize::from((t >> 2) & 3);
            if state == 4 {
                len = 3;
                dist = (h << 2).saturating_add(d).saturating_add(2049);
            } else {
                len = 2;
                dist = (h << 2).saturating_add(d).saturating_add(1);
            }
            trailing = usize::from(t & 3);
        } else if t >= 64 {
            let h = usize::from(inp.byte()?);
            len = if t >= 128 {
                5usize.saturating_add(usize::from((t >> 5) & 3))
            } else {
                3usize.saturating_add(usize::from((t >> 5) & 1))
            };
            dist = (h << 3)
                .saturating_add(usize::from((t >> 2) & 7))
                .saturating_add(1);
            trailing = usize::from(t & 3);
        } else if t >= 32 {
            let l = usize::from(t & 31);
            len = (if l == 0 { inp.extended(31)? } else { l }).saturating_add(2);
            let v = inp.le16()?;
            dist = (v >> 2).saturating_add(1);
            trailing = v & 3;
        } else {
            let l = usize::from(t & 7);
            len = (if l == 0 { inp.extended(7)? } else { l }).saturating_add(2);
            let v = inp.le16()?;
            dist = 16384usize
                .saturating_add(usize::from(t & 8) << 11)
                .saturating_add(v >> 2);
            trailing = v & 3;
            if dist == 16384 {
                // The end marker.
                return Ok(());
            }
        }
        let produced = out.len().saturating_sub(base);
        if dist > produced || out.len().checked_add(len).is_none_or(|end| end > limit) {
            return Err(other(DAMAGED));
        }
        // Source and destination may overlap: copy one byte at a time.
        for _ in 0..len {
            let from = out.len().saturating_sub(dist);
            let b = out.get(from).copied().ok_or_else(|| other(DAMAGED))?;
            out.push(b);
        }
        literals(&mut inp, out, trailing, limit)?;
        state = trailing;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(input: &[u8], limit: usize) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        decompress(input, &mut out, limit).map(|()| out)
    }

    #[test]
    fn literal_and_match_streams() {
        // First byte 17 + 5: five literals, then the end marker.
        let mut s = vec![22];
        s.extend_from_slice(b"hello");
        s.extend_from_slice(&[17, 0, 0]);
        assert_eq!(run(&s, 100).unwrap(), b"hello");
        // "abcabcabc": literals "abc", then a 3-byte match 3 back (state 4,
        // 2049 + ...): use the M2 class instead. 0b01_0_000_00 = 64: length
        // 3, distance (H << 3) + D + 1 with H = 2, D = 0: 17, too far, so
        // use H = 0: distance 1 repeats the last byte.
        let mut s = vec![20];
        s.extend_from_slice(b"abc");
        s.extend_from_slice(&[64 + 8, 0]); // length 3 + 0, dist 3: "abc"
        s.extend_from_slice(&[17, 0, 0]);
        assert_eq!(run(&s, 100).unwrap(), b"abcabc");
    }

    #[test]
    fn hostile_streams_fail_cleanly() {
        // A back reference before the start.
        assert!(run(&[22, 1, 2, 3, 4, 5, 64, 100], 100).is_err());
        // Truncated literal run.
        assert!(run(&[40, 1, 2], 100).is_err());
        // Output limit.
        let mut s = vec![22];
        s.extend_from_slice(b"hello");
        assert!(run(&s, 4).is_err());
        // A long run of zero length bytes ends in an error, not a hang.
        let mut s = vec![0];
        s.extend(std::iter::repeat_n(0u8, 10_000));
        assert!(run(&s, 1 << 20).is_err());
        // Every short input either decodes or errors.
        for a in 0..=255u8 {
            for b in [0u8, 1, 17, 255] {
                let _ = run(&[a, b, b, b], 4096);
                let _ = run(&[22, 9, 9, 9, 9, a, b, b], 4096);
            }
        }
    }
}
