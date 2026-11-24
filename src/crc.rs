// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Julian A. Loy.

//! CRC32C (Castagnoli): the checksum of Btrfs metadata (the default) and the
//! hash of directory entry names.

const POLY: u32 = 0x82F6_3B78;

// Built at compile time: every index is below 256 and the cast is of a loop
// counter below 256.
#[allow(clippy::indexing_slicing, clippy::cast_possible_truncation)]
const TABLE: [u32; 256] = {
    let mut table = [0u32; 256];
    let mut i = 0;
    while i < 256 {
        let mut c = i as u32;
        let mut k = 0;
        while k < 8 {
            c = if c & 1 != 0 { (c >> 1) ^ POLY } else { c >> 1 };
            k += 1;
        }
        table[i] = c;
        i += 1;
    }
    table
};

/// The raw CRC32C update (no initial or final inversion): what the kernel's
/// `crc32c(seed, data, len)` computes.
pub(super) fn update(mut crc: u32, bytes: &[u8]) -> u32 {
    for &b in bytes {
        let index = usize::from(u8::try_from(crc & 0xFF).unwrap_or(0) ^ b);
        // The table has 256 entries and `index` is a byte.
        crc = TABLE.get(index).copied().unwrap_or(0) ^ (crc >> 8);
    }
    crc
}

/// The standard CRC32C of `bytes`: how Btrfs checksums a block.
pub(super) fn crc32c(bytes: &[u8]) -> u32 {
    !update(!0, bytes)
}

/// The hash a `DIR_ITEM` key holds for a name: raw CRC32C seeded with `!1`.
pub(super) fn name_hash(name: &[u8]) -> u32 {
    update(!1, name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_vectors() {
        // The standard check value of CRC32C.
        assert_eq!(crc32c(b"123456789"), 0xE306_9283);
        // The hash of "default" in a real root tree: key offset 2378154706.
        assert_eq!(name_hash(b"default"), 2_378_154_706);
    }
}
