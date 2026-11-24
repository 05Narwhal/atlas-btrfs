// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Julian A. Loy.

//! Seed inputs for the Btrfs fuzz target in `fuzz/`.
//!
//! A real image keeps its trees megabytes in, past the fuzz run's input limit,
//! so the seeds are the small volumes `synth` builds: a valid one, and one
//! whose file data is zlib compressed.

use super::synth::{self, Volume};

/// The seed volumes, by file name. Disk Atlas writes the head of each as a
/// `probe` seed too.
pub fn volumes() -> Vec<(&'static str, Vec<u8>)> {
    let plain = Volume::new().image();
    // `data.bin` as a compressed extent: a zlib stream of 4096 zeros.
    let mut zlib = Volume::new();
    zlib.data[0].1 = miniz_oxide::deflate::compress_to_vec_zlib(&[0u8; 4096], 6);
    for (key, data) in &mut zlib.fs_items {
        if *key == super::tree::Key::new(258, super::tree::EXTENT_DATA, 0) {
            *data = synth::regular_extent(1, 4096, synth::DATA, 4096, 0, 4096);
        }
    }
    vec![("btrfs-synth", plain), ("btrfs-synth-zlib", zlib.image())]
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::Path;
    use std::sync::Arc;

    use atlas_fs_core::fs::FileSystem;
    use atlas_fs_core::io::block::MemSource;

    use super::volumes;

    /// The largest input the fuzz run accepts (`-max_len=1048576`).
    const MAX_SEED: usize = 1 << 20;

    /// Writes the seeds into `$ATLAS_FUZZ_SEEDS/btrfs_mount`, with a `btrfs-`
    /// prefix so other seeds in that folder stay. Run it with
    /// `cargo test --lib write_fuzz_seeds -- --ignored`.
    #[test]
    #[ignore = "writes files; run by the fuzz CI job"]
    fn write_fuzz_seeds() {
        let Some(root) = std::env::var_os("ATLAS_FUZZ_SEEDS") else {
            return;
        };
        let mount_dir = Path::new(&root).join("btrfs_mount");
        fs::create_dir_all(&mount_dir).expect("create seed directory");
        for (name, image) in volumes() {
            fs::write(mount_dir.join(name), &image).expect("write mount seed");
        }
    }

    /// Every seed fits the run's input limit, mounts and lists its root, so the
    /// target starts on the valid path.
    #[test]
    fn mount_seeds_are_valid_and_small() {
        for (name, image) in volumes() {
            assert!(image.len() <= MAX_SEED, "{name}: {} bytes", image.len());
            let volume = crate::mount(Arc::new(MemSource::new(image)))
                .unwrap_or_else(|e| panic!("{name}: {e}"));
            assert!(volume.read_dir(volume.root()).is_ok(), "{name}");
        }
    }
}
