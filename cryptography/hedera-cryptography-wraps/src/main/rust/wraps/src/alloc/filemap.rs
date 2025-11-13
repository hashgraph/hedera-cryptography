// SPDX-License-Identifier: Apache-2.0

use std::borrow::BorrowMut;
use std::cell::{OnceCell, UnsafeCell};
use std::env;
use std::fs::{File, OpenOptions};
use std::path::Path;
use std::sync::{Mutex, OnceLock};
use ark_std::iterable::Iterable;
use memmap2::MmapMut;

/// An instance holder for an optional mutable memory-mapped file.
/// If the environment variable doesn't exist or doesn't specify a file name,
/// then the option is empty.
/// The implementation is thread-safe.
pub struct FileMap {
    file_size: u64,

    // OnceLock to initialize once.
    // UnsafeCell to be able to get mutable references to the MmapMut.
    once_option_cell_map: OnceLock<Option<UnsafeCell<MmapMut>>>
}

// Cannot call env::var inside get_map below because that would want to deallocate the String object
// which in turn would call dealloc(), and it in turn would call get_map() again, locking forever.
// So we read the var into a static object here:
static FILE_NAME: OnceLock<Option<String>> = OnceLock::new();
fn get_file_name() -> &'static Option<String> {
    FILE_NAME.get_or_init(|| {
        match env::var("TSS_LIB_WRAPS_SWAP_FILE") {
            Ok(val) => Some(val),
            Err(_) => None
        }
    })
}

impl FileMap {
    pub const fn new(file_size: u64) -> Self {
        FileMap {
            file_size,
            once_option_cell_map: OnceLock::new()
        }
    }

    /// Get an optional mutable reference to the memory mapped file.
    pub unsafe fn get_map(&self) -> Option<&mut MmapMut> {
        let option_cell = self.once_option_cell_map.get_or_init(|| {
            // The tempfile::tempfile() must be using memory allocation/deallocation because
            // when used here, it produces an infinite hang. A static OnceLock trick doesn't work
            // for the tempfile either as it does for the file name env var above.
            // And the NamedTempFile is not guaranteed to be deleted by OS.
            // So we don't use either of these, and also avoid an extra dependency on tempfile.

            // Instead, we use an env var with a file name to enable the SWAP.

            // If the SWAP file name is undefined, or opening the file or the map fails,
            // just return None and we won't use the SWAP then. We don't want to crash the process
            // just yet because the system may in fact have sufficient RAM already.
            let option_file_name = get_file_name();
            if option_file_name.is_empty() {
                return None;
            }
            // Safe unwrap() because is_empty() is checked above:
            let file_name = option_file_name.as_ref().unwrap();

            if file_name.trim().is_empty() {
                return None;
            }

            let file = match OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .truncate(true)
                .open(Path::new(&file_name)) {
                Ok(file) => file,
                Err(_) => return None
            };

            if file.set_len(self.file_size).is_err() {
                return None
            }

            let map = match MmapMut::map_mut(&file) {
                Ok(val) => val,
                Err(_) => return None
            };

            Some(UnsafeCell::new(map))
        });

        // Convert Option<UnsafeCell<MmapMut>> to Option<&mut MmapMut>:
        option_cell.as_ref().map(|cell| &mut *cell.get())
    }
}
