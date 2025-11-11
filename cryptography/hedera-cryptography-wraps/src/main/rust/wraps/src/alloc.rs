// SPDX-License-Identifier: Apache-2.0

mod filemap;
mod bitmap;

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::UnsafeCell;
use std::sync::Mutex;
use memmap2::{MmapMut, UncheckedAdvice};

use filemap::FileMap;
use bitmap::BitMap;

/// Allocate small objects in RAM, larger objects on disk
const SIZE_THRESHOLD_BYTES: usize = 64 * 1024;

/// Disk file size in bytes. Unfortunately, this must be a compile-time constant.
const HEAP_SIZE_BYTES: u64 = 20 * 1024 * 1024 * 1024;

/// Allocation unit size in bytes. Heap size must be divisible by the block size.
const BLOCK_SIZE_BYTES: usize = SIZE_THRESHOLD_BYTES;

/// Number of blocks in the file on disk.
const NUM_OF_BLOCKS: usize = (HEAP_SIZE_BYTES / BLOCK_SIZE_BYTES as u64) as usize;

/// A memory allocator that attempts to allocate larger objects in a memory mapped file on disk.
pub struct MemmapAllocator {
    // BitMap needs to be thread-safe, so it's in a Mutex:
    bit_map: Mutex<BitMap<NUM_OF_BLOCKS>>,
    file_map: FileMap,
}

impl MemmapAllocator {
    pub const fn new() -> Self {
        MemmapAllocator {
            bit_map: Mutex::new(BitMap::new()),
            file_map: FileMap::new(HEAP_SIZE_BYTES)
        }
    }
}

// Required for allocators defined in static objects.
unsafe impl Sync for MemmapAllocator {}

/// The actual allocator implementation. In case the layout size is smaller than the threshold
/// or if any errors occur with the memory on disk, then fall back to using the system memory.
/// Try to never crash/panic/segfault.
unsafe impl GlobalAlloc for MemmapAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if layout.size() >= SIZE_THRESHOLD_BYTES && self.file_map.get_map().is_some() {
            // Try the map
            let num_of_blocks = (layout.size() + BLOCK_SIZE_BYTES - 1) / BLOCK_SIZE_BYTES;

            // lock() will block until the mutex is available, so it's safe to unwrap().
            // If the lock indeed fails and the Result is an Err then we're already in a bigger trouble.
            // Also, put inside {} to release the lock ASAP.
            let index = { self.bit_map.lock().unwrap().alloc(num_of_blocks) };
            if index < NUM_OF_BLOCKS {
                // unwrap() is safe because we checked is_some() above:
                return self.file_map.get_map().unwrap().as_mut_ptr().add(index * BLOCK_SIZE_BYTES)
            }
        }
        // If size is small or map is full, then use system RAM:
        System.alloc(layout)
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        if self.file_map.get_map().is_some() {
            // unwrap() is safe because we checked is_some() above:
            let start_ptr = self.file_map.get_map().unwrap().as_mut_ptr();
            let finish_ptr = start_ptr.add(HEAP_SIZE_BYTES as usize);
            if ptr >= start_ptr && ptr < finish_ptr {
                let offset = ptr.offset_from(start_ptr) as usize;
                let index = offset as usize / BLOCK_SIZE_BYTES;
                let num_of_blocks = (layout.size() + BLOCK_SIZE_BYTES - 1) / BLOCK_SIZE_BYTES;

                // The below operation is only supported on Linux currently, so we ignore any errors.
                // Any OS will eventually free this range anyway. This is just a hint:
                // unwrap() is safe because we checked is_some() above:
                let _ = self.file_map.get_map().unwrap().unchecked_advise_range(UncheckedAdvice::DontNeed, offset, layout.size());

                // lock() will block until the mutex is available, so it's safe to unwrap().
                // If the lock indeed fails and the Result is an Err then we're already in a bigger trouble.
                self.bit_map.lock().unwrap().dealloc(index, num_of_blocks);
                return;
            }
        }
        // If the pointer is outside the map or there's no map at all, then it's system RAM:
        System.dealloc(ptr, layout);
    }
}
