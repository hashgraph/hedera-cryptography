// SPDX-License-Identifier: Apache-2.0

use std::cell::UnsafeCell;

/// A map of SIZE bits that allows one to allocate/deallocate continuous regions of bits.
/// The SIZE must be a compile-time constant because Rust array sizes must be compile-time constants.
/// The implementation is not thread-safe. A client code is responsible for thread-safety.
pub struct BitMap<const SIZE: usize> {
    // For simplicity, and to avoid taking dependencies on bit-handling crates, we use a [bool].
    // This may not be super efficient. However, with our heap and block sizes, this results
    // in a very reasonable memory usage. E.g. our current 20GB/64KB=320KB, which is a very
    // reasonable size for this array. Shrinking it 8 times wouldn't have a noticeable effect.
    bits: UnsafeCell<[bool; SIZE]>
}

impl<const SIZE: usize> BitMap<SIZE> {
    pub const fn new() -> Self {
        BitMap {
            bits: UnsafeCell::new([false; SIZE])
        }
    }

    /// Allocates `size` bits by flipping them to `true` and returns the start index.
    /// On error (zero size, "out of memory" - aka out of `false` bits, etc.), return usize::MAX.
    pub unsafe fn alloc(&self, size: usize) -> usize {
        if size == 0 {
            return usize::MAX
        }

        let bits_pointer = self.bits.get().cast::<bool>();

        // Trying to maintain the tail of the last allocated block and then start the search from
        // there, and then flip to the head of the map seems like a reasonable approach.
        // However, it may be complex to compute a proper `to` boundary for the second search from
        // the head because there may still be free bits at the beginning of the tail.
        // It would be complex to return two values from the `find` method.
        // Therefore, for simplicity, we just search the array from 0 to SIZE every time.
        // The array is reasonably small (provided the block size is reasonably large),
        // so this shouldn't cause performance problems.
        let index = self.find_false_bits(bits_pointer, size, 0, SIZE);
        if index >= SIZE {
            return usize::MAX
        }

        for i in index..index+size {
            *bits_pointer.add(i) = true;
        }
        index
    }

    /// Deallocates `size` bits at `index` by flipping them to `false`.
    pub unsafe fn dealloc(&self, index: usize, size: usize) {
        // Try to prevent SEGFAULTs:
        if index >= SIZE || index+size > SIZE {
            return;
        }

        let bits_pointer = self.bits.get().cast::<bool>();
        for i in index..index+size {
            *bits_pointer.add(i) = false;
        }
    }

    /// Finds `size` continuous `false` bits and returns the start index, or usize::MAX
    /// from is inclusive, to is exclusive.
    /// A client code is responsible for not deallocating bits that haven't been allocated in the first place.
    unsafe fn find_false_bits(&self, bits_pointer: *const bool, size: usize, from: usize, to: usize) -> usize {
        let mut cur = from;
        while cur <= to - size {
            if *bits_pointer.add(cur) {
                cur += 1;
                continue
            }

            // bits[cur] is false here

            // Small optimization for the smallest case to avoid extra loops/conditions below:
            if size == 1 {
                return cur
            }

            // Generic solution for size > 1
            let start = cur;
            cur += 1;
            while cur - start < size && cur < to && !*bits_pointer.add(cur) {
                cur += 1;
            }
            if cur - start == size && cur < to {
                return start
            }

            // There's no size `false` bits at start.
            // Either cur >= to or bits[cur] == true here.
            // Let's continue search from the next bit:
            cur += 1
        }

        usize::MAX
    }
}
