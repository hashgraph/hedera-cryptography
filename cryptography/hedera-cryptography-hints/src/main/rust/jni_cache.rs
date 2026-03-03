// SPDX-License-Identifier: Apache-2.0

use std::any::Any;
use std::sync::{Arc, RwLock};
use jni::JNIEnv;
use jni::objects::JByteArray;

/// A cache for a value deserializable from a JByteArray.
pub struct JNICache<T> {
    /// The cached value
    /// RwLock provides a thread-safe mutable cell.
    /// Option lets us start with the cache empty.
    /// Arc allows us to share the value as a reference with callers of the get() function.
    option_value_cell: RwLock<Option<Arc<T>>>,

    /// A supplier for a value to initialize the cache.
    supplier: fn(&JNIEnv, &JByteArray) -> Result<T, Box<dyn Any>>
}

impl<T> JNICache<T> {
    /// Create a new cache instance with no value installed.
    pub const fn new(s: fn(&JNIEnv, &JByteArray) -> Result<T, Box<dyn Any>>) -> JNICache<T> {
        JNICache {
            option_value_cell: RwLock::new(None),
            supplier: s
        }
    }

    /// Get the cached value, and initialize it if necessary.
    pub fn get(&self, env: &JNIEnv, jarray: &JByteArray) -> Result<Arc<T>, Box<dyn Any>> {
        // Take locks for the shortest times possible.
        // read()./write().unwrap() is safe. If it fails, we're in a much bigger trouble.
        // Option./result.unwrap() is safe because it's guarded with proper if/else.
        let is_none = { self.option_value_cell.read().unwrap().is_none() };
        if is_none {
            let result = (self.supplier)(env, jarray);
            if result.is_err() {
                return Err(result.err().unwrap());
            }

            *self.option_value_cell.write().unwrap() = Some(Arc::new(result.unwrap()));
        }

        Ok(self.option_value_cell.read().unwrap().as_ref().unwrap().clone())
    }

    /// Clear the cached value.
    pub fn reset(&self) {
        // write().unwrap() is safe. If it fails, we're in a much bigger trouble.
        *self.option_value_cell.write().unwrap() = None;
    }
}
