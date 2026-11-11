//! The environment, through the C library's getenv: the settings SPEC
//! gives the server (BACKEND, FILES, LOG).

use alloc::vec::Vec;
use core::ffi::{c_char, CStr};

#[link(name = "c")]
// rr: escape(unsafe): the signature is the C library's, from stdlib.h.
unsafe extern "C" {
    fn getenv(name: *const c_char) -> *const c_char;
}

/// The value of the variable name, if set.
pub fn var(name: &CStr) -> Option<Vec<u8>> {
    // rr: escape(unsafe): name is NUL-terminated; nothing sets the
    // environment while the server runs.
    let value = unsafe { getenv(name.as_ptr()) };
    if value.is_null() {
        return None;
    }
    // rr: escape(unsafe): getenv's value is NUL-terminated.
    let bytes = unsafe { CStr::from_ptr(value) }.to_bytes();
    // rr: escape(copy): the server keeps the value.
    Some(Vec::from(bytes))
}
