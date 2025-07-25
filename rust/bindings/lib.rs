// SPDX-License-Identifier: GPL-2.0

//! Bindings.
//!
//! Imports the generated bindings by `bindgen`.
//!
//! This crate may not be directly used. If you need a kernel C API that is
//! not ported or wrapped in the `kernel` crate, then do so first instead of
//! using this crate.

#![no_std]
// See <https://github.com/rust-lang/rust-bindgen/issues/1651>.
#![cfg_attr(test, allow(deref_nullptr))]
#![cfg_attr(test, allow(unaligned_references))]
#![cfg_attr(test, allow(unsafe_op_in_unsafe_fn))]
#![allow(
    clippy::all,
    missing_docs,
    non_camel_case_types,
    non_upper_case_globals,
    non_snake_case,
    improper_ctypes,
    unreachable_pub,
    unsafe_op_in_unsafe_fn
)]

#[allow(dead_code)]
#[allow(clippy::cast_lossless)]
#[allow(clippy::ptr_as_ptr)]
#[allow(clippy::ref_as_ptr)]
#[allow(clippy::undocumented_unsafe_blocks)]
#[cfg_attr(CONFIG_RUSTC_HAS_UNNECESSARY_TRANSMUTES, allow(unnecessary_transmutes))]
mod bindings_raw {
    // Manual definition for blocklisted types.
    type __kernel_size_t = usize;
    type __kernel_ssize_t = isize;
    type __kernel_ptrdiff_t = isize;

    // Use glob import here to expose all helpers.
    // Symbols defined within the module will take precedence to the glob import.
    pub use super::bindings_helper::*;
    include!(concat!(
        env!("OBJTREE"),
        "/rust/bindings/bindings_generated.rs"
    ));
}

// When both a directly exposed symbol and a helper exists for the same function,
// the directly exposed symbol is preferred and the helper becomes dead code, so
// ignore the warning here.
#[allow(dead_code)]
mod bindings_helper {
    // Import the generated bindings for types.
    use super::bindings_raw::*;
    include!(concat!(
        env!("OBJTREE"),
        "/rust/bindings/bindings_helpers_generated.rs"
    ));
}

pub use bindings_raw::*;
