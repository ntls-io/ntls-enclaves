#![cfg_attr(not(target_env = "sgx"), no_std)]

use std::vec::Vec;
use std::{ptr, slice};

use sgx_tstd as std;
use sgx_types::*;

#[no_mangle]
pub extern "C" fn row_counter(
    some_string: *const u8,
    some_len: usize,
    count: &mut usize,
) -> sgx_status_t {
    let str_slice = unsafe { slice::from_raw_parts(some_string, some_len) };

    let value = if let Ok(value) = serde_json::from_slice::<Vec<serde_json::Value>>(str_slice) {
        value
    } else {
        return sgx_status_t::SGX_ERROR_UNEXPECTED;
    };
    *count = value.len();

    sgx_status_t::SGX_SUCCESS
}

#[no_mangle]
pub extern "C" fn dataset_hashing(
    some_string: *const u8,
    some_len: usize,
    hash: &mut u8,
) -> sgx_status_t {
    let str_slice = unsafe { slice::from_raw_parts(some_string, some_len) };
    let hash_bytes = blake3::hash(str_slice).to_hex();
    unsafe { ptr::copy_nonoverlapping(hash_bytes.as_ptr(), hash, 64) };
    sgx_status_t::SGX_SUCCESS
}
