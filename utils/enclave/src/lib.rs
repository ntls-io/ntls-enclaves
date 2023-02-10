#![cfg_attr(not(target_env = "sgx"), no_std)]
#![deny(unsafe_op_in_unsafe_fn)]

use std::vec::Vec;
use std::{eprintln, ptr, slice};

use sgx_tstd as std;
use sgx_types::*;

#[no_mangle]
pub unsafe extern "C" fn row_counter(
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
pub unsafe extern "C" fn dataset_hashing(
    some_string: *const u8,
    some_len: usize,
    hash: *mut u8,
) -> sgx_status_t {
    let str_slice = unsafe { slice::from_raw_parts(some_string, some_len) };
    let hash_bytes = blake3::hash(str_slice).to_hex();
    unsafe { ptr::copy_nonoverlapping(hash_bytes.as_ptr(), hash, 64) };
    sgx_status_t::SGX_SUCCESS
}

#[no_mangle]
pub unsafe extern "C" fn dataset_append(
    original_data: *const u8,
    original_data_len: usize,
    new_data: *const u8,
    new_data_len: usize,
    complete_data: *mut u8,
    complete_data_len: &mut usize,
) -> sgx_status_t {
    let original_data = unsafe { slice::from_raw_parts(original_data, original_data_len) };
    let new_data = unsafe { slice::from_raw_parts(new_data, new_data_len) };

    let data: Result<Vec<serde_json::Value>, serde_json::Error> =
        serde_json::from_slice(original_data);
    let mut data = match data {
        Ok(value) => value,
        Err(why) => {
            eprintln!("{why}");
            return sgx_status_t::SGX_ERROR_UNEXPECTED;
        }
    };

    let new_data: Result<Vec<serde_json::Value>, serde_json::Error> =
        serde_json::from_slice(new_data);
    match new_data {
        Ok(value) => data.extend(value),
        Err(why) => {
            eprintln!("{why}");
            return sgx_status_t::SGX_ERROR_UNEXPECTED;
        }
    };

    let data = match serde_json::to_string(&data) {
        Ok(data) => data,
        Err(why) => {
            eprintln!("{why}");
            return sgx_status_t::SGX_ERROR_UNEXPECTED;
        }
    };

    *complete_data_len = data.len();
    unsafe { ptr::copy_nonoverlapping(data.as_ptr(), complete_data, data.len()) };

    sgx_status_t::SGX_SUCCESS
}
