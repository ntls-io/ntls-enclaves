#![cfg_attr(not(target_env = "sgx"), no_std)]

use std::slice;
use std::vec::Vec;

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
