#![cfg_attr(not(target_env = "sgx"), no_std)]
#[allow(unused_unsafe)]
use std::{eprintln, ptr, slice, vec::Vec};

use sgx_tstd as std;
use sgx_types::*;

static ALGORAND_ACCOUNT_SEED_IN_BYTES: usize = 64;
// TODO: place this in a shared crate
static HASH_SIZE_IN_BYTES: usize = 64;

#[no_mangle]
pub unsafe extern "C" fn row_counter_ecall(
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
pub unsafe extern "C" fn dataset_hashing_ecall(
    some_string: *const u8,
    some_len: usize,
    hash: &mut u8,
) -> sgx_status_t {
    let str_slice = unsafe { slice::from_raw_parts(some_string, some_len) };
    let hash_bytes = blake3::hash(str_slice).to_hex();
    unsafe { ptr::copy_nonoverlapping(hash_bytes.as_ptr(), hash, HASH_SIZE_IN_BYTES) };
    sgx_status_t::SGX_SUCCESS
}

#[no_mangle]
pub unsafe extern "C" fn dataset_append_ecall(
    original_data: *const u8,
    original_data_len: usize,
    new_data: *const u8,
    new_data_len: usize,
    complete_data: &mut u8,
    complete_data_len: &mut usize,
    complete_data_hash: &mut u8,
) -> sgx_status_t {
    let original_data = unsafe { slice::from_raw_parts(original_data, original_data_len) };
    let new_data = unsafe { slice::from_raw_parts(new_data, new_data_len) };

    let data: Result<Vec<serde_json::Value>, serde_json::Error> =
        serde_json::from_slice(original_data);
    let mut data = match data {
        Ok(value) => value,
        Err(why) => {
            eprintln!("{}", why);
            return sgx_status_t::SGX_ERROR_UNEXPECTED;
        }
    };

    let new_data: Result<Vec<serde_json::Value>, serde_json::Error> =
        serde_json::from_slice(new_data);
    match new_data {
        Ok(value) => data.extend(value),
        Err(why) => {
            eprintln!("{}", why);
            return sgx_status_t::SGX_ERROR_UNEXPECTED;
        }
    };

    let data = match serde_json::to_string(&data) {
        Ok(data) => data,
        Err(why) => {
            eprintln!("{}", why);
            return sgx_status_t::SGX_ERROR_UNEXPECTED;
        }
    };

    *complete_data_len = data.len();
    unsafe { ptr::copy_nonoverlapping(data.as_ptr(), complete_data, *complete_data_len) };

    let hash_bytes = blake3::hash(data.as_bytes()).to_hex();
    unsafe { ptr::copy(hash_bytes.as_ptr(), complete_data_hash, HASH_SIZE_IN_BYTES) };

    sgx_status_t::SGX_SUCCESS
}

#[no_mangle]
pub unsafe extern "C" fn transaction_sign_ecall(
    transaction: *const u8,
    transaction_len: usize,
    account_seed: *const u8,
    signed_transaction: &mut u8,
    signed_transaction_len: &mut usize,
) -> sgx_status_t {
    let transaction = unsafe { slice::from_raw_parts(transaction, transaction_len) };
    let account_seed =
        unsafe { slice::from_raw_parts(account_seed, ALGORAND_ACCOUNT_SEED_IN_BYTES) };

    *signed_transaction_len = transaction.len();
    unsafe {
        ptr::copy_nonoverlapping(
            transaction.as_ptr(),
            signed_transaction,
            *signed_transaction_len,
        )
    };

    sgx_status_t::SGX_SUCCESS
}
