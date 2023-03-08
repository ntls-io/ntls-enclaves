use std::{slice, str::FromStr};

use dotenvy_macro::dotenv;
use pyo3::{exceptions::PyValueError, prelude::*};
use sgx_types::*;
use sgx_urts::SgxEnclave;

static ENCLAVE_FILE: &str = dotenv!("ENCLAVE_SHARED_OBJECT");
static DATASET_SIZE_LIMIT_IN_BYTES: usize = 1024 * 1024;
static HASH_SIZE_IN_BYTES: usize = 64;

extern "C" {
    fn row_counter_ecall(
        eid: sgx_enclave_id_t,
        retval: *mut sgx_status_t,
        some_string: *const u8,
        len: usize,
        count: *mut uint64_t,
    ) -> sgx_status_t;

    fn dataset_hashing_ecall(
        eid: sgx_enclave_id_t,
        retval: *mut sgx_status_t,
        some_string: *const u8,
        len: usize,
        hash: *mut u8,
    ) -> sgx_status_t;

    fn dataset_append_ecall(
        eid: sgx_enclave_id_t,
        retval: *mut sgx_status_t,
        original_data: *const u8,
        original_data_len: usize,
        new_data: *const u8,
        new_data_len: usize,
        complete_data: *mut u8,
        complete_data_len: *mut usize,
        complete_data_hash: *mut u8,
    ) -> sgx_status_t;

    fn transaction_sign_ecall(
        eid: sgx_enclave_id_t,
        retval: *mut sgx_status_t,
        transaction: *const u8,
        transaction_len: usize,
        account_seed: *const u8,
        signed_transaction: *mut u8,
        signed_transaction_len: *mut usize,
    ) -> sgx_status_t;
}

fn init_enclave() -> SgxResult<SgxEnclave> {
    let mut launch_token: sgx_launch_token_t = [0; 1024];
    let mut launch_token_updated: i32 = 0;
    // call sgx_create_enclave to initialize an enclave instance
    // Debug Support: set 2nd parameter to 1
    let debug = i32::from_str(dotenv!("SGX_DEBUG_MODE")).unwrap_or(1);
    let mut misc_attr = sgx_misc_attribute_t {
        secs_attr: sgx_attributes_t { flags: 0, xfrm: 0 },
        misc_select: 0,
    };
    SgxEnclave::create(
        ENCLAVE_FILE,
        debug,
        &mut launch_token,
        &mut launch_token_updated,
        &mut misc_attr,
    )
}

#[pymodule]
fn utils(_py: Python, module: &PyModule) -> PyResult<()> {
    module.add_function(wrap_pyfunction!(row_counter, module)?)?;
    module.add_function(wrap_pyfunction!(dataset_hashing, module)?)?;
    module.add_function(wrap_pyfunction!(dataset_append, module)?)?;
    module.add_function(wrap_pyfunction!(transaction_sign, module)?)?;
    Ok(())
}

#[pyfunction]
pub fn row_counter(content: &str) -> PyResult<u64> {
    let enclave = match init_enclave() {
        Ok(enclave) => enclave,
        Err(why) => {
            let message = format!("initialising enclave failed: {}!", why);
            return Err(PyValueError::new_err(message));
        }
    };
    let mut retval = sgx_status_t::SGX_SUCCESS;
    let mut count = 0;
    let result = unsafe {
        row_counter_ecall(
            enclave.geteid(),
            &mut retval,
            content.as_ptr(),
            content.len(),
            &mut count,
        )
    };
    enclave.destroy();
    if result != sgx_status_t::SGX_SUCCESS {
        let message = format!("enclave ECALL failed: {}!", result);
        return Err(PyValueError::new_err(message));
    }
    Ok(count)
}

#[pyfunction]
pub fn dataset_hashing(content: &str) -> PyResult<String> {
    let enclave = match init_enclave() {
        Ok(enclave) => enclave,
        Err(why) => {
            let message = format!("initialising enclave failed: {}!", why);
            return Err(PyValueError::new_err(message));
        }
    };
    let mut retval = sgx_status_t::SGX_SUCCESS;
    let mut result_vec: Vec<u8> = vec![0; HASH_SIZE_IN_BYTES];
    let hash = &mut result_vec[..];
    let result = unsafe {
        dataset_hashing_ecall(
            enclave.geteid(),
            &mut retval,
            content.as_ptr(),
            content.len(),
            hash.as_mut_ptr(),
        )
    };
    enclave.destroy();
    if result != sgx_status_t::SGX_SUCCESS {
        let message = format!("enclave ECALL failed: {}!", result);
        return Err(PyValueError::new_err(message));
    }
    let hash = String::from_utf8_lossy(hash);
    Ok(hash.into())
}

#[pyfunction]
pub fn dataset_append(original_data: &str, new_data: &str) -> PyResult<(String, String)> {
    let enclave = match init_enclave() {
        Ok(enclave) => enclave,
        Err(why) => {
            let message = format!("initialising enclave failed: {}!", why);
            return Err(PyValueError::new_err(message));
        }
    };
    let mut retval = sgx_status_t::SGX_SUCCESS;
    let mut complete_data = Vec::with_capacity(DATASET_SIZE_LIMIT_IN_BYTES);
    let mut complete_data_len = 0;
    let mut complete_data_hash = Vec::with_capacity(HASH_SIZE_IN_BYTES);
    let result = unsafe {
        dataset_append_ecall(
            enclave.geteid(),
            &mut retval,
            original_data.as_ptr(),
            original_data.len(),
            new_data.as_ptr(),
            new_data.len(),
            complete_data.as_mut_ptr(),
            &mut complete_data_len,
            complete_data_hash.as_mut_ptr(),
        )
    };
    enclave.destroy();
    if result != sgx_status_t::SGX_SUCCESS {
        let message = format!("enclave ECALL failed: {}!", result);
        return Err(PyValueError::new_err(message));
    }
    let complete_data = unsafe { slice::from_raw_parts(complete_data.as_ptr(), complete_data_len) };
    let complete_data_hash =
        unsafe { slice::from_raw_parts(complete_data_hash.as_ptr(), HASH_SIZE_IN_BYTES) };
    let complete_data = String::from_utf8_lossy(complete_data);
    let complete_data_hash = String::from_utf8_lossy(complete_data_hash);
    Ok((complete_data.into(), complete_data_hash.into()))
}

#[pyfunction]
pub fn transaction_sign(transaction: &str, account_seed: &str) -> PyResult<Vec<u8>> {
    let enclave = match init_enclave() {
        Ok(enclave) => enclave,
        Err(why) => {
            let message = format!("initialising enclave failed: {}!", why);
            return Err(PyValueError::new_err(message));
        }
    };
    let mut retval = sgx_status_t::SGX_SUCCESS;
    let mut signed_transaction = Vec::with_capacity(100); // TODO avoid magic number
    let mut signed_transaction_len = 0;
    let result = unsafe {
        transaction_sign_ecall(
            enclave.geteid(),
            &mut retval,
            transaction.as_ptr(),
            transaction.len(),
            account_seed.as_ptr(),
            signed_transaction.as_mut_ptr(),
            &mut signed_transaction_len,
        )
    };
    enclave.destroy();
    if result != sgx_status_t::SGX_SUCCESS {
        let message = format!("enclave ECALL failed: {}!", result);
        return Err(PyValueError::new_err(message));
    }
    let signed_transaction =
        unsafe { slice::from_raw_parts(signed_transaction.as_ptr(), signed_transaction_len) };
    Ok(signed_transaction.into())
}
