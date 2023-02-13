use std::str::FromStr;

use dotenvy_macro::dotenv;
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use sgx_types::*;
use sgx_urts::SgxEnclave;

static ENCLAVE_FILE: &str = dotenv!("ENCLAVE_SHARED_OBJECT");

extern "C" {
    fn row_counter(
        eid: sgx_enclave_id_t,
        retval: *mut sgx_status_t,
        some_string: *const u8,
        len: usize,
        count: *mut uint64_t,
    ) -> sgx_status_t;

    fn dataset_hashing(
        eid: sgx_enclave_id_t,
        retval: *mut sgx_status_t,
        some_string: *const u8,
        len: usize,
        hash: *mut u8,
    ) -> sgx_status_t;

    fn dataset_append(
        eid: sgx_enclave_id_t,
        retval: *mut sgx_status_t,
        original_data: *const u8,
        original_data_len: usize,
        new_data: *const u8,
        new_data_len: usize,
        complete_data: *mut u8,
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
    module.add_function(wrap_pyfunction!(row_counter_call, module)?)?;
    module.add_function(wrap_pyfunction!(dataset_hashing_call, module)?)?;
    module.add_function(wrap_pyfunction!(dataset_append_call, module)?)?;
    Ok(())
}

#[pyfunction]
pub fn row_counter_call(content: &str) -> PyResult<u64> {
    let enclave = match init_enclave() {
        Ok(enclave) => enclave,
        Err(why) => {
            let message = format!("initialising enclave failed: {why}!");
            return Err(PyValueError::new_err(message));
        }
    };
    let mut retval = sgx_status_t::SGX_SUCCESS;
    let mut count = 0;
    let result = unsafe {
        row_counter(
            enclave.geteid(),
            &mut retval,
            content.as_ptr(),
            content.len(),
            &mut count,
        )
    };
    if result != sgx_status_t::SGX_SUCCESS {
        let message = format!("enclave ECALL failed: {result}!");
        return Err(PyValueError::new_err(message));
    }
    enclave.destroy();
    Ok(count)
}

#[pyfunction]
pub fn dataset_hashing_call(content: &str) -> PyResult<String> {
    let enclave = match init_enclave() {
        Ok(enclave) => enclave,
        Err(why) => {
            let message = format!("initialising enclave failed: {why}!");
            return Err(PyValueError::new_err(message));
        }
    };
    let mut retval = sgx_status_t::SGX_SUCCESS;
    let mut result_vec: Vec<u8> = vec![0; 64];
    let hash = &mut result_vec[..];
    let result = unsafe {
        dataset_hashing(
            enclave.geteid(),
            &mut retval,
            content.as_ptr(),
            content.len(),
            hash.as_mut_ptr(),
        )
    };
    if result != sgx_status_t::SGX_SUCCESS {
        let message = format!("enclave ECALL failed: {result}!");
        return Err(PyValueError::new_err(message));
    }
    enclave.destroy();
    let hash = String::from_utf8_lossy(hash);
    Ok(hash.into())
}

#[pyfunction]
pub fn dataset_append_call(original_data: &str, new_data: &str) -> PyResult<String> {
    let enclave = match init_enclave() {
        Ok(enclave) => enclave,
        Err(why) => {
            let message = format!("initialising enclave failed: {why}!");
            return Err(PyValueError::new_err(message));
        }
    };
    let mut retval = sgx_status_t::SGX_SUCCESS;
    let mut complete_data: Vec<u8> = Vec::new();
    let result = unsafe {
        dataset_append(
            enclave.geteid(),
            &mut retval,
            original_data.as_ptr(),
            original_data.len(),
            new_data.as_ptr(),
            new_data.len(),
            complete_data.as_mut_ptr(),
        )
    };
    if result != sgx_status_t::SGX_SUCCESS {
        let message = format!("enclave ECALL failed: {result}!");
        return Err(PyValueError::new_err(message));
    }
    enclave.destroy();
    Ok(String::from_utf8_lossy(&complete_data).into())
}
