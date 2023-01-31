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
fn row_counter_module(_py: Python, module: &PyModule) -> PyResult<()> {
    module.add_function(wrap_pyfunction!(run, module)?)?;
    Ok(())
}

#[pyfunction]
pub fn run(content: &str) -> PyResult<u64> {
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
