use std::str::FromStr;

use dotenvy_macro::dotenv;
use pyo3::exceptions::PyException;
use pyo3::types::PyModule;
use pyo3::{create_exception, pyclass, pymethods, pymodule, PyResult, Python};
use sgx_types::*;
use sgx_urts::SgxEnclave;

static ENCLAVE_FILE: &'static str = dotenv!("ENCLAVE_SHARED_OBJECT");

pub mod ecall;

create_exception!(
    user_auth_sgx,
    InvalidPassword,
    PyException,
    "password does not match the supplied hash"
);
create_exception!(
    user_auth_sgx,
    EmptyUserId,
    PyException,
    "supplied user id is empty"
);
create_exception!(
    user_auth_sgx,
    EmptyPassword,
    PyException,
    "supplied user password is empty"
);
create_exception!(
    user_auth_sgx,
    InvalidHashString,
    PyException,
    "supplied hash is not a valid PHC string"
);

#[pymodule]
fn user_auth_sgx(py: Python<'_>, m: &PyModule) -> PyResult<()> {
    m.add("InvalidPassword", py.get_type::<InvalidPassword>())?;
    m.add("EmtpyUserId", py.get_type::<EmptyUserId>())?;
    m.add("EmtpyPassword", py.get_type::<EmptyPassword>())?;
    m.add("InvalidHashString", py.get_type::<InvalidHashString>())?;
    m.add_class::<UserAuthEnclave>()?;
    m.add_class::<VerifyPasswordStatus>()?;
    Ok(())
}

#[pyclass]
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum VerifyPasswordStatus {
    PasswordVerified = 0,
    InvalidPassword = 1,
}

#[pyclass]
#[derive(Debug, Default, Clone)]
struct UserAuthEnclave(SgxEnclave);

#[pymethods]
impl UserAuthEnclave {
    #[new]
    fn create_enclave() -> PyResult<Self> {
        let mut launch_token: sgx_launch_token_t = [0; 1024];
        let mut launch_token_updated: i32 = 0;
        // Debug Support: if desired, set "SGX_DEBUG_MODE" to 1 before
        // compiling. Otherwise, set it to 0;
        let debug = i32::from_str(dotenv!("SGX_DEBUG_MODE")).unwrap();
        // PANIC: panics if debug is set to any i32 other than 0 or 1
        assert!(debug == 0 || debug == 1);
        let mut misc_attr = sgx_misc_attribute_t {
            secs_attr: sgx_attributes_t { flags: 0, xfrm: 0 },
            misc_select: 0,
        };
        Ok(UserAuthEnclave(
            SgxEnclave::create(
                ENCLAVE_FILE,
                debug,
                &mut launch_token,
                &mut launch_token_updated,
                &mut misc_attr,
            )
            .expect("failed to initialize SGX enclave"),
        ))
    }
    /// Compute a new password hash using the current enclave instance.
    fn hash_password(&self, user_id: &[u8], password: &str) -> PyResult<String> {
        let Self(enclave) = self;
        ecall::safe_hash_password(enclave.geteid(), user_id, password)
            .map_err(|err| PyException::new_err(err.to_string()))
    }
    /// Verify a user-supplied password against an existing hash (from the
    /// database) using the current enclave instance.
    fn verify_password(
        &self,
        user_id: &[u8],
        password: &str,
        stored_hash_string: &str,
    ) -> PyResult<VerifyPasswordStatus> {
        let Self(enclave) = self;
        ecall::safe_verify_password(enclave.geteid(), user_id, password, stored_hash_string)
            .map(|status| match status {
                ecall::VerifyPasswordStatus::InvalidPassword => {
                    VerifyPasswordStatus::InvalidPassword
                }
                ecall::VerifyPasswordStatus::PasswordVerified => {
                    VerifyPasswordStatus::PasswordVerified
                }
            })
            .map_err(|err| match err {
                ecall::AuthError::EmptyUserId => EmptyUserId::new_err(err.to_string()),
                ecall::AuthError::EmptyPassword => EmptyPassword::new_err(err.to_string()),
                ecall::AuthError::InvalidHashString => InvalidHashString::new_err(err.to_string()),
            })
    }
}
