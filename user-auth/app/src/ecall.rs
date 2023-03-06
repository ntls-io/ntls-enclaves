use password_hash::rand_core::OsRng;
use password_hash::{PasswordHashString, SaltString};
use sgx_types::*;
use thiserror::Error;
use user_auth_common::*;

extern "C" {
    fn hash_password(
        eid: sgx_enclave_id_t,
        retval: *mut sgx_status_t,
        password: *const u8,
        password_length: usize,
        salt: *const u8,
        user_id: *const u8,
        user_id_length: usize,
        hash_string: *mut u8,
    ) -> sgx_status_t;
    fn verify_password(
        eid: sgx_enclave_id_t,
        retval: *mut sgx_status_t,
        password: *const u8,
        password_length: usize,
        user_id: *const u8,
        user_id_length: usize,
        stored_hash_string: *const u8,
        verify_status: *mut VerifyPasswordStatus,
    ) -> sgx_status_t;
}

#[derive(Debug, Error)]
pub enum AuthError {
    #[error("supplied hash is not a valid PHC hash string")]
    InvalidHashString,
}

/// Compute a new password hash.
pub fn safe_hash_password(
    eid: sgx_enclave_id_t,
    user_id: &[u8],
    password: &str,
) -> Result<String, AuthError> {
    // generate a 16 byte salt using entropy supplied by the OS
    let salt = SaltString::generate(&mut OsRng);
    let mut hash_string_buf = [0u8; HASH_STRING_LENGTH];
    let ecall_return = &mut sgx_status_t::default();
    unsafe {
        hash_password(
            eid,
            ecall_return,
            password.as_bytes().as_ptr(),
            password.len(),
            salt.as_str().as_bytes().as_ptr(),
            user_id.as_ptr(),
            user_id.len(),
            hash_string_buf.as_mut_ptr(),
        )
    };
    Ok(String::from_utf8(Vec::from(hash_string_buf)).expect("invalid UTF-8 string received"))
}

/// Verify a user-supplied password against an existing hash (from the
/// database).
pub fn safe_verify_password(
    eid: sgx_enclave_id_t,
    user_id: &[u8],
    password: &str,
    stored_hash_string: &str,
) -> Result<VerifyPasswordStatus, AuthError> {
    let mut verify_status = VerifyPasswordStatus::InvalidPassword;
    let ecall_return = &mut sgx_status_t::default();

    if PasswordHashString::parse(stored_hash_string, password_hash::Encoding::B64).is_err() {
        return Err(AuthError::InvalidHashString);
    }
    unsafe {
        verify_password(
            eid,
            ecall_return,
            password.as_bytes().as_ptr(),
            password.len(),
            user_id.as_ptr(),
            user_id.len(),
            stored_hash_string.as_bytes().as_ptr(),
            &mut verify_status,
        )
    };

    match verify_status {
        VerifyPasswordStatus::InvalidPassword => Ok(VerifyPasswordStatus::InvalidPassword),
        VerifyPasswordStatus::PasswordVerified => Ok(VerifyPasswordStatus::PasswordVerified),
    }
}
