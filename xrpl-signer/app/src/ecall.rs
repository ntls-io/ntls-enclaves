use sgx_types::*;
use thiserror::Error;

extern "C" {
    fn generate_seed(eid: sgx_enclave_id_t, retval: *mut sgx_status_t) -> sgx_status_t;
    fn verify_password(eid: sgx_enclave_id_t, retval: *mut sgx_status_t) -> sgx_status_t;
}

#[derive(Debug, Error)]
pub enum AuthError {
    #[error("password does not match the given hash")]
    EmptyUserId,
    #[error("empty password supplied")]
    EmptyPassword,
    #[error("supplied hash is not a valid PHC hash string")]
    InvalidHashString,
}
