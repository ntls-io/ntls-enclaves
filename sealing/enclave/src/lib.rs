#![no_std]
#![deny(unsafe_op_in_unsafe_fn)]

use std::{eprintln, slice};

use sealing::{Nonce, SecretKey};
use sgx_keys::{SgxKeyPolicy, SgxSecretBuilder};
use sgx_rand::{Rng, SgxRng};
use sgx_tstd as std;
use sgx_types::sgx_status_t;

/// Seal private user data.
#[no_mangle]
pub unsafe extern "C" fn seal_user_data(
    // input parameters
    user_id: *const u8,
    user_id_length: usize,
    // dual-purpose parameters
    user_data: *mut u8,
    // output parameters
    sealed_user_data_size: usize,
    sealed_user_sealing_key: *mut u8,
) -> sgx_status_t {
    let user_id = unsafe { slice::from_raw_parts(user_id, user_id_length) };
    let user_data_buf = unsafe { slice::from_raw_parts(user_data, sealed_user_data_size) };

    let mut rng = SgxRng::new().expect("SGX: RDRAND instruction failed");
    let mut user_sealing_key = SecretKey::new([0u8; 32]);
    rng.fill_bytes(user_sealing_key.as_mut());

    let user_data_nonce = Nonce::new([0u8; Nonce::SIZE]);
    let sealed_user_data =
        match sealing::seal(user_data_buf, user_sealing_key, user_data_nonce, user_id) {
            Ok(sealed_data) => sealed_data,
            Err(_) => {
                eprintln!("sealing(user_data); invalid operation attempted");
                return sgx_status_t::SGX_ERROR_UNEXPECTED;
            }
        };

    let enclave_key = SecretKey::try_from(
        SgxSecretBuilder::<{ SecretKey::SIZE }>::new()
            .key_id(user_id)
            .policy(SgxKeyPolicy::MRSIGNER)
            .build()
            .as_ref(),
    )
    .unwrap(); // never panics due to array usage

    let enclave_key_nonce = Nonce::new([0u8; Nonce::SIZE]);
    let sealed_key = match sealing::seal(user_data_buf, enclave_key, enclave_key_nonce, user_id) {
        Ok(sealed_key) => sealed_key,
        Err(_) => {
            eprintln!("sealing(user_sealing_key): invalid operation attempted");
            return sgx_status_t::SGX_ERROR_UNEXPECTED;
        }
    };

    unsafe {
        user_data.copy_from_nonoverlapping(sealed_user_data.as_ptr(), sealed_user_data_size);
        sealed_user_sealing_key.copy_from_nonoverlapping(sealed_key.as_ptr(), sealed_key.len());
    }
    sgx_status_t::SGX_SUCCESS
}
