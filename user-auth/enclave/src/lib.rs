#![no_std]
#![deny(unsafe_op_in_unsafe_fn)]

use std::slice;

use argon2::{Algorithm, Argon2, Params, PasswordHasher, PasswordVerifier, Version};
use once_cell::unsync::OnceCell;
use password_hash::PasswordHashString;
use sgx_keys::{SgxKeyPolicy, SgxSecret, SgxSecretBuilder};
use sgx_tstd as std;
use sgx_types::*;
use user_auth_common::*;

fn new_pepper(user_id: &[u8]) -> SgxSecret {
    SgxSecretBuilder::new()
        .key_id(&user_id)
        .policy(SgxKeyPolicy::MRSIGNER)
        .build()
}
fn new_hash_context(pepper: &[u8]) -> Result<Argon2, argon2::Error> {
    Argon2::new_with_secret(
        pepper.as_ref(),
        Algorithm::default(),
        Version::default(),
        // The parameters chosen here are, respectively, the maximum between the
        // default set by the Argon2 library and the value recommended at:
        //
        // https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html
        Params::new(M_COST_KIB, 3, 1, None).unwrap(),
    )
}

///# Safety: guaranteed by the trusted bridge routine generated with the
/// Intel SDK's `sgx_edger8r` tool
#[no_mangle]
pub unsafe extern "C" fn hash_password(
    // Input paramaters
    password: *const u8,
    password_length: usize,
    salt: *const u8,
    user_id: *const u8,
    user_id_length: usize,
    // Output paramaters
    //
    // See https://github.com/P-H-C/phc-string-format/blob/master/phc-sf-spec.md#argon2-encoding
    hash_string: *mut u8,
) -> sgx_status_t {
    let password_buf = OnceCell::<&[u8]>::new();
    let user_id_buf = OnceCell::<&[u8]>::new();
    let salt_buf = OnceCell::<&str>::new();
    unsafe {
        password_buf
            .set(slice::from_raw_parts(password, password_length))
            .unwrap();
        user_id_buf
            .set(slice::from_raw_parts(user_id, user_id_length))
            .unwrap();
        salt_buf
            .set(std::str::from_utf8(slice::from_raw_parts(salt, SALT_LENGTH)).unwrap())
            .unwrap();
    }

    let pepper = new_pepper(user_id_buf.get().unwrap());
    let hash_ctx = new_hash_context(pepper.as_ref());

    match hash_ctx {
        Err(_) => sgx_status_t::SGX_ERROR_UNEXPECTED,
        Ok(ctx) => ctx
            .hash_password(password_buf.get().unwrap(), *salt_buf.get().unwrap())
            .map_or_else(
                |_| sgx_status_t::SGX_ERROR_UNEXPECTED,
                |hash| {
                    unsafe {
                        hash_string.copy_from_nonoverlapping(
                            hash.serialize().as_str().as_bytes().as_ptr(),
                            HASH_STRING_LENGTH,
                        );
                    }
                    sgx_status_t::SGX_SUCCESS
                },
            ),
    }
}

///# Safety: guaranteed by the trusted bridge routine generated with the
/// Intel SDK's `sgx_edger8r` tool
#[no_mangle]
pub unsafe extern "C" fn verify_password(
    // input paramaters
    password: *const u8,
    password_length: usize,
    user_id: *const u8,
    user_id_length: usize,
    stored_hash_string: *const u8,
    // output paramaters
    verify_status: *mut VerifyPasswordStatus,
) -> sgx_status_t {
    let password_buf = OnceCell::<&[u8]>::new();
    let user_id_buf = OnceCell::<&[u8]>::new();
    let hash_string_buf = OnceCell::<&[u8]>::new();
    unsafe {
        password_buf
            .set(slice::from_raw_parts(password, password_length))
            .unwrap();
        user_id_buf
            .set(slice::from_raw_parts(user_id, user_id_length))
            .unwrap();
        hash_string_buf
            .set(slice::from_raw_parts(
                stored_hash_string,
                HASH_STRING_LENGTH,
            ))
            .unwrap();
    }

    let hash_string = std::str::from_utf8(hash_string_buf.get().unwrap()).unwrap();
    let pepper = new_pepper(user_id_buf.get().unwrap());
    new_hash_context(pepper.as_ref()).map_or_else(
        |_| sgx_status_t::SGX_ERROR_UNEXPECTED,
        |ctx| match ctx.verify_password(
            password_buf.get().unwrap(),
            &PasswordHashString::parse(hash_string, password_hash::Encoding::default())
                .unwrap()
                .password_hash(),
        ) {
            Ok(()) => {
                unsafe { *verify_status = VerifyPasswordStatus::PasswordVerified };
                sgx_status_t::SGX_SUCCESS
            }
            Err(password_hash::Error::Password) => {
                unsafe { *verify_status = VerifyPasswordStatus::InvalidPassword };
                sgx_status_t::SGX_SUCCESS
            }
            Err(_) => sgx_status_t::SGX_ERROR_UNEXPECTED,
        },
    )
}
