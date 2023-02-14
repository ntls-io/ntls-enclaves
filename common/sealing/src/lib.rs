//! A crate that facilitates sealing using ChaCha20-Poly1305, an algorithm for
//! [AEAD][aead].
//!
//! [aead]: https://en.wikipedia.org/wiki/Authenticated_encryption
//! [chacha]: https://en.wikipedia.org/wiki/ChaCha20-Poly1305
#![no_std]

extern crate alloc;

use alloc::boxed::Box;
use alloc::vec::Vec;

use ring_compat::aead::{AeadInPlace, ChaCha20Poly1305, KeyInit};
use ring_compat::generic_array::typenum::{U12, U32};
use ring_compat::generic_array::GenericArray;
pub use zeroize::Zeroizing;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// A nonce should only ever be used once for any given key, across your entire
/// code base.  Nonces may either be randomly generated or, otherwise, carefully
/// selected to ensure uniqueness.
#[derive(Debug)] // core
#[derive(Zeroize, ZeroizeOnDrop)] // zeroize
pub struct Nonce([u8; 12]);

impl Nonce {
    pub const SIZE: usize = 12;

    pub fn new(nonce: [u8; Self::SIZE]) -> Self {
        Nonce::from(nonce)
    }
}

#[derive(Debug, Clone)] // core
#[derive(Zeroize, ZeroizeOnDrop)] // zeroize
/// A key used for symmetric encryption.
pub struct SecretKey([u8; 32]);

impl SecretKey {
    pub const SIZE: usize = 32;

    pub fn new(key: [u8; Self::SIZE]) -> Self {
        SecretKey::from(key)
    }
}

impl From<[u8; SecretKey::SIZE]> for SecretKey {
    fn from(secret: [u8; SecretKey::SIZE]) -> Self {
        SecretKey(secret)
    }
}

impl From<[u8; Nonce::SIZE]> for Nonce {
    fn from(nonce: [u8; Nonce::SIZE]) -> Self {
        Nonce(nonce)
    }
}

impl From<SecretKey> for [u8; SecretKey::SIZE] {
    fn from(SecretKey(bytes): SecretKey) -> Self {
        bytes
    }
}

impl From<Nonce> for [u8; Nonce::SIZE] {
    fn from(Nonce(bytes): Nonce) -> Self {
        bytes
    }
}

type NonceSize = U12;
type SecretKeySize = U32;

/// Cryptographically seal and authenticate a message using the
/// [ChaCha20-Poly1305][chacha20poly1305] algorithm for [AEAD][aead].
/// Associated data is also authenticated, but not encrypted.
///
/// [aead]: https://en.wikipedia.org/wiki/Authenticated_encryption
/// [chacha]: https://en.wikipedia.org/wiki/ChaCha20-Poly1305
pub fn seal(
    msg: &[u8],
    key: SecretKey,
    nonce: Nonce,
    aad: &[u8],
) -> Result<Box<[u8]>, ring_compat::aead::Error> {
    let mut buffer = Vec::from(msg);
    let aead = ChaCha20Poly1305::new(&GenericArray::<u8, SecretKeySize>::from_slice(&<[u8;
        SecretKey::SIZE]>::from(
        key
    )));
    aead.encrypt_in_place(
        &GenericArray::<u8, NonceSize>::from_slice(&<[u8; Nonce::SIZE]>::from(nonce)),
        aad,
        &mut buffer,
    )?;
    Ok(Box::from(buffer))
}

pub type SecretBytes = Zeroizing<Box<[u8]>>;
/// Cryptographically unseal and authenticate a message by supplying it
/// alongside its associated data.
pub fn open(
    sealed_msg: &[u8],
    key: SecretKey,
    nonce: Nonce,
    aad: &[u8],
) -> Result<SecretBytes, ring_compat::aead::Error> {
    let mut buffer = Vec::from(sealed_msg);
    let aead = ChaCha20Poly1305::new(&GenericArray::from_slice(&<[u8; SecretKey::SIZE]>::from(
        key,
    )));
    aead.decrypt_in_place(
        &GenericArray::from_slice(&<[u8; 12]>::from(nonce)),
        aad,
        &mut buffer,
    )?;
    Ok(Zeroizing::new(Box::from(buffer)))
}

#[cfg(test)]
mod tests {
    use proptest::proptest;

    use super::*;

    fn sealed_test_message_result() -> Result<Box<[u8]>, ring_compat::aead::Error> {
        let msg = b"a self-referential secret message";
        let key = SecretKey([222u8; 32]);
        let aad = b"authenticated associated data";
        let nonce = Nonce([111u8; 12]);
        seal(msg, key, nonce, aad)
    }

    #[test]
    fn seal_message_success() {
        let result = sealed_test_message_result();
        assert!(result.is_ok())
    }

    #[test]
    fn unseal_sealed_message_success() {
        let key = SecretKey([222u8; 32]);
        let aad = b"authenticated associated data";
        let nonce = Nonce([111u8; 12]);

        let sealed_message = sealed_test_message_result().unwrap();
        let result = open(&sealed_message, key, nonce, aad);
        assert!(result.is_ok())
    }

    #[test]
    fn prop_seal_unseal_roundtrips() {
        proptest! {|(msg: Box<[u8]>,  key: [u8; 32], nonce: [u8; 12], aad: Box<[u8]>)| {
            let sealed_msg = seal(msg.as_ref(), SecretKey(key), Nonce(nonce), aad.as_ref()).unwrap();
            let opened_msg = open(sealed_msg.as_ref(), SecretKey(key), Nonce(nonce), aad.as_ref()).unwrap();
            assert_eq!(msg, *opened_msg)
        }}
    }
}
