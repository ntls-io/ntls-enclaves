extern "C" {
    fn seal_user_data(
        eid: u64,
        user_id: *const u8,
        user_id_length: usize,
        private_user_data: *mut u8,
        sealed_user_data_size: usize,
        sealed_user_sealing_key: *mut u8,
    );
}

struct SealedUserData {
    user_id: Box<[u8]>,
    user_data: Box<[u8]>,
    user_sealing_key: [u8; 32 + 16], // size = plaintext key size + Poly1305 tag size
}

/// Seal private user data.
pub fn safe_seal_user_data(user_id: &[u8], user_data: &[u8]) -> SealedUserData {}
