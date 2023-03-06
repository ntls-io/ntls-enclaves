#![no_std]
#![deny(unsafe_op_in_unsafe_fn)]

/// Length of a PHC-encoding of a 16 bit salt
pub const SALT_LENGTH: usize = 22;

/// It is assumed that the hash parameters and other configuration options (e.g.
/// output length) are all set to their default values.  If any of these are
/// changed in the future then this value will either need to be redetermined or
/// dynammically calculated!
// XXX: Certain assumptions are made here that relate to the hash context. See
// the doc comment above.
pub const HASH_STRING_LENGTH: usize = 97;

/// Argon2 memory cost in KiB.
pub const M_COST_KIB: u32 = 19 * 1024;

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum VerifyPasswordStatus {
    PasswordVerified = 0,
    InvalidPassword = 1,
}
