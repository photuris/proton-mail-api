//! Proton's SRP-6a variant (go-srp) and the mailbox key-password derivation.
//! Task 001 implements the functions; the error type is overseer-owned scaffolding
//! so that the transport (task 002) can wrap it.

/// Failures of the SRP primitives. Carries no secret material.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SrpError {
    #[error("modulus signature invalid")]
    InvalidModulusSignature,
    #[error("data after signed modulus")]
    DataAfterModulus,
    #[error("modulus is not valid base64")]
    ModulusDecode,
    #[error("modulus must be exactly 2048 bits")]
    ModulusSize,
    #[error("modulus is not 3 mod 8")]
    ModulusNotThreeMod8,
    #[error("unsupported auth version {0}")]
    UnsupportedVersion(u32),
    #[error("bad salt length {0}")]
    BadSaltLength(usize),
    #[error("bcrypt failed")]
    Bcrypt,
    #[error("server ephemeral out of range")]
    ServerEphemeralOutOfRange,
    #[error("multiplier out of range")]
    MultiplierOutOfRange,
    #[error("client secret out of range")]
    ClientSecretOutOfRange,
}
