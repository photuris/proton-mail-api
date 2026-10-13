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

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use num_bigint::BigUint;
use num_traits::{One, Zero};
use pgp::composed::{CleartextSignedMessage, Deserializable, SignedPublicKey};
use rand::RngCore;
use rand::rngs::OsRng;
use sha2::{Digest, Sha512};
use zeroize::Zeroizing;

/// Modulus size in bits; N, A, B, S and the proofs are this many bits on the wire.
pub const BIT_LENGTH: usize = 2048;
const BYTE_LENGTH: usize = BIT_LENGTH / 8;
/// bcrypt cost fixed by Proton for both the SRP password and the mailbox password.
const BCRYPT_COST: u32 = 10;
/// go-srp `generateClientEphemeral`: the client secret must exceed `2 * BIT_LENGTH`.
const CLIENT_SECRET_LOWER_BOUND: u32 = 2 * BIT_LENGTH as u32;
const END_SIGNATURE: &str = "-----END PGP SIGNATURE-----";

/// Proton's modulus signing key (`modulusPubkey` in go-srp `srp.go`), verbatim.
const MODULUS_PUBKEY: &str = "-----BEGIN PGP PUBLIC KEY BLOCK-----\r\n\r\nxjMEXAHLgxYJKwYBBAHaRw8BAQdAFurWXXwjTemqjD7CXjXVyKf0of7n9Ctm\r\nL8v9enkzggHNEnByb3RvbkBzcnAubW9kdWx1c8J3BBAWCgApBQJcAcuDBgsJ\r\nBwgDAgkQNQWFxOlRjyYEFQgKAgMWAgECGQECGwMCHgEAAPGRAP9sauJsW12U\r\nMnTQUZpsbJb53d0Wv55mZIIiJL2XulpWPQD/V6NglBd96lZKBmInSXX/kXat\r\nSv+y0io+LR8i2+jV+AbOOARcAcuDEgorBgEEAZdVAQUBAQdAeJHUz1c9+KfE\r\nkSIgcBRE3WuXC4oj5a2/U3oASExGDW4DAQgHwmEEGBYIABMFAlwBy4MJEDUF\r\nhcTpUY8mAhsMAAD/XQD8DxNI6E78meodQI+wLsrKLeHn32iLvUqJbVDhfWSU\r\nWO4BAMcm1u02t4VKw++ttECPt+HUgPUq5pqQWe5Q2cW4TMsE\r\n=Y4Mw\r\n-----END PGP PUBLIC KEY BLOCK-----";

/// Verifies the clear-signed modulus text against Proton's modulus key
/// and returns the decoded modulus (256 bytes for a genuine one).
pub fn verify_modulus(clearsigned: &str) -> Result<Vec<u8>, SrpError> {
    // go-srp rejects any bytes after the signed block; only the line ending its decoder consumes
    // (CR/LF) is tolerated, not spaces, tabs or other whitespace.
    let end = clearsigned
        .find(END_SIGNATURE)
        .ok_or(SrpError::InvalidModulusSignature)?
        + END_SIGNATURE.len();
    let (block, rest) = clearsigned.split_at(end);
    if !rest.trim_matches(['\r', '\n']).is_empty() {
        return Err(SrpError::DataAfterModulus);
    }
    let (message, _) = CleartextSignedMessage::from_string(block)
        .map_err(|_| SrpError::InvalidModulusSignature)?;
    let (key, _) = SignedPublicKey::from_string(MODULUS_PUBKEY)
        .map_err(|_| SrpError::InvalidModulusSignature)?;
    message
        .verify(&key)
        .map_err(|_| SrpError::InvalidModulusSignature)?;
    B64.decode(message.signed_text().trim())
        .map_err(|_| SrpError::ModulusDecode)
}

/// SHA-512(data||0) || SHA-512(data||1) || SHA-512(data||2) || SHA-512(data||3): 256 bytes.
pub fn expand_hash(data: &[u8]) -> Vec<u8> {
    (0u8..4)
        .flat_map(|i| {
            Sha512::new()
                .chain_update(data)
                .chain_update([i])
                .finalize()
        })
        .collect()
}

/// bcrypt over a 16-byte raw salt, as the 60-char `$2y$10$` string go-srp feeds on.
fn bcrypt_2y(password: &[u8], salt: &[u8]) -> Result<Zeroizing<String>, SrpError> {
    let salt: [u8; 16] = salt
        .try_into()
        .map_err(|_| SrpError::BadSaltLength(salt.len()))?;
    let parts =
        bcrypt::hash_with_salt(password, BCRYPT_COST, salt).map_err(|_| SrpError::Bcrypt)?;
    Ok(Zeroizing::new(
        parts.format_for_version(bcrypt::Version::TwoY),
    ))
}

/// go-srp `HashPassword` for versions 3 and 4 only. `salt` is the decoded
/// `Salt` (10 bytes); `salt || b"proton"` must be 16 bytes.
/// Result is `expand_hash(bcrypt_60_char_string_bytes || modulus)`.
pub fn hash_password(
    version: u32,
    password: &[u8],
    salt: &[u8],
    modulus: &[u8],
) -> Result<Vec<u8>, SrpError> {
    if !matches!(version, 3 | 4) {
        return Err(SrpError::UnsupportedVersion(version));
    }
    let mut full_salt = salt.to_vec();
    full_salt.extend_from_slice(b"proton");
    if full_salt.len() != 16 {
        return Err(SrpError::BadSaltLength(salt.len()));
    }
    let crypted = bcrypt_2y(password, &full_salt)?;
    let mut input = Zeroizing::new(crypted.as_bytes().to_vec());
    input.extend_from_slice(modulus);
    Ok(expand_hash(&input))
}

/// go-srp `MailboxPassword`, then the last 31 chars of the 60-char hash.
/// `key_salt` must be 16 bytes. The result is the OpenPGP passphrase.
pub fn key_password(password: &[u8], key_salt: &[u8]) -> Result<Zeroizing<String>, SrpError> {
    let crypted = bcrypt_2y(password, key_salt)?;
    Ok(Zeroizing::new(crypted[crypted.len() - 31..].to_owned()))
}

#[derive(Debug)]
pub struct Proofs {
    pub client_ephemeral: Vec<u8>,
    pub client_proof: Vec<u8>,
    pub expected_server_proof: Vec<u8>,
}

/// Integer as a padded 256-byte little-endian buffer (go-srp `fromInt`).
fn to_le256(n: &BigUint) -> Zeroizing<Vec<u8>> {
    let raw = Zeroizing::new(n.to_bytes_le());
    let mut out = Zeroizing::new(vec![0u8; BYTE_LENGTH]);
    out[..raw.len()].copy_from_slice(&raw);
    out
}

/// Checked modulus, server ephemeral and multiplier shared by every client secret tried.
struct Params<'a> {
    n: BigUint,
    n_minus_one: BigUint,
    b_bytes: &'a [u8],
    b: BigUint,
    k: BigUint,
    x: BigUint,
}

impl<'a> Params<'a> {
    fn new(
        modulus: &[u8],
        server_ephemeral: &'a [u8],
        hashed_password: &[u8],
    ) -> Result<Self, SrpError> {
        let n = BigUint::from_bytes_le(modulus);
        if n.bits() != BIT_LENGTH as u64 {
            return Err(SrpError::ModulusSize);
        }
        // N = 3 mod 8: bits 0 and 1 set, bit 2 clear.
        if n.iter_u32_digits().next().unwrap_or(0) & 7 != 3 {
            return Err(SrpError::ModulusNotThreeMod8);
        }
        let n_minus_one = &n - 1u32;
        let b = BigUint::from_bytes_le(server_ephemeral);
        if b <= BigUint::one() || b >= n_minus_one {
            return Err(SrpError::ServerEphemeralOutOfRange);
        }
        // The go-srp safe-prime test is skipped on purpose: the modulus signature is the trust anchor.
        let mut k_input = to_le256(&BigUint::from(2u32)).to_vec();
        k_input.extend_from_slice(&to_le256(&n));
        let k = BigUint::from_bytes_le(&expand_hash(&k_input)) % &n;
        if k <= BigUint::one() || k >= n_minus_one {
            return Err(SrpError::MultiplierOutOfRange);
        }
        Ok(Self {
            x: BigUint::from_bytes_le(hashed_password),
            n,
            n_minus_one,
            b_bytes: server_ephemeral,
            b,
            k,
        })
    }

    /// Proofs for client secret `a`; `None` when `a` is out of range or the scrambler is zero.
    fn proofs(&self, a: &BigUint) -> Option<Proofs> {
        if *a <= BigUint::from(CLIENT_SECRET_LOWER_BOUND) || *a >= self.n_minus_one {
            return None;
        }
        // ponytail: num-bigint modpow is not constant-time and BigUint has no Zeroize, so integer
        // copies and modpow temporaries are never cleared (only the byte buffers below are);
        // single-use secret per login, swap to crypto-bigint if needed
        let two = BigUint::from(2u32);
        let client_ephemeral = to_le256(&two.modpow(a, &self.n));
        let mut ab = client_ephemeral.to_vec();
        ab.extend_from_slice(self.b_bytes);
        let u = BigUint::from_bytes_le(&expand_hash(&ab));
        if u.is_zero() {
            return None;
        }
        // S = (B - k*2^x mod N)^((a + u*x) mod (N-1)) mod N
        let kgx = &self.k * two.modpow(&self.x, &self.n) % &self.n;
        let base = (&self.b + &self.n - kgx) % &self.n;
        let exponent = (a + u * &self.x) % &self.n_minus_one;
        let secret = to_le256(&base.modpow(&exponent, &self.n));

        let mut input = Zeroizing::new(ab);
        input.extend_from_slice(&secret);
        let client_proof = expand_hash(&input);
        let mut input = Zeroizing::new(client_ephemeral.to_vec());
        input.extend_from_slice(&client_proof);
        input.extend_from_slice(&secret);
        Some(Proofs {
            client_ephemeral: client_ephemeral.to_vec(),
            client_proof,
            expected_server_proof: expand_hash(&input),
        })
    }
}

/// Random client secret from `rand::rngs::OsRng`.
pub fn generate_proofs(
    modulus: &[u8],
    server_ephemeral: &[u8],
    hashed_password: &[u8],
) -> Result<Proofs, SrpError> {
    let params = Params::new(modulus, server_ephemeral, hashed_password)?;
    let mut buf = Zeroizing::new(vec![0u8; BYTE_LENGTH]);
    loop {
        // Uniform below N-1 by rejection (N-1 has 2048 bits, so at least half the draws pass).
        OsRng.fill_bytes(&mut buf);
        let a = BigUint::from_bytes_le(&buf);
        if a < params.n_minus_one
            && let Some(proofs) = params.proofs(&a)
        {
            return Ok(proofs);
        }
    }
}

/// Same, with the 256-byte little-endian client secret supplied (test seam).
pub fn generate_proofs_with_secret(
    modulus: &[u8],
    server_ephemeral: &[u8],
    hashed_password: &[u8],
    client_secret: &[u8],
) -> Result<Proofs, SrpError> {
    let params = Params::new(modulus, server_ephemeral, hashed_password)?;
    if client_secret.len() != BYTE_LENGTH {
        return Err(SrpError::ClientSecretOutOfRange);
    }
    params
        .proofs(&BigUint::from_bytes_le(client_secret))
        .ok_or(SrpError::ClientSecretOutOfRange)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn signed_modulus() -> String {
        let v: serde_json::Value =
            serde_json::from_str(include_str!("../tests/fixtures/srp-vectors.json")).unwrap();
        v["modulus_clearsigned"].as_str().unwrap().to_owned()
    }

    #[test]
    fn only_crlf_may_follow_signed_modulus() {
        let signed = signed_modulus();
        for suffix in [" ", "\t", "\u{a0}", " \n", "data"] {
            let result = verify_modulus(&format!("{signed}{suffix}"));
            assert_eq!(result, Err(SrpError::DataAfterModulus), "suffix {suffix:?}");
        }
        for suffix in ["\n", "\r\n"] {
            assert!(verify_modulus(&format!("{signed}{suffix}")).is_ok());
        }
    }
}
