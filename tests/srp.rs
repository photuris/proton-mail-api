//! Unit-level checks for `proton_mail_api::srp` beyond the overseer's probe.

use base64::alphabet::Alphabet;
use base64::engine::general_purpose::{GeneralPurpose, GeneralPurposeConfig};
use base64::engine::{DecodePaddingMode, Engine};
use proton_mail_api::srp::{self, SrpError};

/// go-srp `hash_test.go` `Test_bcryptHash`: password `test!!!`, 22-char bcrypt-base64 salt,
/// expected `$2y$10$` string (60 chars).
const BCRYPT_VECTORS: [(&str, &str); 10] = [
    (
        "PTTsDBs/mlLnSk6VmtFghe",
        "$2y$10$PTTsDBs/mlLnSk6VmtFgheNSiK/lSwtJsrBLLDK3kZYI7193nInqy",
    ),
    (
        "4DZHd6WZX4fEaWKtCfYdde",
        "$2y$10$4DZHd6WZX4fEaWKtCfYddeZfcryISo9eEMgbA90O.Wnnz1s1VKmKC",
    ),
    (
        "RpyeXO7K2eD3r/ZZ/B63V.",
        "$2y$10$RpyeXO7K2eD3r/ZZ/B63V.Tya53OExbyO8LR7TB93KYP4PvC.EPMW",
    ),
    (
        "xVEeHQI8CyNkblUJDhyx3u",
        "$2y$10$xVEeHQI8CyNkblUJDhyx3uZjo8GDXoNNVoRpLwLvssO1GvV3eYFJS",
    ),
    (
        "d4Q1rrFYjGq2jyVUi7YwTu",
        "$2y$10$d4Q1rrFYjGq2jyVUi7YwTuikgSeAgJfaAYJSJZIbIOvW1GBFwx2J6",
    ),
    (
        "/.3KXCwRnsrxURMGxN7.R.",
        "$2y$10$/.3KXCwRnsrxURMGxN7.R.GLpVq0zyBbI9wgS0wB2U/g2btx1RYoy",
    ),
    (
        "tuE3bNGezetI9Ra2aGePqu",
        "$2y$10$tuE3bNGezetI9Ra2aGePqutWPxG2r36BOzMGoXYzM0p2vmGT9fK1i",
    ),
    (
        "GFfbuV2J/9BsY0Mb8sJOCe",
        "$2y$10$GFfbuV2J/9BsY0Mb8sJOCejr2HSgVY2R93m7qQYqSID5ONeYg7ngG",
    ),
    (
        "FYvnvw/ghdYJbOADddZ3Ae",
        "$2y$10$FYvnvw/ghdYJbOADddZ3Ae.XoxSKZqOf5t0S/epYUaNn7YmdxmxD6",
    ),
    (
        "jjMNLFvjPepiyCfuKxYUcO",
        "$2y$10$jjMNLFvjPepiyCfuKxYUcOykUITQRwkNY1oY5ZgxCDIgj6lXypXx2",
    ),
];

/// The bcrypt alphabet, no padding; 22 chars carry 132 bits, so the last 4 are dropped.
fn bcrypt_base64() -> GeneralPurpose {
    let alphabet =
        Alphabet::new("./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789").unwrap();
    GeneralPurpose::new(
        &alphabet,
        GeneralPurposeConfig::new()
            .with_encode_padding(false)
            .with_decode_padding_mode(DecodePaddingMode::RequireNone)
            .with_decode_allow_trailing_bits(true),
    )
}

#[test]
fn bcrypt_vectors_match_go_srp() {
    let engine = bcrypt_base64();
    for (salt, hashed) in BCRYPT_VECTORS {
        let raw = engine.decode(salt).expect("salt decodes");
        assert_eq!(raw.len(), 16);
        // `key_password` is the 31-char hash tail of the same bcrypt string go-srp hashes.
        let tail = srp::key_password(b"test!!!", &raw).expect("key password");
        assert!(
            tail.as_str() == &hashed[hashed.len() - 31..],
            "bcrypt tail differs from the go-srp vector"
        );
    }
}

#[test]
fn modulus_wrong_size_rejected() {
    let mut b = vec![0u8; 128];
    b[0] = 5;
    let result = srp::generate_proofs(&[0xff; 128], &b, &[1u8; 256]);
    assert!(matches!(result, Err(SrpError::ModulusSize)));
}

#[test]
fn modulus_not_3_mod_8_rejected() {
    let mut modulus = vec![0u8; 256];
    modulus[0] = 0b111;
    modulus[255] = 0x80;
    let mut b = vec![0u8; 256];
    b[0] = 5;
    let result = srp::generate_proofs(&modulus, &b, &[1u8; 256]);
    assert!(matches!(result, Err(SrpError::ModulusNotThreeMod8)));
}
