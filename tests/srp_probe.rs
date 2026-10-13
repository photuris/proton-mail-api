//! Black-box probe for `proton_mail_api::srp`, owned by the overseer.
//! Vectors: `tests/fixtures/srp-vectors.json`, captured from ProtonMail/go-srp
//! (see the `note` field). Implementers must not edit this file.

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use proton_mail_api::srp;

#[derive(serde::Deserialize)]
struct KeyPasswordVector {
    password: String,
    key_salt_b64: String,
    key_password: String,
}

#[derive(serde::Deserialize)]
struct Vectors {
    version: u32,
    password: String,
    salt_b64: String,
    modulus_clearsigned: String,
    modulus_b64: String,
    server_ephemeral_b64: String,
    hashed_password_b64: String,
    client_secret_b64: String,
    client_ephemeral_b64: String,
    client_proof_b64: String,
    expected_server_proof_b64: String,
    key_password_vectors: Vec<KeyPasswordVector>,
}

fn vectors() -> Vectors {
    serde_json::from_str(include_str!("fixtures/srp-vectors.json")).expect("fixture parses")
}

fn b64(s: &str) -> Vec<u8> {
    B64.decode(s).expect("fixture base64")
}

#[test]
fn modulus_signature_verifies_and_decodes() {
    let v = vectors();
    let modulus = srp::verify_modulus(&v.modulus_clearsigned).expect("signed modulus verifies");
    assert_eq!(modulus, b64(&v.modulus_b64));
    assert_eq!(modulus.len(), srp::BIT_LENGTH / 8);
}

#[test]
fn tampered_modulus_is_rejected() {
    let v = vectors();
    let tampered = v.modulus_clearsigned.replacen("W2z5HBi8", "W2z5HBi9", 1);
    assert!(matches!(
        srp::verify_modulus(&tampered),
        Err(srp::SrpError::InvalidModulusSignature)
    ));
}

#[test]
fn trailing_data_after_modulus_is_rejected() {
    let v = vectors();
    let extra = format!("{}data after modulus", v.modulus_clearsigned);
    assert!(matches!(
        srp::verify_modulus(&extra),
        Err(srp::SrpError::DataAfterModulus)
    ));
}

#[test]
fn hash_password_v4_matches_go_srp() {
    let v = vectors();
    let hashed = srp::hash_password(
        v.version,
        v.password.as_bytes(),
        &b64(&v.salt_b64),
        &b64(&v.modulus_b64),
    )
    .expect("hash");
    assert!(
        hashed == b64(&v.hashed_password_b64),
        "hashed password differs from the go-srp vector"
    );
}

#[test]
fn unsupported_auth_version_is_an_error() {
    let v = vectors();
    for version in [0u32, 1, 2, 5] {
        assert!(matches!(
            srp::hash_password(version, b"x", &b64(&v.salt_b64), &b64(&v.modulus_b64)),
            Err(srp::SrpError::UnsupportedVersion(_))
        ));
    }
}

#[test]
fn proofs_with_injected_secret_match_go_srp() {
    let v = vectors();
    let proofs = srp::generate_proofs_with_secret(
        &b64(&v.modulus_b64),
        &b64(&v.server_ephemeral_b64),
        &b64(&v.hashed_password_b64),
        &b64(&v.client_secret_b64),
    )
    .expect("proofs");
    assert_eq!(proofs.client_ephemeral, b64(&v.client_ephemeral_b64));
    assert_eq!(proofs.client_proof, b64(&v.client_proof_b64));
    assert_eq!(
        proofs.expected_server_proof,
        b64(&v.expected_server_proof_b64)
    );
}

#[test]
fn random_secret_proofs_are_well_formed_and_differ() {
    let v = vectors();
    let modulus = b64(&v.modulus_b64);
    let b = b64(&v.server_ephemeral_b64);
    let x = b64(&v.hashed_password_b64);
    let p1 = srp::generate_proofs(&modulus, &b, &x).expect("proofs");
    let p2 = srp::generate_proofs(&modulus, &b, &x).expect("proofs");
    assert_eq!(p1.client_ephemeral.len(), 256);
    assert_eq!(p1.client_proof.len(), 256);
    assert_eq!(p1.expected_server_proof.len(), 256);
    assert_ne!(p1.client_ephemeral, p2.client_ephemeral);
}

#[test]
fn server_ephemeral_out_of_range_is_rejected() {
    let v = vectors();
    let modulus = b64(&v.modulus_b64);
    let x = b64(&v.hashed_password_b64);
    let zero = vec![0u8; 256];
    assert!(matches!(
        srp::generate_proofs(&modulus, &zero, &x),
        Err(srp::SrpError::ServerEphemeralOutOfRange)
    ));
}

#[test]
fn key_password_matches_go_srp_mailbox_password() {
    let v = vectors();
    assert!(!v.key_password_vectors.is_empty());
    for kv in v.key_password_vectors {
        let kp = srp::key_password(kv.password.as_bytes(), &b64(&kv.key_salt_b64))
            .expect("key password");
        assert!(
            kp.as_str() == kv.key_password,
            "key password differs from the go-srp vector"
        );
        assert_eq!(kp.len(), 31);
    }
}

#[test]
fn key_password_rejects_wrong_salt_length() {
    assert!(matches!(
        srp::key_password(b"abc123", &[0u8; 10]),
        Err(srp::SrpError::BadSaltLength(10))
    ));
}
