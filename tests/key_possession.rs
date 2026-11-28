//! Phase 6 zero-operator-trust: the `kubetee.attestation.v2` quote-bound
//! **key-possession** proof (replaces the v1 TLS-possession nonce proof).
//!
//! The generator signs the quote-bound 64-byte `report_data` under a
//! **per-boot in-guest generated** P-256 key whose SPKI the v2 statement
//! commits (`pkix_pubkey_b64url`). Verification must confirm that signature
//! verifies under the **bound** key (never the operator-custodied TLS leaf),
//! and fail closed on a missing / mislabelled / wrong-key / wrong-data proof.

use kubetee_attestation_verifier as kv;

mod common;
use common::*;

// ---------------------------------------------------------------------------
// POSITIVE: a correct per-boot key-possession proof verifies.
// ---------------------------------------------------------------------------

#[test]
fn v2_key_possession_verifies_under_the_bound_key() {
    let key = BootKey::from_seed(0x11);
    let env = v2_envelope(&key, &nonce_hex(0xaa), "ctx", rd(0x11), None);
    kv::verify_key_possession(&env).expect("valid per-boot key possession must verify");
}

/// Both ECDSA encodings verify under the bound key: DER (canonical wire form
/// from cryptography / ring) and fixed raw `r||s` (gm-miner parity).
#[test]
fn v2_key_possession_accepts_der_and_raw_encodings() {
    let key = BootKey::from_seed(0x12);
    let report_data = rd(0x12);
    // DER (default) via key.sign(); raw r||s explicitly.
    use p256::ecdsa::signature::Signer as _;
    let sig: p256::ecdsa::Signature = key.signing.sign(&report_data);
    let raw = sig.to_bytes().to_vec();
    let env = v2_envelope(&key, &nonce_hex(0xaa), "ctx", report_data, Some(raw));
    kv::verify_key_possession(&env).expect("raw r||s encoding verifies too");
}

// ---------------------------------------------------------------------------
// FAIL-CLOSED: every corruption of the proof rejects.
// ---------------------------------------------------------------------------

/// A proof under a DIFFERENT per-boot key (the key the quote did NOT bind)
/// must fail: only the committed key can sign the quote-bound report_data.
#[test]
fn v2_possession_under_a_different_key_rejects() {
    let bound = BootKey::from_seed(0x21);
    let impostor = BootKey::from_seed(0x22);
    let report_data = rd(0x21);
    let bad = impostor.sign(&report_data);
    let env = v2_envelope(&bound, &nonce_hex(0xaa), "ctx", report_data, Some(bad));
    assert!(
        kv::verify_key_possession(&env).is_err(),
        "signature under an unbound key must FAIL"
    );
}

/// A signature over the WRONG bytes (not the quote-bound report_data) must
/// fail even under the correct key.
#[test]
fn v2_possession_over_the_wrong_report_data_rejects() {
    let key = BootKey::from_seed(0x23);
    let bad = key.sign(&rd(0x99));
    let env = v2_envelope(&key, &nonce_hex(0xaa), "ctx", rd(0x23), Some(bad));
    assert!(
        kv::verify_key_possession(&env).is_err(),
        "signature over a different report_data must FAIL"
    );
}

/// A missing proof on a v2 envelope must FAIL (never "nothing to check").
#[test]
fn v2_possession_missing_rejects() {
    let key = BootKey::from_seed(0x24);
    let mut env = v2_envelope(&key, &nonce_hex(0xaa), "ctx", rd(0x24), None);
    env.key_possession = None;
    assert!(
        kv::verify_key_possession(&env).is_err(),
        "absent key_possession must FAIL"
    );
}

/// A mislabelled `input` or `alg` must fail closed.
#[test]
fn v2_possession_mislabelled_input_or_alg_rejects() {
    let key = BootKey::from_seed(0x25);
    let mut env = v2_envelope(&key, &nonce_hex(0xaa), "ctx", rd(0x25), None);
    env.key_possession.as_mut().unwrap().input = "sha256(nonce)".to_string();
    assert!(
        kv::verify_key_possession(&env).is_err(),
        "wrong input must FAIL"
    );

    let mut env2 = v2_envelope(&key, &nonce_hex(0xaa), "ctx", rd(0x25), None);
    env2.key_possession.as_mut().unwrap().alg = "RS256".to_string();
    assert!(
        kv::verify_key_possession(&env2).is_err(),
        "wrong alg must FAIL"
    );
}

/// A corrupt / non-ECDSA signature encoding must fail closed.
#[test]
fn v2_possession_bad_signature_encoding_rejects() {
    let key = BootKey::from_seed(0x26);
    let bad = vec![0u8; 7]; // not DER, not 64
    let env = v2_envelope(&key, &nonce_hex(0xaa), "ctx", rd(0x26), Some(bad));
    assert!(
        kv::verify_key_possession(&env).is_err(),
        "non-signature bytes must FAIL"
    );
}

// ---------------------------------------------------------------------------
// The v2 step-5 dispatch + the SPKI-pin guard.
// ---------------------------------------------------------------------------

/// The full `verify()` dispatch: a v2 envelope must be held to key-possession
/// (the bound key), never the v1 TLS-possession path. The AMD chain is
/// exonerated here (its report_data is the synthetic binding value, not a live
/// signed one) — this pins the version-aware step-5 branch.
#[test]
fn v2_step5_dispatch_requires_key_possession() {
    let key = BootKey::from_seed(0x31);
    let env = v2_envelope(&key, &nonce_hex(0xaa), "ctx", rd(0x31), None);
    let leaf = tls_leaf();
    let input = kv::VerifyInput {
        envelope: &env,
        ark_pem: None,
        ask_pem: None,
        vcek_pem: None,
        snp_reference: None,
        registry: None,
        registry_history: None,
        min_revision: None,
        tls_leaf_der: Some(&leaf),
        tls_domain: "llm.kubetee.ai",
        signing_key_b64url: None,
        now_iso: None,
    };
    let report = kv::verify(&input).report();
    assert!(
        report.contains("PASS key-possession spki-pin+ecdsa-p256-over-quote-report-data"),
        "v2 step 5 must take the key-possession path:\n{report}"
    );
    assert!(
        !report.contains("tls-possession"),
        "v2 must NOT fall back to the v1 TLS-possession path:\n{report}"
    );
}

/// The SPKI pin must bind the served keyset to THIS TLS leaf — a keyset whose
/// pin is not the leaf's SPKI must FAIL.
#[test]
fn v2_spki_pin_rejects_a_keyset_that_does_not_name_the_leaf() {
    let key = BootKey::from_seed(0x32);
    let mut env = v2_envelope(&key, &nonce_hex(0xaa), "ctx", rd(0x32), None);
    for entry in &mut env.keyset.tls_public_keys {
        if entry.domain == "llm.kubetee.ai" {
            entry.spki_sha256 = "sha256:".to_string() + &"00".repeat(32);
        }
    }
    let leaf = x509_leaf(&tls_leaf());
    assert!(
        kv::verify_spki_pin(&env, "llm.kubetee.ai", &leaf).is_err(),
        "a keyset pin that is not the leaf's SPKI must FAIL"
    );
}
