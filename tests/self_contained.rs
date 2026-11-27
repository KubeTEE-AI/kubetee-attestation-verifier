//! Frozen `.6` self-contained verification vectors (2026-11-26).
//!
//! The gateway `1.110.2-kubetee.6` delivers the FULL `cert_chain`
//! (`[VCEK, ASK, ARK]`, raw-DER `{cert_type,data}` entries), so the evidence
//! **self-authenticates** — chain + report signature verify from the response
//! alone, with no AMD KDS fetch. These tests prove that path works and FAILS
//! CLOSED on a corrupted / absent chain (the pre-`.6` empty-`cert_chain` gap).

use kubetee_attestation_verifier as kv;

pub const EVIDENCE_V4: &str = include_str!("fixtures/live_evidence_v4.json");
pub const REFERENCE_V4: &str = include_str!("fixtures/reference_v4.json");
pub const REGISTRY_LIVE: &str = include_str!("fixtures/registry_live.json");

fn v4_envelope() -> kv::Envelope {
    kv::parse_envelope(EVIDENCE_V4).expect(".6 evidence parses")
}

/// The .6 cert_chain is [VCEK, ASK, ARK] with raw-DER `data` — the exact format
/// the gateway fix delivers. This is the regression test for the empty-chain gap.
#[test]
fn v4_cert_chain_parses_der_entries() {
    let env = v4_envelope();
    let types: Vec<&str> = env
        .cert_chain
        .iter()
        .map(|c| c.cert_type.as_str())
        .collect();
    assert_eq!(
        types,
        ["VCEK", "ASK", "ARK"],
        "full leaf-to-root chain delivered"
    );
    for c in &env.cert_chain {
        assert!(c.der.len() > 200, "{} DER too small", c.cert_type);
    }
}

/// Self-contained: ARK/ASK/VCEK derived from the envelope's OWN cert_chain,
/// then chain + report-signature verified — NO KDS, no external PEMs.
#[test]
fn v4_self_contained_chain_and_signature_verify() {
    let env = v4_envelope();
    let (ark, ask, vcek) = kv::chain_from_envelope(&env.cert_chain).expect("chain derives");
    assert!(ark.contains("BEGIN CERTIFICATE") && vcek.contains("BEGIN CERTIFICATE"));
    kv::verify_snp_from_chain(&env.snp, &env.cert_chain)
        .expect("self-contained chain + report signature must verify");
    // And the same via the explicit-PEM path (equivalence).
    kv::verify_snp(&env.snp, &ark, &ask, &vcek).expect("explicit PEMs verify too");
}

/// `verify()` with NO PEM overrides uses the envelope's cert_chain end-to-end.
#[test]
fn v4_verify_passes_self_contained() {
    let env = v4_envelope();
    let reference: serde_json::Value = serde_json::from_str(REFERENCE_V4).unwrap();
    let input = kv::VerifyInput {
        envelope: &env,
        ark_pem: None,
        ask_pem: None,
        vcek_pem: None,
        snp_reference: Some(&reference),
        registry: None,
        registry_history: None,
        min_revision: None,
        tls_leaf_der: None,
        tls_domain: "llm.kubetee.ai",
        signing_key_b64url: Some(kv::registry::DEFAULT_SIGNING_KEY_B64URL),
        now_iso: None,
    };
    let verdict = kv::verify(&input);
    assert!(
        verdict.pass,
        "self-contained verify must PASS:\n{}",
        verdict.report()
    );
}

/// The .6 report matches the freshly-published v4 reference (host_data c89e8b5e,
/// the .6 initdata) and the reference's Ed25519 signature verifies.
#[test]
fn v4_report_matches_signed_v4_reference() {
    let env = v4_envelope();
    let reference: serde_json::Value = serde_json::from_str(REFERENCE_V4).unwrap();
    kv::match_snp_reference(&env.snp, &reference).expect(".6 report matches v4 reference");
    kv::verify_registry_signature(&reference, kv::registry::DEFAULT_SIGNING_KEY_B64URL)
        .expect("v4 reference signature verifies");
}

/// The request binding (nonce + keyset digest -> report_data) holds on the .6 capture.
#[test]
fn v4_binding_verifies() {
    let env = v4_envelope();
    kv::verify_binding(&env).expect(".6 binding verifies");
}

// ---- FAIL-CLOSED vectors ------------------------------------------------------

/// A corrupted cert_chain byte must break the self-contained signature/chain.
#[test]
fn v4_corrupt_cert_chain_fails() {
    let mut env = v4_envelope();
    env.cert_chain[0].der[10] ^= 0x01;
    assert!(
        kv::verify_snp_from_chain(&env.snp, &env.cert_chain).is_err(),
        "corrupted VCEK DER must FAIL"
    );
}

/// The PRE-.6 gap: an empty cert_chain must FAIL CLOSED (never silently pass
/// by falling back to something weaker).
#[test]
fn v4_empty_cert_chain_fails_closed() {
    let mut env = v4_envelope();
    env.cert_chain.clear();
    assert!(
        kv::verify_snp_from_chain(&env.snp, &env.cert_chain).is_err(),
        "empty cert_chain (pre-.6 shape) must FAIL, not pass"
    );
    assert!(
        kv::chain_from_envelope(&env.cert_chain).is_err(),
        "chain_from_envelope must reject an empty chain"
    );
}

/// A tampered report field must fail the self-contained signature check.
#[test]
fn v4_tampered_report_fails_signature() {
    let mut env = v4_envelope();
    env.snp.measurement[0] ^= 0x01;
    assert!(
        kv::verify_snp_from_chain(&env.snp, &env.cert_chain).is_err(),
        "tampered measurement must FAIL report signature"
    );
}

/// A tampered nonce must fail the request binding.
#[test]
fn v4_tampered_nonce_fails_binding() {
    let mut env = v4_envelope();
    env.nonce = "ff".repeat(32);
    assert!(
        kv::verify_binding(&env).is_err(),
        "tampered nonce must FAIL binding"
    );
}

/// A tampered keyset digest must fail the request binding (anti-downgrade).
#[test]
fn v4_tampered_keyset_digest_fails_binding() {
    let mut env = v4_envelope();
    env.bindings.keyset_digest = "sha256:".to_string() + &"0".repeat(64);
    assert!(
        kv::verify_binding(&env).is_err(),
        "tampered keyset_digest must FAIL"
    );
}

/// A tampered host_data must fail the reference match.
#[test]
fn v4_tampered_host_data_fails_reference() {
    let mut env = v4_envelope();
    env.snp.host_data[0] ^= 0x01;
    let reference: serde_json::Value = serde_json::from_str(REFERENCE_V4).unwrap();
    assert!(
        kv::match_snp_reference(&env.snp, &reference).is_err(),
        "tampered host_data must FAIL reference"
    );
}

/// The root-of-trust pin: a **forged** ARK (parseable X.509, self-consistent,
/// but not a known AMD root) must be rejected. This is exactly the attack an
/// unanchored chain accepts — an adversary-controlled gateway serving its own
/// ARK->ASK->VCEK to sign a fabricated report. The pin must fail closed before
/// the chain signatures are even consulted.
#[test]
fn a_forged_self_signed_ark_is_rejected() {
    let mut env = v4_envelope();
    // Re-label the ASK certificate as the ARK: a real, parseable X.509 cert
    // that is NOT any built-in AMD root. `build_chain` parses it fine, but the
    // root pin must reject it as untrusted.
    let ask_der = env
        .cert_chain
        .iter()
        .find(|c| c.cert_type == "ASK")
        .expect("ASK present")
        .der
        .clone();
    let ark = env
        .cert_chain
        .iter_mut()
        .find(|c| c.cert_type == "ARK")
        .expect("ARK present");
    ark.der = ask_der;
    let error = kv::verify_snp_from_chain(&env.snp, &env.cert_chain).unwrap_err();
    assert!(
        format!("{error}").contains("not a known AMD root"),
        "forged ARK must be rejected as an untrusted root, got: {error}"
    );
}

/// A **known but wrong-generation** root (Milan ARK presented for a Genoa
/// report) must also be rejected: the pin matches a known root (so it passes),
/// but the Genoa ASK/VCEK do not chain to the Milan ARK, so chain consistency
/// fails. Proves both legs (root pin + chain signatures) are enforced.
#[test]
fn a_known_but_mismatched_root_is_rejected() {
    use sev::certs::snp::builtin;
    let mut env = v4_envelope();
    let ark = env
        .cert_chain
        .iter_mut()
        .find(|c| c.cert_type == "ARK")
        .expect("ARK present");
    // Replace the Genoa ARK with the Milan ARK (a genuine AMD root — passes the
    // pin — but not the one that signed this Genoa ASK). Convert the built-in
    // PEM to DER to match the gateway's raw-DER cert_chain entry format.
    let milan_ark = sev::certs::snp::Certificate::from_pem(builtin::milan::ARK).unwrap();
    ark.der = milan_ark.to_der().unwrap();
    assert!(
        kv::verify_snp_from_chain(&env.snp, &env.cert_chain).is_err(),
        "a mismatched known root must FAIL (Genoa ASK does not chain to the Milan ARK)"
    );
}

/// The live registry signature verifies (frozen served copy).
#[test]
fn v4_registry_signature_verifies() {
    let doc: serde_json::Value = serde_json::from_str(REGISTRY_LIVE).unwrap();
    kv::verify_registry_signature(&doc, kv::registry::DEFAULT_SIGNING_KEY_B64URL)
        .expect("live registry signature verifies");
}
