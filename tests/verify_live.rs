//! Frozen test vectors: a real live-gateway SNP capture (2026-11-26) + its
//! matching AMD VCEK (fetched from KDS by chip_id + reported TCB), plus
//! corrupted variants proving each check FAILS CLOSED.
//!
//! The real capture's ECDSA P-384 signature is the ground truth: if our
//! `AttestationReport` reconstruction is byte-exact, `sev`'s verifier passes
//! against the real VCEK; if any field is misplaced it fails. That is the
//! whole point of reusing `sev`'s `to_bytes()[..0x2a0]` + `crypto_nossl`.

use kubetee_attestation_verifier as kv;

/// Live capture (2026-11-26, `GET /v1/attestation?nonce=...`).
use x509_cert::der::Decode;

pub const LIVE_EVIDENCE: &str = include_str!("fixtures/live_evidence.json");
/// AMD KDS VCEK for the live report's chip_id + reported TCB (blSPL=12
/// teeSPL=0 snpSPL=28 ucodeSPL=88), PEM.
pub const LIVE_VCEK: &str = include_str!("fixtures/vcek.pem");
/// AMD KDS `cert_chain` = [ASK, ARK] for Genoa, PEM.
pub const LIVE_ASK: &str = include_str!("fixtures/ask.pem");
pub const LIVE_ARK: &str = include_str!("fixtures/ark.pem");
/// Signed SNP reference (`tee-measurements.json`).
pub const LIVE_REFERENCE: &str = include_str!("fixtures/reference.json");
/// Signed TDX registry (`tee-measurements-registry.json`).
pub const LIVE_REGISTRY: &str = include_str!("fixtures/registry.json");
/// TLS leaf (DER, base64) served on `llm.kubetee.ai`.
pub const LIVE_TLS_LEAF_DER_B64: &str = include_str!("fixtures/tls_leaf.der.b64");

fn live_envelope() -> kv::Envelope {
    kv::parse_envelope(LIVE_EVIDENCE).expect("live evidence parses")
}

fn live_report() -> kv::SnpReport {
    live_envelope().snp
}

#[test]
fn live_report_parses_to_expected_fields() {
    let r = live_report();
    assert_eq!(r.version, 5, "report version 5 (Milan/Genoa/Turin V5)");
    assert_eq!(r.vmpl, 0);
    assert_eq!(r.sig_algo, 1, "ECDSA P-384 / SHA-384");
    assert_eq!(r.policy, 0x30000);
    assert_eq!(r.reported_tcb.bootloader, Some(12));
    assert_eq!(r.reported_tcb.tee, 0);
    assert_eq!(r.reported_tcb.snp, 28);
    assert_eq!(r.reported_tcb.microcode, Some(88));
    assert_eq!(
        hex::encode(r.measurement),
        "20f0e183b7844cc835118d804699ab8b6cdab297414d8f54d70331378ff0d7fdd8a7548a0253ba561bec21e13a0dcc67"
    );
    assert_eq!(
        hex::encode(r.host_data),
        "52de81477823903d498a9484f61007af3ee9b9e139294d929709b99b54619a2d"
    );
}

/// THE crux: byte-exact reconstruction + AMD chain + report signature.
/// This is the check that would catch a mis-placed field in `to_report`.
#[test]
fn live_report_signature_verifies_against_real_vcek() {
    kv::verify_snp(&live_report(), LIVE_ARK, LIVE_ASK, LIVE_VCEK)
        .expect("live report signature + AMD chain must verify");
}

#[test]
fn live_chain_verifies() {
    let chain = kv::build_chain(LIVE_ARK, LIVE_ASK, LIVE_VCEK).expect("chain builds");
    kv::verify_chain(&chain).expect("ARK->ASK->VCEK chain verifies");
}

/// The binding chain (nonce + keyset digest + statement -> report_data).
#[test]
fn live_binding_verifies() {
    let env = live_envelope();
    let digest = kv::verify_binding(&env).expect("live binding verifies");
    assert_eq!(digest, "sha256:3a6615110163ab6c6e011057d51050738892313c697b186a7137c67c9018f0a8");
}

/// The signed SNP reference (launch_measurement + host_data + report_version).
#[test]
fn live_report_matches_signed_reference() {
    let env = live_envelope();
    let reference: serde_json::Value = serde_json::from_str(LIVE_REFERENCE).unwrap();
    kv::match_snp_reference(&env.snp, &reference).expect("live report matches reference");
    kv::verify_registry_signature(&reference, kv::registry::DEFAULT_SIGNING_KEY_B64URL)
        .expect("reference signature verifies");
}

/// TLS possession + SPKI pin against the live leaf.
#[test]
fn live_tls_possession_verifies() {
    use base64::{engine::general_purpose::STANDARD, Engine};
    let env = live_envelope();
    let der = STANDARD.decode(LIVE_TLS_LEAF_DER_B64.trim()).unwrap();
    let leaf = x509_cert::Certificate::from_der(&der).unwrap();
    kv::verify_tls_possession(&env, "llm.kubetee.ai", &leaf).expect("TLS possession verifies");
}

/// FAIL-CLOSED: a tampered nonce must not verify the binding.
#[test]
fn tampered_nonce_fails_binding() {
    let mut env = live_envelope();
    env.nonce = "ff".repeat(32);
    assert!(kv::verify_binding(&env).is_err(), "tampered nonce must FAIL binding");
}

/// FAIL-CLOSED: a tampered keyset digest must not verify.
#[test]
fn tampered_keyset_digest_fails_binding() {
    let mut env = live_envelope();
    env.bindings.keyset_digest = "sha256:".to_string() + &"0".repeat(64);
    assert!(kv::verify_binding(&env).is_err(), "tampered keyset_digest must FAIL");
}

/// FAIL-CLOSED: a tampered report field must fail the signature check.
#[test]
fn tampered_report_fails_signature() {
    let mut r = live_report();
    r.measurement[0] ^= 0x01;
    assert!(
        kv::verify_snp(&r, LIVE_ARK, LIVE_ASK, LIVE_VCEK).is_err(),
        "tampered measurement must FAIL report signature"
    );
}

/// FAIL-CLOSED: a tampered host_data must fail the reference match.
#[test]
fn tampered_host_data_fails_reference() {
    let mut r = live_report();
    r.host_data[0] ^= 0x01;
    let reference: serde_json::Value = serde_json::from_str(LIVE_REFERENCE).unwrap();
    assert!(kv::match_snp_reference(&r, &reference).is_err(), "tampered host_data must FAIL reference");
}

/// FAIL-CLOSED: an unlisted register set must not match any active record.
#[test]
fn tampered_registers_fail_registry_match() {
    let registry: serde_json::Value = serde_json::from_str(LIVE_REGISTRY).unwrap();
    kv::verify_registry_signature(&registry, kv::registry::DEFAULT_SIGNING_KEY_B64URL)
        .expect("registry signature verifies");
    let records = kv::registry_records(&registry);
    let mut regs = std::collections::BTreeMap::new();
    regs.insert("mrtd".to_string(), "00".repeat(48));
    regs.insert("rtmr0".to_string(), "00".repeat(48));
    regs.insert("rtmr1".to_string(), "00".repeat(48));
    regs.insert("rtmr2".to_string(), "00".repeat(48));
    regs.insert("rtmr3".to_string(), "00".repeat(48));
    regs.insert("mrconfigid".to_string(), "00".repeat(48));
    let now = kv::registry::now_iso_utc();
    assert!(
        kv::match_any_active_record(&regs, &records, &now).is_err(),
        "unlisted registers must FAIL registry match"
    );
}

/// FAIL-CLOSED: a tampered registry signature must not verify.
#[test]
fn tampered_registry_signature_fails() {
    let mut registry: serde_json::Value = serde_json::from_str(LIVE_REGISTRY).unwrap();
    registry["issued_at"] = serde_json::json!("2020-01-01T00:00:00Z");
    assert!(
        kv::verify_registry_signature(&registry, kv::registry::DEFAULT_SIGNING_KEY_B64URL).is_err(),
        "tampered registry must FAIL signature"
    );
}

/// FAIL-CLOSED: a wrong TLS SPKI must not verify possession.
#[test]
fn wrong_tls_spki_fails_possession() {
    use base64::{engine::general_purpose::STANDARD, Engine};
    let env = live_envelope();
    let der = STANDARD.decode(LIVE_TLS_LEAF_DER_B64.trim()).unwrap();
    let leaf = x509_cert::Certificate::from_der(&der).unwrap();
    let mut env2 = env.clone();
    if let Some(tp) = &mut env2.tls_possession {
        tp.tls_cert_sha256 = Some("00".repeat(32));
    }
    assert!(
        kv::verify_tls_possession(&env2, "llm.kubetee.ai", &leaf).is_err(),
        "wrong TLS SPKI must FAIL possession"
    );
}
