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
///
/// The 2026-11-26 live capture is a LEGACY v1 envelope (its `report_data` is
/// the v1 `sha256(statement)||32-zeros` value), which the v2-only verifier
/// **hard rejects** — pinned here as the fail-closed retire-v1 proof. The
/// positive v2 binding path is pinned by the synthetic-v2 vectors in
/// `self_contained.rs` / `key_possession.rs`.
#[test]
fn live_v1_envelope_is_rejected_fail_closed() {
    let env = live_envelope();
    assert!(
        kv::verify_binding(&env).is_err(),
        "legacy v1 capture must be rejected (v2 is the only accepted version)"
    );
}

/// FAIL-CLOSED: a tampered nonce must not verify the binding.
#[test]
fn tampered_nonce_fails_binding() {
    let mut env = live_envelope();
    env.nonce = "ff".repeat(32);
    assert!(
        kv::verify_binding(&env).is_err(),
        "tampered nonce must FAIL binding"
    );
}

/// FAIL-CLOSED: a tampered keyset digest must not verify.
#[test]
fn tampered_keyset_digest_fails_binding() {
    let mut env = live_envelope();
    env.bindings.keyset_digest = "sha256:".to_string() + &"0".repeat(64);
    assert!(
        kv::verify_binding(&env).is_err(),
        "tampered keyset_digest must FAIL"
    );
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
    assert!(
        kv::match_snp_reference(&r, &reference).is_err(),
        "tampered host_data must FAIL reference"
    );
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

/// FAIL-CLOSED: a wrong TLS SPKI must not verify the SPKI pin. The legacy v1
/// capture's `tls_possession` is retired; this vector corrupts a v2 envelope's
/// keyset pin instead.
#[test]
fn wrong_tls_spki_fails_pin() {
    let key = common::BootKey::from_seed(0x41);
    let mut env = common::v2_envelope(
        &key,
        &common::nonce_hex(0xaa),
        "ctx",
        common::rd(0x41),
        None,
    );
    for entry in &mut env.keyset.tls_public_keys {
        if entry.domain == "llm.kubetee.ai" {
            entry.spki_sha256 = "sha256:".to_string() + &"00".repeat(32);
        }
    }
    let leaf = common::x509_leaf(&common::tls_leaf());
    assert!(
        kv::verify_spki_pin(&env, "llm.kubetee.ai", &leaf).is_err(),
        "wrong TLS SPKI must FAIL the pin"
    );
}

mod common;
