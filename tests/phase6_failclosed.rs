//! Phase 6 (zero-operator-trust) vectors: v2 quote-bound key binding +
//! CVE-shaped fail-closed fixtures (EarlyAttestationBleed) +
//! registry anti-rollback transition chain (§3.2).
//!
//! The three CVE shapes each get an explicit reject-on-missing fixture:
//!   1. Expectation absent   — CVE-2026-92701
//!   2. Zero-length bypass   — CVE-2026-92702
//!   3. No-match-accepts     — CVE-2026-100833

use kubetee_attestation_verifier as kv;

pub const EVIDENCE_V4: &str = include_str!("fixtures/live_evidence_v4.json");

fn v4_envelope() -> kv::Envelope {
    kv::parse_envelope(EVIDENCE_V4).expect(".6 evidence parses")
}

// ---------------------------------------------------------------------------
// v2 binding — ReportDataForKeyWithContext (frozen vector)
// ---------------------------------------------------------------------------

/// Frozen derivation vector: the transcript and its report_data are pinned so
/// any change to the tag, framing, or hash breaks this test (contract change).
#[test]
fn v2_report_data_frozen_vector() {
    let pkix = hex::decode(
        "302a300506032b6570032100000102030405060708090a0b0c0d0e0f\
         101112131415161718191a1b1c1d1e1f",
    )
    .unwrap();
    let nonce = [0xaau8; 32];
    let ctx = "kubetee-test-context";

    let preimage = kv::report_data_preimage_v2(&pkix, &nonce, ctx).unwrap();
    // raw tag (50 bytes) + 3 length-framed parts (8-byte BE length prefix each):
    // pkix 44 + nonce 32 + context 20.
    assert_eq!(
        preimage.len(),
        kv::KEY_ATTESTATION_TAG.len() + (8 + 44) + (8 + 32) + (8 + 20),
        "transcript = raw tag || framed(pkix) || framed(nonce) || framed(context)"
    );

    let rd = kv::report_data_v2(&pkix, &nonce, ctx).unwrap();
    assert_eq!(
        hex::encode(rd),
        "7c7f82da79e64d00bb228bf3bd7075ea\
         31b938759d00162f1f1d83021f245e24\
         eff25929ec5761309dbbc014119dc4c0\
         00000000000000000000000000000000"
            .replace(char::is_whitespace, ""),
        "report_data = SHA-384(preimage) || 16 zero bytes"
    );
    assert!(
        rd[48..].iter().all(|b| *b == 0),
        "trailing 16 bytes are the reserved zero suffix"
    );
}

/// Context separation: two contexts must never share a report_data (the
/// domain-separation property the framing exists for).
#[test]
fn v2_context_separates_bindings() {
    let pkix = [1u8; 32];
    let nonce = [2u8; 32];
    let a = kv::report_data_v2(&pkix, &nonce, "ctx-a").unwrap();
    let b = kv::report_data_v2(&pkix, &nonce, "ctx-b").unwrap();
    assert_ne!(a, b, "distinct contexts must not collide");
}

/// v2 statement round-trip: derive -> recompute -> equal (what verify does).
#[test]
fn v2_statement_roundtrip() {
    let digest = "sha256:".to_string() + &"ab".repeat(32);
    let nonce = "aa".repeat(32);
    let pkix_b64 = "AQIDBA";
    let stmt =
        kv::report_data_statement_v2(&digest, &nonce, pkix_b64, "role=nim-terminator").unwrap();
    let v: serde_json::Value = serde_json::from_str(&stmt).unwrap();
    assert_eq!(v["purpose"], kv::PURPOSE_V2);
    let recomputed = kv::report_data_statement_v2(
        &digest,
        &nonce,
        v["pkix_pubkey_b64url"].as_str().unwrap(),
        v["context"].as_str().unwrap(),
    )
    .unwrap();
    assert_eq!(stmt, recomputed, "JCS statement is canonical and stable");
}

/// FAIL-CLOSED (CVE-2026-92702 class): empty pkix/nonce/context must never
/// derive a report_data — an empty input on any leg is an error.
#[test]
fn v2_zero_length_inputs_reject() {
    assert!(kv::report_data_v2(&[], &[1u8; 32], "ctx").is_err());
    assert!(kv::report_data_v2(&[1u8; 32], &[], "ctx").is_err());
    assert!(kv::report_data_v2(&[1u8; 32], &[1u8; 32], "").is_err());
    assert!(kv::decode_pkix_pubkey("").is_err());
}

/// Unknown binding version must FAIL CLOSED (no silent v1 fallback).
#[test]
fn unknown_binding_version_rejects() {
    let mut env = v4_envelope();
    env.bindings.version = "kubetee.attestation.v3".to_string();
    assert!(
        kv::verify_binding(&env).is_err(),
        "unknown version must reject"
    );
    env.bindings.version = "".to_string();
    assert!(
        kv::verify_binding(&env).is_err(),
        "empty version must reject"
    );
}

// ---------------------------------------------------------------------------
// CVE-shaped fail-closed fixtures
// ---------------------------------------------------------------------------

/// CVE-2026-92701 (expectation-absent-accepts): an envelope whose expectation
/// fields are empty must reject, never pass by "nothing to compare".
#[test]
fn fixture_missing_expectation_accepts() {
    let mut env = v4_envelope();
    env.bindings.keyset_digest = String::new();
    assert!(
        kv::verify_binding(&env).is_err(),
        "empty keyset_digest expectation must FAIL"
    );
    let mut env2 = v4_envelope();
    env2.bindings.report_data_statement = String::new();
    assert!(
        kv::verify_binding(&env2).is_err(),
        "empty report_data_statement expectation must FAIL"
    );
}

/// CVE-2026-92702 (zero-length-skips-check): a present-but-blank
/// quote_report_data must FAIL the consistency check, never skip it.
#[test]
fn fixture_zero_length_bypass() {
    let mut env = v4_envelope();
    env.quote_report_data = Some([0u8; 64]);
    assert!(
        kv::verify_binding(&env).is_err(),
        "all-zero quote_report_data must FAIL (not skip) the cross-check"
    );

    // And a present-but-malformed quote_report_data must fail the PARSE
    // (never silently drop to None and skip).
    let mut doc: serde_json::Value = serde_json::from_str(EVIDENCE_V4).unwrap();
    doc["evidence"]["quote_report_data"] = serde_json::json!("AAAA"); // 3 bytes
    let out = serde_json::to_string(&doc).unwrap();
    assert!(
        kv::parse_envelope(&out).is_err(),
        "wrong-length quote_report_data must FAIL the parse (fail closed)"
    );
}

/// CVE-2026-100833 (no-match-accepts): zero matching records must REJECT —
/// and an empty expectation inside a record must reject rather than let that
/// record "match" on nothing.
#[test]
fn fixture_no_match_accepts() {
    // (a) no records at all -> reject.
    let empty_records: Vec<kv::Record> = vec![];
    let mut observed = std::collections::BTreeMap::new();
    observed.insert("mrtd".to_string(), "00".repeat(48));
    let now = kv::registry::now_iso_utc();
    assert!(
        kv::match_any_active_record(&observed, &empty_records, &now).is_err(),
        "zero records must REJECT (no-match-accepts)"
    );

    // (b) a record with an EMPTY expectation must reject (not match on zero
    // compared fields).
    let rec = kv::Record {
        id: "blank-expectation".to_string(),
        tee: "tdx".to_string(),
        status: "active".to_string(),
        valid_until: None,
        measurements: [("mrtd".to_string(), String::new())].into(),
    };
    assert!(
        kv::match_any_active_record(&observed, std::slice::from_ref(&rec), &now).is_err(),
        "empty expectation must FAIL, never skip"
    );

    // (c) an all-deprecated record set -> reject (no-active-record).
    let stale = kv::Record {
        id: "stale".to_string(),
        tee: "tdx".to_string(),
        status: "deprecated".to_string(),
        valid_until: None,
        measurements: [("mrtd".to_string(), "00".repeat(48))].into(),
    };
    assert!(kv::match_any_active_record(&observed, &[stale], &now).is_err());

    // (d) zero-length OBSERVED register must reject (zero-length input class).
    let mut blank_regs = std::collections::BTreeMap::new();
    blank_regs.insert("mrtd".to_string(), String::new());
    let good = kv::Record {
        id: "good".to_string(),
        tee: "tdx".to_string(),
        status: "active".to_string(),
        valid_until: None,
        measurements: [("mrtd".to_string(), "00".repeat(48))].into(),
    };
    assert!(
        kv::match_any_active_record(&blank_regs, &[good], &now).is_err(),
        "empty observed register must FAIL (zero-length input)"
    );
}

// ---------------------------------------------------------------------------
// §3.2 registry anti-rollback: transition-hash chain
// ---------------------------------------------------------------------------

/// A signed revision whose `chain` reproduces end-to-end.
#[test]
fn transition_chain_verifies() {
    let mut doc = serde_json::json!({
        "schema": "kubetee.tee-measurements-registry/1",
        "version": 1u64,
        "issued_at": "2026-11-27T00:00:00Z",
        "records": [{"id": "r1", "tee": "tdx", "status": "active",
                     "measurements": {"mrtd": "00"}}],
    });
    let content = kv::content_hash(&doc);
    let prev = kv::GENESIS_PREVIOUS.to_string();
    let trans = kv::transition_hash(&content, &prev);
    doc["chain"] = serde_json::json!({
        "content_hash": content,
        "previous_transition_hash": prev,
        "transition_hash": trans,
    });

    let (c, t, p) = kv::verify_chain_links(&doc).expect("chain verifies");
    assert_eq!(c, content);
    assert_eq!(t, trans);
    assert_eq!(p, kv::GENESIS_PREVIOUS);

    let (latest, th) = kv::verify_history(&[&doc], None).expect("history verifies");
    assert_eq!(latest, 1);
    assert_eq!(th, trans);
}

/// A spliced history (revision 2 chained from the wrong predecessor) rejects.
#[test]
fn transition_chain_splice_rejects() {
    let make = |version: u64, prev: &str| -> serde_json::Value {
        let mut doc = serde_json::json!({
            "schema": "kubetee.tee-measurements-registry/1",
            "version": version,
            "issued_at": "2026-11-27T00:00:00Z",
            "records": [],
        });
        let content = kv::content_hash(&doc);
        let trans = kv::transition_hash(&content, prev);
        doc["chain"] = serde_json::json!({
            "content_hash": content,
            "previous_transition_hash": prev,
            "transition_hash": trans,
        });
        doc
    };
    let v1 = make(1, kv::GENESIS_PREVIOUS);
    let (_, t1, _) = kv::verify_chain_links(&v1).unwrap();
    let v2 = make(2, &t1);
    kv::verify_history(&[&v1, &v2], None).expect("linked history verifies");

    // Splice: a revision-3 built from a DIFFERENT predecessor.
    let v3_bad = make(3, kv::GENESIS_PREVIOUS);
    assert!(
        kv::verify_history(&[&v1, &v2, &v3_bad], None).is_err(),
        "revision 3 chained from the wrong predecessor must FAIL"
    );
}

/// Monotonic floor: a verifier that accepted revision 3 must reject a served
/// revision 2 (the "stale registry to a revoked record" hole).
#[test]
fn transition_chain_rollback_floor_rejects() {
    let make = |version: u64, prev: &str| -> serde_json::Value {
        let mut doc = serde_json::json!({
            "schema": "kubetee.tee-measurements-registry/1",
            "version": version,
            "issued_at": "2026-11-27T00:00:00Z",
            "records": [],
        });
        let content = kv::content_hash(&doc);
        let trans = kv::transition_hash(&content, prev);
        doc["chain"] = serde_json::json!({
            "content_hash": content,
            "previous_transition_hash": prev,
            "transition_hash": trans,
        });
        doc
    };
    let v1 = make(1, kv::GENESIS_PREVIOUS);
    let (_, t1, _) = kv::verify_chain_links(&v1).unwrap();
    let v2 = make(2, &t1);

    // Fresh verifier (no floor) accepts both.
    kv::verify_history(&[&v1, &v2], None).expect("no floor: accepted");
    // Verifier whose floor is 2 rejects a bare v1 (rollback to revoked state).
    assert!(
        kv::verify_history(&[&v1], Some(2)).is_err(),
        "rollback below the accepted floor must FAIL"
    );
    kv::verify_history(&[&v2], Some(2)).expect("at/above floor: accepted");
}

/// FAIL-CLOSED: a present-but-malformed `chain` must reject (never downgrade
/// to "no chain" — that would be CVE-2026-100833 class).
#[test]
fn transition_chain_malformed_rejects() {
    let mut doc = serde_json::json!({
        "schema": "kubetee.tee-measurements-registry/1",
        "version": 1u64,
        "records": [],
    });
    // No chain at all -> the chain is required.
    assert!(kv::verify_chain_links(&doc).is_err());
    // Blank hash fields -> reject.
    doc["chain"] = serde_json::json!({
        "content_hash": "", "previous_transition_hash": kv::GENESIS_PREVIOUS,
        "transition_hash": "",
    });
    assert!(kv::verify_chain_links(&doc).is_err());
    // Wrong-length hash -> reject.
    doc["chain"] = serde_json::json!({
        "content_hash": "abcd", "previous_transition_hash": kv::GENESIS_PREVIOUS,
        "transition_hash": "abcd",
    });
    assert!(kv::verify_chain_links(&doc).is_err());
}
