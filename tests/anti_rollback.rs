//! Phase 6 §3.2 anti-rollback WIRING regression tests (2026-11-27).
//!
//! `verify_chain_links` / `verify_history` were implemented and unit-tested but
//! never called from the `verify()` entry point — so a chain-less or
//! rolled-back registry sailed through as long as its Ed25519 signature
//! verified. These tests pin the WIRING: the trust root is held to the
//! chain + monotonic floor through `verify()`, fail-closed, for any supplied
//! registry (even a pure-SNP envelope with no TDX backend).

use kubetee_attestation_verifier as kv;

pub const EVIDENCE_V4: &str = include_str!("fixtures/live_evidence_v4.json");

fn envelope() -> kv::Envelope {
    kv::parse_envelope(EVIDENCE_V4).expect("evidence parses")
}

/// Build a chain-linked registry doc (a minimal one — `verify_history` checks
/// the chain + floor, not record contents). `prev` chains from the prior doc.
fn chained(version: u64, prev: Option<&serde_json::Value>) -> serde_json::Value {
    let mut doc = serde_json::json!({
        "schema": "kubetee.tee-measurements-registry/1",
        "version": version,
        "records": [],
    });
    let (prev_trans, prev_version) = match prev {
        None => (kv::GENESIS_PREVIOUS.to_string(), None),
        Some(p) => {
            let c = p["chain"]["transition_hash"].as_str().unwrap().to_string();
            (c, Some(p["version"].as_u64().unwrap()))
        }
    };
    let content = kv::content_hash(&doc);
    let transition = kv::transition_hash(&content, &prev_trans);
    let mut chain = serde_json::json!({
        "algorithm": "sha256",
        "content_hash": content,
        "previous_transition_hash": prev_trans,
        "transition_hash": transition,
    });
    if let Some(v) = prev_version {
        chain["previous_version"] = serde_json::json!(v);
    }
    doc["chain"] = chain;
    doc
}

fn verify_with_registry(
    registry: &serde_json::Value,
    history: Option<&[&serde_json::Value]>,
    min_revision: Option<u64>,
) -> kv::Verdict {
    let env = envelope();
    kv::verify(&kv::VerifyInput {
        envelope: &env,
        ark_pem: None,
        ask_pem: None,
        vcek_pem: None,
        snp_reference: None,
        registry: Some(registry),
        registry_history: history,
        min_revision,
        tls_leaf_der: None,
        tls_domain: "llm.kubetee.ai",
        signing_key_b64url: None,
        now_iso: None,
    })
}

/// A registry with NO `chain` member must be rejected outright (no silent
/// downgrade to the un-chained form — CVE-2026-100833 class).
#[test]
fn a_chainless_registry_is_rejected_by_verify() {
    let chainless = serde_json::json!({
        "schema": "kubetee.tee-measurements-registry/1",
        "version": 1,
        "records": [],
    });
    let verdict = verify_with_registry(&chainless, None, None);
    let report = verdict.report();
    assert!(
        !verdict.pass
            && report.contains("registry-anti-rollback")
            && report.contains("no chain member"),
        "chain-less registry must FAIL the anti-rollback gate:\n{report}"
    );
}

/// A correctly chain-linked registry passes the anti-rollback gate (and the
/// PASS line names the verified revision + floor).
#[test]
fn a_chained_registry_passes_the_anti_rollback_gate() {
    let v1 = chained(1, None);
    let verdict = verify_with_registry(&v1, None, None);
    let report = verdict.report();
    assert!(
        report.contains("PASS registry-anti-rollback chain-links revision 1"),
        "chained registry must PASS the anti-rollback gate:\n{report}"
    );
}

/// The monotonic floor rejects any revision below the verifier's high-water
/// mark — the stale-pre-revocation-registry hole (its signature and chain are
/// valid; only the floor catches it).
#[test]
fn a_revision_below_the_floor_is_rejected() {
    let v1 = chained(1, None);
    let v2 = chained(2, Some(&v1));
    // Fresh verifier accepts v2, then persists floor = 2 ...
    assert!(verify_with_registry(&v2, None, None).pass);
    // ... and now REJECTS v1 (rolled back) even though it chains from genesis.
    let rolled_back = verify_with_registry(&v1, None, Some(2));
    let report = rolled_back.report();
    assert!(
        !rolled_back.pass
            && report.contains("registry-anti-rollback")
            && report.contains("below the verifier's accepted floor"),
        "a rolled-back revision must be rejected by the floor:\n{report}"
    );
}

/// A multi-revision served history verifies end-to-end (each chain link +
/// the floor), and terminates at the newest revision.
#[test]
fn a_linked_history_verifies_and_splices_reject() {
    let v1 = chained(1, None);
    let v2 = chained(2, Some(&v1));
    let v3 = chained(3, Some(&v2));

    let run: Vec<&serde_json::Value> = vec![&v3, &v1, &v2]; // unordered
    let verdict = verify_with_registry(&v3, Some(&run), None);
    assert!(
        verdict.pass,
        "linked history must verify:\n{}",
        verdict.report()
    );
    assert!(
        verdict.report().contains("revision 3"),
        "terminates at the newest revision:\n{}",
        verdict.report()
    );

    // Splice: v3 that does NOT chain from v2 must reject.
    let v3_spliced = chained(3, Some(&v1));
    let bad: Vec<&serde_json::Value> = vec![&v2, &v3_spliced];
    let verdict = verify_with_registry(&v3_spliced, Some(&bad), None);
    let report = verdict.report();
    assert!(
        !verdict.pass && report.contains("history spliced"),
        "a spliced history must be rejected:\n{report}"
    );
}
