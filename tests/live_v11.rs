//! Final deployed `kubetee.attestation.v2` gateway fixture (2026-11-28).
//! Real AMD report + VCEK from AMD KDS + live TLS leaf + signed reference v8.
//! Captured before the reference publication; no secrets or credentials.

use base64::Engine as _;
use kubetee_attestation_verifier as kv;

const EVIDENCE: &str = include_str!("fixtures/live_evidence_v11.json");
const REFERENCE: &str = include_str!("fixtures/reference_v11.json");
const VCEK: &str = include_str!("fixtures/vcek_v11.pem");
const ARK: &str = include_str!("fixtures/ark.pem");
const ASK: &str = include_str!("fixtures/ask.pem");
const TLS_LEAF: &str = include_str!("fixtures/tls_leaf_v11.der.b64");

fn input<'a>(
    raw: &'a serde_json::Value,
    env: &'a kv::Envelope,
    leaf: &'a [u8],
    reference: &'a serde_json::Value,
) -> kv::VerifyInput<'a> {
    kv::VerifyInput {
        raw,
        envelope: env,
        ark_pem: Some(ARK),
        ask_pem: Some(ASK),
        vcek_pem: Some(VCEK),
        snp_reference: Some(reference),
        registry: None,
        registry_history: None,
        min_revision: None,
        tls_leaf_der: Some(leaf),
        tls_domain: "llm.kubetee.ai",
        signing_key_b64url: Some(kv::registry::DEFAULT_SIGNING_KEY_B64URL),
        now_iso: None,
    }
}

fn tls_leaf() -> Vec<u8> {
    base64::engine::general_purpose::STANDARD
        .decode(
            TLS_LEAF
                .chars()
                .filter(|c| !c.is_whitespace())
                .collect::<String>(),
        )
        .expect("TLS leaf base64")
}

#[test]
fn real_v2_final_gateway_verifies_with_amd_snp_and_tls_possession() {
    let raw: serde_json::Value = serde_json::from_str(EVIDENCE).expect("live bundle parses");
    let env = kv::parse_envelope(EVIDENCE).expect("v2 envelope parses");
    let reference: serde_json::Value = serde_json::from_str(REFERENCE).expect("reference");
    let leaf = tls_leaf();
    let verdict = kv::verify(&input(&raw, &env, &leaf, &reference));
    assert!(verdict.pass, "live final v2 evidence: {}", verdict.report());
    let report = verdict.report();
    assert!(report.contains("PASS deployment-config"));
    assert!(report.contains("PASS key-possession"));
}

#[test]
fn mutations_of_v2_deployment_inputs_do_not_fallback() {
    for path in [
        "/nonce",
        "/report_data_input",
        "/evidence/vm_config/initdata_toml",
        "/key_possession/signature_b64",
    ] {
        let mut raw: serde_json::Value = serde_json::from_str(EVIDENCE).unwrap();
        let node = raw
            .pointer_mut(path)
            .unwrap_or_else(|| panic!("real fixture contains {path}"));
        *node = match node {
            serde_json::Value::String(s) => {
                let mut tampered = s.clone();
                let first = if tampered.starts_with('0') { "1" } else { "0" };
                tampered.replace_range(..1, first);
                serde_json::Value::String(tampered)
            }
            _ => panic!("expected a string at {path}"),
        };
        let parsed = serde_json::to_string(&raw).unwrap();
        let env = match kv::parse_envelope(&parsed) {
            Ok(env) => env,
            Err(_) => continue, // fail-closed at parse is already a valid rejection
        };
        let reference: serde_json::Value = serde_json::from_str(REFERENCE).expect("reference");
        let leaf = tls_leaf();
        let verdict = kv::verify(&input(&raw, &env, &leaf, &reference));
        assert!(
            !verdict.pass,
            "tampered {path} must reject: {}",
            verdict.report()
        );
    }
}
