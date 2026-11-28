//! Shared test helpers: a synthetic `kubetee.attestation.v2` envelope builder
//! over the frozen live-capture fixture. The capture is a legacy v1 envelope
//! (real AMD signature whose `report_data` is the v1 value), so it grounds the
//! hardware crypto (chain + report signature + reference) but is **hard
//! rejected** by the v2-only `verify_binding`. The binding / possession / CVE
//! fail-closed tests therefore rebuild the fixture's binding + possession as
//! v2 over a synthetic per-boot key.

#![allow(dead_code)]

use base64::Engine as _;

pub const EVIDENCE_V4: &str = include_str!("../fixtures/live_evidence_v4.json");
pub const TLS_LEAF_B64: &str = include_str!("../fixtures/tls_leaf.der.b64");

pub const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;

/// The fixture TLS leaf DER (base64 in `tls_leaf.der.b64`).
pub fn tls_leaf() -> Vec<u8> {
    let b64 = TLS_LEAF_B64
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect::<String>();
    B64.decode(&b64).unwrap()
}

/// A per-boot key: a P-256 signing key + its DER SubjectPublicKeyInfo.
pub struct BootKey {
    pub signing: p256::ecdsa::SigningKey,
    pub pkix: Vec<u8>,
}

impl BootKey {
    /// Deterministic per-boot key from a seed byte (no RNG dependency).
    pub fn from_seed(seed: u8) -> Self {
        let mut scalar = [seed | 1; 32]; // non-zero, < n
        scalar[0] = 0x01;
        let field: p256::FieldBytes = scalar.into();
        let signing = p256::ecdsa::SigningKey::from_bytes(&field).unwrap();
        use p256::pkcs8::EncodePublicKey as _;
        let pkix = p256::ecdsa::VerifyingKey::from(&signing)
            .to_public_key_der()
            .unwrap()
            .as_bytes()
            .to_vec();
        Self { signing, pkix }
    }

    /// Sign the raw 64 report-data bytes -> DER ECDSA P-256/SHA-256.
    pub fn sign(&self, report_data: &[u8; 64]) -> Vec<u8> {
        use p256::ecdsa::signature::Signer as _;
        let sig: p256::ecdsa::Signature = self.signing.sign(report_data);
        sig.to_der().as_bytes().to_vec()
    }
}

/// Build a v2 envelope whose binding + possession are consistent over
/// `report_data`, under `key`. `possession_signature` overrides the proof's
/// signature (for corruption vectors).
pub fn v2_envelope(
    key: &BootKey,
    nonce: &str,
    context: &str,
    report_data: [u8; 64],
    possession_signature: Option<Vec<u8>>,
) -> kubetee_attestation_verifier::Envelope {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use kubetee_attestation_verifier as kv;

    let pkix_b64url = URL_SAFE_NO_PAD.encode(&key.pkix);
    let lower = nonce.trim().to_lowercase();

    let mut doc: serde_json::Value = serde_json::from_str(EVIDENCE_V4).unwrap();
    doc["nonce"] = serde_json::json!(nonce);
    // The served keyset is the fixture's own — the binding's `keyset_digest`
    // MUST be the real digest of it (verify_binding recomputes it).
    let digest = {
        let tmp = kv::parse_envelope(&doc.to_string()).expect("fixture parses");
        kv::keyset_digest(&tmp.keyset)
    };
    let statement = kv::report_data_statement_v2(&digest, &lower, &pkix_b64url, context).unwrap();
    doc["bindings"]["version"] = serde_json::json!(kv::PURPOSE_V2);
    doc["bindings"]["report_data_statement"] = serde_json::json!(statement);
    doc["bindings"]["keyset_digest"] = serde_json::json!(digest);
    doc["evidence"]["snp"]["attestation_report"]["report_data"] =
        serde_json::json!(report_data.to_vec());
    doc["evidence"]["quote_report_data"] = serde_json::json!(B64.encode(report_data));

    let signature = possession_signature.unwrap_or_else(|| key.sign(&report_data));
    doc["key_possession"] = serde_json::json!({
        "input": kv::POSSESSION_INPUT,
        "alg": kv::POSSESSION_ALG,
        "signature_b64": B64.encode(signature),
    });
    doc.as_object_mut().unwrap().remove("tls_possession");

    kv::parse_envelope(&doc.to_string()).expect("synthetic v2 envelope parses")
}

/// A 64-byte report-data with the 16-byte zero-suffix shape preserved.
pub fn rd(seed: u8) -> [u8; 64] {
    let mut r = [seed; 64];
    r[48..].fill(0);
    r
}

/// The v2 report_data a binding over this key/nonce/context COMMITS (what a
/// real quote would carry). `verify_binding` re-derives exactly this value.
pub fn bound_rd(key: &BootKey, nonce: &str, context: &str) -> [u8; 64] {
    use kubetee_attestation_verifier as kv;
    let lower = nonce.trim().to_lowercase();
    let nonce_bytes = hex::decode(&lower).unwrap();
    kv::report_data_v2(&key.pkix, &nonce_bytes, context).unwrap()
}

/// A self-consistent v2 envelope: the quote's `report_data` is the real
/// derivation output for `key`/`nonce`/`context` (so `verify_binding` passes
/// end-to-end), and the possession proof signs it under `key`.
pub fn v2_bound_envelope(
    key: &BootKey,
    nonce: &str,
    context: &str,
) -> kubetee_attestation_verifier::Envelope {
    let report_data = bound_rd(key, nonce, context);
    v2_envelope(key, nonce, context, report_data, None)
}

pub fn nonce_hex(seed: u8) -> String {
    format!("{seed:02x}").repeat(32)
}

pub fn x509_leaf(der: &[u8]) -> x509_cert::Certificate {
    use x509_cert::der::Decode as _;
    x509_cert::Certificate::from_der(der).unwrap()
}
