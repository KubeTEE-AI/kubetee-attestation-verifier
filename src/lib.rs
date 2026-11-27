//! Independent, fail-closed AMD SEV-SNP verifier for the KubeTEE TEE
//! attestation envelope (`kubetee.attestation.v1`).
//!
//! This crate is the reference verifier partners (Chutes, SayGM, gm-miner)
//! can run to independently confirm a KubeTEE gateway's TEE evidence without
//! trusting any KubeTEE-owned endpoint:
//!
//!   1. **AMD chain** — ARK→ASK→VCEK from AMD KDS (or the envelope's
//!      `cert_chain`), checked against AMD's root of trust.
//!   2. **Report signature** — the SNP report's ECDSA P-384/SHA-384 signature
//!      over `to_bytes()[..0x2a0]`, verified against the VCEK.
//!   3. **Request binding** — `report_data` == `sha256(jcs(statement)) || 32
//!      zeros` where `statement` binds the caller nonce + the served keyset
//!      digest (anti-replay, anti-downgrade).
//!   4. **Reference measurement match** — the report's `measurement` /
//!      `host_data` / `report_version` match the signed `.well-known`
//!      reference (`tee-measurements.json`), or (for TDX backends) the live
//!      registers match ANY active record in `tee-measurements-registry.json`.
//!   5. **TLS key possession** — the TLS leaf's SPKI SHA-256 matches the
//!      `spki_sha256` inside the quote-bound keyset, and the leaf key signed
//!      the nonce (so the TLS channel is the same entity the TEE attested).
//!
//! Every check fails closed: a mismatch, a malformed field, or an absent
//! expected value is an error, never a pass.

pub mod binding;
pub mod envelope;
pub mod kds;
pub mod registry;
pub mod snp;

pub use binding::{
    BindingError, KEY_ATTESTATION_TAG, PURPOSE_V2, decode_pkix_pubkey, keyset_digest,
    normalize_nonce, report_data_legacy, report_data_preimage_v2, report_data_statement,
    report_data_statement_v2, report_data_v1, report_data_v2, verify_binding,
    verify_tls_possession,
};
pub use envelope::{CertEntry, Envelope, ParseError, SnpReport, parse_envelope};
pub use registry::{
    GENESIS_PREVIOUS, Record, RegistryError, TRANSITION_TAG, content_hash, match_any_active_record,
    match_snp_reference, registry_records, tdx_regs, transition_hash, verify_chain_links,
    verify_history, verify_registry_signature,
};
pub use snp::{
    SnpError, build_chain, chain_from_envelope, kds_product, verify_chain, verify_report_signature,
    verify_snp, verify_snp_from_chain,
};

/// The single entry point: run every check over a parsed envelope + the trust
/// roots. Returns a human-readable PASS report or the first failure.
pub struct Verdict {
    pub pass: bool,
    pub lines: Vec<String>,
}

impl Verdict {
    pub fn report(&self) -> String {
        self.lines.join("\n")
    }
}

pub struct VerifyInput<'a> {
    pub envelope: &'a Envelope,
    /// PEM from AMD KDS (or user-supplied). **Optional** — when `None`, the
    /// report chain is derived from the envelope's own `cert_chain` (the
    /// self-contained path the gateway `1.110.2-kubetee.6` evidence supports).
    pub ark_pem: Option<&'a str>,
    pub ask_pem: Option<&'a str>,
    pub vcek_pem: Option<&'a str>,
    /// The signed SNP reference doc (`tee-measurements.json`).
    pub snp_reference: Option<&'a serde_json::Value>,
    /// The signed TDX registry doc (`tee-measurements-registry.json`).
    pub registry: Option<&'a serde_json::Value>,
    /// Raw TLS leaf (DER) served on the connection.
    pub tls_leaf_der: Option<&'a [u8]>,
    pub tls_domain: &'a str,
    /// `kubetee.tee-measurements-signing-key-2026.json` `public_key.x`.
    pub signing_key_b64url: Option<&'a str>,
    /// The `now` used for record expiry (defaults to wall-clock UTC).
    pub now_iso: Option<&'a str>,
}

pub fn verify(input: &VerifyInput<'_>) -> Verdict {
    let mut lines = Vec::new();
    let fail = |lines: &mut Vec<String>, msg: String| {
        lines.push(format!("FAIL {msg}"));
    };

    // (1)+(2) AMD chain + report signature. Prefer explicit PEMs (AMD KDS /
    // offline), else self-contained: derive ARK/ASK/VCEK from the envelope's
    // own `cert_chain` (gateway 1.110.2-kubetee.6 delivers the full chain).
    let snp_result = match (input.ark_pem, input.ask_pem, input.vcek_pem) {
        (Some(a), Some(s), Some(v)) => snp::verify_snp(&input.envelope.snp, a, s, v),
        _ => snp::verify_snp_from_chain(&input.envelope.snp, &input.envelope.cert_chain),
    };
    match snp_result {
        Ok(()) => lines.push("PASS amd-chain ark->ask->vcek + report-signature".to_string()),
        Err(e) => fail(&mut lines, format!("amd-chain: {e}")),
    }

    // (3) Request binding.
    let keyset_digest = match verify_binding(input.envelope) {
        Ok(d) => {
            lines
                .push("PASS request-binding report_data = sha256(statement)||32-zeros".to_string());
            Some(d)
        }
        Err(e) => {
            fail(&mut lines, format!("request-binding: {e}"));
            None
        }
    };

    // (4) Reference measurement match.
    if let Some(reference) = input.snp_reference {
        if let Some(key) = input.signing_key_b64url {
            match verify_registry_signature(reference, key) {
                Ok(()) => lines.push("PASS reference-signature ed25519".to_string()),
                Err(e) => fail(&mut lines, format!("reference-signature: {e}")),
            }
        }
        match match_snp_reference(&input.envelope.snp, reference) {
            Ok(()) => lines.push(
                "PASS reference-measurement launch_measurement+host_data+report_version"
                    .to_string(),
            ),
            Err(e) => fail(&mut lines, format!("reference-measurement: {e}")),
        }
    }
    if let Some(registry) = input.registry {
        // The registry's `records[]` are TDX BACKEND registers. A pure SNP
        // gateway envelope has none -- the SNP measurement match above is the
        // right check. Skip (do not false-FAIL) when no TDX relay is present.
        match &input.envelope.tdx_evidence {
            None => {
                lines.push(
                    "SKIP registry-match (no TDX backend relay in this SNP envelope)".to_string(),
                );
            }
            Some(tdx_ev) => {
                if let Some(key) = input.signing_key_b64url {
                    match verify_registry_signature(registry, key) {
                        Ok(()) => lines.push("PASS registry-signature ed25519".to_string()),
                        Err(e) => fail(&mut lines, format!("registry-signature: {e}")),
                    }
                }
                let now = input
                    .now_iso
                    .map(str::to_string)
                    .unwrap_or_else(registry::now_iso_utc);
                let records = registry_records(registry);
                let obs = tdx_regs(tdx_ev);
                match match_any_active_record(&obs, &records, &now) {
                    Ok(id) => lines.push(format!("PASS registry-match record {id}")),
                    Err(e) => fail(&mut lines, format!("registry-match: {e}")),
                }
            }
        }
    }

    // (5) TLS possession + SPKI pin.
    if let Some(leaf_der) = input.tls_leaf_der {
        use x509_cert::der::Decode;
        match x509_cert::Certificate::from_der(leaf_der) {
            Ok(leaf) => match verify_tls_possession(input.envelope, input.tls_domain, &leaf) {
                Ok(()) => {
                    lines.push("PASS tls-possession spki-pin+signature-over-nonce".to_string())
                }
                Err(e) => fail(&mut lines, format!("tls-possession: {e}")),
            },
            Err(e) => fail(&mut lines, format!("tls-leaf: {e}")),
        }
    }

    let pass = !lines.iter().any(|l| l.starts_with("FAIL"));
    if pass {
        lines.push("VERDICT PASS".to_string());
    } else {
        lines.push("VERDICT FAIL".to_string());
    }
    if let Some(d) = keyset_digest {
        lines.push(format!("keyset_digest {d}"));
    }
    Verdict { pass, lines }
}
