//! Client-facing reference measurement registry (`.well-known`).
//!
//! Two signed documents:
//!   * `tee-measurements-registry.json` — the multi-record allowlist
//!     (`records[]`, schema `kubetee.tee-measurements-registry/1`) used for
//!     TDX backends. Matches ANY active (non-expired) record.
//!   * `tee-measurements.json` — the single-record SNP reference
//!     (`snp.launch_measurement.sha384`, `snp.host_data.*`, schema
//!     `kubetee.tee-measurements/2`).
//!
//! Both are Ed25519-signed over the RFC 8785 (JCS) serialization of the
//! document **minus its `signature` member** (`canonicalization`:
//! `RFC8785-without-signature-member`). The pinned public key is in
//! `tee-measurements-signing-key-2026.json`; a verifier MUST check it.

use crate::envelope::{SnpReport, jcs};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};

pub const REGISTRY_SCHEMA: &str = "kubetee.tee-measurements-registry/1";
pub const REFERENCE_SCHEMA: &str = "kubetee.tee-measurements/2";

/// The pinned KubeTEE measurements signing key (public — not a secret).
/// Matches `tee-measurements-signing-key-2026.json` `public_key.x` (32 bytes).
/// SPKI SHA-256: `046b732aa6bb0695a15c00af9d58d64661e5e27ec3d169851ea77dc0bbf6f530`.
pub const DEFAULT_SIGNING_KEY_B64URL: &str = "FekS2fBdTq91Xe6IIUoGWot_ig7uybpX9vhO5WN_1Wc";

#[derive(Debug, thiserror::Error)]
pub enum RegistryError {
    #[error("invalid registry JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error("registry signature invalid: {0}")]
    Signature(String),
    #[error("registry rejected: {0}")]
    Rejected(String),
}

/// Verify the registry's Ed25519 `signature` over `jcs(doc minus signature)`.
pub fn verify_registry_signature(
    doc: &serde_json::Value,
    signing_key_b64url: &str,
) -> Result<(), RegistryError> {
    let sig_block = doc
        .get("signature")
        .and_then(|s| s.as_object())
        .ok_or_else(|| RegistryError::Signature("registry has no signature member".to_string()))?;
    let sig_b64 = sig_block
        .get("sig")
        .and_then(|s| s.as_str())
        .ok_or_else(|| RegistryError::Signature("signature.sig missing".to_string()))?;
    let alg = sig_block.get("alg").and_then(|s| s.as_str()).unwrap_or("");
    if !alg.eq_ignore_ascii_case("ed25519") {
        return Err(RegistryError::Signature(format!("unsupported alg {alg:?}")));
    }

    let key_bytes = URL_SAFE_NO_PAD
        .decode(signing_key_b64url)
        .map_err(|e| RegistryError::Signature(format!("signing key: {e}")))?;
    let pk: [u8; 32] = key_bytes
        .as_slice()
        .try_into()
        .map_err(|_| RegistryError::Signature("signing key is not 32 bytes".to_string()))?;
    let vk = VerifyingKey::from_bytes(&pk)
        .map_err(|e| RegistryError::Signature(format!("signing key: {e}")))?;

    let sig_bytes = URL_SAFE_NO_PAD
        .decode(sig_b64)
        .map_err(|e| RegistryError::Signature(format!("signature: {e}")))?;
    let sig = Signature::from_slice(&sig_bytes)
        .map_err(|e| RegistryError::Signature(format!("signature: {e}")))?;

    // Preimage = the doc with the `signature` member removed, JCS-canonicalized.
    let mut unsigned = doc.clone();
    if let serde_json::Value::Object(ref mut map) = unsigned {
        map.remove("signature");
    }
    let preimage = jcs(&unsigned);

    vk.verify(preimage.as_bytes(), &sig)
        .map_err(|_| RegistryError::Signature("Ed25519 signature does NOT verify".to_string()))
}

/// A measurement record from `tee-measurements-registry.json`.
#[derive(Debug, Clone)]
pub struct Record {
    pub id: String,
    pub tee: String,
    pub status: String,
    pub valid_until: Option<String>,
    /// Register name -> hex expectation (lowercased, `hex:` prefix stripped).
    pub measurements: std::collections::BTreeMap<String, String>,
}

/// Parse `records[]` from the registry.
pub fn registry_records(doc: &serde_json::Value) -> Vec<Record> {
    let empty = Vec::new();
    let arr = doc
        .get("records")
        .and_then(|r| r.as_array())
        .unwrap_or(&empty);
    arr.iter()
        .filter_map(|r| {
            let obj = r.as_object()?;
            let id = obj.get("id")?.as_str()?.to_string();
            let tee = obj
                .get("tee")
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .to_string();
            let status = obj
                .get("status")
                .and_then(|x| x.as_str())
                .unwrap_or("active")
                .to_string();
            let valid_until = obj
                .get("valid_until")
                .and_then(|x| x.as_str())
                .map(str::to_string);
            let mut measurements = std::collections::BTreeMap::new();
            if let Some(m) = obj.get("measurements").and_then(|m| m.as_object()) {
                for (k, v) in m {
                    if let Some(hexstr) = v.as_str() {
                        measurements
                            .insert(k.clone(), hexstr.trim_start_matches("hex:").to_lowercase());
                    }
                }
            }
            Some(Record {
                id,
                tee,
                status,
                valid_until,
                measurements,
            })
        })
        .collect()
}

fn is_active(rec: &Record, now_iso: &str) -> bool {
    let status = rec.status.to_lowercase();
    if matches!(status.as_str(), "deprecated" | "revoked" | "retired") {
        return false;
    }
    match &rec.valid_until {
        Some(until) => until.as_str() > now_iso,
        None => true,
    }
}

/// Match live TDX registers against ANY active record. Returns the matching
/// record id. `regs` maps `mrtd|rtmr0..3|mrconfigid` -> hex. A record matches
/// when every field it declares is present and equal. Records outside their
/// `valid_until` window are deprecated and skipped (90-day lifecycle).
///
/// Fail-closed (CVE-2026-92702 / CVE-2026-100833 class): an empty or `_`-prefixed
/// expectation is an ERROR (not a silent skip), so a record can never "match"
/// on zero compared fields. Zero matching records → `Rejected`, never accept.
pub fn match_any_active_record(
    regs: &std::collections::BTreeMap<String, String>,
    records: &[Record],
    now_iso: &str,
) -> Result<String, RegistryError> {
    let mut active_checked = 0;
    for rec in records {
        if !is_active(rec, now_iso) {
            continue;
        }
        active_checked += 1;
        let mut compared = 0;
        let mut mismatches = Vec::new();
        for (name, expected) in &rec.measurements {
            if name.starts_with('_') {
                // Metadata key (capture notes) — not an expectation.
                continue;
            }
            if expected.is_empty() {
                return Err(RegistryError::Rejected(format!(
                    "record {}: empty expectation for {name} (fail-closed: a blank expectation must not be skipped)",
                    rec.id
                )));
            }
            match regs.get(name) {
                Some(got) if !got.is_empty() && got == expected => compared += 1,
                Some(got) if got.is_empty() => {
                    return Err(RegistryError::Rejected(format!(
                        "observed register {name} is empty (fail-closed: zero-length input must not match)"
                    )));
                }
                Some(got) => {
                    compared += 1;
                    mismatches.push(format!(
                        "{name}-drift: got {}.. expected {}..",
                        &got[..got.len().min(16)],
                        &expected[..expected.len().min(16)]
                    ));
                }
                None => mismatches.push(format!("{name}-absent")),
            }
        }
        if compared > 0 && mismatches.is_empty() {
            return Ok(rec.id.clone());
        }
    }
    if active_checked == 0 {
        return Err(RegistryError::Rejected(
            "registry-no-active-record: every record is deprecated/expired".to_string(),
        ));
    }
    Err(RegistryError::Rejected(format!(
        "registry-no-match: live registers match no active record ({active_checked} active checked)"
    )))
}

/// Extract the TDX registers from a relayed backend evidence node
/// (`evidence.tdx.regs` or `evidence.claims.quote.body.*`). Returns empty when
/// absent (an SNP backend has no TDX registers).
pub fn tdx_regs(evidence: &serde_json::Value) -> std::collections::BTreeMap<String, String> {
    let mut out = std::collections::BTreeMap::new();
    let body = evidence.get("tdx").and_then(|t| t.get("regs")).or_else(|| {
        evidence
            .get("claims")
            .and_then(|c| c.get("quote"))
            .and_then(|q| q.get("body"))
    });
    let Some(body) = body.and_then(|b| b.as_object()) else {
        return out;
    };
    for (src, dst) in [
        ("mr_td", "mrtd"),
        ("rt_mr0", "rtmr0"),
        ("rt_mr1", "rtmr1"),
        ("rt_mr2", "rtmr2"),
        ("rt_mr3", "rtmr3"),
        ("mr_config_id", "mrconfigid"),
    ] {
        if let Some(v) = body.get(src).and_then(|x| x.as_str()) {
            let v = v.trim().to_lowercase();
            if v.chars().all(|c| c.is_ascii_hexdigit()) && !v.is_empty() {
                out.insert(dst.to_string(), v);
            }
        }
    }
    out
}

/// Match a live SNP report against the SNP reference document
/// (`tee-measurements.json`, schema `kubetee.tee-measurements/2`):
///   * `snp.launch_measurement.sha384` (hex) == report `measurement`.
///   * `snp.host_data.sha384_uncompressed_initdata_toml_prefix32` == report `host_data`.
///   * `snp.report_version` == report `version`.
pub fn match_snp_reference(
    report: &SnpReport,
    reference: &serde_json::Value,
) -> Result<(), RegistryError> {
    let snp = reference
        .get("snp")
        .ok_or_else(|| RegistryError::Rejected("reference has no snp member".to_string()))?;

    let expected_m = snp
        .get("launch_measurement")
        .and_then(|l| l.get("sha384"))
        .and_then(|x| x.as_str())
        .ok_or_else(|| {
            RegistryError::Rejected("reference has no snp.launch_measurement.sha384".to_string())
        })?
        .trim_start_matches("sha384:")
        .to_lowercase();
    let got_m = hex::encode(report.measurement);
    if got_m != expected_m {
        return Err(RegistryError::Rejected(format!(
            "snp.launch_measurement drift: got {got_m}, expected {expected_m}"
        )));
    }

    let expected_hd = snp
        .get("host_data")
        .and_then(|h| h.get("sha384_uncompressed_initdata_toml_prefix32"))
        .and_then(|x| x.as_str())
        .ok_or_else(|| {
            RegistryError::Rejected("reference has no snp.host_data prefix32".to_string())
        })?
        .trim_start_matches("sha384:")
        .to_lowercase();
    let got_hd = hex::encode(report.host_data);
    if got_hd != expected_hd {
        return Err(RegistryError::Rejected(format!(
            "snp.host_data drift: got {got_hd}, expected {expected_hd}"
        )));
    }

    if let Some(rv) = snp.get("report_version").and_then(|x| x.as_u64())
        && rv != u64::from(report.version)
    {
        return Err(RegistryError::Rejected(format!(
            "snp.report_version mismatch: got {}, expected {rv}",
            report.version
        )));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// §3.2 registry anti-rollback: signed transition-hash chain (Contrast-style
// manifest history) + monotonic revision floor.
//
// Each published record-set is additionally bound to a `chain` member:
//     chain.content_hash           = sha256(jcs(doc-without-signature-and-chain))
//     chain.previous_transition    = the previous doc's `chain.transition_hash`
//                                    (genesis = 64 zeros)
//     chain.transition_hash        = sha256("kubetee.registry.transition/1"
//                                          ‖ framed(content_hash)
//                                          ‖ framed(previous_transition))
// The Ed25519 `signature` covers the doc minus `signature` (i.e. INCLUDING
// `chain`), so an attacker cannot splice a different history onto a signed
// record-set. A verifier that has ever seen revision N rejects anything with
// `version < N` and verifies each served revision's chain end-to-end.
// ---------------------------------------------------------------------------

/// Domain-separation tag for the registry transition hash.
pub const TRANSITION_TAG: &[u8] = b"kubetee.registry.transition/1";

/// The genesis `previous_transition_hash` (64 hex zeros).
pub const GENESIS_PREVIOUS: &str =
    "0000000000000000000000000000000000000000000000000000000000000000";

/// Compute `chain.content_hash` = `sha256(jcs(doc minus signature and chain))`.
pub fn content_hash(doc: &serde_json::Value) -> String {
    let mut unsigned = doc.clone();
    if let serde_json::Value::Object(ref mut map) = unsigned {
        map.remove("signature");
        map.remove("chain");
    }
    let mut hasher = Sha256::new();
    hasher.update(jcs(&unsigned).as_bytes());
    hex::encode(hasher.finalize())
}

/// Compute `chain.transition_hash` = `sha256(tag ‖ framed(content_hash) ‖
/// framed(previous_transition))` (hex, 64 chars).
pub fn transition_hash(content_hash_hex: &str, previous_transition_hex: &str) -> String {
    let mut preimage = Vec::new();
    preimage.extend_from_slice(TRANSITION_TAG);
    for part in [
        content_hash_hex.as_bytes(),
        previous_transition_hex.as_bytes(),
    ] {
        preimage.extend_from_slice(&(part.len() as u64).to_be_bytes());
        preimage.extend_from_slice(part);
    }
    let mut hasher = Sha256::new();
    hasher.update(&preimage);
    hex::encode(hasher.finalize())
}

fn is_hex64(s: &str) -> bool {
    s.len() == 64 && s.chars().all(|c| c.is_ascii_hexdigit())
}

/// Verify one document's internal chain (if it carries one) and return its
/// `(content_hash, transition_hash, previous_transition_hash)`.
///
/// Fail-closed: a present-but-malformed `chain` member (missing/blank/wrong
/// length hash fields, or a transition_hash that doesn't reproduce) is an
/// error — never silently treated as "no chain" (that would be a downgrade
/// to the un-chained form, CVE-2026-100833 class).
pub fn verify_chain_links(
    doc: &serde_json::Value,
) -> Result<(String, String, String), RegistryError> {
    let Some(chain) = doc.get("chain").and_then(|c| c.as_object()) else {
        return Err(RegistryError::Rejected(
            "expectation-absent: registry has no chain member (anti-rollback chain required)"
                .to_string(),
        ));
    };
    let get = |k: &str| -> Result<&str, RegistryError> {
        chain
            .get(k)
            .and_then(|v| v.as_str())
            .filter(|s| is_hex64(s))
            .ok_or_else(|| {
                RegistryError::Rejected(format!("chain.{k} missing or not 64 hex chars"))
            })
    };
    let served_content = get("content_hash")?;
    let served_prev = get("previous_transition_hash")?;
    let served_transition = get("transition_hash")?;

    let computed_content = content_hash(doc);
    if computed_content != served_content {
        return Err(RegistryError::Rejected(format!(
            "chain.content_hash mismatch: computed {computed_content}, served {served_content}"
        )));
    }
    let computed_transition = transition_hash(served_content, served_prev);
    if computed_transition != served_transition {
        return Err(RegistryError::Rejected(format!(
            "chain.transition_hash mismatch: computed {computed_transition}, served {served_transition}"
        )));
    }
    Ok((
        computed_content,
        served_transition.to_string(),
        served_prev.to_string(),
    ))
}

/// Verify a served history of registry revisions (newest last or first —
/// ordered internally by `version`), enforcing:
///   1. Each revision's `chain` links `previous_transition_hash` to the
///      PREVIOUS revision's `transition_hash` (by ascending `version`),
///      genesis revision's `previous` == `GENESIS_PREVIOUS`.
///   2. **Monotonic floor**: if `min_revision` is set (the highest `version`
///      this verifier has ever accepted), every served revision with a lower
///      `version` is rejected outright — closing the "serve an old registry
///      to a revoked-record's verifier" hole.
///   3. The latest revision's chain terminates the verified run.
///
/// Returns the verified latest `(version, transition_hash)`.
pub fn verify_history(
    docs: &[&serde_json::Value],
    min_revision: Option<u64>,
) -> Result<(u64, String), RegistryError> {
    if docs.is_empty() {
        return Err(RegistryError::Rejected(
            "history-empty: no registry revisions served (fail-closed)".to_string(),
        ));
    }
    let mut keyed: Vec<(u64, &serde_json::Value)> = Vec::with_capacity(docs.len());
    for d in docs {
        let v = d
            .get("version")
            .and_then(|x| x.as_u64())
            .ok_or_else(|| RegistryError::Rejected("revision missing version".to_string()))?;
        keyed.push((v, *d));
    }
    keyed.sort_by_key(|(v, _)| *v);

    // Monotonic floor: nothing below the verifier's high-water mark.
    if let Some(min) = min_revision {
        for (v, _) in &keyed {
            if *v < min {
                return Err(RegistryError::Rejected(format!(
                    "anti-rollback: served revision {v} is below the verifier's accepted floor {min}"
                )));
            }
        }
    }

    // Genesis check + sequential link check.
    let (first_version, first_doc) = keyed.first().expect("non-empty");
    let (_, first_transition, first_prev) = verify_chain_links(first_doc)?;
    if *first_version == 1 && first_prev != GENESIS_PREVIOUS {
        return Err(RegistryError::Rejected(
            "chain.genesis: revision 1 must chain from 64 zeros".to_string(),
        ));
    }
    let mut prev_transition = first_transition;
    let mut prev_version = *first_version;
    for (v, d) in keyed.iter().skip(1) {
        let (_, transition, prev) = verify_chain_links(d)?;
        if *v == prev_version {
            return Err(RegistryError::Rejected(format!(
                "duplicate revision {v} in served history"
            )));
        }
        if prev != prev_transition {
            return Err(RegistryError::Rejected(format!(
                "anti-rollback: revision {v} chains from {prev}, but revision {prev_version} transitioned to {prev_transition} (history spliced)"
            )));
        }
        prev_transition = transition;
        prev_version = *v;
    }
    Ok((prev_version, prev_transition))
}

/// Build the observed-registry `now` in the same `YYYY-MM-DDTHH:MM:SSZ` form
/// the registry's `valid_until` uses (UTC, second precision).
pub fn now_iso_utc() -> String {
    // Minimal UTC formatter without chrono (keeps the dependency tree lean).
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let days = secs / 86400;
    let rem = secs % 86400;
    let (h, m, s) = (rem / 3600, (rem % 3600) / 60, rem % 60);
    // Civil-from-days (Howard Hinnant's algorithm).
    let z = days as i64 + 719468;
    let era = z / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let mth = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if mth <= 2 { y + 1 } else { y };
    format!("{y:04}-{mth:02}-{d:02}T{h:02}:{m:02}:{s:02}Z")
}
