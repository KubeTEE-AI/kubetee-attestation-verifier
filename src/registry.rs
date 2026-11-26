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
            if name.starts_with('_') || expected.is_empty() {
                continue;
            }
            match regs.get(name) {
                Some(got) if got == expected => compared += 1,
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
