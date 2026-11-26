//! Envelope parsing for the `kubetee.attestation.v1` evidence document.
//!
//! The gateway (`/v1/attestation`) serves a JSON envelope with an
//! `evidence.snp.attestation_report` whose fields are the *parsed* AMD
//! SEV-SNP report plus an empty `cert_chain` (the raw-report gap). This module
//! is the wire contract on the KubeTEE side, kept byte-consistent with
//! `litellm/tools/kubetee-litellm-overlay/kubetee_attestation.py`.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use sha2::{Digest, Sha256};

#[derive(Debug, thiserror::Error)]
pub enum ParseError {
    #[error("invalid JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error("missing field: {0}")]
    Missing(&'static str),
    #[error("bad hex/array field {field}: {why}")]
    Field {
        field: &'static str,
        why: String,
    },
}

/// RFC 8785 (JCS) — the exact serialization the binding + registry sign over.
/// Sorted keys, no whitespace, UTF-8. Mirrors `kubetee_binding._jcs` /
/// `build-tee-measurements-registry.jcs`.
pub fn jcs(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::Null => "null".to_string(),
        serde_json::Value::Bool(true) => "true".to_string(),
        serde_json::Value::Bool(false) => "false".to_string(),
        serde_json::Value::Number(n) => n.to_string(),
        serde_json::Value::String(s) => jcs_string(s),
        serde_json::Value::Array(items) => {
            let body: Vec<String> = items.iter().map(jcs).collect();
            format!("[{}]", body.join(","))
        }
        serde_json::Value::Object(map) => {
            let mut pairs: Vec<String> = map
                .iter()
                .map(|(k, v)| format!("{}:{}", jcs_string(k), jcs(v)))
                .collect();
            pairs.sort();
            format!("{{{}}}", pairs.join(","))
        }
    }
}

fn jcs_string(s: &str) -> String {
    // serde_json's Display for String is RFC 8785-compatible for our inputs
    // (sorted-keys object with ASCII/UTF-8 values, no control chars).
    serde_json::Value::String(s.to_string()).to_string()
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Tcb {
    pub fmc: Option<u8>,
    pub bootloader: Option<u8>,
    pub tee: u8,
    pub snp: u8,
    pub microcode: Option<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Version3 {
    pub major: u8,
    pub minor: u8,
    pub build: u8,
}

#[derive(Debug, Clone)]
pub struct SnpReport {
    pub version: u32,
    pub guest_svn: u32,
    pub policy: u64,
    pub family_id: [u8; 16],
    pub image_id: [u8; 16],
    pub vmpl: u32,
    pub sig_algo: u32,
    pub current_tcb: Tcb,
    pub plat_info: u64,
    pub key_info: u32,
    pub report_data: [u8; 64],
    pub measurement: [u8; 48],
    pub host_data: [u8; 32],
    pub id_key_digest: [u8; 48],
    pub author_key_digest: [u8; 48],
    pub report_id: [u8; 32],
    pub report_id_ma: [u8; 32],
    pub reported_tcb: Tcb,
    pub cpuid_fam_id: Option<u8>,
    pub cpuid_mod_id: Option<u8>,
    pub cpuid_step: Option<u8>,
    pub chip_id: [u8; 64],
    pub committed_tcb: Tcb,
    pub current: Version3,
    pub committed: Version3,
    pub launch_tcb: Tcb,
    pub launch_mit_vector: Option<u64>,
    pub current_mit_vector: Option<u64>,
    pub current_etcb: Option<[u8; 16]>,
    pub launch_etcb: Option<[u8; 16]>,
    pub committed_etcb: Option<[u8; 16]>,
    pub signature_r: [u8; 72],
    pub signature_s: [u8; 72],
}

#[derive(Debug, Clone)]
pub struct KeysetEntry {
    pub domain: String,
    pub spki_sha256: String,
}

#[derive(Debug, Clone)]
pub struct Keyset {
    pub subject: String,
    pub not_after: String,
    pub tls_public_keys: Vec<KeysetEntry>,
    pub signing_keys: Vec<KeysetEntry>,
    pub e2ee_keys: Vec<KeysetEntry>,
    /// The keyset object as served — used to recompute `keyset_digest`.
    pub raw: serde_json::Value,
}

#[derive(Debug, Clone)]
pub struct Bindings {
    pub version: String,
    pub report_data_statement: String,
    pub keyset_digest: String,
}

#[derive(Debug, Clone)]
pub struct TlsPossession {
    pub tls_signature: String,
    pub tls_signature_alg: String,
    pub tls_signature_input: String,
    pub tls_cert_sha256: Option<String>,
}

#[derive(Debug, Clone)]
pub struct Envelope {
    pub nonce: String,
    pub report_data_input: String,
    pub tee: String,
    pub runtime_class: String,
    pub pod: String,
    pub keyset: Keyset,
    pub bindings: Bindings,
    pub tls_possession: Option<TlsPossession>,
    /// `evidence.snp.cert_chain` (PEM list) — the empty-cert_chain gap.
    pub cert_chain_pem: Vec<String>,
    pub snp: SnpReport,
    /// `evidence.quote_report_data` (base64, 64 bytes) — equals `snp.report_data`.
    pub quote_report_data: Option<[u8; 64]>,
}

fn bytes_field<const N: usize>(
    raw: &serde_json::Value,
    field: &'static str,
) -> Result<[u8; N], ParseError> {
    let arr = raw
        .get(field)
        .and_then(|v| v.as_array())
        .ok_or(ParseError::Missing(field))?;
    let mut out = [0u8; N];
    if arr.len() != N {
        return Err(ParseError::Field {
            field,
            why: format!("expected {N} bytes, got {}", arr.len()),
        });
    }
    for (i, v) in arr.iter().enumerate() {
        out[i] = v.as_u64().and_then(|n| u8::try_from(n).ok()).ok_or(
            ParseError::Field {
                field,
                why: format!("entry {i} is not a byte"),
            },
        )?;
    }
    Ok(out)
}

fn tcb(raw: &serde_json::Value, field: &'static str) -> Result<Tcb, ParseError> {
    let obj = raw
        .get(field)
        .and_then(|v| v.as_object())
        .ok_or(ParseError::Missing(field))?;
    let get = |k: &str| -> Option<u8> { obj.get(k).and_then(|v| v.as_u64()).and_then(|n| u8::try_from(n).ok()) };
    let tee = get("tee").ok_or(ParseError::Missing("tee"))?;
    let snp = get("snp").ok_or(ParseError::Missing("snp"))?;
    Ok(Tcb {
        fmc: get("fmc"),
        bootloader: get("bootloader"),
        tee,
        snp,
        microcode: get("microcode"),
    })
}

fn version3(raw: &serde_json::Value, field: &'static str) -> Result<Version3, ParseError> {
    let obj = raw
        .get(field)
        .and_then(|v| v.as_object())
        .ok_or(ParseError::Missing(field))?;
    let get = |k: &str| -> Result<u8, ParseError> {
        obj.get(k)
            .and_then(|v| v.as_u64())
            .and_then(|n| u8::try_from(n).ok())
            .ok_or(ParseError::Missing("version field"))
    };
    Ok(Version3 {
        major: get("major")?,
        minor: get("minor")?,
        build: get("build")?,
    })
}

fn etcb16(raw: &serde_json::Value, field: &'static str) -> Option<[u8; 16]> {
    // Extended TCB (Venice/V6) is a 16-byte array when present; absent on V5.
    let arr = raw.get(field)?.as_array()?;
    if arr.len() != 16 {
        return None;
    }
    let mut out = [0u8; 16];
    for (i, v) in arr.iter().enumerate() {
        out[i] = v.as_u64()?.try_into().ok()?;
    }
    Some(out)
}

fn parse_keyset(node: &serde_json::Value, field: &'static str) -> Result<Vec<KeysetEntry>, ParseError> {
    let arr = node.get(field).and_then(|v| v.as_array()).ok_or(ParseError::Missing(field))?;
    let mut out = Vec::with_capacity(arr.len());
    for e in arr {
        let obj = e.as_object().ok_or(ParseError::Field {
            field,
            why: "keyset entry is not an object".to_string(),
        })?;
        out.push(KeysetEntry {
            domain: obj
                .get("domain")
                .and_then(|v| v.as_str())
                .ok_or(ParseError::Missing("domain"))?
                .to_string(),
            spki_sha256: obj
                .get("spki_sha256")
                .and_then(|v| v.as_str())
                .ok_or(ParseError::Missing("spki_sha256"))?
                .to_string(),
        });
    }
    Ok(out)
}

pub fn parse_envelope(doc: &str) -> Result<Envelope, ParseError> {
    let v: serde_json::Value = serde_json::from_str(doc)?;

    let snp_node = v
        .get("evidence")
        .and_then(|e| e.get("snp"))
        .ok_or(ParseError::Missing("evidence.snp"))?;
    let report = snp_node
        .get("attestation_report")
        .ok_or(ParseError::Missing("evidence.snp.attestation_report"))?;

    let snp = SnpReport {
        version: report.get("version").and_then(|x| x.as_u64()).ok_or(ParseError::Missing("version"))? as u32,
        guest_svn: report.get("guest_svn").and_then(|x| x.as_u64()).ok_or(ParseError::Missing("guest_svn"))? as u32,
        policy: report.get("policy").and_then(|x| x.as_u64()).ok_or(ParseError::Missing("policy"))?,
        family_id: bytes_field(report, "family_id")?,
        image_id: bytes_field(report, "image_id")?,
        vmpl: report.get("vmpl").and_then(|x| x.as_u64()).ok_or(ParseError::Missing("vmpl"))? as u32,
        sig_algo: report.get("sig_algo").and_then(|x| x.as_u64()).ok_or(ParseError::Missing("sig_algo"))? as u32,
        current_tcb: tcb(report, "current_tcb")?,
        plat_info: report.get("plat_info").and_then(|x| x.as_u64()).ok_or(ParseError::Missing("plat_info"))?,
        key_info: report.get("key_info").and_then(|x| x.as_u64()).ok_or(ParseError::Missing("key_info"))? as u32,
        report_data: bytes_field(report, "report_data")?,
        measurement: bytes_field(report, "measurement")?,
        host_data: bytes_field(report, "host_data")?,
        id_key_digest: bytes_field(report, "id_key_digest")?,
        author_key_digest: bytes_field(report, "author_key_digest")?,
        report_id: bytes_field(report, "report_id")?,
        report_id_ma: bytes_field(report, "report_id_ma")?,
        reported_tcb: tcb(report, "reported_tcb")?,
        cpuid_fam_id: report.get("cpuid_fam_id").and_then(|x| x.as_u64()).map(|n| n as u8),
        cpuid_mod_id: report.get("cpuid_mod_id").and_then(|x| x.as_u64()).map(|n| n as u8),
        cpuid_step: report.get("cpuid_step").and_then(|x| x.as_u64()).map(|n| n as u8),
        chip_id: bytes_field(report, "chip_id")?,
        committed_tcb: tcb(report, "committed_tcb")?,
        current: version3(report, "current")?,
        committed: version3(report, "committed")?,
        launch_tcb: tcb(report, "launch_tcb")?,
        launch_mit_vector: report.get("launch_mit_vector").and_then(|x| x.as_u64()),
        current_mit_vector: report.get("current_mit_vector").and_then(|x| x.as_u64()),
        current_etcb: etcb16(report, "current_etcb"),
        launch_etcb: etcb16(report, "launch_etcb"),
        committed_etcb: etcb16(report, "committed_etcb"),
        signature_r: {
            let sig = report.get("signature").ok_or(ParseError::Missing("signature"))?;
            bytes_field(sig, "r")?
        },
        signature_s: {
            let sig = report.get("signature").ok_or(ParseError::Missing("signature"))?;
            bytes_field(sig, "s")?
        },
    };

    let keyset_node = v.get("keyset").ok_or(ParseError::Missing("keyset"))?;
    let keyset = Keyset {
        subject: keyset_node
            .get("subject")
            .and_then(|x| x.as_str())
            .ok_or(ParseError::Missing("keyset.subject"))?
            .to_string(),
        not_after: keyset_node
            .get("not_after")
            .and_then(|x| x.as_str())
            .ok_or(ParseError::Missing("keyset.not_after"))?
            .to_string(),
        tls_public_keys: parse_keyset(keyset_node, "tls_public_keys")?,
        signing_keys: keyset_node
            .get("signing_keys")
            .map(|n| n)
            .filter(|n| n.is_array())
            .map(|_| parse_keyset(keyset_node, "signing_keys"))
            .transpose()?
            .unwrap_or_default(),
        e2ee_keys: keyset_node
            .get("e2ee_keys")
            .map(|n| n)
            .filter(|n| n.is_array())
            .map(|_| parse_keyset(keyset_node, "e2ee_keys"))
            .transpose()?
            .unwrap_or_default(),
        raw: keyset_node.clone(),
    };

    let bindings_node = v.get("bindings").ok_or(ParseError::Missing("bindings"))?;
    let bindings = Bindings {
        version: bindings_node
            .get("version")
            .and_then(|x| x.as_str())
            .ok_or(ParseError::Missing("bindings.version"))?
            .to_string(),
        report_data_statement: bindings_node
            .get("report_data_statement")
            .and_then(|x| x.as_str())
            .ok_or(ParseError::Missing("bindings.report_data_statement"))?
            .to_string(),
        keyset_digest: bindings_node
            .get("keyset_digest")
            .and_then(|x| x.as_str())
            .ok_or(ParseError::Missing("bindings.keyset_digest"))?
            .to_string(),
    };

    let tls_possession = v.get("tls_possession").and_then(|tp| {
        Some(TlsPossession {
            tls_signature: tp.get("tls_signature")?.as_str()?.to_string(),
            tls_signature_alg: tp.get("tls_signature_alg")?.as_str()?.to_string(),
            tls_signature_input: tp.get("tls_signature_input")?.as_str()?.to_string(),
            tls_cert_sha256: tp.get("tls_cert_sha256").and_then(|x| x.as_str()).map(str::to_string),
        })
    });

    let cert_chain_pem: Vec<String> = snp_node
        .get("cert_chain")
        .and_then(|c| c.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|x| x.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default();

    let quote_report_data = v
        .get("evidence")
        .and_then(|e| e.get("quote_report_data"))
        .and_then(|q| q.as_str())
        .map(|b64| {
            let bytes = URL_SAFE_NO_PAD
                .decode(b64)
                .ok()
                .filter(|b| b.len() == 64)?;
            let mut out = [0u8; 64];
            out.copy_from_slice(&bytes);
            Some(out)
        })
        .flatten();

    Ok(Envelope {
        nonce: v.get("nonce").and_then(|x| x.as_str()).unwrap_or("").to_string(),
        report_data_input: v
            .get("report_data_input")
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .to_string(),
        tee: v.get("tee").and_then(|x| x.as_str()).unwrap_or("").to_string(),
        runtime_class: v.get("runtime_class").and_then(|x| x.as_str()).unwrap_or("").to_string(),
        pod: v.get("pod").and_then(|x| x.as_str()).unwrap_or("").to_string(),
        keyset,
        bindings,
        tls_possession,
        cert_chain_pem,
        snp,
        quote_report_data,
    })
}
