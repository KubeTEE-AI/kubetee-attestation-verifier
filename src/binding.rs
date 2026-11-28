//! `kubetee.attestation.v2` request binding + key-possession proof.
//!
//! v2 is the ONLY accepted binding version (legacy v1 is retired and hard
//! rejected fail-closed). The quote binds a **per-boot in-guest generated**
//! evidence key; the possession proof signs the quote-bound `report_data`
//! under that key (zero-operator trust).

use crate::envelope::{Bindings, Envelope, Keyset, jcs, sha256_hex};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use sha2::{Digest, Sha384};

#[derive(Debug, thiserror::Error)]
pub enum BindingError {
    #[error("binding mismatch: {0}")]
    Mismatch(String),
    #[error("unsupported binding version: {0}")]
    BadVersion(String),
    #[error("TLS possession proof failed: {0}")]
    TlsPossession(String),
    #[error("key possession proof failed: {0}")]
    KeyPossession(String),
}

/// Phase 6 (zero-operator-trust) binding version: the quote binds a
/// **per-boot in-guest generated evidence key** (`REPORTDATA = H(pubkey ‖
/// nonce ‖ context)`, `ReportDataForKeyWithContext`-style domain-separated
/// transcript). The KBS-released identity key is retired from the serving
/// path.
pub const PURPOSE_V2: &str = "kubetee.attestation.v2";

/// Domain-separation tag for the v2 report-data derivation. Changing this
/// string is a contract change (it is inside the frozen test vector).
pub const KEY_ATTESTATION_TAG: &[u8] = b"kubetee.attestation.v2/ReportDataForKeyWithContext";

/// Normalize + validate the caller nonce: 64 lowercase hex chars. ASCII-only
/// (rejects control chars / Unicode whitespace that `trim()` alone would let
/// through — zero-length-input bypass class, CVE-2026-92702).
pub fn normalize_nonce(nonce: &str) -> Result<String, BindingError> {
    if !nonce.is_ascii() {
        return Err(BindingError::Mismatch(
            "nonce must be ASCII hex".to_string(),
        ));
    }
    let n = nonce.trim().to_lowercase();
    if n.len() != 64 || !n.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(BindingError::Mismatch(format!(
            "nonce must be 64 hex chars, got {:?}",
            nonce
        )));
    }
    Ok(n)
}

/// `keyset_digest` = `sha256:<hex>` over `jcs(keyset)`.
pub fn keyset_digest(keyset: &Keyset) -> String {
    format!("sha256:{}", sha256_hex(jcs(&keyset.raw).as_bytes()))
}

/// The `key_possession.input` the v2 proof must name.
pub const POSSESSION_INPUT: &str = "quote_report_data";
/// The `key_possession.alg` the v2 proof must name (ECDSA P-256 / SHA-256).
pub const POSSESSION_ALG: &str = "ecdsa-secp256r1-sha256";

/// Length-framed concatenation (`u64-be length ‖ bytes`) — the
/// `ReportDataForKeyWithContext` transcript pattern. Framing prevents any two
/// distinct `(pkix, nonce, context)` tuples from sharing a preimage.
fn framed(parts: &[&[u8]]) -> Vec<u8> {
    let mut out = Vec::new();
    for p in parts {
        out.extend_from_slice(&(p.len() as u64).to_be_bytes());
        out.extend_from_slice(p);
    }
    out
}

/// The exact byte string the v2 report-data hash consumes:
/// `SHA-384(tag ‖ framed(pkix_pubkey) ‖ framed(nonce) ‖ framed(context))` —
/// the tag is raw (domain separation), the three inputs are length-framed.
/// Inputs are DER PKIX SPKI bytes (`pkix_pubkey`), the caller nonce (raw 32
/// bytes), and a UTF-8 domain-separation `context`.
pub fn report_data_preimage_v2(
    pkix_pubkey: &[u8],
    nonce: &[u8],
    context: &str,
) -> Result<Vec<u8>, BindingError> {
    if pkix_pubkey.is_empty() {
        return Err(BindingError::Mismatch(
            "v2 pkix_pubkey must be non-empty".to_string(),
        ));
    }
    if nonce.is_empty() {
        return Err(BindingError::Mismatch(
            "v2 nonce must be non-empty".to_string(),
        ));
    }
    if context.is_empty() {
        return Err(BindingError::Mismatch(
            "v2 context must be non-empty (no uncontextualized key binding)".to_string(),
        ));
    }
    let mut out = Vec::new();
    out.extend_from_slice(KEY_ATTESTATION_TAG);
    out.extend_from_slice(&framed(&[pkix_pubkey, nonce, context.as_bytes()]));
    Ok(out)
}

/// v2 `report_data` = `SHA-384(preimage) ‖ 16 zero bytes` (64 bytes total —
/// the SNP report-data field size). The zero suffix keeps the field layout
/// while reserving it against cross-purpose collisions.
pub fn report_data_v2(
    pkix_pubkey: &[u8],
    nonce: &[u8],
    context: &str,
) -> Result<[u8; 64], BindingError> {
    let preimage = report_data_preimage_v2(pkix_pubkey, nonce, context)?;
    let mut hasher = Sha384::new();
    hasher.update(&preimage);
    let digest = hasher.finalize();
    let mut out = [0u8; 64];
    out[..48].copy_from_slice(&digest);
    Ok(out)
}

/// The JCS statement the envelope serves (and the backend signs) for v2:
/// `{"context":..,"keyset_digest":..,"nonce":..,"pkix_pubkey_b64url":..,
/// "purpose":"kubetee.attestation.v2"}`. `report_data_v2_statement` derives
/// the served `report_data_statement`; verification recomputes both.
pub fn report_data_statement_v2(
    keyset_digest: &str,
    nonce: &str,
    pkix_pubkey_b64url: &str,
    context: &str,
) -> Result<String, BindingError> {
    if !keyset_digest.starts_with("sha256:")
        || keyset_digest.len() != 7 + 64
        || !keyset_digest[7..].chars().all(|c| c.is_ascii_hexdigit())
    {
        return Err(BindingError::Mismatch(format!(
            "malformed keyset_digest: {keyset_digest:?}"
        )));
    }
    let nonce = normalize_nonce(nonce)?;
    if pkix_pubkey_b64url.is_empty() {
        return Err(BindingError::Mismatch(
            "v2 pkix_pubkey_b64url must be non-empty".to_string(),
        ));
    }
    if context.is_empty() {
        return Err(BindingError::Mismatch(
            "v2 context must be non-empty".to_string(),
        ));
    }
    // JCS (sorted keys): context < keyset_digest < nonce < pkix_pubkey_b64url < purpose.
    let v = serde_json::json!({
        "context": context,
        "keyset_digest": keyset_digest,
        "nonce": nonce,
        "pkix_pubkey_b64url": pkix_pubkey_b64url,
        "purpose": PURPOSE_V2,
    });
    Ok(jcs(&v))
}

/// Decode the served `pkix_pubkey_b64url` (URL-safe, no pad — standard pad
/// accepted). Fails closed on empty / bad base64.
pub fn decode_pkix_pubkey(pkix_pubkey_b64url: &str) -> Result<Vec<u8>, BindingError> {
    if pkix_pubkey_b64url.is_empty() {
        return Err(BindingError::Mismatch(
            "v2 pkix_pubkey_b64url is empty".to_string(),
        ));
    }
    let mut s = pkix_pubkey_b64url.trim().to_string();
    while !s.len().is_multiple_of(4) {
        s.push('=');
    }
    URL_SAFE_NO_PAD
        .decode(s.trim_end_matches('='))
        .or_else(|_| base64::engine::general_purpose::STANDARD.decode(&s))
        .map_err(|e| BindingError::Mismatch(format!("v2 pkix_pubkey_b64url: {e}")))
}

/// Verify the envelope's binding chain end-to-end and fail closed on any
/// mismatch. **Only `kubetee.attestation.v2` is accepted** — the legacy v1
/// binding (`sha256(statement)||32-zero-bytes`) and the pre-v1 `sha512(nonce)`
/// forms are hard retired and rejected here fail-closed (no fallback flag).
///
///   1. `bindings.version` == `kubetee.attestation.v2` (nothing else).
///   2. `bindings.keyset_digest` == `sha256(jcs(keyset))` (the served keyset).
///   3. `bindings.report_data_statement` == the recomputed v2 statement.
///   4. `snp.report_data` == the derived v2 report data.
///   5. `evidence.quote_report_data` — when present it MUST equal
///      `snp.report_data` (absent skips; a zero-length value FAILS CLOSED —
///      never silently falls back, CVE-2026-92702 class).
pub fn verify_binding(env: &Envelope) -> Result<String, BindingError> {
    let Bindings {
        version,
        report_data_statement: served_statement,
        keyset_digest: served_digest,
    } = &env.bindings;

    if version != PURPOSE_V2 {
        return Err(BindingError::BadVersion(format!(
            "only {PURPOSE_V2} is accepted (legacy v1 is retired); got {version:?}"
        )));
    }

    if served_digest.is_empty() || served_statement.is_empty() {
        return Err(BindingError::Mismatch(
            "expectation-absent: keyset_digest/report_data_statement empty".to_string(),
        ));
    }

    verify_binding_v2_inner(env, served_statement, served_digest)
}

/// v2 chain: the served statement's `pkix_pubkey_b64url` + `context` must
/// reproduce `snp.report_data` via `report_data_v2`, and the served statement
/// must be the JCS form of exactly those values (anti-downgrade: the fields in
/// the statement are re-verified against the derivation, not trusted).
fn verify_binding_v2_inner(
    env: &Envelope,
    served_statement: &str,
    served_digest: &str,
) -> Result<String, BindingError> {
    let computed_digest = keyset_digest(&env.keyset);
    if computed_digest != *served_digest {
        return Err(BindingError::Mismatch(format!(
            "keyset_digest: computed {computed_digest}, served {served_digest}"
        )));
    }

    // Parse the served statement (JCS JSON) and re-derive it.
    let v: serde_json::Value = serde_json::from_str(served_statement)
        .map_err(|e| BindingError::Mismatch(format!("v2 statement is not JSON: {e}")))?;
    let pkix_b64 = v
        .get("pkix_pubkey_b64url")
        .and_then(|x| x.as_str())
        .ok_or_else(|| {
            BindingError::Mismatch("v2 statement missing pkix_pubkey_b64url".to_string())
        })?;
    let context = v
        .get("context")
        .and_then(|x| x.as_str())
        .ok_or_else(|| BindingError::Mismatch("v2 statement missing context".to_string()))?;
    let stmt_nonce = v
        .get("nonce")
        .and_then(|x| x.as_str())
        .ok_or_else(|| BindingError::Mismatch("v2 statement missing nonce".to_string()))?;
    if normalize_nonce(stmt_nonce)? != normalize_nonce(&env.nonce)? {
        return Err(BindingError::Mismatch(
            "v2 statement nonce != envelope nonce".to_string(),
        ));
    }

    let computed_statement =
        report_data_statement_v2(served_digest, &env.nonce, pkix_b64, context)?;
    if computed_statement != *served_statement {
        return Err(BindingError::Mismatch(format!(
            "v2 report_data_statement mismatch:\n  computed {computed_statement}\n  served   {served_statement}"
        )));
    }

    let pkix = decode_pkix_pubkey(pkix_b64)?;
    let nonce = normalize_nonce(&env.nonce)?;
    let expected_rd = report_data_v2(&pkix, &bytes_from_hex32(&nonce)?, context)?;
    if expected_rd != env.snp.report_data {
        return Err(BindingError::Mismatch(
            "v2 report_data != SHA-384(tag||framed(pkix)||framed(nonce)||framed(context))||16-zeros"
                .to_string(),
        ));
    }

    cross_check_quote_report_data(env)?;

    Ok(computed_digest)
}

/// `evidence.quote_report_data` cross-check (fail closed): present-and-empty
/// FAILS; present-and-non-empty MUST equal `snp.report_data`; absent is a
/// skip (the field is optional on older captures).
fn cross_check_quote_report_data(env: &Envelope) -> Result<(), BindingError> {
    let Some(qrd) = env.quote_report_data.as_ref() else {
        return Ok(());
    };
    if qrd.iter().all(|b| *b == 0) {
        return Err(BindingError::Mismatch(
            "quote_report_data is zero-length/blank (fail-closed: never skip the check)"
                .to_string(),
        ));
    }
    if qrd != &env.snp.report_data {
        return Err(BindingError::Mismatch(
            "quote_report_data != snp.report_data (evidence inconsistent)".to_string(),
        ));
    }
    Ok(())
}

fn bytes_from_hex32(hex_str: &str) -> Result<Vec<u8>, BindingError> {
    if hex_str.len() != 64 || !hex_str.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(BindingError::Mismatch("nonce hex length".to_string()));
    }
    (0..32)
        .map(|i| {
            u8::from_str_radix(&hex_str[i * 2..i * 2 + 2], 16)
                .map_err(|e| BindingError::Mismatch(format!("nonce hex: {e}")))
        })
        .collect()
}

/// SPKI SHA-256 (hex) of an X.509 certificate's SubjectPublicKeyInfo.
pub fn spki_sha256(cert: &x509_cert::Certificate) -> Result<String, BindingError> {
    use x509_cert::der::Encode;
    let spki = cert
        .tbs_certificate()
        .subject_public_key_info()
        .to_der()
        .map_err(|e| BindingError::TlsPossession(format!("SPKI DER: {e}")))?;
    Ok(sha256_hex(&spki))
}

/// The SPKI-pin check for the v2 (key-possession) path: the served keyset
/// must name THIS TLS leaf's SPKI. The leaf binds the transport that carried
/// the evidence.
///
/// - `spki_sha256` of the leaf must equal the served
///   `tls_public_keys[].spki_sha256` for `tls_domain`.
pub fn verify_spki_pin(
    env: &Envelope,
    tls_domain: &str,
    leaf: &x509_cert::Certificate,
) -> Result<(), BindingError> {
    let spki_sha = spki_sha256(leaf)?;
    let expected = env
        .keyset
        .tls_public_keys
        .iter()
        .find(|k| k.domain == tls_domain)
        .map(|k| k.spki_sha256.trim_start_matches("sha256:").to_lowercase())
        .ok_or_else(|| {
            BindingError::TlsPossession(format!("keyset names no tls key for domain {tls_domain}"))
        })?;
    if spki_sha != expected {
        return Err(BindingError::TlsPossession(format!(
            "TLS SPKI pin mismatch: leaf {spki_sha}, keyset {expected}"
        )));
    }
    Ok(())
}

/// Verify the v2 quote-bound key-possession proof (the zero-operator-trust
/// step): the `key_possession` ECDSA P-256/SHA-256 signature over the quote-
/// bound 64-byte `report_data` must verify under the **per-boot in-guest
/// generated** key the v2 statement commits (`pkix_pubkey_b64url`) — never
/// under the operator-custodied TLS leaf. This proves the guest holds the
/// fresh per-boot key the hardware quote bound.
///
/// Fail-closed: a missing proof, a mislabelled `input`/`alg`, a bad encoding,
/// or a signature under any other key is an error.
pub fn verify_key_possession(env: &Envelope) -> Result<(), BindingError> {
    let kp = env
        .key_possession
        .as_ref()
        .ok_or_else(|| BindingError::KeyPossession("envelope has no key_possession".to_string()))?;
    if kp.input != POSSESSION_INPUT {
        return Err(BindingError::KeyPossession(format!(
            "key_possession input is {}, expected {POSSESSION_INPUT}",
            kp.input
        )));
    }
    if kp.alg != POSSESSION_ALG {
        return Err(BindingError::KeyPossession(format!(
            "key_possession alg is {}, expected {POSSESSION_ALG}",
            kp.alg
        )));
    }

    // The bound key: the per-boot key the v2 statement commits.
    let served = &env.bindings.report_data_statement;
    let v: serde_json::Value = serde_json::from_str(served)
        .map_err(|e| BindingError::KeyPossession(format!("v2 statement is not JSON: {e}")))?;
    let pkix_b64 = v
        .get("pkix_pubkey_b64url")
        .and_then(|x| x.as_str())
        .ok_or_else(|| {
            BindingError::KeyPossession("v2 statement missing pkix_pubkey_b64url".to_string())
        })?;
    let pkix = decode_pkix_pubkey(pkix_b64)?;

    let sig = URL_SAFE_NO_PAD
        .decode(kp.signature_b64.as_str())
        .or_else(|_| base64::engine::general_purpose::STANDARD.decode(kp.signature_b64.as_str()))
        .map_err(|e| BindingError::KeyPossession(format!("bad key_possession signature: {e}")))?;

    use p256::ecdsa::VerifyingKey;
    use p256::ecdsa::signature::Verifier as _;
    use spki::DecodePublicKey as _;
    let vk = VerifyingKey::from_public_key_der(&pkix)
        .map_err(|e| BindingError::KeyPossession(format!("v2 bound key (SPKI): {e}")))?;
    let signature = parse_p256_signature(&sig)?;
    vk.verify(&env.snp.report_data, &signature)
        .map_err(|_| BindingError::KeyPossession("signature does not verify".to_string()))
}

/// Parse an ECDSA P-256 signature: DER (ASN.1) first — the canonical wire
/// encoding the generator (cryptography / ring ECDSA) produces — then the
/// fixed raw `r||s` form (parity with gm-miner).
fn parse_p256_signature(sig: &[u8]) -> Result<p256::ecdsa::Signature, BindingError> {
    use p256::ecdsa::Signature;
    if let Ok(s) = Signature::from_der(sig) {
        return Ok(s);
    }
    if sig.len() == 64 {
        let mut r = [0u8; 32];
        r.copy_from_slice(&sig[..32]);
        let mut s = [0u8; 32];
        s.copy_from_slice(&sig[32..]);
        if let Ok(s) = Signature::from_scalars(r, s) {
            return Ok(s);
        }
    }
    Err(BindingError::KeyPossession(
        "bad ECDSA signature encoding".to_string(),
    ))
}
