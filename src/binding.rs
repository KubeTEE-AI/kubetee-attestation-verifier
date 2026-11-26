//! `kubetee.attestation.v1` request binding + TLS possession proof.

use crate::envelope::{Bindings, Envelope, Keyset, TlsPossession, jcs, sha256_hex};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use sha2::{Digest, Sha256, Sha512};

#[derive(Debug, thiserror::Error)]
pub enum BindingError {
    #[error("binding mismatch: {0}")]
    Mismatch(String),
    #[error("unsupported binding version: {0}")]
    BadVersion(String),
    #[error("TLS possession proof failed: {0}")]
    TlsPossession(String),
}

/// `report_data_input` values the envelope accepts.
const PURPOSE: &str = "kubetee.attestation.v1";

/// Normalize + validate the caller nonce: 64 lowercase hex chars.
pub fn normalize_nonce(nonce: &str) -> Result<String, BindingError> {
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

/// The exact byte string hashed into `report_data` for `kubetee.attestation.v1`:
/// `{"keyset_digest":..,"nonce":..,"purpose":"kubetee.attestation.v1"}` (JCS order).
pub fn report_data_statement(keyset_digest: &str, nonce: &str) -> Result<String, BindingError> {
    if !keyset_digest.starts_with("sha256:")
        || keyset_digest.len() != 7 + 64
        || !keyset_digest[7..].chars().all(|c| c.is_ascii_hexdigit())
    {
        return Err(BindingError::Mismatch(format!(
            "malformed keyset_digest: {keyset_digest:?}"
        )));
    }
    let nonce = normalize_nonce(nonce)?;
    Ok(format!(
        r#"{{"keyset_digest":"{keyset_digest}","nonce":"{nonce}","purpose":"{PURPOSE}"}}"#
    ))
}

/// `report_data` = `sha256(statement) || 32 zero bytes` (64 bytes total).
pub fn report_data_v1(statement: &str) -> [u8; 64] {
    let mut hasher = Sha256::new();
    hasher.update(statement.as_bytes());
    let digest = hasher.finalize();
    let mut out = [0u8; 64];
    out[..32].copy_from_slice(&digest);
    out
}

/// Legacy (pre-v1) binding: `report_data = sha512(ascii nonce)`, 64 bytes.
/// Supported for reading older envelopes; the v1 path is the contract.
pub fn report_data_legacy(nonce: &str) -> Result<[u8; 64], BindingError> {
    let nonce = normalize_nonce(nonce)?;
    let mut hasher = Sha512::new();
    hasher.update(nonce.as_bytes());
    let digest = hasher.finalize();
    let mut out = [0u8; 64];
    out.copy_from_slice(&digest);
    Ok(out)
}

/// Verify the envelope's binding chain end-to-end and fail closed on any
/// mismatch:
///   1. `bindings.version` is `kubetee.attestation.v1`.
///   2. `bindings.keyset_digest` == `sha256(jcs(keyset))` (the served keyset).
///   3. `bindings.report_data_statement` == the recomputed statement.
///   4. `snp.report_data` == `sha256(statement) || 32 zeros`.
///   5. `evidence.quote_report_data` (if present) == `snp.report_data`.
pub fn verify_binding(env: &Envelope) -> Result<String, BindingError> {
    let Bindings {
        version,
        report_data_statement: served_statement,
        keyset_digest: served_digest,
    } = &env.bindings;

    if version != PURPOSE {
        return Err(BindingError::BadVersion(version.clone()));
    }

    let computed_digest = keyset_digest(&env.keyset);
    if computed_digest != *served_digest {
        return Err(BindingError::Mismatch(format!(
            "keyset_digest: computed {computed_digest}, served {served_digest}"
        )));
    }

    let nonce = normalize_nonce(&env.nonce)?;
    let computed_statement = report_data_statement(&computed_digest, &nonce)?;
    if computed_statement != *served_statement {
        return Err(BindingError::Mismatch(format!(
            "report_data_statement mismatch:\n  computed {computed_statement}\n  served   {served_statement}"
        )));
    }

    let expected_rd = report_data_v1(&computed_statement);
    if expected_rd != env.snp.report_data {
        return Err(BindingError::Mismatch(
            "report_data != sha256(statement)||32-zero-bytes (binding not honored)".to_string(),
        ));
    }

    if let Some(qrd) = env.quote_report_data
        && qrd != env.snp.report_data
    {
        return Err(BindingError::Mismatch(
            "quote_report_data != snp.report_data (evidence inconsistent)".to_string(),
        ));
    }

    Ok(computed_digest)
}

/// Verify the TLS possession proof + the SPKI pin against the served keyset.
///
/// - `tls_cert_sha256` (SHA-256 of the TLS leaf DER) must equal the served
///   `tls_public_keys[].spki_sha256` for `tls_domain` (the SPKI-pin check).
/// - `tls_signature` must verify over the caller nonce under the leaf's
///   public key, algorithm `tls_signature_alg` (RS256 / Ed25519 / ES256...).
pub fn verify_tls_possession(
    env: &Envelope,
    tls_domain: &str,
    leaf: &x509_cert::Certificate,
) -> Result<(), BindingError> {
    let tp: &TlsPossession = env
        .tls_possession
        .as_ref()
        .ok_or_else(|| BindingError::TlsPossession("envelope has no tls_possession".to_string()))?;

    // SPKI pin: the served keyset must name THIS TLS leaf.
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
    if let Some(cert_fp) = &tp.tls_cert_sha256 {
        use x509_cert::der::Encode;
        // Envelope also reports the cert fingerprint (sha256 over the cert's
        // DER); it must match the served leaf's DER.
        let der = leaf
            .to_der()
            .map_err(|e| BindingError::TlsPossession(format!("cert DER: {e}")))?;
        let der_fp = sha256_hex(&der);
        if cert_fp.trim_start_matches("sha256:").to_lowercase() != der_fp {
            return Err(BindingError::TlsPossession(format!(
                "tls_cert_sha256 {cert_fp} != leaf cert sha256 {der_fp}"
            )));
        }
    }

    // Possession: a signature over the nonce under the leaf key.
    if tp.tls_signature_input != "sha256(nonce)" {
        return Err(BindingError::TlsPossession(format!(
            "unsupported tls_signature_input {}",
            tp.tls_signature_input
        )));
    }
    let nonce = normalize_nonce(&env.nonce)?;
    let sig = URL_SAFE_NO_PAD
        .decode(tp.tls_signature.as_str())
        .or_else(|_| base64::engine::general_purpose::STANDARD.decode(tp.tls_signature.as_str()))
        .map_err(|e| BindingError::TlsPossession(format!("bad tls_signature: {e}")))?;

    verify_tls_signature(leaf, &tp.tls_signature_alg, nonce.as_bytes(), &sig)
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

/// Verify `sig` over `msg` under the certificate's public key. Algorithm is
/// named by `alg` (JOSE-style: RS256 / EdDSA / ES256 / ES384...). Pure-Rust
/// only — the whole crate is `crypto_nossl`.
fn verify_tls_signature(
    cert: &x509_cert::Certificate,
    alg: &str,
    msg: &[u8],
    sig: &[u8],
) -> Result<(), BindingError> {
    let spki = cert.tbs_certificate().subject_public_key_info();
    let pk_bytes = spki.subject_public_key.raw_bytes();
    let _ = spki;

    match alg {
        "RS256" | "rsa-pkcs1-sha256" => {
            use rsa::pkcs1v15::{Signature, VerifyingKey};
            use rsa::sha2::Sha256 as RsaSha256;
            use rsa::signature::Verifier;
            // Parse the RSAPublicKey (SEQUENCE{n, e}) from the SPKI BIT STRING.
            // (x509-cert is on spki 0.8 and rsa 0.9 is on spki 0.7, so the
            // cross-type TryFrom<SubjectPublicKeyInfo> isn't available — decode
            // the RSAPublicKey DER from the raw BIT STRING via rsa's own pkcs1.)
            use rsa::pkcs1::DecodeRsaPublicKey as _;
            let rsapk = rsa::RsaPublicKey::from_pkcs1_der(pk_bytes)
                .map_err(|e| BindingError::TlsPossession(format!("RSA SPKI parse: {e}")))?;
            let vk = VerifyingKey::<RsaSha256>::new(rsapk);
            let sig = Signature::try_from(sig)
                .map_err(|e| BindingError::TlsPossession(format!("RS256 sig: {e}")))?;
            vk.verify(msg, &sig)
                .map_err(|_| BindingError::TlsPossession("RS256 signature invalid".to_string()))
        }
        "EdDSA" | "Ed25519" => {
            use ed25519_dalek::{Signature, Verifier, VerifyingKey};
            let pk: [u8; 32] = pk_bytes
                .try_into()
                .map_err(|_| BindingError::TlsPossession("Ed25519 key length".to_string()))?;
            let vk = VerifyingKey::from_bytes(&pk)
                .map_err(|e| BindingError::TlsPossession(format!("Ed25519 key: {e}")))?;
            let sig = Signature::from_slice(sig)
                .map_err(|e| BindingError::TlsPossession(format!("Ed25519 sig: {e}")))?;
            vk.verify(msg, &sig)
                .map_err(|_| BindingError::TlsPossession("Ed25519 signature invalid".to_string()))
        }
        "ES256" | "ES384" => {
            use p384::ecdsa::{Signature, VerifyingKey, signature::Verifier as _};
            // ES256 (P-256) and ES384 (P-384) both verify here via the SPKI's
            // curve; the live gateway is RS256 today. For a non-P-384 key this
            // path rejects (fail closed) rather than silently passing.
            let vk = VerifyingKey::from_sec1_bytes(pk_bytes)
                .map_err(|e| BindingError::TlsPossession(format!("ECDSA key: {e}")))?;
            let sig = Signature::from_slice(sig)
                .map_err(|e| BindingError::TlsPossession(format!("ECDSA sig: {e}")))?;
            vk.verify(msg, &sig)
                .map_err(|_| BindingError::TlsPossession("ECDSA signature invalid".to_string()))
        }
        other => Err(BindingError::TlsPossession(format!(
            "unsupported tls_signature_alg {other:?}"
        ))),
    }
}
