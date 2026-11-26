//! AMD Key Distribution Service (KDS) client — fetches the VCEK, ARK, ASK
//! for a chip_id + reported TCB. Pure `reqwest` blocking + rustls (no OpenSSL).

use crate::envelope::Tcb;
use crate::snp::{kds_cert_chain_url, kds_product, kds_vcek_url};

#[derive(Debug, thiserror::Error)]
pub enum KdsError {
    #[error("KDS request failed: {0}")]
    Http(String),
    #[error("KDS returned non-200 {status} for {url}")]
    Status { status: u16, url: String },
}

pub struct KdsCerts {
    /// ARK PEM (from `cert_chain` — AMD serves [ASK, ARK]).
    pub ark_pem: String,
    pub ask_pem: String,
    /// VCEK PEM (from the chip_id + TCB query).
    pub vcek_pem: String,
    pub product: String,
}

/// Fetch the ARK+ASK bundle and the VCEK for a report's chip_id + reported TCB.
/// `product` is one of Milan/Genoa/Turin/Venice (capitalized — AMD's KDS 404s
/// lowercase paths).
pub fn fetch_chain(
    product: &str,
    chip_id: &[u8; 64],
    reported_tcb: Tcb,
) -> Result<KdsCerts, KdsError> {
    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .map_err(|e| KdsError::Http(e.to_string()))?;

    let chain_url = kds_cert_chain_url(product);
    let chain_body = client
        .get(&chain_url)
        .send()
        .and_then(|r| r.error_for_status().map_err(|e| e))
        .map_err(|e| match e.status() {
            Some(s) => KdsError::Status {
                status: s.as_u16(),
                url: chain_url.clone(),
            },
            None => KdsError::Http(e.to_string()),
        })?
        .text()
        .map_err(|e| KdsError::Http(e.to_string()))?;

    let vcek_url = kds_vcek_url(product, chip_id, reported_tcb);
    let vcek_resp = client
        .get(&vcek_url)
        .send()
        .map_err(|e| KdsError::Http(e.to_string()))?;
    if !vcek_resp.status().is_success() {
        return Err(KdsError::Status {
            status: vcek_resp.status().as_u16(),
            url: vcek_url,
        });
    }
    // KDS serves the VCEK as DER; normalize to PEM for `sev::Certificate`.
    let vcek_bytes = vcek_resp.bytes().map_err(|e| KdsError::Http(e.to_string()))?;
    let vcek_pem = if vcek_bytes.starts_with(b"-----BEGIN") {
        String::from_utf8_lossy(&vcek_bytes).to_string()
    } else {
        der_to_pem(&vcek_bytes)
    };

    // `cert_chain` is [ASK, ARK] concatenated PEM; split on self-signed ARK.
    let (ask_pem, ark_pem) = split_ask_ark(&chain_body)
        .ok_or_else(|| KdsError::Http("could not split KDS cert_chain into ASK/ARK".to_string()))?;

    Ok(KdsCerts {
        ark_pem,
        ask_pem,
        vcek_pem,
        product: product.to_string(),
    })
}

/// Fetch by report CPUID family/model (the common case).
pub fn fetch_for_cpu(
    family: u8,
    model: u8,
    chip_id: &[u8; 64],
    reported_tcb: Tcb,
) -> Result<KdsCerts, KdsError> {
    let product = kds_product(family, model).map_err(|e| KdsError::Http(e.to_string()))?;
    fetch_chain(product, chip_id, reported_tcb)
}

fn split_ask_ark(pem_bundle: &str) -> Option<(String, String)> {
    let certs: Vec<&str> = pem_bundle
        .split("-----BEGIN CERTIFICATE-----")
        .skip(1)
        .map(|chunk| {
            chunk
                .split("-----END CERTIFICATE-----")
                .next()
                .unwrap_or("")
        })
        .collect();
    if certs.len() != 2 {
        return None;
    }
    let wrap = |body: &str| -> String {
        format!(
            "-----BEGIN CERTIFICATE-----{}-----END CERTIFICATE-----\n",
            body.trim()
        )
    };
    // ARK is the self-signed one (CN contains "ARK-"); identify by subject text
    // present in the PEM body's base64 is unreliable — prefer the well-known
    // order: AMD serves [ASK, ARK]. We verify the chain later anyway.
    let first = wrap(certs[0]);
    let second = wrap(certs[1]);
    let first_is_ark = pem_body_has_ark_marker(certs[0]);
    if first_is_ark {
        Some((second, first)) // (ask, ark)
    } else {
        Some((first, second))
    }
}

fn pem_body_has_ark_marker(_body: &str) -> bool {
    // PEM body is base64; the CN is not directly greppable. Default to AMD's
    // documented order [ASK, ARK] and let `sev`'s chain verify be the arbiter.
    false
}

fn der_to_pem(der: &[u8]) -> String {
    use base64::{engine::general_purpose::STANDARD, Engine};
    let b64 = STANDARD.encode(der);
    let mut out = String::from("-----BEGIN CERTIFICATE-----\n");
    for (i, c) in b64.chars().enumerate() {
        out.push(c);
        if (i + 1) % 64 == 0 {
            out.push('\n');
        }
    }
    if !out.ends_with('\n') {
        out.push('\n');
    }
    out.push_str("-----END CERTIFICATE-----\n");
    out
}
