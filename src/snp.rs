//! AMD SEV-SNP report + certificate-chain verification.
//!
//! Fail-closed. The report signature is checked over the exact 672-byte signed
//! body (`to_bytes()[..0x2a0]`) using the VCEK's P-384 key; the ARK→ASK→VCEK
//! chain is checked against AMD's KDS root of trust. We reuse `sev`'s
//! `crypto_nossl` verifier for the byte-exact reconstruction + ECDSA — the
//! crate is the reference implementation and doing this by hand is the known
//! footgun (`virtee/sev` maintainers flag `to_bytes` as tricky).

use crate::envelope::{self, SnpReport, Tcb};
use sev::certs::snp::{Certificate, Chain, Verifiable};
use sev::firmware::guest::{AttestationReport, Version};
use sev::firmware::host::TcbVersion;

#[derive(Debug, thiserror::Error)]
pub enum SnpError {
    #[error("unsupported report: {0}")]
    Unsupported(String),
    #[error("bad certificate: {0}")]
    Cert(String),
    #[error("report signature does NOT verify against the VCEK")]
    SignatureMismatch,
    #[error("certificate chain does NOT verify (ARK->ASK->VCEK)")]
    ChainInvalid,
    #[error("sev: {0}")]
    Sev(String),
}

fn to_tcb(t: Tcb) -> TcbVersion {
    TcbVersion::new(t.fmc, t.bootloader, t.tee, t.snp, t.microcode)
}

fn to_version(v: envelope::Version3) -> Version {
    Version::new(v.major, v.minor, v.build)
}

/// Rebuild the `sev` report struct from the parsed envelope fields.
///
/// The 3 ETCB fields are Venice/V6-only; `sev`'s encoder zero-fills them
/// unless `(V6, Venice)`. They are None on our Milan/Genoa/Turin V5 reports,
/// which is correct.
fn to_report(r: &SnpReport) -> Result<AttestationReport, SnpError> {
    if r.sig_algo != 1 {
        return Err(SnpError::Unsupported(format!(
            "sig_algo {} != 1 (only ECDSA P-384 / SHA-384 is supported)",
            r.sig_algo
        )));
    }
    let mut rep = AttestationReport::default();
    rep.version = r.version;
    rep.guest_svn = r.guest_svn;
    rep.policy = r.policy.into();
    rep.family_id = r.family_id;
    rep.image_id = r.image_id;
    rep.vmpl = r.vmpl;
    rep.sig_algo = r.sig_algo;
    rep.current_tcb = to_tcb(r.current_tcb);
    rep.plat_info = r.plat_info.into();
    rep.key_info = r.key_info.into();
    rep.report_data = r.report_data;
    rep.measurement = r.measurement;
    rep.host_data = r.host_data;
    rep.id_key_digest = r.id_key_digest;
    rep.author_key_digest = r.author_key_digest;
    rep.report_id = r.report_id;
    rep.report_id_ma = r.report_id_ma;
    rep.reported_tcb = to_tcb(r.reported_tcb);
    rep.cpuid_fam_id = r.cpuid_fam_id;
    rep.cpuid_mod_id = r.cpuid_mod_id;
    rep.cpuid_step = r.cpuid_step;
    rep.chip_id = r.chip_id;
    rep.committed_tcb = to_tcb(r.committed_tcb);
    rep.current = to_version(r.current);
    rep.committed = to_version(r.committed);
    rep.launch_tcb = to_tcb(r.launch_tcb);
    rep.launch_mit_vector = r.launch_mit_vector;
    rep.current_mit_vector = r.current_mit_vector;
    // ETCB (Venice/V6) — left None on V5 Milan/Genoa/Turin.
    rep.signature = sev::certs::snp::ecdsa::Signature::new(r.signature_r, r.signature_s);
    Ok(rep)
}

/// Build the ARK→ASK→VCEK chain from PEM. AMD's KDS serves `cert_chain` as
/// [ASK, ARK]; the `sev` `From<(Certificate, Certificate, Certificate)>`
/// takes **(ASK, ARK, VCEK)** in that order.
pub fn build_chain(ark_pem: &str, ask_pem: &str, vcek_pem: &str) -> Result<Chain, SnpError> {
    let ark = Certificate::from_pem(ark_pem.as_bytes())
        .map_err(|e| SnpError::Cert(format!("ARK: {e}")))?;
    let ask = Certificate::from_pem(ask_pem.as_bytes())
        .map_err(|e| SnpError::Cert(format!("ASK: {e}")))?;
    let vcek = Certificate::from_pem(vcek_pem.as_bytes())
        .map_err(|e| SnpError::Cert(format!("VCEK: {e}")))?;
    Ok((ask, ark, vcek).into())
}

/// Verify the AMD chain (ARK self-signed + ARK signs ASK + ASK signs VCEK).
pub fn verify_chain(chain: &Chain) -> Result<(), SnpError> {
    chain.verify().map_err(|_| SnpError::ChainInvalid)?;
    Ok(())
}

/// Verify the report signature against the VCEK in the chain.
///
/// `sev`'s `(&Chain, &AttestationReport).verify()` re-serializes the report
/// with `to_bytes()[..0x2a0]`, SHA-384s it, and checks the ECDSA P-384
/// signature. A mismatch means the report bytes are not the ones AMD signed —
/// tampered, or our reconstruction is wrong. Either way: fail closed.
pub fn verify_report_signature(
    chain: &Chain,
    report: &AttestationReport,
) -> Result<(), SnpError> {
    use sev::certs::snp::Verifiable as _;
    (&*chain, &*report)
        .verify()
        .map_err(|_| SnpError::SignatureMismatch)?;
    Ok(())
}

/// Full SNP check: chain + report signature. Returns the *live* report fields
/// for downstream binding/measurement checks.
pub fn verify_snp(
    r: &SnpReport,
    ark_pem: &str,
    ask_pem: &str,
    vcek_pem: &str,
) -> Result<(), SnpError> {
    let chain = build_chain(ark_pem, ask_pem, vcek_pem)?;
    verify_chain(&chain)?;
    let report = to_report(r)?;
    verify_report_signature(&chain, &report)?;
    Ok(())
}

/// The FULL raw report bytes exactly as AMD encodes them (`sev::to_bytes`,
/// `ATT_REP_FW_LEN` = 1184 bytes). This is the byte-level ground truth a
/// verifier checks the signature over (`[..0x2a0]`) and the exact blob the
/// gateway should serve as `raw_report`. Reuses `sev`'s encoder — never
/// hand-assembled (the `to_bytes` layout is the known footgun).
pub fn report_bytes(r: &SnpReport) -> Result<Vec<u8>, SnpError> {
    let report = to_report(r)?;
    sev::parser::ByteParser::to_bytes(&report)
        .map(|b| b.to_vec())
        .map_err(|e| SnpError::Sev(format!("to_bytes: {e}")))
}

/// Diagnostics helper: recompute the 672-byte signed body (for error output).
#[allow(dead_code)]
pub fn signed_body_hex(r: &SnpReport) -> Result<String, SnpError> {
    let bytes = report_bytes(r)?;
    Ok(hex::encode(&bytes[..0x2a0]))
}

/// AMD KDS product family name (capitalized) for a CPU family/model pair.
/// `sev::Generation` has no `Display`/KDS-string; we map from the same
/// family/model ranges `sev::Generation::identify_cpu` uses.
pub fn kds_product(family: u8, model: u8) -> Result<&'static str, SnpError> {
    match (family, model) {
        (0x19, 0x00..=0x0F) => Ok("Milan"),
        (0x19, 0x10..=0x1F) | (0x19, 0xA0..=0xAF) => Ok("Genoa"),
        (0x1A, 0x00..=0x1F) => Ok("Turin"),
        (0x1A, 0x50..=0x5F) | (0x1A, 0xC0..=0xCF) => Ok("Venice"),
        _ => Err(SnpError::Unsupported(format!(
            "unknown CPU family/model 0x{family:x}/0x{model:x}"
        ))),
    }
}

/// The KDS VCEK query for a chip_id + reported TCB.
pub fn kds_vcek_url(product: &str, chip_id: &[u8; 64], reported: Tcb) -> String {
    format!(
        "https://kdsintf.amd.com/vcek/v1/{product}/{chip}?blSPL={bl}&teeSPL={tee}&snpSPL={snp}&ucodeSPL={ucode}",
        product = product,
        chip = hex::encode(chip_id),
        bl = reported.bootloader.unwrap_or(0),
        tee = reported.tee,
        snp = reported.snp,
        ucode = reported.microcode.unwrap_or(0),
    )
}

/// The KDS ARK/ASK bundle URL for a product.
pub fn kds_cert_chain_url(product: &str) -> String {
    format!("https://kdsintf.amd.com/vcek/v1/{product}/cert_chain")
}
