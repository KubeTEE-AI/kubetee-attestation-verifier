use clap::{Parser, Subcommand};
use kubetee_attestation_verifier as kv;
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "kubetee-attestation-verifier",
    about = "Independent, fail-closed AMD SEV-SNP verifier for the KubeTEE TEE attestation envelope",
    version
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Verify an evidence envelope file against AMD KDS + the .well-known references.
    Verify {
        /// Path to the evidence JSON (from `GET /v1/attestation?nonce=...`).
        #[arg(long)]
        evidence: PathBuf,
        /// The TLS leaf (DER or PEM) served on the connection. Omit to skip TLS-possession.
        #[arg(long)]
        tls_leaf: Option<PathBuf>,
        /// TLS domain for the SPKI-pin check (default llm.kubetee.ai).
        #[arg(long, default_value = "llm.kubetee.ai")]
        tls_domain: String,
        /// Path to the signed SNP reference (`tee-measurements.json`).
        #[arg(long)]
        reference: Option<PathBuf>,
        /// Path to the signed TDX registry (`tee-measurements-registry.json`).
        #[arg(long)]
        registry: Option<PathBuf>,
        /// Pinned measurements signing key (base64url, 32 bytes). Omit to skip sig check.
        #[arg(long)]
        signing_key: Option<String>,
        /// Fetch ARK/ASK/VCEK from AMD KDS (default). Offline: pass --vcek/--ark/--ask.
        #[arg(long, default_value_t = true)]
        kds: bool,
        /// Offline VCEK PEM file (skips KDS).
        #[arg(long)]
        vcek: Option<PathBuf>,
        #[arg(long)]
        ark: Option<PathBuf>,
        #[arg(long)]
        ask: Option<PathBuf>,
    },
    /// Print the report's KDS query + the 672-byte signed body (diagnostics).
    Inspect { evidence: PathBuf },
}

fn read(path: &PathBuf) -> String {
    std::fs::read_to_string(path).unwrap_or_else(|e| {
        eprintln!("cannot read {}: {e}", path.display());
        std::process::exit(2);
    })
}

fn main() {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Inspect { evidence } => {
            let env = parse_or_exit(&read(&evidence));
            let r = &env.snp;
            let product = kv::kds_product(
                r.cpuid_fam_id.unwrap_or(0),
                r.cpuid_mod_id.unwrap_or(0),
            )
            .unwrap_or("UNKNOWN");
            println!("tee:                {}", env.tee);
            println!("runtime_class:      {}", env.runtime_class);
            println!("pod:                {}", env.pod);
            println!("report version:     {}", r.version);
            println!("vmpl:               {}", r.vmpl);
            println!("sig_algo:           {}", r.sig_algo);
            println!("policy:             0x{:08x}", r.policy);
            println!(
                "cpuid family/model: {} / {}",
                r.cpuid_fam_id.unwrap_or(0),
                r.cpuid_mod_id.unwrap_or(0)
            );
            println!("AMD KDS product:    {product}");
            println!("chip_id:            {}", hex::encode(r.chip_id));
            println!(
                "reported_tcb:       bl={} tee={} snp={} ucode={:?}",
                r.reported_tcb.bootloader.unwrap_or(0),
                r.reported_tcb.tee,
                r.reported_tcb.snp,
                r.reported_tcb.microcode
            );
            println!("measurement:        {}", hex::encode(r.measurement));
            println!("host_data:          {}", hex::encode(r.host_data));
            println!("report_data:        {}", hex::encode(r.report_data));
            println!("keyset_digest:      {}", env.bindings.keyset_digest);
            println!(
                "statement:          {}",
                env.bindings.report_data_statement
            );
            match kv::snp::signed_body_hex(r) {
                Ok(body) => println!("signed body (672B): {body}"),
                Err(e) => println!("signed body:        <recompute failed: {e}>"),
            }
        }
        Cmd::Verify {
            evidence,
            tls_leaf,
            tls_domain,
            reference,
            registry,
            signing_key,
            kds: use_kds,
            vcek,
            ark,
            ask,
        } => {
            let env = parse_or_exit(&read(&evidence));

            // (1) Chain: from AMD KDS or offline PEMs.
            let (ark_pem, ask_pem, vcek_pem) = if use_kds && vcek.is_none() {
                let product = kv::kds_product(
                    env.snp.cpuid_fam_id.unwrap_or(0),
                    env.snp.cpuid_mod_id.unwrap_or(0),
                )
                .unwrap_or_else(|e| {
                    eprintln!("cannot determine KDS product: {e}");
                    std::process::exit(2);
                });
                match kv::kds::fetch_chain(product, &env.snp.chip_id, env.snp.reported_tcb) {
                    Ok(c) => (c.ark_pem, c.ask_pem, c.vcek_pem),
                    Err(e) => {
                        eprintln!("KDS fetch failed (offline? pass --ark/--ask/--vcek): {e}");
                        std::process::exit(2);
                    }
                }
            } else {
                (
                    read(&ark.expect("--ark required with --vcek")),
                    read(&ask.expect("--ask required with --vcek")),
                    read(&vcek.expect("--vcek required")),
                )
            };

            let reference_doc = reference.map(|p| read(&p)).and_then(|s| serde_json::from_str(&s).ok());
            let registry_doc = registry.map(|p| read(&p)).and_then(|s| serde_json::from_str(&s).ok());
            let tls_leaf_der = tls_leaf.as_ref().and_then(|p| read_leaf(p));

            let input = kv::VerifyInput {
                envelope: &env,
                ark_pem: &ark_pem,
                ask_pem: &ask_pem,
                vcek_pem: &vcek_pem,
                snp_reference: reference_doc.as_ref(),
                registry: registry_doc.as_ref(),
                tls_leaf_der: tls_leaf_der.as_deref(),
                tls_domain: &tls_domain,
                signing_key_b64url: signing_key.as_deref().or(Some(kv::registry::DEFAULT_SIGNING_KEY_B64URL)),
                now_iso: None,
            };
            let verdict = kv::verify(&input);
            println!("{}", verdict.report());
            std::process::exit(if verdict.pass { 0 } else { 1 });
        }
    }
}

fn parse_or_exit(doc: &str) -> kv::Envelope {
    match kv::parse_envelope(doc) {
        Ok(e) => e,
        Err(e) => {
            eprintln!("envelope parse error: {e}");
            std::process::exit(2);
        }
    }
}

fn read_leaf(path: &PathBuf) -> Option<Vec<u8>> {
    let raw = std::fs::read(path).ok()?;
    if raw.starts_with(b"-----BEGIN") {
        // PEM: decode the first cert to DER via the x509-cert PEM reader.
        let text = String::from_utf8_lossy(&raw).to_string();
        let der = pem_first_cert_der(&text)?;
        Some(der)
    } else {
        Some(raw)
    }
}

fn pem_first_cert_der(pem: &str) -> Option<Vec<u8>> {
    use base64::{engine::general_purpose::STANDARD, Engine};
    let body = pem
        .split("-----BEGIN CERTIFICATE-----")
        .nth(1)?
        .split("-----END CERTIFICATE-----")
        .next()?;
    let b64: String = body.chars().filter(|c| !c.is_whitespace()).collect();
    STANDARD.decode(b64).ok()
}
