//! Byte-level oracle: reconstruct the exact AMD SEV-SNP report bytes from a
//! structured `attestation_report` (CoCo native JSON) using `sev::to_bytes`.
//!
//! This is the ground truth used to keep the Python gateway serializer
//! (`litellm/tools/kubetee-litellm-overlay/kubetee_attestation.py`) byte-exact:
//! feed it the same structured report and compare its `raw_report` output to
//! this hex. Usage:
//!
//! ```text
//! cargo run --bin snp-report-bytes -- report.json   # or pipe JSON on stdin
//! ```
//!
//! Prints the full 1184-byte report as hex on stdout; a short summary
//! (length + the 672-byte signed body) on stderr.

use kubetee_attestation_verifier as kv;

fn main() {
    let doc = match std::env::args().nth(1) {
        Some(p) => std::fs::read_to_string(p).expect("read evidence JSON"),
        None => {
            use std::io::Read;
            let mut s = String::new();
            std::io::stdin()
                .read_to_string(&mut s)
                .expect("read JSON on stdin");
            s
        }
    };
    let v: serde_json::Value = serde_json::from_str(&doc).expect("valid JSON");
    let report = v
        .get("attestation_report")
        .or_else(|| v.pointer("/evidence/snp/attestation_report"))
        .unwrap_or(&v);
    let r = kv::envelope::parse_snp_report(report).expect("parse structured report");
    let bytes = kv::snp::report_bytes(&r).expect("sev::to_bytes");
    let signed = 0x2a0.min(bytes.len());
    eprintln!("report bytes: {}", bytes.len());
    eprintln!(
        "signed body hex ({} B): {}",
        signed,
        hex::encode(&bytes[..signed])
    );
    println!("{}", hex::encode(&bytes));
}
