# kubetee-attestation-verifier

Independent, **fail-closed** AMD SEV-SNP verifier for the KubeTEE TEE
attestation envelope (`kubetee.attestation.v1`). A third party — Chutes, SayGM,
gm-miner, an auditor — can run this to confirm a KubeTEE gateway's TEE evidence
**without trusting any KubeTEE-owned endpoint**.

## What it proves

| # | Check | Evidence it reads | Trust root |
|---|-------|-------------------|-----------|
| 1 | **AMD chain** ARK→ASK→VCEK | `cert_chain` (or AMD KDS) | AMD root key (built into `sev`) |
| 2 | **Report signature** | SNP report ECDSA P-384/SHA-384 over `to_bytes()[..0x2a0]` | the VCEK from (1) |
| 3 | **Request binding** | `report_data == sha256(jcs(statement)) ‖ 32 zeros` | the caller's nonce + served keyset digest |
| 4 | **Reference measurement** | `measurement` / `host_data` / `report_version` match `tee-measurements.json` (SNP) or registers match ANY active record in `tee-measurements-registry.json` (TDX) | the signed `.well-known` docs (Ed25519) |
| 5 | **TLS key possession** | TLS leaf SPKI SHA-256 == `spki_sha256` in the quote-bound keyset + a signature over the nonce | the TEE-attested keyset |

Every check **fails closed**: a mismatch, a malformed field, or an absent
expected value is a FAIL, never a pass.

## Build

```bash
cargo build --release
```

Pure-Rust crypto (`crypto_nossl`) — **no OpenSSL**, so it builds on macOS-ARM
(this is what the SayGM / Chutes verifiers require).

## Usage

```bash
# 1. Fetch evidence with a caller nonce (64 hex chars):
NONCE=$(python3 -c 'import secrets;print(secrets.token_hex(32))')
curl -sS "https://llm.kubetee.ai/v1/attestation?nonce=$NONCE" > evidence.json

# 2. Fetch the signed reference + signing key:
curl -sS https://kubetee.ai/.well-known/tee-measurements.json > reference.json
curl -sS https://kubetee.ai/.well-known/tee-measurements-registry.json > registry.json

# 3. Verify (AMD KDS is queried for the VCEK + ARK/ASK automatically):
openssl s_client -connect llm.kubetee.ai:443 -servername llm.kubetee.ai \
  </dev/null 2>/dev/null | openssl x509 -outform DER > tls_leaf.der

kubetee-attestation-verifier verify \
  --evidence evidence.json \
  --reference reference.json \
  --registry registry.json \
  --tls-leaf tls_leaf.der \
  --tls-domain llm.kubetee.ai
```

Exit code `0` = all checks PASS; `1` = at least one FAIL (each line prefixed
`PASS ` / `FAIL `); `2` = usage / IO error.

Offline (no KDS) — pass the PEMs you already fetched:

```bash
kubetee-attestation-verifier verify \
  --evidence evidence.json --kds=false \
  --ark ark.pem --ask ask.pem --vcek vcek.pem \
  --reference reference.json
```

Diagnostics — see the KDS query + the 672-byte signed body:

```bash
kubetee-attestation-verifier inspect evidence.json
```

## Provenance

This crate is `sev = "=9.0.0"` with `default-features = false,
features = ["snp", "crypto_nossl"]` — pure-Rust, no OpenSSL. The
`virtee/sev` `9.0.0` release has no git tag yet (the repo's release list
still shows `v.8.0.0`), so the source↔publish binding is content + checksum,
reproducible by anyone:

* **Source commit:** `feaf142ec916c23e7658f088802921177ee290f9`
  ("Bump SEV to version 9.0.0", `virtee/sev` `main`).
* **crates.io `9.0.0` tarball sha256:**
  `4d16d4e670d6cc97c9c5c3a7c7c33595a0dd1f1ef4a5b7bd71f04244d4f2a8fb`.

Verify it yourself:

```bash
curl -sS https://raw.githubusercontent.com/virtee/sev/feaf142/Cargo.toml | grep '^version'
curl -sSL https://crates.io/api/v1/crates/sev/9.0.0/download | sha256sum
```

Dependency policy: `use-latest-library-versions.mdc` — every dep is pinned
exactly to the latest stable upstream release, re-checked on every manifest
touch.

## Test vectors

`tests/` freezes the live-gateway capture (a real SNP report + its VCEK from
AMD KDS) plus corrupted variants (tampered nonce, tampered keyset, tampered
registers) proving each check **fails closed**. `cargo test` runs them
offline against frozen fixtures — no network needed at test time.

## Related

* `kubetee-subnet/docs/CLIENT-FACING-ATTESTATION.md` — the client-facing
  contract this verifier implements.
* `kubetee-subnet/docs/ATTESTATION-SPEC-v1.md` — the `kubetee.attestation.v1`
  binding spec (report_data = `sha256(jcs(statement)) ‖ 32 zeros`).
* `gm-miner/attestd/src/kubetee_verify` — the deployed gm-miner verifier.
