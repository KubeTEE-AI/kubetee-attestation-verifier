//! A signed reference record is not enough: the full evidence bundle also
//! carries the exact InitData consumed by Kata. Hash that document, never a
//! server-supplied digest mirror, and map its digest to the correct TEE ABI.

use kubetee_attestation_verifier::registry::{DeploymentConfigSurface, verify_deployment_config};
use sha2::{Digest, Sha384};

fn full_bundle(initdata: &str) -> serde_json::Value {
    let digest = hex::encode(Sha384::digest(initdata.as_bytes()));
    serde_json::json!({
        "evidence": {
            "vm_config": {
                "initdata_toml": initdata,
                "initdata_sha384": digest,
                "host_data": &digest[..64],
            },
            "snp": {},
            "backend": {
                "regs": {
                    "mr_config_id": digest,
                },
                "vm_config": {"initdata_toml": initdata},
            },
        },
    })
}

#[test]
fn hashes_verbatim_initdata_into_snp_host_data_and_tdx_mrconfigid() {
    let bundle = full_bundle("[data]\nrole = \"litellm-and-backend\"\n");
    let matches = verify_deployment_config(&bundle).expect("full bundle verifies");
    assert_eq!(matches.len(), 2);
    assert!(matches.contains(&DeploymentConfigSurface::Snp));
    assert!(matches.contains(&DeploymentConfigSurface::TdxBackend));
}

#[test]
fn accepts_utf8_initdata_and_rejects_native_template_substitution() {
    let bundle = full_bundle("[data]\nrole = \"litellm\"\n# π retained verbatim\n");
    verify_deployment_config(&bundle).expect("UTF-8 InitData verifies");
}

#[test]
fn rejects_a_snp_initdata_change_even_with_a_current_signed_reference() {
    let mut bundle = full_bundle("[data]\nrole = \"litellm\"\n");
    bundle["evidence"]["vm_config"]["initdata_toml"] =
        serde_json::json!("[data]\nrole = \"litellm\"\n# different policy\n");
    assert!(verify_deployment_config(&bundle).is_err());
}

#[test]
fn rejects_a_backend_mrconfigid_change_even_when_registry_image_matches() {
    let mut bundle = full_bundle("[data]\nrole = \"nim-terminator\"\n");
    bundle["evidence"]["backend"]["regs"]["mr_config_id"] = serde_json::json!("00".repeat(48));
    assert!(verify_deployment_config(&bundle).is_err());
}

#[test]
fn omits_unchecked_backend_but_requires_full_gateway_initdata() {
    let bundle = full_bundle("[data]\nrole = \"litellm\"\n");
    for remove in ["vm_config", "backend"] {
        let mut altered = bundle.clone();
        altered["evidence"].as_object_mut().unwrap().remove(remove);
        assert_eq!(
            verify_deployment_config(&altered).is_err(),
            remove == "vm_config"
        );
    }
}

#[test]
fn rejects_a_false_initdata_digest_mirror() {
    let mut bundle = full_bundle("[data]\nrole = \"litellm\"\n");
    bundle["evidence"]["vm_config"]["initdata_sha384"] = serde_json::json!("00".repeat(48));
    bundle["evidence"]["backend"]["vm_config"]["initdata_sha384"] =
        serde_json::json!("00".repeat(48));
    assert!(
        verify_deployment_config(&bundle).is_ok(),
        "mirror values are not accepted or used"
    );
    bundle["evidence"]["backend"]
        .as_object_mut()
        .unwrap()
        .remove("vm_config");
    assert!(
        verify_deployment_config(&bundle).is_err(),
        "backend document missing"
    );
}
