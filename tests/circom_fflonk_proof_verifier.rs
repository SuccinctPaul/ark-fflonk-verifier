use ark_fflonk_verifier::proof::Proof;
use ark_fflonk_verifier::utils::load_public_input;
use ark_fflonk_verifier::verifier::fflonk_verifier;
use ark_fflonk_verifier::vk::{SnarkJSVK, VerificationKey};
use std::fs::File;
use std::io::Read;

#[test]
fn circom_fflonk_proof_verifier() {
    let current_dir = std::env::current_dir().unwrap();
    let circom_file_path = current_dir.join("resources/circom/");

    let public_file = circom_file_path.join("public.json");
    // let vk_file = circom_file_path.join("verification_key.json");
    let vk_file = circom_file_path.join("zksync_vk.json");
    let proof_file = circom_file_path.join("proof.json");

    let snarkjs_vk = SnarkJSVK::load(vk_file).unwrap();
    let vk: VerificationKey = snarkjs_vk.into();
    let proof = Proof::load(proof_file).unwrap();
    let pubs = load_public_input(public_file).unwrap();
    println!("snarkjs_vk: {:?}", pubs);
    fflonk_verifier(&vk, &proof, &pubs, false);
}
