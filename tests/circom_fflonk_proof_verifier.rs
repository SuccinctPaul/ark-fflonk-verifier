use ark_fflonk_verifier::proof::Proof;
use ark_fflonk_verifier::transcript::{Blake3TranscriptHash, Keccak256TranscriptHash};
use ark_fflonk_verifier::utils::load_public_input;
use ark_fflonk_verifier::verifier::fflonk_verifier;
use ark_fflonk_verifier::vk::{SnarkJSVK, VerificationKey};
use ark_std::{end_timer, start_timer};

// keccak256:
//      cargo test circom_fflonk_proof_verifier  --features keccak256 -- --nocapture
//
// blake3:
//      cargo test circom_fflonk_proof_verifier --features blake3 --no-default-features  -- --nocapture
#[test]
fn circom_fflonk_proof_verifier() {
    circom_fflonk_proof_verifier_keccak256();
    circom_fflonk_proof_verifier_blake3();
}

fn circom_fflonk_proof_verifier_keccak256() {
    let start = start_timer!(|| "circom_fflonk_proof_verifier_blake3");
    let current_dir = std::env::current_dir().unwrap();

    let circom_file_path = current_dir.join("resources/circom/");

    let public_file = circom_file_path.join("public.json");
    let vk_file = circom_file_path.join("verification_key.json");
    let proof_file = circom_file_path.join("proof.json");
    let snarkjs_vk = SnarkJSVK::load(vk_file).unwrap();
    let vk: VerificationKey = snarkjs_vk.into();
    let proof = Proof::load(proof_file).unwrap();
    let pubs = load_public_input(public_file).unwrap();
    let res = fflonk_verifier::<Keccak256TranscriptHash>(&vk, &proof, &pubs, false);
    println!("circom_fflonk_proof_verifier_keccak256 res: {res}");
    assert!(res);
    // assert!(fflonk_verifier(&vk, &proof, &pubs, true));
    end_timer!(start);
}

fn circom_fflonk_proof_verifier_blake3() {
    let start = start_timer!(|| "circom_fflonk_proof_verifier_blake3");
    let current_dir = std::env::current_dir().unwrap();

    let circom_file_path = current_dir.join("resources/circom-blake3/");

    let public_file = circom_file_path.join("public.json");
    let vk_file = circom_file_path.join("verification_key.json");
    let proof_file = circom_file_path.join("proof.json");
    let snarkjs_vk = SnarkJSVK::load(vk_file).unwrap();
    let vk: VerificationKey = snarkjs_vk.into();
    let proof = Proof::load(proof_file).unwrap();
    let pubs = load_public_input(public_file).unwrap();
    let res = fflonk_verifier::<Blake3TranscriptHash>(&vk, &proof, &pubs, false);
    println!("circom_fflonk_proof_verifier_blake3 res: {res}");
    assert!(res);
    end_timer!(start);
}
