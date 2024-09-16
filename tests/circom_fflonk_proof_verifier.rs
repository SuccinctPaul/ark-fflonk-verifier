use ark_fflonk_verifier::proof::Proof;
use ark_fflonk_verifier::utils::load_public_input;
use ark_fflonk_verifier::verifier::fflonk_verifier;
use ark_fflonk_verifier::vk::{SnarkJSVK, VerificationKey};

// keccak256:
//      cargo test circom_fflonk_proof_verifier  --features keccak256 -- --nocapture
//
// blake3:
//      cargo test circom_fflonk_proof_verifier --features blake3 --no-default-features  -- --nocapture
#[test]
fn circom_fflonk_proof_verifier() {
    let current_dir = std::env::current_dir().unwrap();

    #[cfg(feature = "blake3")]
    let circom_file_path = current_dir.join("resources/circom-blake3/");
    #[cfg(feature = "keccak256")]
    let circom_file_path = current_dir.join("resources/circom/");

    let public_file = circom_file_path.join("public.json");
    let vk_file = circom_file_path.join("verification_key.json");
    let proof_file = circom_file_path.join("proof.json");
    let snarkjs_vk = SnarkJSVK::load(vk_file).unwrap();
    let vk: VerificationKey = snarkjs_vk.into();
    let proof = Proof::load(proof_file).unwrap();
    let pubs = load_public_input(public_file).unwrap();
    let res = fflonk_verifier(&vk, &proof, &pubs, false);
    println!("circom_fflonk_proof_verifier res: {res}");
    assert!(res);
    // assert!(fflonk_verifier(&vk, &proof, &pubs, true));
}
