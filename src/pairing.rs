use crate::proof::Proof;
use crate::vk::VerificationKey;
use ark_bn254::{Bn254, G1Affine};
use ark_ec::bn::{G1Prepared, G2Prepared};
use ark_ec::pairing::Pairing;
use ark_ec::CurveGroup;
use num_traits::One;
use on_proving_pairings::prover::PairingProver;
use on_proving_pairings::setup::PairingPVKey;
use on_proving_pairings::verifier::PairingVerifier;

pub fn check_pairing(vk: &VerificationKey, proof: &Proof, a1: &G1Affine) -> bool {
    // prepare pairing data
    let p1 = a1;
    let p2 = proof.polynomials.w2.into_affine();

    // Pi: [p1, proof.w2]
    let lhs: [G1Prepared<ark_bn254::Config>; 2] = [p1.into(), p2.into()];
    // Qi: [vk.g2, -vk.X2]
    let rhs: [G2Prepared<ark_bn254::Config>; 2] = [vk.g2.into(), (-vk.x2).into()];

    let res = Bn254::multi_pairing(lhs, rhs);

    // assert!(res.0.is_one(), "Proof verification failed!");
    res.0.is_one()
}

// prove and verify pairings:
//      e(p1,vk.g2)=e(proof.w2,-vk.X2)
pub fn prove_and_verify_pairing(vk: &VerificationKey, proof: &Proof, a1: &G1Affine) -> bool {
    // prepare pairing data
    let p1 = a1;
    let p2 = proof.polynomials.w2.into_affine();

    // Pi: [p1, proof.w2]
    let lhs: [G1Prepared<ark_bn254::Config>; 2] = [p1.into(), p2.into()];
    // Qi: [vk.g2, -vk.X2]
    let rhs: [G2Prepared<ark_bn254::Config>; 2] = [vk.g2.into(), (-vk.x2).into()];

    // setup: finding_c
    let pairing_pvk = PairingPVKey::setup(lhs.to_vec(), rhs.to_vec());

    // eval_points: [P1,P2]
    let eval_points = vec![*p1, p2];
    // precompute lines: [Q1,Q2,Q3]
    let q_prepared_lines = rhs[0..2].to_vec();

    let final_f = PairingProver::prove_dual_pairing(eval_points, &q_prepared_lines, &pairing_pvk);

    // verify
    PairingVerifier::verify(&pairing_pvk, final_f)
}
