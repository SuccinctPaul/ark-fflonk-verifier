use crate::challenge::Challenges;
use crate::compute_fej::FEJ;
use crate::proof::Proof;
use crate::vk::VerificationKey;
use ark_bn254::{Bn254, Fq, Fq2, G1Affine, G2Affine};
use ark_ec::bn::{G1Prepared, G2Prepared};
use ark_ec::pairing::Pairing;
use ark_ec::{bn, AffineRepr, CurveGroup};
use num_traits::One;
use std::ops::{Add, Mul};
use std::str::FromStr;

pub fn check_pairing(vk: &VerificationKey, proof: &Proof, fej: FEJ, challenges: Challenges) {
    let W2 = proof.polynomials.w2;

    // first pairing value
    // let p1 = F.add(-E).add(-J).add(W2.mul(challenges.y)).into_affine();
    let p1 = (fej.F - fej.E - fej.J + W2 * challenges.y).into_affine();

    let p2 = -W2;

    // Pi
    let lhs: [G1Prepared<ark_bn254::Config>; 2] = [p1.into(), p2.into()];
    // Qi
    let rhs: [G2Prepared<ark_bn254::Config>; 2] = [vk.g2.into(), vk.x2.into()];
    let res = Bn254::multi_pairing(lhs, rhs);

    assert!(res.0.is_one(), "Proof verification failed!");
}
