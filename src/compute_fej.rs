use crate::challenge::Challenges;
use crate::inversion::Inversion;
use crate::proof::Proof;
use crate::vk::VerificationKey;
use ark_bn254::{Fq, Fr, G1Affine, G1Projective};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{BigInteger, PrimeField};
use num_traits::One;

#[derive(Debug, Default, Eq, PartialEq, Copy, Clone)]
pub struct FEJ {
    // [F]_1: full batched polynomial commitment
    pub F: G1Affine,
    // [E]_1: group-encoded batch evaluation
    pub E: G1Affine,
    // [J]_1: the full difference
    pub J: G1Affine,
}

impl FEJ {
    // Compute full batched polynomial commitment [F]_1, group-encoded batch evaluation [E]_1 and the full difference [J]_1
    pub fn compute(
        vk: &VerificationKey,
        proof: &Proof,
        challenge: &Challenges,
        invers_tuple: &Inversion,
        h0w8: Vec<Fr>,
        R0: Fr,
        R1: Fr,
        R2: Fr,
    ) -> Self {
        let polynomials = &proof.polynomials;
        let numerator = h0w8
            .iter()
            .fold(Fr::one(), |acc, h0_w8_i| acc * (challenge.y - *h0_w8_i));
        let quotient1 = challenge.alpha * numerator * invers_tuple.denH1;
        let quotient2 = challenge.alpha * challenge.alpha * numerator * invers_tuple.denH2;

        let f = polynomials.c1 * quotient1 + polynomials.c2 * quotient2 + vk.c0;
        let e = G1Affine::generator() * (R0 + quotient1 * R1 + quotient2 * R2);
        let j = polynomials.w1 * numerator;

        Self {
            F: f.into_affine(),
            E: e.into_affine(),
            J: j.into_affine(),
        }
    }
}
