use crate::challenge::Challenges;
use crate::inversion::Inversion;
use crate::proof::Proof;
use crate::vk::VerificationKey;
use ark_bn254::{Fq, Fr, G1Affine, G1Projective};
use ark_ec::{AffineRepr, CurveGroup};

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
        let (y, alpha) = (challenge.y, challenge.alpha);
        let numerator = (y - h0w8[0])
            * (y - h0w8[1])
            * (y - h0w8[2])
            * (y - h0w8[3])
            * (y - h0w8[4])
            * (y - h0w8[5])
            * (y - h0w8[6])
            * (y - h0w8[7]);

        let quotient1 = alpha * numerator * invers_tuple.denH1;
        let quotient2 = alpha * alpha * numerator * invers_tuple.denH2;

        // F point
        let c2_agg = vk.c0 + proof.polynomials.c1 * quotient1 + proof.polynomials.c2 * quotient2;
        // E point
        let g1_acc = G1Affine::generator() * (R0 + quotient1 * R1 + quotient2 * R2);
        // J Point
        let w1_agg = proof.polynomials.w1 * numerator;

        Self {
            F: c2_agg.into_affine(),
            E: g1_acc.into_affine(),
            J: w1_agg.into_affine(),
        }
    }
}
