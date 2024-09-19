use crate::challenge::Challenges;
use crate::inversion::Inversion;
use crate::proof::Proof;
use crate::vk::VerificationKey;
use ark_bn254::{Fr, G1Affine};
use ark_ec::{AffineRepr, CurveGroup};
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
    pub fn compute_scalars(
        challenge: &Challenges,
        invers_tuple: &Inversion,
        R0: Fr,
        R1: Fr,
        R2: Fr,
    ) -> (Fr, Fr, Fr, Fr) {
        let numerator = challenge
            .roots
            .h0w8
            .iter()
            .fold(Fr::one(), |acc, h0_w8_i| acc * (challenge.y - *h0_w8_i));
        let quotient1 = challenge.alpha * numerator * invers_tuple.den_h1;
        let quotient2 = challenge.alpha * challenge.alpha * numerator * invers_tuple.den_h2;

        let e_scalar = R0 + quotient1 * R1 + quotient2 * R2;

        (quotient1, quotient2, e_scalar, numerator)
    }

    // Compute full batched polynomial commitment [F]_1, group-encoded batch evaluation [E]_1 and the full difference [J]_1
    pub fn compute(
        vk: &VerificationKey,
        proof: &Proof,
        challenge: &Challenges,
        invers_tuple: &Inversion,
        R0: Fr,
        R1: Fr,
        R2: Fr,
    ) -> Self {
        let (quotient1, quotient2, e_scalar, numerator) =
            Self::compute_scalars(challenge, invers_tuple, R0, R1, R2);

        let polynomials = &proof.polynomials;

        let f = polynomials.c1 * quotient1 + polynomials.c2 * quotient2 + vk.c0;
        let e = G1Affine::generator() * e_scalar;
        let j = polynomials.w1 * numerator;

        Self {
            F: f.into_affine(),
            E: e.into_affine(),
            J: j.into_affine(),
        }
    }
}
