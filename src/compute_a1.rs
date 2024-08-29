use crate::challenge::Challenges;
use crate::compute_fej::FEJ;
use crate::proof::Proof;
use crate::vk::VerificationKey;
use ark_bn254::G1Affine;
use ark_ec::CurveGroup;

// Compute P1 in the pairing.
//      F = F - E - J + y·W2
pub fn compute_a1(proof: &Proof, fej: &FEJ, challenges: &Challenges) -> G1Affine {
    let W2 = proof.polynomials.w2;

    // F = F - E - J + y·W2
    let p1 = (fej.F - fej.E - fej.J + W2 * challenges.y).into_affine();
    p1
}
