use crate::challenge::Challenges;
use crate::compute_fej::FEJ;
use crate::compute_r::compute_r;
use crate::inversion::Inversion;
use crate::pairing::{check_pairing, prove_and_verify_pairing};

use crate::proof::Proof;
use crate::transcript::TranscriptHash;
use crate::utils::{compute_a1, compute_pi, LangrangePolynomialEvaluation};
use crate::vk::VerificationKey;
use ark_bn254::Fr;

/// Use the given verification key `vk` to verify the `proof`` against the given `pubs` public inputs.
/// Can fail if:
/// - the provided inverse in the proof is wrong
/// - the pair checking is wrong
///
/// Params:
///  @is_recursive_verifier:
///       if true, will leverage power of `prove and verify pairing`.
///       if false, will use default pairing.
pub fn fflonk_verifier<T: TranscriptHash>(
    vk: &VerificationKey,
    proof: &Proof,
    pub_input: &Fr,
    is_recursive_verifier: bool,
) -> bool {
    // 1. compute challenge
    let challenges = Challenges::compute::<T>(vk, proof, pub_input);

    // 2. compute inversion
    //     Compute public input polynomial evaluation PI(xi) = \sum_i^l -public_input_i·L_i(xi)
    let inv_tuple = Inversion::build(vk, proof, &challenges);

    // 3. compute lagrange of L_1
    let L_1 = LangrangePolynomialEvaluation::compute_L1_polynomial_evaluation(
        &challenges.zh,
        &inv_tuple.eval_l1,
    );

    // 4. Compute public input polynomial evaluation PI(xi) = PI(xi) = -\sum_i^l public_input_i·L_i(xi)
    let pi = compute_pi(&[*pub_input], &[L_1]);

    // 5. Computes r1(y) and r2(y)
    let (R0, R1, R2) = compute_r(vk, proof, &challenges, &inv_tuple, &L_1, &pi);

    // 6. compute fej
    // Compute full batched polynomial commitment [F]_1, group-encoded batch evaluation [E]_1 and the full difference [J]_1
    let fej = FEJ::compute(vk, proof, &challenges, &inv_tuple, R0, R1, R2);

    // 7. compute_a1
    let a1 = compute_a1(proof, &fej, &challenges);

    // 8. Validate all evaluations
    if is_recursive_verifier {
        prove_and_verify_pairing(vk, proof, &a1)
    } else {
        check_pairing(vk, proof, &a1)
    }
}
