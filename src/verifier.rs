use crate::challenge::{decimal_to_hex, Challenges};
use crate::compute_fej::compute_fej;
use crate::compute_r::compute_r;
use crate::inversion::Inversion;
use crate::pairing::check_pairing;

use crate::proof::Proof;
use crate::vk::VerificationKey;
use ark_bn254::Fr;

/// Use the given verification key `vk` to verify the `proof`` against the given `pubs` public inputs.
/// Can fail if:
/// - the provided inverse in the proof is wrong
/// - the pair checking is wrong
pub fn fflonk_verifier(vk: &VerificationKey, proof: Proof, pub_input: &Fr) {
    // 1. compute challenge
    let (challenges, roots) = Challenges::compute(vk, &proof, pub_input);

    // 2. compute inversion
    //     Compute public input polynomial evaluation PI(xi) = \sum_i^l -public_input_i·L_i(xi)
    let inv_tuple = Inversion::build(vk, &proof, &challenges, &roots);

    // 3. Compute public input polynomial evaluation PI(xi) = \sum_i^l -public_input_i·L_i(xi)
    let pi = -inv_tuple.eval_l1 * pub_input;

    // 4. Computes r1(y) and r2(y)
    let (R0, R1, R2) = compute_r(vk, &proof, &challenges, &roots, &inv_tuple, &pi);

    // 5. compute fej
    // Compute full batched polynomial commitment [F]_1, group-encoded batch evaluation [E]_1 and the full difference [J]_1
    let fej = compute_fej(
        vk,
        &proof,
        &challenges,
        &inv_tuple,
        roots.h0w8.to_vec(),
        R0,
        R1,
        R2,
    );

    // 6. Validate all evaluations
    check_pairing(vk, &proof, fej, challenges);
}
