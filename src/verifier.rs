use crate::challenge::{decimal_to_hex, Challenges};
use crate::compute_r::compute_r;
use crate::inversion::Inversion;
use crate::pairing::check_pairing;
use crate::proof::precompute_c0;
use crate::{compute_fej::compute_fej, compute_pi::compute_pi, vk::VerifierProcessedInputs, Proof};
use num_bigint::BigInt;

use ark_bn254::Fr;

/// Use the given verification key `vk` to verify the `proof`` against the given `pubs` public inputs.
/// Can fail if:
/// - the provided inverse in the proof is wrong
/// - the pair checking is wrong
pub fn fflonk_verifier(vpi: VerifierProcessedInputs, proof: Proof, pub_signal: Fr) {
    // 1. compute challenge
    let (challenges, roots) = Challenges::compute(vpi, pub_signal.clone());

    // 2. compute inversion
    //     Compute public input polynomial evaluation PI(xi) = \sum_i^l -public_input_i·L_i(xi)
    let inv_tuple = Inversion::build(challenges.y, challenges.xi, challenges.zh, &roots);

    // 3. compute pi
    let pi = compute_pi(pub_signal, inv_tuple.eval_l1);

    // 4. Computes r1(y) and r2(y)
    let (R0, R1, R2) = compute_r(
        &proof,
        &challenges,
        &roots,
        &inv_tuple,
        &pi,
        &challenges.zh,
        &inv_tuple.eval_l1,
    );

    // 5. compute fej
    // Compute full batched polynomial commitment [F]_1, group-encoded batch evaluation [E]_1 and the full difference [J]_1
    let points = compute_fej(
        challenges.y,
        roots.h0w8.to_vec(),
        inv_tuple.denH1,
        inv_tuple.denH2,
        challenges.alpha,
        &proof,
        precompute_c0(),
        R0,
        R1,
        R2,
    );

    // 6. Validate all evaluations
    check_pairing(&proof, points, challenges);
}
