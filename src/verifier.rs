use crate::challenge::{decimal_to_hex, Challenges};
use crate::compute_fej::FEJ;
use crate::compute_r::compute_r;
use crate::inversion::Inversion;
use crate::pairing::check_pairing;

use crate::proof::Proof;
use crate::vk::VerificationKey;
use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField};

/// Use the given verification key `vk` to verify the `proof`` against the given `pubs` public inputs.
/// Can fail if:
/// - the provided inverse in the proof is wrong
/// - the pair checking is wrong
pub fn fflonk_verifier(vk: &VerificationKey, proof: Proof, pub_input: &Fr) {
    // 1. compute challenge
    let (challenges, roots) = Challenges::compute(vk, &proof, pub_input);
    // println!("challenge.y: {:?}", challenges.y.to_string());
    // println!("challenge.y: {:?}", challenges.y.into_bigint().to_bytes_be());

    // 2. compute inversion
    //     Compute public input polynomial evaluation PI(xi) = \sum_i^l -public_input_i·L_i(xi)
    let inv_tuple = Inversion::build(vk, &proof, &challenges, &roots);
    println!(
        "inverse.den_h1: {:?}",
        &inv_tuple.denH1.into_bigint().to_bytes_be()
    );
    println!(
        "inverse.den_h1: {:?}",
        &inv_tuple.denH2.into_bigint().to_bytes_be()
    );
    // println!("inverse.li_s0_inv: {:?}", &inv_tuple.lis_values.li_s0_inv.into_bigint().to_bytes_be());
    // println!("inverse.li_s1_inv: {:?}", &inv_tuple.lis_values.li_s1_inv.into_bigint().to_bytes_be());
    // println!("inverse.li_s2_inv: {:?}", &inv_tuple.lis_values.li_s2_inv.into_bigint().to_bytes_be());

    // 3. Compute public input polynomial evaluation PI(xi) = \sum_i^l -public_input_i·L_i(xi)
    let pi = -inv_tuple.eval_l1 * pub_input;
    // println!("pi: {:?}", &pi.into_bigint().to_bytes_be());

    // 4. Computes r1(y) and r2(y)
    let (R0, R1, R2) = compute_r(vk, &proof, &challenges, &roots, &inv_tuple, &pi);
    // println!("r0: {:?}", &R0.into_bigint().to_bytes_be());
    // println!("r1: {:?}", &R1.into_bigint().to_bytes_be());
    // println!("r2: {:?}", &R2.into_bigint().to_bytes_be());

    // 5. compute fej
    // TODO: needs redebug fej
    // Compute full batched polynomial commitment [F]_1, group-encoded batch evaluation [E]_1 and the full difference [J]_1
    let fej = FEJ::compute(
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
