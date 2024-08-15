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
    println!("\n\n===========");
    println!("R0: {:?}", decimal_to_hex(&R0.to_string()));
    println!("R1: {:?}", decimal_to_hex(&R1.to_string()));
    println!("R2: {:?}", decimal_to_hex(&R2.to_string()));
    println!("\n\n===========");
    // ===========
    // R0: "Fp256 \"(28510E91068E4E9AFBFABA468FAC94B17F0EC611374F317B6263EA6E75E50F93)\""
    // R1: "Fp256 \"(13934CF1C60C15B80344978D2BE3DB82DF442FF50521AD4BE5046A00C3C49B7F)\""
    // R2: "Fp256 \"(16E876FD3219A1F588BCAD072EA296C950D384B8A2264EB759A74E294B99043A)\""

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
    println!("\n\n===========");
    println!(
        "points.0: x:{:?}, y:{:?}",
        decimal_to_hex(&points.0.x.to_string()),
        decimal_to_hex(&points.0.y.to_string()),
    );
    println!(
        "points.1: x:{:?}, y:{:?}",
        decimal_to_hex(&points.1.x.to_string()),
        decimal_to_hex(&points.1.y.to_string()),
    );
    println!(
        "points.2: x:{:?}, y:{:?}",
        decimal_to_hex(&points.2.x.to_string()),
        decimal_to_hex(&points.2.y.to_string()),
    );
    println!("\n\n===========");
    // ===========
    // points.0: x:"Fp256 \"(0413862B151D16482B7C21F9D614D3EDE4203D20C5ABC0392F530971FEE0A37E)\"", y:"Fp256 \"(22BA943DBF4D60EC0BC60487A11D31697D1E828C336E013F170C99993F291615)\""
    // points.1: x:"Fp256 \"(006149277711EC98FBD5973C055B42B1618F78D2D242B3579B746EAA530C26D8)\"", y:"Fp256 \"(0F15A2343EEBA4C1B50EB87C7BACA1925DF1F8B55C176741C77735A7330DC4EA)\""
    // points.2: x:"Fp256 \"(2BA21793E805F6C9213AA886E16D00D0BB563C8C648744D7350313F48ADFC0CC)\"", y:"Fp256 \"(26EB78A133336C209DEDB188A4275CD9E622BF1155C7EC254D916FCE25FABBA6)\""

    // 6. Validate all evaluations
    check_pairing(&proof, points, challenges);
}
