use crate::challenge::Challenges;
use crate::inversion::Inversion;
use crate::proof::Proof;
use crate::vk::precompute_c0;
use ark_bn254::{Fq, Fr, G1Affine, G1Projective};
use ark_ec::CurveGroup;
use ark_ff::One;
use std::ops::{Add, Mul, Sub};
use std::str::FromStr;

// Compute full batched polynomial commitment [F]_1, group-encoded batch evaluation [E]_1 and the full difference [J]_1
pub fn compute_fej(
    proof: &Proof,
    challenge: &Challenges,
    invers_tuple: &Inversion,
    h0w8: Vec<Fr>,
    R0: Fr,
    R1: Fr,
    R2: Fr,
) -> (G1Affine, G1Affine, G1Affine) {
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

    // TODO: replace with vk.c0
    let c0_x = Fq::from_str(
        "7005013949998269612234996630658580519456097203281734268590713858661772481668",
    )
    .unwrap();

    let c0_y =
        Fq::from_str("869093939501355406318588453775243436758538662501260653214950591532352435323")
            .unwrap();

    let c0_affine = G1Projective::new(c0_x, c0_y, Fq::one()).into_affine();

    let c1_agg = c0_affine + proof.c1 * quotient1;
    //  F point
    let c2_agg = c1_agg + proof.c2 * quotient2;

    let r_agg = R0 + quotient1 * R1 + quotient2 * R2;
    // E point
    let g1_acc = precompute_c0() * r_agg;
    // J Point
    let w1_agg = proof.w1 * numerator;

    (
        c2_agg.into_affine(),
        g1_acc.into_affine(),
        w1_agg.into_affine(),
    )
}
