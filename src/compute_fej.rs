use crate::Proof;
use ark_bn254::{Fq, Fr, G1Affine, G1Projective};
use ark_ec::{AffineCurve, ProjectiveCurve};
use ark_ff::One;
use std::ops::{Add, Mul, Sub};
use std::str::FromStr;

// Compute full batched polynomial commitment [F]_1, group-encoded batch evaluation [E]_1 and the full difference [J]_1
pub fn compute_fej(
    y: Fr,
    h0w8: Vec<Fr>,
    denH1: Fr,
    denH2: Fr,
    alpha: Fr,
    proof: &Proof,
    g1: G1Affine,
    R0: Fr,
    R1: Fr,
    R2: Fr,
) -> (G1Affine, G1Affine, G1Affine) {
    let mut numerator = y.sub(h0w8[0]);
    numerator = numerator.mul(y.sub(h0w8[1]));
    numerator = numerator.mul(y.sub(h0w8[2]));
    numerator = numerator.mul(y.sub(h0w8[3]));
    numerator = numerator.mul(y.sub(h0w8[4]));
    numerator = numerator.mul(y.sub(h0w8[5]));
    numerator = numerator.mul(y.sub(h0w8[6]));
    numerator = numerator.mul(y.sub(h0w8[7]));

    let c1 = proof.c1;
    let c2 = proof.c2;
    let w1 = proof.w1;

    let quotient1 = alpha.mul(numerator.mul(denH1));
    let quotient2 = alpha.mul(alpha.mul(numerator.mul(denH2)));

    let c0_x = Fq::from_str(
        "7005013949998269612234996630658580519456097203281734268590713858661772481668",
    )
    .unwrap();

    let c0_y =
        Fq::from_str("869093939501355406318588453775243436758538662501260653214950591532352435323")
            .unwrap();

    let c0_affine = G1Projective::new(c0_x, c0_y, Fq::one()).into_affine();

    let c1_agg = c0_affine.add(c1.mul(quotient1).into_affine());
    //  F point
    let c2_agg = c1_agg.add(c2.mul(quotient2).into_affine());

    let r_agg = R0.add(quotient1.mul(R1).add(quotient2.mul(R2)));
    // E point
    let g1_acc = g1.mul(r_agg).into_affine();
    // J Point
    let w1_agg = w1.mul(numerator).into_affine();

    (c2_agg, g1_acc, w1_agg)
}
