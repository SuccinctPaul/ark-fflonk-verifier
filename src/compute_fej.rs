use crate::Proof;
use ark_bn254::g1::Parameters;
use ark_bn254::{Fr, FrParameters, G1Affine, G1Projective};
use ark_ec::short_weierstrass_jacobian::GroupAffine;
use ark_ec::{AffineCurve, ProjectiveCurve};
use ark_ff::{Fp256, One};
use std::ops::{Add, Mul, Sub};
use std::str::FromStr;

// Compute full batched polynomial commitment [F]_1, group-encoded batch evaluation [E]_1 and the full difference [J]_1
pub fn compute_fej(
    y: Fr,
    h0w8: Vec<Fr>,
    denH1: Fr,
    denH2: Fr,
    alpha: Fr,
    proof: Proof,
    g1: GroupAffine<Parameters>,
    R0: Fr,
    R1: Fr,
    R2: Fr,
) -> (
    GroupAffine<Parameters>,
    GroupAffine<Parameters>,
    GroupAffine<Parameters>,
) {
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

    let mut quotient1 = alpha.mul(numerator.mul(denH1));
    let mut quotient2 = alpha.mul(alpha.mul(numerator.mul(denH2)));

    let c0_x = <G1Affine as AffineCurve>::BaseField::from_str(
        "7005013949998269612234996630658580519456097203281734268590713858661772481668",
    )
    .unwrap();

    let c0_y = <G1Affine as AffineCurve>::BaseField::from_str(
        "869093939501355406318588453775243436758538662501260653214950591532352435323",
    )
    .unwrap();

    let c0_affine = G1Projective::new(
        c0_x,
        c0_y,
        <G1Projective as ProjectiveCurve>::BaseField::one(),
    )
    .into_affine();
    // pf -> c0x
    // pf + 32 -> c0y
    // pf, pc1, quotient1

    // min -> c1x
    // min + 32 -> c1y
    // min + 64 -> quotient1

    // multiply c1 * quotient1

    // min + 64 -> c0x
    // min + 96 -> c0y

    // adding points c1 * quotient1 + c0

    // print!("Quotient 1: {:?}", quotient1.to_string());
    // print!("Quotient 2: {:?}", quotient2.to_string());

    let c1_agg = c0_affine.add(c1.mul(quotient1).into_affine());

    let c2_agg = c1_agg.add(c2.mul(quotient2).into_affine()); //  F point
                                                              // println!("c2_agg: {:?}", c2_agg.x.to_string());
                                                              // println!("c2_agg: {:?}", c2_agg.y.to_string());

    let r_agg = R0.add(quotient1.mul(R1).add(quotient2.mul(R2)));

    let g1_acc = g1.mul(r_agg).into_affine(); // E point
                                              // println!("g1_acc: {:?}", g1_acc.x.to_string());
                                              // println!("g1_acc: {:?}", g1_acc.y.to_string());

    let w1_agg = w1.mul(numerator).into_affine(); // J Point

    // println!("w1_agg: {:?}", w1_agg.x.to_string());
    // println!("w1_agg: {:?}", w1_agg.y.to_string());
    // pE, g1x, g1y, r_agg
    // min -> g1x
    // min + 32 -> g1y
    // min + 64 -> r_agg

    // multiply g1 * r_agg

    // min + 64 -> 0
    // min + 96 -> 0
    (c2_agg, g1_acc, w1_agg)
}
