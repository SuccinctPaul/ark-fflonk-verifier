//! A simple program to be proven inside the zkVM.

mod challenge;
mod dummy;
mod inversion;
mod pairing;
mod verifier;

pub use crate::dummy::{
    get_domain_size, get_omegas, get_proof, get_pubSignals, padd_bytes32, Omegas, Proof,
};

use crate::dummy::get_proog_bigint;
use ark_bn254::{
    g1, g1::Parameters, Bn254, Fq, FqParameters, Fr, FrParameters, G1Affine, G1Projective,
    G2Projective,
};
use ark_bn254::{g2, Fq2, Fq2Parameters, G2Affine};
use ark_ec::short_weierstrass_jacobian::GroupAffine;
use ark_ec::*;
use ark_ff::{
    field_new, Field, Fp256, Fp256Parameters, Fp2ParamsWrapper, One, PrimeField, QuadExtField,
    UniformRand, Zero,
};
use ark_poly::{domain, Polynomial};
use core::num;
use std::fmt::{format, Debug, DebugMap, Display};
use std::hash::Hash;
use std::marker::PhantomData;
use std::ops::{Add, Mul, Neg, Sub};

use num_bigint::*;
use std::str::FromStr;
use tiny_keccak::Hasher;

pub struct VerifierProcessedInputs {
    pub c0x: BigInt,
    pub c0y: BigInt,
    pub x2x1: BigInt,
    pub x2x2: BigInt,
    pub x2y1: BigInt,
    pub x2y2: BigInt,
}

pub fn compute_lagrange(
    zh: Fp256<FrParameters>,
    eval_l1: Fp256<FrParameters>,
) -> Fp256<FrParameters> {
    let w = Fr::from_str("1").unwrap();
    eval_l1.mul(zh)
}

pub fn computePi(
    pubSignals: Fp256<FrParameters>,
    eval_l1: Fp256<FrParameters>,
) -> Fp256<FrParameters> {
    let pi = Fr::from_str("0").unwrap();

    let q = Fr::from_str(
        "21888242871839275222246405745257275088548364400416034343698204186575808495617",
    )
    .unwrap();

    q.add(pi.sub(eval_l1.mul(pubSignals)))
}

fn calculateR0(
    xi: Fp256<FrParameters>,
    proof: Proof,
    y: Fp256<FrParameters>,
    h0w8: Vec<Fp256<FrParameters>>,
    li_s0_inv: [Fp256<FrParameters>; 8],
) -> Fp256<FrParameters> {
    let Proof {
        eval_ql,
        eval_qr,
        eval_qm,
        eval_qo,
        eval_qc,
        eval_s1,
        eval_s2,
        eval_s3,
        ..
    } = proof;

    let mut num = Fr::from_str("1").unwrap();
    let y__8 = y.pow([8]);
    num = num.mul(y__8);
    num = num.add(-xi);

    let mut h0w80 = h0w8[0];
    let pH0w8_1_term = h0w8[1];
    let pH0w8_2_term = h0w8[2];
    let pH0w8_3_term = h0w8[3];
    let pH0w8_4_term = h0w8[4];
    let pH0w8_5_term = h0w8[5];
    let pH0w8_6_term = h0w8[6];
    let pH0w8_7_term = h0w8[7];

    let pLiS0Inv_term = li_s0_inv[0];
    let pLiS0Inv_32_term = li_s0_inv[1];
    let pLiS0Inv_64_term = li_s0_inv[2];
    let pLiS0Inv_96_term = li_s0_inv[3];
    let pLiS0Inv_128_term = li_s0_inv[4];
    let pLiS0Inv_160_term = li_s0_inv[5];
    let pLiS0Inv_192_term = li_s0_inv[6];
    let pLiS0Inv_224_term = li_s0_inv[7];

    let mut c0Value = eval_ql.add(h0w80.mul(eval_qr));

    let mut h0w8i = h0w80.mul(h0w80);
    c0Value = c0Value.add(eval_qo.mul(h0w8i));

    h0w8i = h0w8i.mul(h0w80);
    c0Value = c0Value.add(eval_qm.mul(h0w8i));

    h0w8i = h0w8i.mul(h0w80);
    c0Value = c0Value.add(eval_qc.mul(h0w8i));

    h0w8i = h0w8i.mul(h0w80);
    c0Value = c0Value.add(eval_s1.mul(h0w8i));

    h0w8i = h0w8i.mul(h0w80);
    c0Value = c0Value.add(eval_s2.mul(h0w8i));

    h0w8i = h0w8i.mul(h0w80);
    c0Value = c0Value.add(eval_s3.mul(h0w8i));

    let res = c0Value.mul(num.mul(pLiS0Inv_term));

    h0w80 = pH0w8_1_term;
    c0Value = eval_ql.add(h0w80.mul(eval_qr));

    h0w8i = h0w80.mul(h0w80);
    c0Value = c0Value.add(eval_qo.mul(h0w8i));

    h0w8i = h0w8i.mul(h0w80);
    c0Value = c0Value.add(eval_qm.mul(h0w8i));

    h0w8i = h0w8i.mul(h0w80);
    c0Value = c0Value.add(eval_qc.mul(h0w8i));

    h0w8i = h0w8i.mul(h0w80);
    c0Value = c0Value.add(eval_s1.mul(h0w8i));

    h0w8i = h0w8i.mul(h0w80);
    c0Value = c0Value.add(eval_s2.mul(h0w8i));

    h0w8i = h0w8i.mul(h0w80);
    c0Value = c0Value.add(eval_s3.mul(h0w8i));

    let res_2 = res.add(c0Value.mul(num.mul(pLiS0Inv_32_term)));

    h0w80 = pH0w8_2_term;
    c0Value = eval_ql.add(h0w80.mul(eval_qr));

    h0w8i = h0w80.mul(h0w80);
    c0Value = c0Value.add(eval_qo.mul(h0w8i));

    h0w8i = h0w8i.mul(h0w80);
    c0Value = c0Value.add(eval_qm.mul(h0w8i));

    h0w8i = h0w8i.mul(h0w80);
    c0Value = c0Value.add(eval_qc.mul(h0w8i));

    h0w8i = h0w8i.mul(h0w80);
    c0Value = c0Value.add(eval_s1.mul(h0w8i));

    h0w8i = h0w8i.mul(h0w80);
    c0Value = c0Value.add(eval_s2.mul(h0w8i));

    h0w8i = h0w8i.mul(h0w80);
    c0Value = c0Value.add(eval_s3.mul(h0w8i));

    let res_3 = res_2.add(c0Value.mul(num.mul(pLiS0Inv_64_term)));

    h0w80 = pH0w8_3_term;
    c0Value = eval_ql.add(h0w80.mul(eval_qr));

    h0w8i = h0w80.mul(h0w80);
    c0Value = c0Value.add(eval_qo.mul(h0w8i));

    h0w8i = h0w8i.mul(h0w80);
    c0Value = c0Value.add(eval_qm.mul(h0w8i));

    h0w8i = h0w8i.mul(h0w80);
    c0Value = c0Value.add(eval_qc.mul(h0w8i));

    h0w8i = h0w8i.mul(h0w80);
    c0Value = c0Value.add(eval_s1.mul(h0w8i));

    h0w8i = h0w8i.mul(h0w80);
    c0Value = c0Value.add(eval_s2.mul(h0w8i));

    h0w8i = h0w8i.mul(h0w80);
    c0Value = c0Value.add(eval_s3.mul(h0w8i));

    let res_4 = res_3.add(c0Value.mul(num.mul(pLiS0Inv_96_term)));

    h0w80 = pH0w8_4_term;
    c0Value = eval_ql.add(h0w80.mul(eval_qr));

    h0w8i = h0w80.mul(h0w80);
    c0Value = c0Value.add(eval_qo.mul(h0w8i));

    h0w8i = h0w8i.mul(h0w80);
    c0Value = c0Value.add(eval_qm.mul(h0w8i));

    h0w8i = h0w8i.mul(h0w80);
    c0Value = c0Value.add(eval_qc.mul(h0w8i));

    h0w8i = h0w8i.mul(h0w80);
    c0Value = c0Value.add(eval_s1.mul(h0w8i));

    h0w8i = h0w8i.mul(h0w80);
    c0Value = c0Value.add(eval_s2.mul(h0w8i));

    h0w8i = h0w8i.mul(h0w80);
    c0Value = c0Value.add(eval_s3.mul(h0w8i));

    let res_5 = res_4.add(c0Value.mul(num.mul(pLiS0Inv_128_term)));

    h0w80 = pH0w8_5_term;
    c0Value = eval_ql.add(h0w80.mul(eval_qr));

    h0w8i = h0w80.mul(h0w80);
    c0Value = c0Value.add(eval_qo.mul(h0w8i));

    h0w8i = h0w8i.mul(h0w80);
    c0Value = c0Value.add(eval_qm.mul(h0w8i));

    h0w8i = h0w8i.mul(h0w80);
    c0Value = c0Value.add(eval_qc.mul(h0w8i));

    h0w8i = h0w8i.mul(h0w80);
    c0Value = c0Value.add(eval_s1.mul(h0w8i));

    h0w8i = h0w8i.mul(h0w80);
    c0Value = c0Value.add(eval_s2.mul(h0w8i));

    h0w8i = h0w8i.mul(h0w80);
    c0Value = c0Value.add(eval_s3.mul(h0w8i));

    let res_6 = res_5.add(c0Value.mul(num.mul(pLiS0Inv_160_term)));

    h0w80 = pH0w8_6_term;
    c0Value = eval_ql.add(h0w80.mul(eval_qr));

    h0w8i = h0w80.mul(h0w80);
    c0Value = c0Value.add(eval_qo.mul(h0w8i));

    h0w8i = h0w8i.mul(h0w80);
    c0Value = c0Value.add(eval_qm.mul(h0w8i));

    h0w8i = h0w8i.mul(h0w80);
    c0Value = c0Value.add(eval_qc.mul(h0w8i));

    h0w8i = h0w8i.mul(h0w80);
    c0Value = c0Value.add(eval_s1.mul(h0w8i));

    h0w8i = h0w8i.mul(h0w80);
    c0Value = c0Value.add(eval_s2.mul(h0w8i));

    h0w8i = h0w8i.mul(h0w80);
    c0Value = c0Value.add(eval_s3.mul(h0w8i));

    let res_7 = res_6.add(c0Value.mul(num.mul(pLiS0Inv_192_term)));

    h0w80 = pH0w8_7_term;
    c0Value = eval_ql.add(h0w80.mul(eval_qr));

    h0w8i = h0w80.mul(h0w80);
    c0Value = c0Value.add(eval_qo.mul(h0w8i));

    h0w8i = h0w8i.mul(h0w80);
    c0Value = c0Value.add(eval_qm.mul(h0w8i));

    h0w8i = h0w8i.mul(h0w80);
    c0Value = c0Value.add(eval_qc.mul(h0w8i));

    h0w8i = h0w8i.mul(h0w80);
    c0Value = c0Value.add(eval_s1.mul(h0w8i));

    h0w8i = h0w8i.mul(h0w80);
    c0Value = c0Value.add(eval_s2.mul(h0w8i));

    h0w8i = h0w8i.mul(h0w80);
    c0Value = c0Value.add(eval_s3.mul(h0w8i));

    let res_8 = res_7.add(c0Value.mul(num.mul(pLiS0Inv_224_term)));

    res_8
}

fn calculateR1(
    xi: Fp256<FrParameters>,
    proof: Proof,
    y: Fp256<FrParameters>,
    pi: Fp256<FrParameters>,
    h1w4: Vec<Fp256<FrParameters>>,
    li_s1_inv: [Fp256<FrParameters>; 4],
    zinv: Fp256<FrParameters>,
) -> Fp256<FrParameters> {
    let mut num = Fr::from_str("1").unwrap();
    let Proof {
        eval_a,
        eval_b,
        eval_c,
        eval_ql,
        eval_qc,
        eval_qr,
        eval_qo,
        eval_qm,
        ..
    } = proof;

    let H1w4_0 = h1w4[0];
    let H1w4_1 = h1w4[1];
    let H1w4_2 = h1w4[2];
    let H1w4_3 = h1w4[3];

    let pLiS1Inv_0_term = li_s1_inv[0];
    let pLiS1Inv_32_term = li_s1_inv[1];
    let pLiS1Inv_64_term = li_s1_inv[2];
    let pLiS1Inv_96_term = li_s1_inv[3];

    let y__4 = y.pow([4]);
    num = num.mul(y__4);
    num = num.add(-xi);

    let mut t0 = eval_ql.mul(eval_a);
    t0 = t0.add(eval_qr.mul(eval_b));
    t0 = t0.add(eval_qm.mul(eval_a.mul(eval_b)));
    t0 = t0.add(eval_qo.mul(eval_c));
    t0 = t0.add(eval_qc);
    t0 = t0.add(pi);
    t0 = t0.mul(zinv);

    let mut c1Value = eval_a;
    c1Value = c1Value.add(H1w4_0.mul(eval_b));
    let mut square = H1w4_0.mul(H1w4_0);
    c1Value = c1Value.add(eval_c.mul(square));
    c1Value = c1Value.add(t0.mul(square.mul(H1w4_0)));

    let res_1 = c1Value.mul(num.mul(pLiS1Inv_0_term));

    c1Value = eval_a;
    c1Value = c1Value.add(H1w4_1.mul(eval_b));
    let mut square = H1w4_1.mul(H1w4_1);
    c1Value = c1Value.add(eval_c.mul(square));
    c1Value = c1Value.add(t0.mul(square.mul(H1w4_1)));

    let res_2 = res_1.add(c1Value.mul(num.mul(pLiS1Inv_32_term)));
    // pLiS1Inv_32_term

    c1Value = eval_a;
    c1Value = c1Value.add(H1w4_2.mul(eval_b));
    let mut square = H1w4_2.mul(H1w4_2);
    c1Value = c1Value.add(eval_c.mul(square));
    c1Value = c1Value.add(t0.mul(square.mul(H1w4_2)));

    let res_3 = res_2.add(c1Value.mul(num.mul(pLiS1Inv_64_term)));

    c1Value = eval_a;
    c1Value = c1Value.add(H1w4_3.mul(eval_b));
    let mut square = H1w4_3.mul(H1w4_3);
    c1Value = c1Value.add(eval_c.mul(square));
    c1Value = c1Value.add(t0.mul(square.mul(H1w4_3)));

    let res_4 = res_3.add(c1Value.mul(num.mul(pLiS1Inv_96_term)));

    res_4
}

fn calculateR2(
    xi: Fp256<FrParameters>,
    gamma: Fp256<FrParameters>,
    beta: Fp256<FrParameters>,
    proof: Proof,
    y: Fp256<FrParameters>,
    eval_l1: Fp256<FrParameters>,
    zinv: Fp256<FrParameters>,
    h2w3: Vec<Fp256<FrParameters>>,
    h3w3: Vec<Fp256<FrParameters>>,
    li_s2_inv: [Fp256<FrParameters>; 6],
) -> Fp256<FrParameters> {
    let Proof {
        eval_a,
        eval_b,
        eval_c,
        eval_z,
        eval_s1,
        eval_s2,
        eval_s3,
        eval_zw,
        eval_t1w,
        eval_t2w,
        ..
    } = proof;

    let w1 = get_omegas().w1;
    let mut num = Fr::from_str("1").unwrap();

    let betaxi = beta.mul(xi);

    let y__6 = y.pow([6]);
    let k1 = Fr::from_str("2").unwrap();
    let k2 = Fr::from_str("3").unwrap();

    let h2w3_0 = h2w3[0];
    let h2w3_1 = h2w3[1];
    let h2w3_2 = h2w3[2];
    let h3w3_0 = h3w3[0];
    let h3w3_1 = h3w3[1];
    let h3w3_2 = h3w3[2];

    let pLiS2Inv_0_term = li_s2_inv[0];
    let pLiS2Inv_32_term = li_s2_inv[1];
    let pLiS2Inv_64_term = li_s2_inv[2];
    let pLiS2Inv_96_term = li_s2_inv[3];
    let pLiS2Inv_128_term = li_s2_inv[4];
    let pLiS2Inv_160_term = li_s2_inv[5];

    num = num.mul(y__6);

    let mut num2 = Fr::one();
    num2 = num2.mul(y.pow([3]));

    num2 = num2.mul(xi.add(xi.mul(w1)));

    num = num.sub(num2);

    num2 = xi.mul(xi.mul(w1));
    num = num.add(num2);

    let mut t2 = eval_a.add(betaxi.add(gamma));
    t2 = t2.mul(eval_b.add(gamma.add(betaxi.mul(k1))));
    t2 = t2.mul(eval_c.add(gamma.add(betaxi.mul(k2))));
    t2 = t2.mul(eval_z);

    let mut t1 = eval_a.add(gamma.add(beta.mul(eval_s1)));
    t1 = t1.mul(eval_b.add(gamma.add(beta.mul(eval_s2))));
    t1 = t1.mul(eval_c.add(gamma.add(beta.mul(eval_s3))));
    t1 = t1.mul(eval_zw);

    t2 = t2.sub(t1);
    t2 = t2.mul(zinv);

    t1 = eval_z.sub(Fr::one());
    t1 = t1.mul(eval_l1);
    t1 = t1.mul(zinv);

    let mut gamma_r2 = Fr::zero();
    let mut hw = h2w3_0;
    let mut c2Value = eval_z.add(hw.mul(t1));
    c2Value = c2Value.add(t2.mul(hw.mul(hw)));
    gamma_r2 = gamma_r2.add(c2Value.mul(num.mul(pLiS2Inv_0_term)));

    hw = h2w3_1;
    c2Value = eval_z.add(hw.mul(t1));
    c2Value = c2Value.add(t2.mul(hw.mul(hw)));
    gamma_r2 = gamma_r2.add(c2Value.mul(num.mul(pLiS2Inv_32_term)));

    hw = h2w3_2;
    c2Value = eval_z.add(hw.mul(t1));
    c2Value = c2Value.add(t2.mul(hw.mul(hw)));
    gamma_r2 = gamma_r2.add(c2Value.mul(num.mul(pLiS2Inv_64_term)));

    hw = h3w3_0;
    c2Value = eval_zw.add(hw.mul(eval_t1w));
    c2Value = c2Value.add(eval_t2w.mul(hw.mul(hw)));
    gamma_r2 = gamma_r2.add(c2Value.mul(num.mul(pLiS2Inv_96_term)));

    hw = h3w3_1;
    c2Value = eval_zw.add(hw.mul(eval_t1w));
    c2Value = c2Value.add(eval_t2w.mul(hw.mul(hw)));
    gamma_r2 = gamma_r2.add(c2Value.mul(num.mul(pLiS2Inv_128_term)));

    hw = h3w3_2;
    c2Value = eval_zw.add(hw.mul(eval_t1w));
    c2Value = c2Value.add(eval_t2w.mul(hw.mul(hw)));
    gamma_r2 = gamma_r2.add(c2Value.mul(num.mul(pLiS2Inv_160_term)));

    gamma_r2
}

fn computeFEJ(
    y: Fp256<FrParameters>,
    h0w8: Vec<Fp256<FrParameters>>,
    denH1: Fp256<FrParameters>,
    denH2: Fp256<FrParameters>,
    alpha: Fp256<FrParameters>,
    proof: Proof,
    g1: GroupAffine<Parameters>,
    R0: Fp256<FrParameters>,
    R1: Fp256<FrParameters>,
    R2: Fp256<FrParameters>,
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
