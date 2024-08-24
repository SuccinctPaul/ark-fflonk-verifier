use crate::challenge::{Challenges, Roots};
use crate::inversion::Inversion;
use crate::proof::{Evaluations, Proof};
use crate::vk::VerificationKey;
use ark_bn254::Fr;
use ark_ff::{Field, One, Zero};
use std::ops::{Add, Mul, Sub};
use std::str::FromStr;

pub fn compute_r(
    vk: &VerificationKey,
    proof: &Proof,
    challenges: &Challenges,
    inversion: &Inversion,
    pi: &Fr,
) -> (Fr, Fr, Fr) {
    let roots = &challenges.roots;
    let R0 = calculateR0(&proof, challenges, inversion.lis_values.li_s0_inv);
    let R1 = calculateR1(
        &proof,
        challenges,
        pi,
        inversion.lis_values.li_s1_inv,
        &inversion.zh_inv,
    );
    let R2 = calculateR2(
        vk,
        proof,
        challenges,
        &inversion.eval_l1,
        &inversion.zh_inv,
        inversion.lis_values.li_s2_inv,
    );

    (R0, R1, R2)
}

// Compute r0(y) by interpolating the polynomial r0(X) using 8 points (x,y)
// where x = {h9, h0w8, h0w8^2, h0w8^3, h0w8^4, h0w8^5, h0w8^6, h0w8^7}
// and   y = {C0(h0), C0(h0w8), C0(h0w8^2), C0(h0w8^3), C0(h0w8^4), C0(h0w8^5), C0(h0w8^6), C0(h0w8^7)}
// and computing C0(xi)
fn calculateR0(proof: &Proof, challenges: &Challenges, li_s0_inv: [Fr; 8]) -> Fr {
    let h0w8 = challenges.roots.h0w8.to_vec();
    let Evaluations {
        ql,
        qr,
        qm,
        qo,
        qc,
        s1,
        s2,
        s3,
        ..
    } = proof.evaluations;

    // compute num
    let num = challenges.y.pow([8]) - challenges.xi;

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

    let mut c0Value = proof.evaluations.ql + h0w8[0] * proof.evaluations.qr;

    let mut h0w8i = h0w80.mul(h0w80);
    c0Value = c0Value.add(qo.mul(&h0w8i));

    h0w8i = h0w8i.mul(h0w80);
    c0Value = c0Value.add(qm.mul(&h0w8i));

    h0w8i = h0w8i.mul(h0w80);
    c0Value = c0Value.add(qc.mul(&h0w8i));

    h0w8i = h0w8i.mul(h0w80);
    c0Value = c0Value.add(s1.mul(&h0w8i));

    h0w8i = h0w8i.mul(h0w80);
    c0Value = c0Value.add(s2.mul(&h0w8i));

    h0w8i = h0w8i.mul(h0w80);
    c0Value = c0Value.add(s3.mul(&h0w8i));

    let res = c0Value * num * pLiS0Inv_term;

    h0w80 = pH0w8_1_term;
    c0Value = ql.add(&h0w80.mul(qr));

    h0w8i = h0w80.mul(h0w80);
    c0Value = c0Value.add(qo.mul(&h0w8i));

    h0w8i = h0w8i.mul(h0w80);
    c0Value = c0Value.add(qm.mul(&h0w8i));

    h0w8i = h0w8i.mul(h0w80);
    c0Value = c0Value.add(qc.mul(&h0w8i));

    h0w8i = h0w8i.mul(h0w80);
    c0Value = c0Value.add(s1.mul(&h0w8i));

    h0w8i = h0w8i.mul(h0w80);
    c0Value = c0Value.add(s2.mul(&h0w8i));

    h0w8i = h0w8i.mul(h0w80);
    c0Value = c0Value.add(s3.mul(&h0w8i));

    let res_2 = res + c0Value * num * pLiS0Inv_32_term;

    h0w80 = pH0w8_2_term;
    c0Value = ql.add(&h0w80.mul(qr));

    h0w8i = h0w80.mul(h0w80);
    c0Value = c0Value.add(qo.mul(&h0w8i));

    h0w8i = h0w8i.mul(h0w80);
    c0Value = c0Value.add(qm.mul(&h0w8i));

    h0w8i = h0w8i.mul(h0w80);
    c0Value = c0Value.add(qc.mul(&h0w8i));

    h0w8i = h0w8i.mul(h0w80);
    c0Value = c0Value.add(s1.mul(&h0w8i));

    h0w8i = h0w8i.mul(h0w80);
    c0Value = c0Value.add(s2.mul(&h0w8i));

    h0w8i = h0w8i.mul(h0w80);
    c0Value = c0Value.add(s3.mul(&h0w8i));

    let res_3 = res_2 + c0Value * num * pLiS0Inv_64_term;

    h0w80 = pH0w8_3_term;
    c0Value = ql.add(&h0w80.mul(qr));

    h0w8i = h0w80.mul(h0w80);
    c0Value = c0Value.add(qo.mul(&h0w8i));

    h0w8i = h0w8i.mul(h0w80);
    c0Value = c0Value.add(qm.mul(&h0w8i));

    h0w8i = h0w8i.mul(h0w80);
    c0Value = c0Value.add(qc.mul(&h0w8i));

    h0w8i = h0w8i.mul(h0w80);
    c0Value = c0Value.add(s1.mul(&h0w8i));

    h0w8i = h0w8i.mul(h0w80);
    c0Value = c0Value.add(s2.mul(&h0w8i));

    h0w8i = h0w8i.mul(h0w80);
    c0Value = c0Value.add(s3.mul(&h0w8i));

    let res_4 = res_3 + c0Value * num * pLiS0Inv_96_term;

    h0w80 = pH0w8_4_term;
    c0Value = ql.add(&h0w80.mul(qr));

    h0w8i = h0w80.mul(h0w80);
    c0Value = c0Value.add(qo.mul(&h0w8i));

    h0w8i = h0w8i.mul(h0w80);
    c0Value = c0Value.add(qm.mul(&h0w8i));

    h0w8i = h0w8i.mul(h0w80);
    c0Value = c0Value.add(qc.mul(&h0w8i));

    h0w8i = h0w8i.mul(h0w80);
    c0Value = c0Value.add(s1.mul(&h0w8i));

    h0w8i = h0w8i.mul(h0w80);
    c0Value = c0Value.add(s2.mul(&h0w8i));

    h0w8i = h0w8i.mul(h0w80);
    c0Value = c0Value.add(s3.mul(&h0w8i));

    let res_5 = res_4 + c0Value * num * pLiS0Inv_128_term;

    h0w80 = pH0w8_5_term;
    c0Value = ql.add(&h0w80.mul(qr));

    h0w8i = h0w80.mul(h0w80);
    c0Value = c0Value.add(qo.mul(&h0w8i));

    h0w8i = h0w8i.mul(h0w80);
    c0Value = c0Value.add(qm.mul(&h0w8i));

    h0w8i = h0w8i.mul(h0w80);
    c0Value = c0Value.add(qc.mul(&h0w8i));

    h0w8i = h0w8i.mul(h0w80);
    c0Value = c0Value.add(s1.mul(&h0w8i));

    h0w8i = h0w8i.mul(h0w80);
    c0Value = c0Value.add(s2.mul(&h0w8i));

    h0w8i = h0w8i.mul(h0w80);
    c0Value = c0Value.add(s3.mul(&h0w8i));

    let res_6 = res_5 + c0Value * num * pLiS0Inv_160_term;

    h0w80 = pH0w8_6_term;
    c0Value = ql.add(&h0w80.mul(qr));

    h0w8i = h0w80.mul(h0w80);
    c0Value = c0Value.add(qo.mul(&h0w8i));

    h0w8i = h0w8i.mul(h0w80);
    c0Value = c0Value.add(qm.mul(&h0w8i));

    h0w8i = h0w8i.mul(h0w80);
    c0Value = c0Value.add(qc.mul(&h0w8i));

    h0w8i = h0w8i.mul(h0w80);
    c0Value = c0Value.add(s1.mul(&h0w8i));

    h0w8i = h0w8i.mul(h0w80);
    c0Value = c0Value.add(s2.mul(&h0w8i));

    h0w8i = h0w8i.mul(h0w80);
    c0Value = c0Value.add(s3.mul(&h0w8i));

    let res_7 = res_6 + c0Value * num * pLiS0Inv_192_term;

    h0w80 = pH0w8_7_term;
    c0Value = ql.add(&h0w80.mul(qr));

    h0w8i = h0w80.mul(h0w80);
    c0Value = c0Value.add(qo.mul(&h0w8i));

    h0w8i = h0w8i.mul(h0w80);
    c0Value = c0Value.add(qm.mul(&h0w8i));

    h0w8i = h0w8i.mul(h0w80);
    c0Value = c0Value.add(qc.mul(&h0w8i));

    h0w8i = h0w8i.mul(h0w80);
    c0Value = c0Value.add(s1.mul(&h0w8i));

    h0w8i = h0w8i.mul(h0w80);
    c0Value = c0Value.add(s2.mul(&h0w8i));

    h0w8i = h0w8i.mul(h0w80);
    c0Value = c0Value.add(s3.mul(&h0w8i));

    let res_8 = res_7 + c0Value * num * pLiS0Inv_224_term;

    res_8
}

// Compute r1(y) by interpolating the polynomial r1(X) using 4 points (x,y)
// where x = {h1, h1w4, h1w4^2, h1w4^3}
// and   y = {C1(h1), C1(h1w4), C1(h1w4^2), C1(h1w4^3)}
// and computing T0(xi)
fn calculateR1(
    proof: &Proof,
    challenges: &Challenges,
    pi: &Fr,
    li_s1_inv: [Fr; 4],
    zinv: &Fr,
) -> Fr {
    let (xi, y, h1w4) = (challenges.xi, challenges.y, challenges.roots.h1w4.to_vec());

    let mut num = Fr::one();
    let Evaluations {
        a,
        b,
        c,
        ql,
        qc,
        qr,
        qo,
        qm,
        ..
    } = &proof.evaluations;

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

    let mut t0 = ql.mul(a);
    t0 = t0.add(qr.mul(b));
    t0 = t0.add(qm.mul(&a.mul(b)));
    t0 = t0.add(qo.mul(c));
    t0 = t0.add(qc);
    t0 = t0.add(pi);
    // TODO: here should be inverse
    t0 = t0.mul(zinv);

    let mut c1Value = *a;
    c1Value = c1Value.add(H1w4_0.mul(b));
    let square = H1w4_0.mul(H1w4_0);
    c1Value = c1Value.add(c.mul(&square));
    c1Value = c1Value.add(t0.mul(square.mul(H1w4_0)));

    let res_1 = c1Value.mul(num.mul(pLiS1Inv_0_term));

    let mut c1Value = *a;
    c1Value = c1Value.add(H1w4_1.mul(b));
    let square = H1w4_1.mul(H1w4_1);
    c1Value = c1Value.add(c.mul(&square));
    c1Value = c1Value.add(t0.mul(square.mul(H1w4_1)));

    let res_2 = res_1.add(c1Value.mul(num.mul(pLiS1Inv_32_term)));
    // pLiS1Inv_32_term

    let mut c1Value = *a;
    c1Value = c1Value.add(H1w4_2.mul(b));
    let square = H1w4_2.mul(H1w4_2);
    c1Value = c1Value.add(c.mul(&square));
    c1Value = c1Value.add(t0.mul(square.mul(H1w4_2)));

    let res_3 = res_2.add(c1Value.mul(num.mul(pLiS1Inv_64_term)));

    let mut c1Value = *a;
    c1Value = c1Value.add(H1w4_3.mul(b));
    let square = H1w4_3.mul(H1w4_3);
    c1Value = c1Value.add(c.mul(&square));
    c1Value = c1Value.add(t0.mul(square.mul(H1w4_3)));

    let res_4 = res_3.add(c1Value.mul(num.mul(pLiS1Inv_96_term)));

    res_4
}

// Compute r2(y) by interpolating the polynomial r2(X) using 6 points (x,y)
// where x = {[h2, h2w3, h2w3^2], [h3, h3w3, h3w3^2]}
// and   y = {[C2(h2), C2(h2w3), C2(h2w3^2)], [CChallenges::C0x.into_fr()2(h3), C2(h3w3), C2(h3w3^2)]}
// and computing T1(xi) and T2(xi)
fn calculateR2(
    vk: &VerificationKey,
    proof: &Proof,
    challenges: &Challenges,
    eval_l1: &Fr,
    zinv: &Fr,
    li_s2_inv: [Fr; 6],
) -> Fr {
    let (xi, y, gamma, beta, h2w3, h3w3) = (
        challenges.xi,
        challenges.y,
        challenges.gamma,
        challenges.beta,
        challenges.roots.h2w3.to_vec(),
        challenges.roots.h3w3.to_vec(),
    );

    let Evaluations {
        a,
        b,
        c,
        z,
        s1,
        s2,
        s3,
        zw,
        t1w,
        t2w,
        ..
    } = &proof.evaluations;

    let w1 = vk.omega.w;
    let mut num = Fr::one();

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

    let mut t2 = a.add(&betaxi.add(gamma));
    t2 = t2.mul(b.add(&gamma.add(betaxi.mul(k1))));
    t2 = t2.mul(c.add(&gamma.add(betaxi.mul(k2))));
    t2 = t2.mul(z);

    let mut t1 = a.add(&gamma.add(beta.mul(s1)));
    t1 = t1.mul(b.add(&gamma.add(beta.mul(s2))));
    t1 = t1.mul(c.add(&gamma.add(beta.mul(s3))));
    t1 = t1.mul(zw);

    t2 = t2.sub(t1);
    t2 = t2.mul(zinv);

    t1 = z.sub(&Fr::one());
    t1 = t1.mul(eval_l1);
    t1 = t1.mul(zinv);

    let mut gamma_r2 = Fr::zero();
    let mut hw = h2w3_0;
    let mut c2Value = z.add(&hw.mul(t1));
    c2Value = c2Value.add(t2.mul(hw.mul(hw)));
    gamma_r2 = gamma_r2.add(c2Value.mul(num.mul(pLiS2Inv_0_term)));

    hw = h2w3_1;
    c2Value = z.add(&hw.mul(t1));
    c2Value = c2Value.add(t2.mul(hw.mul(hw)));
    gamma_r2 = gamma_r2.add(c2Value.mul(num.mul(pLiS2Inv_32_term)));

    hw = h2w3_2;
    c2Value = z.add(&hw.mul(t1));
    c2Value = c2Value.add(t2.mul(hw.mul(hw)));
    gamma_r2 = gamma_r2.add(c2Value.mul(num.mul(pLiS2Inv_64_term)));

    hw = h3w3_0;
    c2Value = zw.add(&hw.mul(t1w));
    c2Value = c2Value.add(t2w.mul(&hw.mul(hw)));
    gamma_r2 = gamma_r2.add(c2Value.mul(num.mul(pLiS2Inv_96_term)));

    hw = h3w3_1;
    c2Value = zw.add(&hw.mul(t1w));
    c2Value = c2Value.add(t2w.mul(&hw.mul(hw)));
    gamma_r2 = gamma_r2.add(c2Value.mul(num.mul(pLiS2Inv_128_term)));

    hw = h3w3_2;
    c2Value = zw.add(&hw.mul(t1w));
    c2Value = c2Value.add(t2w.mul(&hw.mul(hw)));
    gamma_r2 = gamma_r2.add(c2Value.mul(num.mul(pLiS2Inv_160_term)));

    gamma_r2
}
