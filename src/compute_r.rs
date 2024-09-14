use crate::challenge::Challenges;
use crate::inversion::Inversion;
use crate::proof::{Proof};
use crate::utils::polynomial_eval;
use crate::vk::VerificationKey;
use ark_bn254::Fr;
use ark_ff::{Field, One};

pub fn compute_r(
    vk: &VerificationKey,
    proof: &Proof,
    challenges: &Challenges,
    inversion: &Inversion,
    L_1: &Fr,
    pi: &Fr,
) -> (Fr, Fr, Fr) {
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
        L_1,
        &inversion.zh_inv,
        inversion.lis_values.li_s2_inv,
    );

    (R0, R1, R2)
}

// Compute r0(y) by interpolating the polynomial r0(X) using 8 points (x,y)
// where x = {h9, h0w8, h0w8^2, h0w8^3, h0w8^4, h0w8^5, h0w8^6, h0w8^7}
// and   y = {C0(h0), C0(h0w8), C0(h0w8^2), C0(h0w8^3), C0(h0w8^4), C0(h0w8^5), C0(h0w8^6), C0(h0w8^7)}
// and computing C0(xi)
pub fn calculateR0(proof: &Proof, challenges: &Challenges, li_s0_inv: [Fr; 8]) -> Fr {
    // compute num
    let num = challenges.y.pow([8]) - challenges.xi;

    let evaluations = &proof.evaluations;

    let coefficients = [
        evaluations.ql,
        evaluations.qr,
        evaluations.qo,
        evaluations.qm,
        evaluations.qc,
        evaluations.s1,
        evaluations.s2,
        evaluations.s3,
    ];

    // Compute c0Value = ql + (h0w8[i]) qr + (h0w8[i])^2 qo + (h0w8[i])^3 qm + (h0w8[i])^4 qc +
    //                      + (h0w8[i])^5 S1 + (h0w8[i])^6 S2 + (h0w8[i])^7 S3
    polynomial_eval(num, &coefficients, &challenges.roots.h0w8, &li_s0_inv, None)
}
// Compute r1(y) by interpolating the polynomial r1(X) using 4 points (x,y)
// where x = {h1, h1w4, h1w4^2, h1w4^3}
// and   y = {C1(h1), C1(h1w4), C1(h1w4^2), C1(h1w4^3)}
// and computing T0(xi)
pub fn calculateR1(
    proof: &Proof,
    challenges: &Challenges,
    pi: &Fr,
    li_s1_inv: [Fr; 4],
    zh_inv: &Fr,
) -> Fr {
    let num = challenges.y.pow([4]) - challenges.xi;
    let evaluations = &proof.evaluations;

    let t0 = (evaluations.ql * evaluations.a
        + evaluations.qr * evaluations.b
        + evaluations.qm * evaluations.a * evaluations.b
        + evaluations.qo * evaluations.c
        + evaluations.qc
        + pi)
        * zh_inv;
    let coefficients = [evaluations.a, evaluations.b, evaluations.c, t0];

    polynomial_eval(num, &coefficients, &challenges.roots.h1w4, &li_s1_inv, None)
}

// Compute r2(y) by interpolating the polynomial r2(X) using 6 points (x,y)
// where x = {[h2, h2w3, h2w3^2], [h3, h3w3, h3w3^2]}
// and   y = {[C2(h2), C2(h2w3), C2(h2w3^2)], [CChallenges::C0x.into_fr()2(h3), C2(h3w3), C2(h3w3^2)]}
// and computing T1(xi) and T2(xi)
pub fn calculateR2(
    vk: &VerificationKey,
    proof: &Proof,
    challenges: &Challenges,
    L_1: &Fr,
    zh_inv: &Fr,
    li_s2_inv: [Fr; 6],
) -> Fr {
    // base = y^6 - y^3*xi*(1-w) + xi^2*w
    let base = challenges.y.pow([6])
        - (challenges.y.pow([3]) * challenges.xi * (Fr::one() + vk.omega.w))
        + (challenges.xi * challenges.xi * vk.omega.w);
    let evaluations = &proof.evaluations;

    let t1 = (evaluations.z - Fr::one()) * L_1 * zh_inv;
    let beta_xi = challenges.beta * challenges.xi;

    let t2 = (((evaluations.a + beta_xi + challenges.gamma)
        * (evaluations.b + beta_xi * vk.k1 + challenges.gamma)
        * (evaluations.c + beta_xi * vk.k2 + challenges.gamma)
        * evaluations.z)
        - ((evaluations.a + challenges.beta * evaluations.s1 + challenges.gamma)
            * (evaluations.b + challenges.beta * evaluations.s2 + challenges.gamma)
            * (evaluations.c + challenges.beta * evaluations.s3 + challenges.gamma)
            * evaluations.zw))
        * zh_inv;

    let coefficients = [evaluations.z, t1, t2];
    let gamma = polynomial_eval(
        base,
        &coefficients,
        &challenges.roots.h2w3,
        &li_s2_inv[0..3],
        None,
    );

    let coefficients = [evaluations.zw, evaluations.t1w, evaluations.t2w];
    polynomial_eval(
        base,
        &coefficients,
        &challenges.roots.h3w3,
        &li_s2_inv[3..],
        Some(gamma),
    )
}
