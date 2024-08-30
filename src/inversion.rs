use crate::challenge::{Challenges, Roots};
use crate::proof::Proof;
use crate::vk::{Omega, VerificationKey};
use ark_bn254::{Fq, Fr};
use ark_ff::{Field, One, PrimeField, Zero};
use num_bigint::BigUint;
use num_traits::FromPrimitive;
use std::ops::{Add, Mul, Sub};
use std::str::FromStr;

// pub type LiS0 = [Fr; 8];
// pub type LiS1 = [Fr; 4];
// pub type LiS2 = [Fr; 6];
#[derive(Debug, Default, Eq, PartialEq, Copy, Clone)]
pub struct Inversion {
    // L[1], it's related with pub_input numbers.
    pub eval_l1: Fr,
    pub lis_values: LISValues,
    pub den_h1: Fr,
    pub den_h2: Fr,
    // ZH
    pub zh_inv: Fr,
}

#[derive(Debug, Default, Eq, PartialEq, Copy, Clone)]
pub struct LISValues {
    pub li_s0_inv: [Fr; 8],
    pub li_s1_inv: [Fr; 4],
    pub li_s2_inv: [Fr; 6],
}

impl Inversion {
    pub fn compute_den_h1_base(roots: &Roots, y: &Fr) -> Fr {
        (y - &roots.h1w4[0]) * (y - &roots.h1w4[1]) * (y - &roots.h1w4[2]) * (y - &roots.h1w4[3])
    }
    pub fn compute_den_h2_base(roots: &Roots, y: &Fr) -> Fr {
        (y - &roots.h2w3[0])
            * (y - &roots.h2w3[1])
            * (y - &roots.h2w3[2])
            * (y - &roots.h3w3[0])
            * (y - &roots.h3w3[1])
            * (y - &roots.h3w3[2])
    }

    // Li_2 = n * (xi - 1)
    pub fn compute_eval_l1_base(xi: &Fr, n: &Fr) -> Fr {
        (xi - &Fr::one()) * n
    }

    // Li_2 = n * (xi - w1)
    pub fn compute_eval_l2_base(xi: &Fr, n: &Fr, w1: &Fr) -> Fr {
        (xi - w1) * n
    }

    // To divide prime fields the Extended Euclidean Algorithm for computing modular inverses is needed.
    // The Montgomery batch inversion algorithm allow us to compute n inverses reducing to a single one inversion.
    // More info: https://vitalik.ca/general/2018/07/21/starks_part_3.html
    // To avoid this single inverse computation on-chain, it has been computed in proving time and send it to the verifier.
    // Therefore, the verifier:
    //      1) Prepare all the denominators to inverse
    //      2) Check the inverse sent by the prover it is what it should be
    //      3) Compute the others inverses using the Montgomery Batched Algorithm using the inverse sent to avoid the inversion operation it does.
    pub fn build(vk: &VerificationKey, proof: &Proof, challenges: &Challenges) -> Inversion {
        let roots = &challenges.roots;
        let (y, xi, zh) = (challenges.y, challenges.xi, challenges.zh);

        // 1. compute den_h1_base
        let den_h1_base = Self::compute_den_h1_base(&roots, &y);
        // 1. compute den_h2_base
        let den_h2_base = Self::compute_den_h2_base(&roots, &y);

        let li_s0 = Self::compute_li_s0(y, &roots.h0w8);

        let li_s1 = Self::compute_li_s1(y, &roots.h1w4);

        let li_s2 = Self::compute_li_s2(vk, y, xi, &roots.h2w3, &roots.h3w3);

        let eval_l1_base = Self::compute_eval_l1_base(&xi, &vk.n);

        let (lis_values, den_h1, den_h2, eval_l1) = Self::inverse_array(
            proof,
            &den_h1_base,
            &den_h2_base,
            &zh,
            &li_s0,
            &li_s1,
            &li_s2,
            &eval_l1_base,
        );
        // assert_eq!(Self::compute_eval_l1_base(&xi, &vk.n)*eval_l1, Fr::one());

        Inversion {
            eval_l1,
            lis_values,
            den_h1,
            den_h2,
            zh_inv: zh.inverse().unwrap(),
        }
    }

    pub fn compute_li_s0(y: Fr, h0w8: &[Fr]) -> [Fr; 8] {
        // root0^6 * 8
        let den1 = h0w8[0].pow([6]) * Fr::from(8);

        let mut li_s0_inv: [Fr; 8] = [Fr::zero(); 8];

        for i in 0..8 {
            li_s0_inv[i] = den1 * h0w8[(i * 7) % 8] * (y - h0w8[i]);
        }

        li_s0_inv
    }

    pub fn compute_li_s1(y: Fr, h1w4: &[Fr]) -> [Fr; 4] {
        let den1 = h1w4[0].pow([2]) * Fr::from(4);

        let mut li_s1_inv: [Fr; 4] = [Fr::zero(); 4];

        for i in 0..4 {
            li_s1_inv[i] = den1 * h1w4[(i * 3) % 4] * (y - h1w4[i]);
        }

        li_s1_inv
    }

    pub fn compute_li_s2(vk: &VerificationKey, y: Fr, xi: Fr, h2w3: &[Fr], h3w3: &[Fr]) -> [Fr; 6] {
        let xiw = xi * vk.omega.w;

        let den1 = Fr::from(3) * h2w3[0] * (xi - xiw);

        let mut li_s2_inv: [Fr; 6] = [Fr::zero(); 6];

        for i in 0..3 {
            li_s2_inv[i] = den1 * h2w3[(i * 2) % 3] * (y - h2w3[i]);
        }

        let den1 = Fr::from(3) * h3w3[0] * (xiw - xi);
        for i in 0..3 {
            li_s2_inv[i + 3] = den1 * h3w3[(i * 2) % 3] * (y - h3w3[i]);
        }

        li_s2_inv
    }

    // build accumulator
    //      [0]=zh
    //      [1]=zh*den_h1_base
    //      [2]=zh*den_h1_base*den_h2_base
    //      [3..10]=zh*den_h1_base*den_h2_base*MUL(li_s0[i])
    //      [11..14]=zh*den_h1_base*den_h2_base*MUL(li_s0[i])*MUL(li_s1[i])
    //      [15..20]=zh*den_h1_base*den_h2_base*MUL(li_s0[i])*MUL(li_s1[i])*MUL(li_s2[i])
    //      [21]=zh*den_h1_base*den_h2_base*MUL(li_s0[i])*MUL(li_s1[i])*MUL(li_s2[i])*eval_l1
    pub fn accumulator(
        den_h1_base: &Fr,
        den_h2_base: &Fr,
        zh: &Fr,
        li_s0: &[Fr; 8],
        li_s1: &[Fr; 4],
        li_s2: &[Fr; 6],
        eval_l1: &Fr,
    ) -> Vec<Fr> {
        let mut accumulator: Vec<Fr> = Vec::new();
        accumulator.push(zh.clone());

        // acc = zh*den_h1
        let mut acc = zh.mul(den_h1_base);
        accumulator.push(acc.clone());

        // acc = zh*den_h1*den_h2
        acc = acc.mul(den_h2_base);
        accumulator.push(acc.clone());

        // acc = zh*den_h1*den_h2 * MUL(li_s0[i])
        for i in 0..8 {
            acc = acc * li_s0[i];
            accumulator.push(acc);
        }
        // acc = zh*den_h1*den_h2 * MUL(li_s0[i]) * MUL(li_s1[i])
        for i in 0..4 {
            acc = acc * li_s1[i];
            accumulator.push(acc);
        }
        // acc = zh*den_h1*den_h2 * MUL(li_s0[i]) * MUL(li_s1[i]) * MUL(li_s2[i])
        for i in 0..6 {
            acc = acc * li_s2[i];
            accumulator.push(acc);
        }

        // acc = zh*den_h1*den_h2 * MUL(li_s0[i]) * MUL(li_s1[i]) * MUL(li_s2[i])* eval_l1
        acc = acc * eval_l1.clone();
        accumulator.push(acc);
        accumulator
    }

    pub fn check_accumulator(accumulator: &Vec<Fr>, proof: &Proof) {
        // check `zh*den_h1*den_h2 * MUL(li_s0[i]) * MUL(li_s1[i]) * MUL(li_s2[i])* eval_l1 * proof.inv = 1`
        assert_eq!(
            accumulator.last().unwrap() * &proof.evaluations.inv,
            Fr::one()
        );
    }

    pub fn inverse_with_accumulator(
        accumulator: &mut Vec<Fr>,
        proof: &Proof,
        den_h1_base: &Fr,
        den_h2_base: &Fr,
        zh: &Fr,
        li_s0: &[Fr; 8],
        li_s1: &[Fr; 4],
        li_s2: &[Fr; 6],
        eval_l1: &Fr,
    ) -> (LISValues, Fr, Fr, Fr) {
        // Start Inverse:

        // pop eval_li out
        accumulator.pop();

        // Inverse is : inverse of the value computed by accumulator.
        // eg: zh*den_h1*den_h2 * MUL(li_s0[i]) * MUL(li_s1[i]) * MUL(li_s2[i])* eval_l1 * proof.inv = 1
        //     So that
        //      eval_l1_inv
        //          = eval_l1.inverse()
        //          = zh*den_h1*den_h2 * MUL(li_s0[i]) * MUL(li_s1[i]) * MUL(li_s2[i]) * proof.inv

        // inv = proof.inv
        let mut inv = proof.evaluations.inv;
        // acc = proof.inv
        let mut acc = proof.evaluations.inv;

        // inv = proof.inv * zh*den_h1*den_h2 * MUL(li_s0[i]) * MUL(li_s1[i]) * MUL(li_s2[i])=eval_inv
        inv = acc * accumulator.pop().unwrap();
        // acc = inv*eval
        acc = acc.mul(eval_l1.clone());
        let eval_l1_inv = inv * zh;

        let mut local_li_s2_inv = [Fr::zero(); 6];

        for i in (0..6).rev() {
            inv = acc * accumulator.pop().unwrap();
            acc = acc.mul(li_s2[i]);
            local_li_s2_inv[i] = inv;
        }

        let mut local_li_s1_inv = [Fr::zero(); 4];
        for i in (0..4).rev() {
            inv = acc * accumulator.pop().unwrap();

            acc = acc.mul(li_s1[i]);
            local_li_s1_inv[i] = inv;
        }

        let mut local_li_s0_inv = [Fr::zero(); 8];
        for i in (0..8).rev() {
            inv = acc * accumulator.pop().unwrap();
            acc = acc.mul(li_s0[i]);
            local_li_s0_inv[i] = inv;
        }

        inv = acc * accumulator.pop().unwrap();
        acc = acc.mul(den_h2_base);
        let local_den_h2 = inv;
        assert_eq!(local_den_h2, den_h2_base.inverse().unwrap());

        inv = acc * accumulator.pop().unwrap();
        acc = acc.mul(den_h1_base);
        let local_den_h1 = inv;
        assert_eq!(local_den_h1, den_h1_base.inverse().unwrap());

        let local_zh_inv = acc;
        assert_eq!(local_zh_inv, zh.inverse().unwrap());

        let lis_values = LISValues {
            li_s0_inv: local_li_s0_inv,
            li_s1_inv: local_li_s1_inv,
            li_s2_inv: local_li_s2_inv,
        };

        (lis_values, local_den_h1, local_den_h2, eval_l1_inv)
    }

    // Computes the inverse of an array of values
    // See https://vitalik.ca/general/2018/07/21/starks_part_3.html in section where explain fields operations
    // To save the inverse to be computed on chain the prover sends the inverse as an evaluation in commits.eval_inv
    pub fn inverse_array(
        proof: &Proof,
        den_h1_base: &Fr,
        den_h2_base: &Fr,
        zh: &Fr,
        li_s0: &[Fr; 8],
        li_s1: &[Fr; 4],
        li_s2: &[Fr; 6],
        eval_l1: &Fr,
    ) -> (LISValues, Fr, Fr, Fr) {
        let mut accumulator = Self::accumulator(
            &den_h1_base,
            &den_h2_base,
            &zh,
            &li_s0,
            &li_s1,
            &li_s2,
            eval_l1,
        );

        Self::check_accumulator(&accumulator, proof);

        Self::inverse_with_accumulator(
            &mut accumulator,
            proof,
            den_h1_base,
            den_h2_base,
            zh,
            li_s0,
            li_s1,
            li_s2,
            &eval_l1,
        )
    }
}
