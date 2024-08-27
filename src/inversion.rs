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
    pub zh_inv: Fr,
}

#[derive(Debug, Default, Eq, PartialEq, Copy, Clone)]
pub struct LISValues {
    pub li_s0_inv: [Fr; 8],
    pub li_s1_inv: [Fr; 4],
    pub li_s2_inv: [Fr; 6],
}

impl Inversion {
    fn compute_den_h1_base(roots: &Roots, y: &Fr) -> Fr {
        (y - &roots.h1w4[0]) * (y - &roots.h1w4[1]) * (y - &roots.h1w4[2]) * (y - &roots.h1w4[3])
    }
    fn compute_den_h2_base(roots: &Roots, y: &Fr) -> Fr {
        (y - &roots.h2w3[0])
            * (y - &roots.h2w3[1])
            * (y - &roots.h2w3[2])
            * (y - &roots.h3w3[0])
            * (y - &roots.h3w3[1])
            * (y - &roots.h3w3[2])
    }

    fn compute_eval_l1_base(xi: &Fr, n: &Fr) -> Fr {
        (xi - &Fr::one()) * n
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

        // 1. compute den_h1,den_h2 base
        let den_h1_base = Self::compute_den_h1_base(&roots, &y);
        let den_h2_base = Self::compute_den_h2_base(&roots, &y);

        let li_s0 = Self::compute_li_s0(y, &roots.h0w8);

        let li_s1 = Self::compute_li_s1(y, &roots.h1w4);

        let li_s2 = Self::compute_li_s2(vk, y, xi, &roots.h2w3, &roots.h3w3);

        let mut eval_l1 = Self::compute_eval_l1_base(&xi, &vk.n);

        let (lis_values, den_h1, den_h2) = Self::inverseArray(
            proof,
            den_h1_base,
            den_h2_base,
            zh,
            li_s0,
            li_s1,
            li_s2,
            &mut eval_l1,
        );

        eval_l1 *= zh;

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
        let mut den1 = h0w8[0].pow([6]) * Fr::from(8);

        let mut li_s0_inv: [Fr; 8] = [Fr::zero(); 8];

        for i in 0..8 {
            let coeff = (i * 7) % 8;
            li_s0_inv[i] = den1 * h0w8[0 + coeff] * (y - h0w8[0 + (i)]);
        }

        li_s0_inv
    }

    pub fn compute_li_s1(y: Fr, h1w4: &[Fr]) -> [Fr; 4] {
        let mut den1 = h1w4[0].pow([2]) * Fr::from(4);

        let mut li_s1_inv: [Fr; 4] = [Fr::zero(); 4];

        for i in 0..4 {
            let coeff = (i * 3) % 4;

            li_s1_inv[i] = den1 * h1w4[0 + coeff] * (y - h1w4[0 + (i)]);
        }

        li_s1_inv
    }

    pub fn compute_li_s2(vk: &VerificationKey, y: Fr, xi: Fr, h2w3: &[Fr], h3w3: &[Fr]) -> [Fr; 6] {
        let mut den1 = Fr::from(3) * h2w3[0] * (xi - xi * vk.omega.w);

        let mut li_s2_inv: [Fr; 6] = [Fr::zero(); 6];

        for i in 0..3 {
            let coeff = (i * 2) % 3;
            li_s2_inv[i] = den1 * h2w3[0 + coeff] * (y - h2w3[0 + (i)]);
        }

        let den1 = Fr::from(3) * h3w3[0] * (xi * vk.omega.w - xi);
        for i in 0..3 {
            let coeff = (i * 2) % 3;
            li_s2_inv[i + 3] = den1 * h3w3[0 + coeff] * (y - h3w3[0 + (i)]);
        }

        li_s2_inv
    }

    pub fn inverseArray(
        proof: &Proof,
        den_h1: Fr,
        den_h2: Fr,
        zhInv: Fr,
        li_s0_inv: [Fr; 8],
        li_s1_inv: [Fr; 4],
        li_s2_inv: [Fr; 6],
        eval_l1: &mut Fr,
    ) -> (LISValues, Fr, Fr) {
        let mut local_den_h1 = den_h1.clone();
        let mut local_den_h2 = den_h2.clone();
        let mut local_zh_inv = zhInv.clone();
        let mut local_li_s0_inv = li_s0_inv.clone();
        let mut local_li_s1_inv = li_s1_inv.clone();
        let mut local_li_s2_inv = li_s2_inv.clone();

        let mut _acc: Vec<Fr> = Vec::new();

        _acc.push(zhInv.clone());

        let mut acc = zhInv.mul(den_h1);
        _acc.push(acc.clone());

        acc = acc.mul(den_h2);
        _acc.push(acc.clone());

        for i in 0..8 {
            acc = acc * local_li_s0_inv[i];
            _acc.push(acc);
        }
        for i in 0..4 {
            acc = acc * local_li_s1_inv[i];

            _acc.push(acc);
        }
        for i in 0..6 {
            acc = acc * local_li_s2_inv[i];
            _acc.push(acc);
        }
        acc = acc * eval_l1.clone();

        _acc.push(acc);

        let check = acc * proof.evaluations.inv;
        assert_eq!(check, Fr::one());

        let mut inv = proof.evaluations.inv;
        let mut acc = inv.clone();

        _acc.pop();
        inv = acc.mul(_acc.last().unwrap().clone());
        acc = acc.mul(eval_l1.clone());
        *eval_l1 = inv;

        for i in (0..6).rev() {
            _acc.pop();
            inv = acc.mul(_acc.last().unwrap().clone());
            acc = acc.mul(local_li_s2_inv[i]);
            local_li_s2_inv[i] = inv;
        }

        for i in (0..4).rev() {
            _acc.pop();
            inv = acc.mul(_acc.last().unwrap().clone());
            acc = acc.mul(local_li_s1_inv[i]);
            local_li_s1_inv[i] = inv;
        }

        for i in (0..8).rev() {
            _acc.pop();
            inv = acc.mul(_acc.last().unwrap().clone());
            acc = acc.mul(local_li_s0_inv[i]);
            local_li_s0_inv[i] = inv;
        }

        _acc.pop();
        inv = acc.mul(_acc.last().unwrap().clone());
        acc = acc.mul(den_h2);
        local_den_h2 = inv;

        _acc.pop();
        inv = acc.mul(_acc.last().unwrap().clone());
        acc = acc.mul(den_h1);
        local_den_h1 = inv;

        local_zh_inv = acc;

        let lis_values = LISValues {
            li_s0_inv: local_li_s0_inv,
            li_s1_inv: local_li_s1_inv,
            li_s2_inv: local_li_s2_inv,
        };

        (lis_values, local_den_h1, local_den_h2)
    }
}
