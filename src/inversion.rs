use crate::challenge::Roots;
use crate::{get_domain_size, get_omegas, get_proof};
use ark_bn254::{Fr};
use ark_ff::{One, Zero};
use std::ops::{Add, Mul, Sub};
use std::str::FromStr;

// pub type LiS0 = [Fr; 8];
// pub type LiS1 = [Fr; 4];
// pub type LiS2 = [Fr; 6];
#[derive(Debug, PartialEq)]
pub struct Inversion {
    pub eval_l1: Fr,
    pub lis_values: LISValues,
    pub denH1: Fr,
    pub denH2: Fr,
    // pub zh_inv: Fr,
}

#[derive(Debug, PartialEq)]
pub struct LISValues {
    pub li_s0_inv: [Fr; 8],
    pub li_s1_inv: [Fr; 4],
    pub li_s2_inv: [Fr; 6],
}

impl Inversion {
    // To divide prime fields the Extended Euclidean Algorithm for computing modular inverses is needed.
    // The Montgomery batch inversion algorithm allow us to compute n inverses reducing to a single one inversion.
    // More info: https://vitalik.ca/general/2018/07/21/starks_part_3.html
    // To avoid this single inverse computation on-chain, it has been computed in proving time and send it to the verifier.
    // Therefore, the verifier:
    //      1) Prepare all the denominators to inverse
    //      2) Check the inverse sent by the prover it is what it should be
    //      3) Compute the others inverses using the Montgomery Batched Algorithm using the inverse sent to avoid the inversion operation it does.

    pub fn build(y: Fr, xi: Fr, zh: Fr, roots: &Roots) -> Inversion {
        // 1. compute den_h1 base
        let mut w = y.sub(roots.h1w4[0]).mul(
            y.sub(roots.h1w4[1])
                .mul(y.sub(roots.h1w4[2]).mul(y.sub(roots.h1w4[3]))),
        );
        // println!("w: {}", (w));

        let denH1 = w.clone();

        w = y.sub(roots.h2w3[0]).mul(
            y.sub(roots.h2w3[1]).mul(y.sub(roots.h2w3[2])).mul(
                y.sub(roots.h3w3[0])
                    .mul(y.sub(roots.h3w3[1]).mul(y.sub(roots.h3w3[2]))),
            ),
        );

        let denH2 = w.clone();

        let li_s0_inv = Self::computeLiS0(y, &roots.h0w8);

        let li_s1_inv = Self::computeLiS1(y, &roots.h1w4);

        let li_s2_inv = Self::computeLiS2(y, xi, &roots.h2w3, &roots.h3w3);

        let w = Fr::one();

        let mut eval_l1 = get_domain_size().mul(xi.sub(w));

        let (lis_values, denH1, denH2) = Self::inverseArray(
            denH1,
            denH2,
            zh,
            li_s0_inv,
            li_s1_inv,
            li_s2_inv,
            &mut eval_l1,
        );

        eval_l1 *= zh;

        Inversion {
            eval_l1,
            lis_values,
            denH1,
            denH2,
        }
    }

    pub fn computeLiS0(y: Fr, h0w8: &[Fr]) -> [Fr; 8] {
        let root0 = h0w8[0];

        let mut den1 = Fr::one();
        den1 = den1
            .mul(root0)
            .mul(root0)
            .mul(root0)
            .mul(root0)
            .mul(root0)
            .mul(root0);

        // println!("den1: {}", den1);

        den1 = den1.mul(Fr::from_str("8").unwrap());

        let mut den2;
        let mut den3;

        let mut li_s0_inv: [Fr; 8] = [Fr::zero(); 8];

        let q = Fr::from_str(
            "21888242871839275222246405745257275088548364400416034343698204186575808495617",
        )
        .unwrap();

        for i in 0..8 {
            let coeff = (i * 7) % 8;
            den2 = h0w8[0 + coeff];
            // println!("den2: {}", den2);
            den3 = y.add(q.sub(h0w8[0 + (i)]));
            // println!("den3: {}", den3);

            li_s0_inv[i] = den1.mul(den2).mul(den3);

            // println!("li_s0_inv: {}", li_s0_inv[i]);
            // println!();
        }
        // println!("li_s0_inv: {}", li_s0_inv[7]);

        li_s0_inv
    }

    pub fn computeLiS1(y: Fr, h1w4: &[Fr]) -> [Fr; 4] {
        let root0 = h1w4[0];
        let mut den1 = Fr::one();
        den1 = den1.mul(root0).mul(root0);

        den1 = den1.mul(Fr::from_str("4").unwrap());

        let q = Fr::from_str(
            "21888242871839275222246405745257275088548364400416034343698204186575808495617",
        )
        .unwrap();

        let mut den2;
        let mut den3;

        let mut li_s1_inv: [Fr; 4] = [Fr::zero(); 4];

        for i in 0..4 {
            let coeff = (i * 3) % 4;
            den2 = h1w4[0 + coeff];
            den3 = y.add(q.sub(h1w4[0 + (i)]));
            li_s1_inv[i] = den1.mul(den2).mul(den3);
        }

        // println!("li_s1_inv: {}", li_s1_inv[3]);
        li_s1_inv
    }

    pub fn computeLiS2(y: Fr, xi: Fr, h2w3: &[Fr], h3w3: &[Fr]) -> [Fr; 6] {
        let q = Fr::from_str(
            "21888242871839275222246405745257275088548364400416034343698204186575808495617",
        )
        .unwrap();

        // let den1 := mulmod(mulmod(3,mload(add(pMem, pH2w3_0)),q), addmod(mload(add(pMem, pXi)) ,mod(sub(q, mulmod(mload(add(pMem, pXi)), w1 ,q)), q), q), q)
        let omegas = get_omegas();
        let mut den1 =
            (Fr::from_str("3").unwrap().mul(h2w3[0])).mul(xi.add(q.sub(xi.mul(omegas.w1))));

        let mut den2;
        let mut den3;

        let mut li_s2_inv: [Fr; 6] = [Fr::zero(); 6];

        for i in 0..3 {
            let coeff = (i * 2) % 3;
            den2 = h2w3[0 + coeff];
            den3 = y.add(q.sub(h2w3[0 + (i)]));
            li_s2_inv[i] = den1.mul(den2).mul(den3);
        }

        den1 = (Fr::from_str("3").unwrap().mul(h3w3[0])).mul(xi.mul(omegas.w1).add(q.sub(xi)));

        for i in 0..3 {
            let coeff = (i * 2) % 3;
            den2 = h3w3[0 + coeff];
            den3 = y.add(q.sub(h3w3[0 + (i)]));
            li_s2_inv[i + 3] = den1.mul(den2).mul(den3);
        }

        li_s2_inv
    }

    pub fn inverseArray(
        denH1: Fr,
        denH2: Fr,
        zhInv: Fr,
        li_s0_inv: [Fr; 8],
        li_s1_inv: [Fr; 4],
        li_s2_inv: [Fr; 6],
        eval_l1: &mut Fr,
    ) -> (LISValues, Fr, Fr) {
        // let mut local_eval_l1 = eval_l1.clone();
        let mut local_den_h1 = denH1.clone();
        let mut local_den_h2 = denH2.clone();
        let mut local_zh_inv = zhInv.clone();
        let mut local_li_s0_inv = li_s0_inv.clone();
        let mut local_li_s1_inv = li_s1_inv.clone();
        let mut local_li_s2_inv = li_s2_inv.clone();

        let mut _acc: Vec<Fr> = Vec::new();

        _acc.push(zhInv.clone());

        let mut acc = zhInv.mul(denH1);
        _acc.push(acc.clone());

        acc = acc.mul(denH2);
        _acc.push(acc.clone());

        for i in 0..8 {
            acc = acc.mul(local_li_s0_inv[i]);
            _acc.push(acc);
        }
        for i in 0..4 {
            acc = acc.mul(local_li_s1_inv[i]);
            _acc.push(acc);
        }
        for i in 0..6 {
            acc = acc.mul(local_li_s2_inv[i]);
            _acc.push(acc);
        }
        acc = acc.mul(eval_l1.clone());
        _acc.push(acc);
        // println!("acc: {}", acc);
        // println!("acc wala xeval_l1: {}", eval_l1);

        let mut inv = get_proof().eval_inv;

        // println!("inv: {}", inv);

        let check = inv.mul(acc);
        // println!("check: {}", check);
        assert!(check == Fr::one());

        acc = inv.clone();

        _acc.pop();
        inv = acc.mul(_acc.last().unwrap().clone());
        acc = acc.mul(eval_l1.clone());
        *eval_l1 = inv;
        // println!("herer eval_l1: {}", eval_l1);

        for i in (0..6).rev() {
            _acc.pop();
            inv = acc.mul(_acc.last().unwrap().clone());
            acc = acc.mul(local_li_s2_inv[i]);
            local_li_s2_inv[i] = inv;
        }
        // println!("local_li_s2_inv_0: {}", local_li_s2_inv[0]);

        for i in (0..4).rev() {
            _acc.pop();
            inv = acc.mul(_acc.last().unwrap().clone());
            acc = acc.mul(local_li_s1_inv[i]);
            local_li_s1_inv[i] = inv;
        }

        // println!("local_li_s1_inv_0: {}", local_li_s1_inv[0]);

        for i in (0..8).rev() {
            _acc.pop();
            inv = acc.mul(_acc.last().unwrap().clone());
            acc = acc.mul(local_li_s0_inv[i]);
            local_li_s0_inv[i] = inv;
        }

        // println!("local_li_s0_inv_0: {}", local_li_s0_inv[0]);

        _acc.pop();
        inv = acc.mul(_acc.last().unwrap().clone());
        acc = acc.mul(denH2);
        local_den_h2 = inv;

        _acc.pop();
        inv = acc.mul(_acc.last().unwrap().clone());
        acc = acc.mul(denH1);
        local_den_h1 = inv;

        local_zh_inv = acc;

        let lis_values = LISValues {
            li_s0_inv: local_li_s0_inv,
            li_s1_inv: local_li_s1_inv,
            li_s2_inv: local_li_s2_inv,
        };

        (lis_values, local_den_h1, local_den_h2)
        // println!("local_zh_inv: {}", local_zh_inv);
    }
}
