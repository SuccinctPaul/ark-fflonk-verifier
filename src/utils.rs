use crate::challenge::Challenges;
use crate::compute_fej::FEJ;
use crate::proof::Proof;
use ark_bn254::{Fr, G1Affine};
use ark_ec::CurveGroup;
use ark_ff::{Field, PrimeField};
use num_traits::{One, Zero};
use std::fs::File;
use std::io::Read;
use std::ops::Neg;
use std::path::Path;
use std::str::FromStr;

// Compute zero polynomial evaluation
//      Z_H(xi) = xi^n - 1
pub fn compute_zero_poly_evals(xi: &Fr, n: &Fr) -> Fr {
    // 1. Compute xin = xi^n
    let xin = xi.pow(n.into_bigint());

    // 2. zh = xin - 1
    let zh = xin - Fr::one();
    zh
}

// Compute Lagrange polynomial evaluation
//      Li(xi)= w(x^n-1)/(n*(xi-w)
//            = w*zh/(n*(xi-w)
//
// Note: w means omega
pub struct LangrangePolynomialEvaluation;
impl LangrangePolynomialEvaluation {
    // Compute Langrange polynomial evaluation base:
    //      Li_base = n * (xi - omega)
    // eg:
    //  Li_1_base = n * (xi - 1), which omega=w0=1
    //  Li_2_base = n * (xi - w1), which omega = w1
    pub fn compute_lagrange_base(xi: &Fr, n: &Fr, omega: &Fr) -> Fr {
        (xi - omega) * n
    }
    pub fn compute_L1_base(xi: &Fr, n: &Fr) -> Fr {
        Self::compute_lagrange_base(xi, n, &Fr::one())
    }

    // Compute Lagrange polynomial evaluation L_i(xi)
    //      Li = omega * zh * Li_base
    //
    // eg:
    //  Li_1 = zh * Li_1_base_inv, which omega=w0=1
    //  Li_2 = w1 * zh * Li_2_base_inv , which omega = w1
    pub fn compute_lagrange_polynomial_evaluation(zh: &Fr, Li_inv: &Fr, omega: &Fr) -> Fr {
        omega * zh * Li_inv
    }

    pub fn compute_L1_polynomial_evaluation(zh: &Fr, L1_base_inv: &Fr) -> Fr {
        Self::compute_lagrange_polynomial_evaluation(zh, L1_base_inv, &Fr::one())
    }
}

// Compute public input polynomial evaluation `PI(xi)`:
// $PI(xi) = -\sum_i^l PublicInput_i·L_i(xi)$
pub fn compute_pi(pub_inputs: &[Fr], eval_ls: &[Fr]) -> Fr {
    pub_inputs
        .iter()
        .zip(eval_ls.iter())
        .map(|(pub_input_i, eval_li)| pub_input_i * eval_li)
        .sum::<Fr>()
        .neg()
}

// Compute P1 in the pairing.
//      F = F - E - J + y·W2
pub fn compute_a1(proof: &Proof, fej: &FEJ, challenges: &Challenges) -> G1Affine {
    let W2 = proof.polynomials.w2;

    // F = F - E - J + y·W2
    (fej.F - fej.E - fej.J + W2 * challenges.y).into_affine()
}

pub fn polynomial_eval(
    base: Fr,
    coefficients: &[Fr],
    challenges: &[Fr],
    inv: &[Fr],
    acc: Option<Fr>,
) -> Fr {
    let mut acc = acc.unwrap_or(Fr::zero());
    for (i, root) in challenges.iter().enumerate() {
        let mut h = Fr::one();
        let mut c1_value = Fr::zero();
        for c in coefficients {
            c1_value += (*c) * h;
            h *= *root
        }
        acc += c1_value * base * inv[i]
    }
    acc
}

// For now, only support single public inputs.
pub fn load_public_input<P: AsRef<Path>>(pi_path: P) -> anyhow::Result<Fr> {
    let mut file = File::open(pi_path)?;
    let mut vk_json = String::new();
    file.read_to_string(&mut vk_json)?;
    let mut pub_inputs: Vec<String> = serde_json::from_str(&vk_json)?;
    assert_eq!(pub_inputs.len(), 1);
    let fr_str = pub_inputs.pop().unwrap();
    Ok(Fr::from_str(&fr_str).unwrap())
}
