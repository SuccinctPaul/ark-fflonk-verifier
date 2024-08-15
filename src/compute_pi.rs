use ark_bn254::Fr;
use ark_ff::Zero;
use std::ops::{Add, Mul, Sub};
use std::str::FromStr;

// Compute public input polynomial evaluation PI(xi) = \sum_i^l -public_input_i·L_i(xi)
pub fn compute_pi(pubSignals: &Fr, eval_l1: Fr) -> Fr {
    let pi = Fr::zero();

    let q = Fr::from_str(
        "21888242871839275222246405745257275088548364400416034343698204186575808495617",
    )
    .unwrap();

    q.add(pi.sub(eval_l1.mul(pubSignals)))
}
