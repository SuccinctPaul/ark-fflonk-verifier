//! A simple program to be proven inside the zkVM.

pub mod challenge;
pub mod compute_fej;
pub mod compute_pi;
pub mod compute_r;
pub mod inversion;
pub mod pairing;
pub mod proof;
pub mod test;
pub mod verifier;
pub mod vk;

pub use crate::proof::{get_domain_size, get_omegas, get_pubSignals, padd_bytes32, Omegas, Proof};

use ark_bn254::Fr;
use ark_ec::*;
use std::ops::Mul;

pub fn compute_lagrange(zh: Fr, eval_l1: Fr) -> Fr {
    // let w = Fr::one();
    eval_l1.mul(zh)
}
