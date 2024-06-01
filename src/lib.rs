//! A simple program to be proven inside the zkVM.

mod challenge;
mod compute_fej;
mod compute_pi;
mod compute_r;
mod dummy;
mod inversion;
mod pairing;
mod verifier;
mod vk;

pub use crate::dummy::{
    get_domain_size, get_omegas, get_proof, get_pubSignals, padd_bytes32, Omegas, Proof,
};

use ark_bn254::{
    Fr,
};
use ark_ec::*;
use std::ops::{Mul};


pub fn compute_lagrange(zh: Fr, eval_l1: Fr) -> Fr {
    // let w = Fr::one();
    eval_l1.mul(zh)
}
