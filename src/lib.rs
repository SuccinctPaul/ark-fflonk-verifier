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

pub fn compute_lagrange(zh: Fr, eval_l1: Fr) -> Fr {
    // let w = Fr::one();
    eval_l1.mul(zh)
}
