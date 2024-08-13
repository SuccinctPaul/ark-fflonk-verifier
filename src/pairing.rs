use crate::challenge::Challenges;
use crate::Proof;
use ark_bn254::{Bn254, Fq, Fq2, G1Affine, G2Affine, G2Projective};
use ark_ec::pairing::Pairing;
use ark_ec::{AffineRepr, CurveGroup};
use num_traits::One;
use std::ops::{Add, Mul};
use std::str::FromStr;

pub fn check_pairing(
    proof: &Proof,
    points: (G1Affine, G1Affine, G1Affine),
    challenges: Challenges,
) {
    let F = points.0;
    let E = points.1;
    let J = points.2;

    let W2 = proof.w2;

    // first pairing value
    let p1 = F.add(-E).add(-J).add(W2.mul(challenges.y)).into_affine();

    // second pairing value
    let g2_val = G2Affine::generator();

    // third pairing value
    let p3 = -W2;

    // fourth pairing value. TODO: mark
    let x2x1 = Fq::from_str(
        "21831381940315734285607113342023901060522397560371972897001948545212302161822",
    )
    .unwrap();
    let x2x2 = Fq::from_str(
        "17231025384763736816414546592865244497437017442647097510447326538965263639101",
    )
    .unwrap();
    let x2y1 = Fq::from_str(
        "2388026358213174446665280700919698872609886601280537296205114254867301080648",
    )
    .unwrap();
    let x2y2 = Fq::from_str(
        "11507326595632554467052522095592665270651932854513688777769618397986436103170",
    )
    .unwrap();

    let x2_val = G2Affine::new(Fq2::new(x2x1, x2x2), Fq2::new(x2y1, x2y2));
    println!("\n\n==lhs:");
    println!("p1: x: {:?}, y:{:?}", p1.x, p1.y);
    println!("g2_val: {:?}", g2_val);

    println!("\n==rhs:");
    println!("p3: {:?}", p3);
    println!("x2_val: {:?}", x2_val);
    let lhs = Bn254::pairing(p1, g2_val);
    let rhs = Bn254::pairing(p3, x2_val);

    if lhs == rhs {
        println!("Proof Verified!");
        // return true;
    } else {
        panic!("Proof verification failed!");
    }
}
