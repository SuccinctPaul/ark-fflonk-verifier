use crate::challenge::{decimal_to_hex, Challenges};
use crate::Proof;
use ark_bn254::{Bn254, Fq, Fq12, Fq2, G1Affine, G2Affine, G2Projective};
use ark_ec::bn::{G1Prepared, G2Prepared};
use ark_ec::pairing::Pairing;
use ark_ec::{bn, AffineRepr, CurveGroup};
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
    // let g2_val = G2Affine::generator();
    let g2x1 = Fq::from_str(
        "10857046999023057135944570762232829481370756359578518086990519993285655852781",
    )
    .unwrap();
    // g2x1: BigInteger256([10269251484633538598, 15918845024527909234, 18138289588161026783, 1825990028691918907])
    // println!("g2x1");
    let g2x2 = Fq::from_str(
        "11559732032986387107991004021392285783925812861821192530917403151452391805634",
    )
    .unwrap();

    let g2y1 =
        Fq::from_str("869093939501355406318588453775243436758538662501260653214950591532352435323")
            .unwrap();
    let g2y2 = Fq::from_str(
        "4082367875863433681332203403145435568316851327593401208105741076214120093531",
    )
    .unwrap();

    // second pairing value
    let g2_val = G2Affine {
        x: Fq2::new(g2x1, g2x2),
        y: Fq2::new(g2y1, g2y2),
        infinity: true,
    };

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

    // let x2_val = G2Affine::new(Fq2::new(x2x1, x2x2), Fq2::new(x2y1, x2y2));
    let x2_val = G2Affine {
        x: Fq2::new(x2x1, x2x2),
        y: Fq2::new(x2y1, x2y2),
        infinity: true,
    };

    let lhs: [G1Prepared<ark_bn254::Config>; 2] = [p1.into(), p3.into()];
    let rhs: [G2Prepared<ark_bn254::Config>; 2] = [g2_val.into(), x2_val.into()];
    let res = Bn254::multi_pairing(lhs, rhs);

    assert!(res.0.is_one(), "Proof verification failed!");
}
