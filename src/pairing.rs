use crate::challenge::{decimal_to_hex, Challenges};
use crate::Proof;
use ark_bn254::{Bn254, Fq, Fq12, Fq2, G1Affine, G2Affine, G2Projective};
use ark_ec::pairing::Pairing;
use ark_ec::{bn, AffineRepr, CurveGroup};
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
    output_point(p1.clone());
    println!("p1.x: {:?}", p1.x.0);
    println!("p1.y: {:?}", p1.y.0);
    // p1.x: BigInteger256([10584569519187674000, 8610978561992104508, 5476655366647144939, 635933919438646234])
    // p1.y: BigInteger256([16115314718666400513, 13398080506121126817, 4129442988357580437, 517614468129541399])

    // second pairing value
    // let g2_val = G2Affine::generator();
    let g2x1 = Fq::from_str(
        "10857046999023057135944570762232829481370756359578518086990519993285655852781",
    )
    .unwrap();
    println!("g2x1: {:?}", g2x1.0);
    // g2x1: BigInteger256([10269251484633538598, 15918845024527909234, 18138289588161026783, 1825990028691918907])
    // println!("g2x1");
    let g2x2 = Fq::from_str(
        "11559732032986387107991004021392285783925812861821192530917403151452391805634",
    )
    .unwrap();
    println!("g2x2: {:?}", g2x2.0);

    let g2y1 =
        Fq::from_str("869093939501355406318588453775243436758538662501260653214950591532352435323")
            .unwrap();
    let g2y2 = Fq::from_str(
        "4082367875863433681332203403145435568316851327593401208105741076214120093531",
    )
    .unwrap();

    // TODO: debug. here.
    let g2_x = Fq2::new(g2x1, g2x2);
    println!("");
    println!("g2_x_c0: {:?}", g2_x.c0);
    println!("g2_x_c1: {:?}", g2_x.c1);
    println!("g2_x: {:?}", g2_x);
    // second pairing value
    let g2_val = G2Affine {
        x: g2_x,
        y: Fq2::new(g2y1, g2y2),
        infinity: true,
    };
    println!("");
    println!("g2_val.x: {:?}", g2_val.x);
    println!("g2_val.y: {:?}", g2_val.y);
    println!("");

    // third pairing value
    let p3 = -W2;
    println!("");
    println!("p3.x: {:?}", p3.x.0);
    println!("p3.y: {:?}", p3.y.0);
    println!("");

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
    // println!("\n\n==lhs:");
    // println!("p1: x: {:?}, y:{:?}", p1.x, p1.y);
    // println!("g2_val: {:?}", g2_val);
    //
    // println!("\n==rhs:");
    // println!("p3: {:?}", p3);
    // println!("x2_val: {:?}", x2_val);
    let lhs = Bn254::pairing(p1, g2_val);
    let rhs = Bn254::pairing(p3, x2_val);
    // let lhs: [G1Prepared<ark_bn254::Config>; 2] = [p1.into(), p3.into()];
    // let rhs: [G2Prepared<ark_bn254::Config>; 2] = [g2_val.into(), x2_val.into()];
    //
    // let res = Bn254::multi_pairing(lhs, rhs);

    // assert_eq!( lhs.0, rhs.0);
    // println!("\n\n\n ==============pairing");
    // println!("{:?}", lhs.0.to_string());
    // println!("{:?}", rhs.0.to_string());
    if lhs == rhs {
        // if res.0.is_one(){
        println!("Proof Verified!");
        // return true;
    } else {
        panic!("Proof verification failed!");
    }
}

pub fn output_point(point: G1Affine) {
    println!(
        "points.2: x:{:?}, y:{:?}",
        decimal_to_hex(&point.x.to_string()),
        decimal_to_hex(&point.y.to_string()),
    );
}

//
// g2_val.x: QuadExtField { c0: Fp256(BigInteger256([10269251484633538598, 15918845024527909234, 18138289588161026783, 1825990028691918907])), c1: Fp256(BigInteger256([12660871435976991040, 6936631231174072516, 714191060563144582, 1512910971262892907])) }
// g2_val.y: QuadExtField { c0: Fp256(BigInteger256([11794916965376424501, 11279295704354203205, 7945688752144908487, 2651588760368207651])), c1: Fp256(BigInteger256([7208393106848765678, 15877432936589245627, 6195041853444001910, 983087530859390082])) }
//

// g2_x: QuadExtField { c0: Fp256(BigInteger256([10269251484633538598, 15918845024527909234, 18138289588161026783, 1825990028691918907])), c1: Fp256(BigInteger256([12660871435976991040, 6936631231174072516, 714191060563144582, 1512910971262892907])) }
//
// g2_val.x: QuadExtField { c0: Fp256(BigInteger256([10269251484633538598, 15918845024527909234, 18138289588161026783, 1825990028691918907])), c1: Fp256(BigInteger256([12660871435976991040, 6936631231174072516, 714191060563144582, 1512910971262892907])) }
// g2_val.y: QuadExtField { c0: Fp256(BigInteger256([11794916965376424501, 11279295704354203205, 7945688752144908487, 2651588760368207651])), c1: Fp256(BigInteger256([7208393106848765678, 15877432936589245627, 6195041853444001910, 983087530859390082])) }
//
//
// g2x1: BigInteger256([10269251484633538598, 15918845024527909234, 18138289588161026783, 1825990028691918907])
// g2x2: BigInteger256([12660871435976991040, 6936631231174072516, 714191060563144582, 1512910971262892907])
// g2_x_c0: Fp256(BigInteger256([10269251484633538598, 15918845024527909234, 18138289588161026783, 1825990028691918907]))
// g2_x_c1: Fp256(BigInteger256([12660871435976991040, 6936631231174072516, 714191060563144582, 1512910971262892907]))
// g2_x: QuadExtField { c0: Fp256(BigInteger256([10269251484633538598, 15918845024527909234, 18138289588161026783, 1825990028691918907])), c1: Fp256(BigInteger256([12660871435976991040, 6936631231174072516, 714191060563144582, 1512910971262892907])) }
//
//
