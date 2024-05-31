use crate::dummy::get_proog_bigint;
use crate::{get_omegas, padd_bytes32, Roots, VerifierProcessedInputs};
use ark_bn254::{Fr, FrParameters};
use ark_ff::{Fp256, One};
use num_bigint::BigInt;
use std::ops::{Mul, Sub};
use std::str::FromStr;
use tiny_keccak::{Hasher, Keccak};

pub struct Challenges {
    pub alpha: Fp256<FrParameters>,
    pub beta: Fp256<FrParameters>,
    pub gamma: Fp256<FrParameters>,
    pub y: Fp256<FrParameters>,
    pub xiSeed: Fp256<FrParameters>,
    pub xiSeed2: Fp256<FrParameters>,
    pub xi: Fp256<FrParameters>,
}

pub fn compute_challenges(
    challenges: &mut Challenges,
    roots: &mut Roots,
    mut zh: &mut Fp256<FrParameters>,
    zhinv: &mut Fp256<FrParameters>,
    vpi: VerifierProcessedInputs,
    pubSignals: BigInt,
) {
    let mut hasher = Keccak::v256();

    let val1 = vpi.c0x.to_bytes_be();
    let val2 = vpi.c0y.to_bytes_be();
    let val3 = pubSignals.to_bytes_be();
    let val4 = get_proog_bigint().c1.0.to_bytes_be();
    let val5 = get_proog_bigint().c1.1.to_bytes_be();

    let mut concatenated = Vec::new();
    concatenated.extend_from_slice(&padd_bytes32(val1.1));
    concatenated.extend_from_slice(&padd_bytes32(val2.1));
    concatenated.extend_from_slice(&padd_bytes32(val3.1));
    concatenated.extend_from_slice(&padd_bytes32(val4.1));
    concatenated.extend_from_slice(&padd_bytes32(val5.1));

    hasher.update(&concatenated);

    let mut out = [0u8; 32];
    hasher.finalize(&mut out);
    let _beta = BigInt::from_bytes_be(num_bigint::Sign::Plus, &out);

    let beta = Fr::from_str(&_beta.to_string()).unwrap();

    //gamma
    hasher = Keccak::v256();

    let _beta_string = beta.to_string();
    let beta_string = &_beta_string[8..8 + 64];
    let val6 = BigInt::parse_bytes(beta_string.trim_start_matches("0x").as_bytes(), 16)
        .unwrap()
        .to_bytes_be();
    concatenated = Vec::new();
    concatenated.extend_from_slice(&padd_bytes32(val6.1));
    hasher.update(&concatenated);
    out = [0u8; 32];
    hasher.finalize(&mut out);
    let _gamma = BigInt::from_bytes_be(num_bigint::Sign::Plus, &out);
    let gamma = Fr::from_str(&_gamma.to_string()).unwrap();

    //xiseed
    let mut hasher3 = Keccak::v256();
    let _gamma_string = gamma.to_string();
    let gamma_string = &_gamma_string[8..8 + 64];
    // println!("gamma_string: {:?}", gamma_string);
    let val7 = BigInt::parse_bytes(gamma_string.as_bytes(), 16)
        .unwrap()
        .to_bytes_be();
    let val8 = get_proog_bigint().c2.0.to_bytes_be();
    let val9 = get_proog_bigint().c2.1.to_bytes_be();

    concatenated = Vec::new();
    concatenated.extend_from_slice(&padd_bytes32(val7.1));
    concatenated.extend_from_slice(&padd_bytes32(val8.1));
    concatenated.extend_from_slice(&padd_bytes32(val9.1));

    hasher3.update(&concatenated);
    out = [0u8; 32];
    hasher3.finalize(&mut out);
    let _xiSeed = BigInt::from_bytes_be(num_bigint::Sign::Plus, &out);
    let xiSeed = Fr::from_str(&_xiSeed.to_string()).unwrap();

    // println!("xiSeed: {:?}", xiSeed.to_string());

    //xiSeed2
    let mut xiSeed2 = xiSeed.mul(xiSeed);
    // println!("xiSeed2: {:?}", xiSeed2.to_string());

    //roots h0w8
    roots.h0w8[0] = xiSeed2.mul(xiSeed); // x^3
    roots.h0w8[1] = roots.h0w8[0].mul(get_omegas().w8_1);
    roots.h0w8[2] = roots.h0w8[0].mul(get_omegas().w8_2);
    roots.h0w8[3] = roots.h0w8[0].mul(get_omegas().w8_3);
    roots.h0w8[4] = roots.h0w8[0].mul(get_omegas().w8_4);
    roots.h0w8[5] = roots.h0w8[0].mul(get_omegas().w8_5);
    roots.h0w8[6] = roots.h0w8[0].mul(get_omegas().w8_6);
    roots.h0w8[7] = roots.h0w8[0].mul(get_omegas().w8_7);

    //roots h1w4
    roots.h1w4[0] = roots.h0w8[0].mul(roots.h0w8[0]); // x^6
    roots.h1w4[1] = roots.h1w4[0].mul(get_omegas().w4);
    roots.h1w4[2] = roots.h1w4[0].mul(get_omegas().w4_2);
    roots.h1w4[3] = roots.h1w4[0].mul(get_omegas().w4_3);

    //roots h2w3
    roots.h2w3[0] = roots.h1w4[0].mul(xiSeed2); // x^8
    roots.h2w3[1] = roots.h2w3[0].mul(get_omegas().w3);
    roots.h2w3[2] = roots.h2w3[0].mul(get_omegas().w3_2);

    //roots h3w3
    roots.h3w3[0] = roots.h2w3[0].mul(get_omegas().wr);
    roots.h3w3[1] = roots.h3w3[0].mul(get_omegas().w3);
    roots.h3w3[2] = roots.h3w3[0].mul(get_omegas().w3_2);

    //zh and zhInv
    let mut xin = roots.h2w3[0].mul(roots.h2w3[0]).mul(roots.h2w3[0]);
    let mut Xin = xin;
    for _ in 0..24 {
        xin = xin.mul(xin);
    }

    xin = xin.sub(Fr::one());

    *zh = xin;
    *zhinv = xin;
    // println!("zh: {:?}", zh.to_string());

    // alpha
    let mut hasher4 = Keccak::v256();

    let _xiseed_string = xiSeed.to_string();
    let xiseed_string = &_xiseed_string[8..8 + 64];
    // let val6 = BigInt::parse_bytes(beta_string.trim_start_matches("0x").as_bytes(), 16).unwrap().to_bytes_be();
    let val10 = BigInt::parse_bytes(xiseed_string.to_string().as_bytes(), 16)
        .unwrap()
        .to_bytes_be();

    let val11 = get_proog_bigint().eval_ql.to_bytes_be();
    let val12 = get_proog_bigint().eval_qr.to_bytes_be();
    let val13 = get_proog_bigint().eval_qm.to_bytes_be();
    let val14 = get_proog_bigint().eval_qo.to_bytes_be();
    let val15 = get_proog_bigint().eval_qc.to_bytes_be();
    let val16 = get_proog_bigint().eval_s1.to_bytes_be();
    let val17 = get_proog_bigint().eval_s2.to_bytes_be();
    let val18 = get_proog_bigint().eval_s3.to_bytes_be();
    let val19 = get_proog_bigint().eval_a.to_bytes_be();
    let val20 = get_proog_bigint().eval_b.to_bytes_be();
    let val21 = get_proog_bigint().eval_c.to_bytes_be();
    let val22 = get_proog_bigint().eval_z.to_bytes_be();
    let val23 = get_proog_bigint().eval_zw.to_bytes_be();
    let val24 = get_proog_bigint().eval_t1w.to_bytes_be();
    let val25 = get_proog_bigint().eval_t2w.to_bytes_be();

    concatenated = Vec::new();
    concatenated.extend_from_slice(&padd_bytes32(val10.1));
    concatenated.extend_from_slice(&padd_bytes32(val11.1));
    concatenated.extend_from_slice(&padd_bytes32(val12.1));
    concatenated.extend_from_slice(&padd_bytes32(val13.1));
    concatenated.extend_from_slice(&padd_bytes32(val14.1));
    concatenated.extend_from_slice(&padd_bytes32(val15.1));
    concatenated.extend_from_slice(&padd_bytes32(val16.1));
    concatenated.extend_from_slice(&padd_bytes32(val17.1));
    concatenated.extend_from_slice(&padd_bytes32(val18.1));
    concatenated.extend_from_slice(&padd_bytes32(val19.1));
    concatenated.extend_from_slice(&padd_bytes32(val20.1));
    concatenated.extend_from_slice(&padd_bytes32(val21.1));
    concatenated.extend_from_slice(&padd_bytes32(val22.1));
    concatenated.extend_from_slice(&padd_bytes32(val23.1));
    concatenated.extend_from_slice(&padd_bytes32(val24.1));
    concatenated.extend_from_slice(&padd_bytes32(val25.1));

    hasher4.update(&concatenated);

    out = [0u8; 32];
    hasher4.finalize(&mut out);
    let _alpha = BigInt::from_bytes_be(num_bigint::Sign::Plus, &out);
    let alpha = Fr::from_str(&_alpha.to_string()).unwrap();

    println!("alpha: {:?}", alpha.to_string());
    //y
    let mut hasher5 = Keccak::v256();
    let _alpha_string = alpha.to_string();
    let alpha_string = &_alpha_string[8..8 + 64];
    let val26 = BigInt::parse_bytes(alpha_string.to_string().as_bytes(), 16)
        .unwrap()
        .to_bytes_be();
    let val27 = get_proog_bigint().w1.0.to_bytes_be();
    let val28 = get_proog_bigint().w1.1.to_bytes_be();

    concatenated = Vec::new();
    concatenated.extend_from_slice(&(val26.1));
    concatenated.extend_from_slice(&(val27.1));
    concatenated.extend_from_slice(&(val28.1));

    hasher5.update(&concatenated);
    out = [0u8; 32];
    hasher5.finalize(&mut out);
    let _y = BigInt::from_bytes_be(num_bigint::Sign::Plus, &out);
    let y = Fr::from_str(&_y.to_string()).unwrap();

    println!("y: {:?}", y.to_string());

    challenges.alpha = alpha;
    challenges.beta = beta;
    challenges.gamma = gamma;
    challenges.y = y;
    challenges.xiSeed = xiSeed;
    challenges.xiSeed2 = xiSeed2;
    challenges.xi = Xin;
}
