use crate::dummy::get_proog_bigint;
use crate::{get_omegas, padd_bytes32, vk::VerifierProcessedInputs};
use ark_bn254::{Fr, FrParameters};
use ark_ff::{Field, Fp256, One, Zero};
use num_bigint::{BigInt, BigUint};

use num_traits::FromPrimitive;
use std::ops::{Mul, Sub};
use std::str::FromStr;
use tiny_keccak::{Hasher, Keccak};

pub struct Roots {
    pub h0w8: [Fr; 8],
    pub h1w4: [Fr; 4],
    pub h2w3: [Fr; 3],
    pub h3w3: [Fr; 3],
}

pub struct Challenges {
    pub alpha: Fr,
    pub beta: Fr,
    pub gamma: Fr,
    pub y: Fr,
    pub xiSeed: Fr,
    pub xiSeed2: Fr,
    pub xi: Fr,
}

impl Challenges {
    // compute challenge and roots:
    //  beta, gamma, xi, alpha and y ∈ F, h1w4/h2w3/h3w3 roots, xiN and zh(xi)

    pub fn compute(
        mut zh: &mut Fr,
        zhinv: &mut Fr,
        vpi: VerifierProcessedInputs,
        pub_signal: Fr,
    ) -> (Challenges, Roots) {
        let mut roots = Roots {
            h0w8: [Fr::zero(); 8],
            h1w4: [Fr::zero(); 4],
            h2w3: [Fr::zero(); 3],
            h3w3: [Fr::zero(); 3],
        };

        let val1 = vpi.c0x.to_bytes_be();
        let val2 = vpi.c0y.to_bytes_be();
        let pub_sig_biguint: BigUint = pub_signal.into();
        let val3 = pub_sig_biguint.to_bytes_be();
        let val4 = get_proog_bigint().c1.0.to_bytes_be();
        let val5 = get_proog_bigint().c1.1.to_bytes_be();

        let mut concatenated = Vec::new();
        concatenated.extend_from_slice(&padd_bytes32(val1.1));
        concatenated.extend_from_slice(&padd_bytes32(val2.1));
        concatenated.extend_from_slice(&padd_bytes32(val3));
        concatenated.extend_from_slice(&padd_bytes32(val4.1));
        concatenated.extend_from_slice(&padd_bytes32(val5.1));

        let beta = keccak_hash(concatenated);

        //gamma

        let _beta_string = beta.to_string();
        let beta_string = &_beta_string[8..8 + 64];
        let val6 = BigInt::parse_bytes(beta_string.trim_start_matches("0x").as_bytes(), 16)
            .unwrap()
            .to_bytes_be();
        concatenated = Vec::new();
        concatenated.extend_from_slice(&padd_bytes32(val6.1));

        let gamma = keccak_hash(concatenated);

        //xiseed
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

        let xiSeed = keccak_hash(concatenated);

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
        let mut Xin = roots.h2w3[0].mul(roots.h2w3[0]).mul(roots.h2w3[0]);
        let xin = Xin.pow(&BigUint::from_u128(1 << 24).unwrap().to_u64_digits()) - Fr::one();

        *zh = xin;
        *zhinv = xin;
        // println!("zh: {:?}", zh.to_string());

        // alpha
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

        let alpha = keccak_hash(concatenated);

        println!("alpha: {:?}", alpha.to_string());
        //y
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

        let y = keccak_hash(concatenated);

        println!("y: {:?}", y.to_string());
        let challenges = Challenges {
            alpha,
            beta,
            gamma,
            y,
            xiSeed,
            xiSeed2,
            xi: Xin,
        };
        (challenges, roots)
    }
}

fn keccak_hash(bytes: Vec<u8>) -> Fr {
    let mut hasher = Keccak::v256();
    hasher.update(&bytes);

    let mut out = [0u8; 32];
    hasher.finalize(&mut out);
    let res_bigint = BigInt::from_bytes_be(num_bigint::Sign::Plus, &out);

    let res = Fr::from_str(&res_bigint.to_string()).unwrap();
    res
}

#[cfg(test)]
mod test {
    use crate::padd_bytes32;
    use ark_bn254::Fr;
    use ark_ff::BigInteger;
    use num_bigint::{BigInt, BigUint};
    use std::str::FromStr;

    #[test]
    fn test_fr_to_bytes_be() {
        let pubSignalBigInt = BigInt::parse_bytes(
            b"14516932981781041565586298118536599721399535462624815668597272732223874827152",
            10,
        )
        .unwrap();
        let bytes = pubSignalBigInt.to_bytes_be().1;
        println!("expect_bytes: {:?}", bytes);
        let expect_bigint = padd_bytes32(bytes);
        println!("expect_bigint: {:?}", expect_bigint);

        // second
        println!("");
        let pubSignalBigInt = BigUint::from_str(
            "14516932981781041565586298118536599721399535462624815668597272732223874827152",
        )
        .unwrap();
        let bytes = pubSignalBigInt.to_bytes_be();
        println!("expect_bytes: {:?}", bytes);
        let expect_biguint = padd_bytes32(bytes);
        println!("expect_biguint: {:?}", expect_biguint);

        assert_eq!(expect_biguint, expect_bigint);

        println!("\n======\n");
        let pub_sig = Fr::from_str(
            "14516932981781041565586298118536599721399535462624815668597272732223874827152",
        )
        .unwrap();
        // dones't work
        let actual_bytes = pub_sig.0.to_bytes_be();
        println!("actual_bytes: {:?}", actual_bytes);
        let actual = padd_bytes32(actual_bytes);
        println!("actual: {:?}", actual);

        println!("");
        let sig_biguint: BigUint = pub_sig.into();
        let actual_biguint_bytes = sig_biguint.to_bytes_be();
        println!("actual_biguint_bytes: {:?}", actual_biguint_bytes);
        let actual_biguint_bytes = padd_bytes32(actual_biguint_bytes);
        println!("actual_biguint_bytes: {:?}", actual_biguint_bytes);

        // assert_eq!(expect_biguint, expect_bigint);

        assert_eq!(actual_biguint_bytes, expect_biguint);
    }
}
