use crate::dummy::get_proog_bigint;
use crate::{get_omegas, padd_bytes32, vk::VerifierProcessedInputs};
use ark_bn254::{Fr};
use ark_ff::{Field, One};
use num_bigint::{BigInt, BigUint};

use num_traits::FromPrimitive;
use std::ops::{Mul};
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
    pub xi_seed: Fr,
    pub xi_seed_2: Fr,
    pub xi: Fr,
    pub zh: Fr,
}

impl Challenges {
    // compute challenge and roots:
    //  beta, gamma, xi, alpha and y ∈ F, h1w4/h2w3/h3w3 roots, xiN and zh(xi)

    pub fn compute(vpi: VerifierProcessedInputs, pub_signal: Fr) -> (Challenges, Roots) {
        // 1.beta
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

        // 2.gamma
        let _beta_string = beta.to_string();
        let beta_string = &_beta_string[8..8 + 64];
        let val6 = BigInt::parse_bytes(beta_string.trim_start_matches("0x").as_bytes(), 16)
            .unwrap()
            .to_bytes_be();
        concatenated = Vec::new();
        concatenated.extend_from_slice(&padd_bytes32(val6.1));
        let gamma = keccak_hash(concatenated);

        // 3.xi_seed
        let _gamma_string = gamma.to_string();
        let gamma_string = &_gamma_string[8..8 + 64];
        // println!("gamma_string: {:?}", gamma_string);
        let val7 = BigInt::parse_bytes(gamma_string.as_bytes(), 16)
            .unwrap()
            .to_bytes_be();
        let val8 = get_proog_bigint().c2.0.to_bytes_be();
        let val9 = get_proog_bigint().c2.1.to_bytes_be();

        let mut concatenated = Vec::new();
        concatenated.extend_from_slice(&padd_bytes32(val7.1));
        concatenated.extend_from_slice(&padd_bytes32(val8.1));
        concatenated.extend_from_slice(&padd_bytes32(val9.1));

        let xi_seed = keccak_hash(concatenated);

        // 4.xi_seed_2
        let xi_seed_2 = xi_seed.mul(xi_seed);

        // 5. roots h0w8
        let xi_seed_3 = xi_seed * xi_seed_2;
        let h0w8 = [
            xi_seed_3,
            xi_seed_3 * get_omegas().w8_1,
            xi_seed_3 * get_omegas().w8_2,
            xi_seed_3 * get_omegas().w8_3,
            xi_seed_3 * get_omegas().w8_4,
            xi_seed_3 * get_omegas().w8_5,
            xi_seed_3 * get_omegas().w8_6,
            xi_seed_3 * get_omegas().w8_7,
        ];

        // 6.roots h1w4
        let xi_seed_6 = xi_seed_3 * xi_seed_3;
        let h1w4 = [
            xi_seed_6,
            xi_seed_6 * get_omegas().w4,
            xi_seed_6 * get_omegas().w4_2,
            xi_seed_6 * get_omegas().w4_3,
        ];

        // 7.roots h2w3
        let xi_seed_8 = xi_seed_6 * xi_seed_2;
        let h2w3 = [
            xi_seed_8,
            xi_seed_8 * get_omegas().w3,
            xi_seed_8 * get_omegas().w3_2,
        ];

        // 8.roots h3w3
        let h3w3_0 = xi_seed_8 * get_omegas().wr;
        let h3w3 = [h3w3_0, h3w3_0 * get_omegas().w3, h3w3_0 * get_omegas().w3_2];

        // 9. Compute xi^n
        //zh and zhInv
        let xi = xi_seed_8 * xi_seed_8 * xi_seed_8;
        // TODO: does here means be k=24 ?
        // let zh = xi.pow(precomputed.n.into_bigint()) - Fr::one();
        let zh = xi.pow(&BigUint::from_u128(1 << 24).unwrap().to_u64_digits()) - Fr::one();

        // 10.alpha
        let _xi_seed_string = xi_seed.to_string();
        let xi_seed_string = &_xi_seed_string[8..8 + 64];
        // let val6 = BigInt::parse_bytes(beta_string.trim_start_matches("0x").as_bytes(), 16).unwrap().to_bytes_be();
        let val10 = BigInt::parse_bytes(xi_seed_string.to_string().as_bytes(), 16)
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

        // 11.y
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
        let roots = Roots {
            h0w8,
            h1w4,
            h2w3,
            h3w3,
        };

        let challenges = Challenges {
            alpha,
            beta,
            gamma,
            y,
            xi_seed,
            xi_seed_2,
            xi,
            zh,
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
