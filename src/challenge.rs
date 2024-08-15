use crate::vk::VerificationKey;
use ark_bn254::Fr;
use ark_ff::{BigInteger, Field, One, PrimeField};
use num_bigint::{BigInt, BigUint};
use std::fmt;

use crate::proof::Proof;
use crate::vk::Omega;
use ark_ec::AffineRepr;
use num_traits::FromPrimitive;
use std::ops::Mul;
use std::str::FromStr;
use tiny_keccak::{Hasher, Keccak};

#[derive(Debug, Default, Eq, PartialEq, Copy, Clone)]
pub struct Roots {
    pub h0w8: [Fr; 8],
    pub h1w4: [Fr; 4],
    pub h2w3: [Fr; 3],
    pub h3w3: [Fr; 3],
}

impl fmt::Display for Roots {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Roots: [")?;
        write!(f, "h0w8:[");
        for (i, v) in self.h0w8.iter().enumerate() {
            if i != 0 {
                write!(f, ", ")?;
            }
            write!(f, "{}", v.to_string())?;
        }
        write!(f, "], ");

        write!(f, "h1w4:[");
        for (i, v) in self.h1w4.iter().enumerate() {
            if i != 0 {
                write!(f, ", ")?;
            }
            write!(f, "{}", v.to_string())?;
        }
        write!(f, "], ");

        write!(f, "h2w3:[");
        for (i, v) in self.h2w3.iter().enumerate() {
            if i != 0 {
                write!(f, ", ")?;
            }
            write!(f, "{}", v.to_string())?;
        }
        write!(f, "], ");

        write!(f, "h3w3:[");
        for (i, v) in self.h3w3.iter().enumerate() {
            if i != 0 {
                write!(f, ", ")?;
            }
            write!(f, "{}", v.to_string())?;
        }
        write!(f, "] ");

        write!(f, "]")
    }
}

#[derive(Debug, Default, Eq, PartialEq, Copy, Clone)]
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
    pub fn compute(vk: &VerificationKey, proof: &Proof, pub_input: &Fr) -> (Challenges, Roots) {
        // 1. compute beta: keccak_hash with c0, pub_input, c1
        let concatenated = vec![
            vk.c0.x.into_bigint().to_bytes_be(),
            vk.c0.y.into_bigint().to_bytes_be(),
            pub_input.into_bigint().to_bytes_be(),
            proof.c1.x.into_bigint().to_bytes_be(),
            proof.c1.y.into_bigint().to_bytes_be(),
        ]
        .into_iter()
        .flatten()
        .collect::<Vec<_>>();
        let beta = keccak_hash(concatenated);

        // 2. compute gamma: keccak_hash with beta
        let concatenated = beta.into_bigint().to_bytes_be();
        let gamma = keccak_hash(concatenated);

        // 3. compute xi_seed: keccak_hash with gamma,c2
        let mut concatenated = vec![
            gamma.into_bigint().to_bytes_be(),
            proof.c2.x.into_bigint().to_bytes_be(),
            proof.c2.y.into_bigint().to_bytes_be(),
        ]
        .into_iter()
        .flatten()
        .collect::<Vec<_>>();
        let xi_seed = keccak_hash(concatenated);

        // 4. compute alpha: keccak_hash with xi_seed, eval_lines
        let mut concatenated = vec![
            xi_seed.into_bigint().to_bytes_be(),
            proof.eval_ql.into_bigint().to_bytes_be(),
            proof.eval_qr.into_bigint().to_bytes_be(),
            proof.eval_qm.into_bigint().to_bytes_be(),
            proof.eval_qo.into_bigint().to_bytes_be(),
            proof.eval_qc.into_bigint().to_bytes_be(),
            proof.eval_s1.into_bigint().to_bytes_be(),
            proof.eval_s2.into_bigint().to_bytes_be(),
            proof.eval_s3.into_bigint().to_bytes_be(),
            proof.eval_a.into_bigint().to_bytes_be(),
            proof.eval_b.into_bigint().to_bytes_be(),
            proof.eval_c.into_bigint().to_bytes_be(),
            proof.eval_z.into_bigint().to_bytes_be(),
            proof.eval_zw.into_bigint().to_bytes_be(),
            proof.eval_t1w.into_bigint().to_bytes_be(),
            proof.eval_t2w.into_bigint().to_bytes_be(),
        ]
        .into_iter()
        .flatten()
        .collect::<Vec<_>>();
        let alpha = keccak_hash(concatenated);

        // 5. compute y: keccak_hash with alpha, w1
        let mut concatenated = vec![
            alpha.into_bigint().to_bytes_be(),
            proof.w1.x.into_bigint().to_bytes_be(),
            proof.w1.y.into_bigint().to_bytes_be(),
        ]
        .into_iter()
        .flatten()
        .collect::<Vec<_>>();
        let y = keccak_hash(concatenated);

        /////////////////////////////////////////////
        //////////// Above is keccak hash
        /////////////////////////////////////////////

        // 6.xi_seed_2, xi_seed_3
        let xi_seed_2 = xi_seed.mul(xi_seed);
        let xi_seed_3 = xi_seed * xi_seed_2;

        // 7. roots h0w8
        let omegas = &vk.omega;
        let h0w8 = [
            xi_seed_3,
            xi_seed_3 * omegas.w8_1,
            xi_seed_3 * omegas.w8_2,
            xi_seed_3 * omegas.w8_3,
            xi_seed_3 * omegas.w8_4,
            xi_seed_3 * omegas.w8_5,
            xi_seed_3 * omegas.w8_6,
            xi_seed_3 * omegas.w8_7,
        ];

        // 8.roots h1w4
        let xi_seed_6 = xi_seed_3 * xi_seed_3;
        let h1w4 = [
            xi_seed_6,
            xi_seed_6 * omegas.w4,
            xi_seed_6 * omegas.w4_2,
            xi_seed_6 * omegas.w4_3,
        ];

        // 9.roots h2w3
        let xi_seed_8 = xi_seed_6 * xi_seed_2;
        let h2w3 = [xi_seed_8, xi_seed_8 * omegas.w3, xi_seed_8 * omegas.w3_2];

        // 10.roots h3w3
        let h3w3_0 = xi_seed_8 * omegas.wr;
        let h3w3 = [h3w3_0, h3w3_0 * omegas.w3, h3w3_0 * omegas.w3_2];

        // 11. Compute xi^n
        let xi = xi_seed_8 * xi_seed_8 * xi_seed_8;
        // 12. zh and zhInv
        let zh = xi.pow(vk.n.into_bigint()) - Fr::one();

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

impl fmt::Display for Challenges {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "alpha: {:?}", self.alpha.to_string());
        write!(f, "beta: {}", self.beta.to_string());
        write!(f, "gamma: {}", self.gamma.to_string());
        write!(f, "y: {}", self.y.to_string());
        write!(f, "xi: {}", self.xi.to_string());
        write!(f, "xi_seed: {}", self.xi_seed.to_string());
        write!(f, "xi_seed_2: {}", self.xi_seed_2.to_string());
        write!(f, "zh: {}", self.zh.to_string())
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

// Convert decimal_str to upper_str by fmt macro.
#[deprecated]
pub fn decimal_to_hex(decimal_str: &str) -> String {
    let decimal_number = BigInt::from_str(decimal_str).expect("Invalid decimal string");
    format!("{:X}", decimal_number)
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::mock::{MOCK_PROOF_DATA, MOCK_PUB_INPUT};
    use crate::proof::Proof;
    use ark_bn254::Fr;
    use ark_ff::{BigInteger, PrimeField};
    use num_bigint::{BigInt, BigUint};
    use std::str::FromStr;

    pub fn padd_bytes32(input: Vec<u8>) -> Vec<u8> {
        let mut result = input.clone();
        let mut padding = vec![0; 32 - input.len()];
        padding.append(&mut result);
        padding
    }

    #[test]
    fn test_keccak() {
        let beta = Fr::from_str(
            "14516932981781041565586298118536599721399535462624815668597272732223874827152",
        )
        .unwrap();
        // _beta_string: 14516932981781041565586298118536599721399535462624815668597272732223874827152
        let _beta_string = beta.to_string();

        // _beta_string: Fp256 "(20184AFB0D281C14053177E751B3EB51201D07C072500460B4E511D80F908390)"
        // let beta_string = &_beta_string[8..8 + 64];
        let beta_string = decimal_to_hex(&_beta_string);
        println!("_beta_string: {:}", _beta_string);
        println!("beta_string: {:}", beta_string);

        let pre_bytes = beta_string.trim_start_matches("0x").as_bytes();
        println!("actual_pre_bytes: {:?}", pre_bytes);
        let val6 = BigInt::parse_bytes(pre_bytes, 16).unwrap().to_bytes_be();
        println!("actual_bytes: {:?}", val6);
        let mut concatenated = Vec::new();
        concatenated.extend_from_slice(&padd_bytes32(val6.1));
        let actual_gamma = keccak_hash(concatenated);

        println!("");
        let expect_pre_bytes = "20184AFB0D281C14053177E751B3EB51201D07C072500460B4E511D80F908390"
            .trim_start_matches("0x")
            .as_bytes();
        println!("expect_pre_bytes: {:?}", expect_pre_bytes);
        let val6 = BigInt::parse_bytes(expect_pre_bytes, 16)
            .unwrap()
            .to_bytes_be();
        println!("expect_bytes: {:?}", val6);

        let mut concatenated = Vec::new();
        concatenated.extend_from_slice(&padd_bytes32(val6.1));
        let expect_gamma = keccak_hash(concatenated);
        println!("expect_gamma: {:?}", expect_gamma.to_string());

        assert_eq!(actual_gamma, expect_gamma);
    }

    #[test]
    fn test_decimal_to_hex() {
        let expect_hex_str =
            "20184AFB0D281C14053177E751B3EB51201D07C072500460B4E511D80F908390".to_string();

        let try_1_pre_bytes =
            "14516932981781041565586298118536599721399535462624815668597272732223874827152"
                .to_string();
        let actual_hex_str = decimal_to_hex(&try_1_pre_bytes);
        println!("actual_hex_str {:?}", actual_hex_str);

        assert_eq!(expect_hex_str, actual_hex_str);
    }

    #[test]
    fn test_compute_challenge() {
        let pub_input = Fr::from_str(MOCK_PUB_INPUT).unwrap();

        let vk = VerificationKey::default();
        let proof = Proof::construct(MOCK_PROOF_DATA.to_vec());
        let (challenges, roots) = Challenges::compute(&vk, &proof, &pub_input);

        // println!("beta.: {:?}", challenges.beta.to_string());
        println!(
            "gamma.: {:?}",
            decimal_to_hex(&challenges.gamma.to_string())
        );
        println!(
            "xi_seed.: {:?}",
            decimal_to_hex(&challenges.xi_seed.to_string())
        );
        println!(
            "xi_seed_2.: {:?}",
            decimal_to_hex(&challenges.xi_seed_2.to_string())
        );
        println!("");
        println!("h0w8.: {:?}", decimal_to_hex(&roots.h0w8[0].to_string()));
        println!("h1w4.: {:?}", decimal_to_hex(&roots.h1w4[0].to_string()));
        println!("h2w3.: {:?}", decimal_to_hex(&roots.h2w3[0].to_string()));
        println!("h3w3.: {:?}", decimal_to_hex(&roots.h3w3[0].to_string()));
        println!("y.: {:?}", decimal_to_hex(&challenges.y.to_string()));
        println!(
            "alpha : {:?}",
            decimal_to_hex(&challenges.alpha.to_string())
        );
        // println!("challenge.: {:?}", challenges.to_string());
        // println!("");
        // println!("roots: {:?}", roots.to_string());

        // gamma.: "Fp256 \"(0F61D905AA7AB6431ED37538CE6EBBD8A9BC0ADC26B2E79334897832D4ED7A61)\""
        // xi_seed.: "Fp256 \"(11754717ACAD945191E1FF79806878BC9FD858505FDEC854A5A86F5560A9BF60)\""
        // xi_seed_2.: "Fp256 \"(1437DB2A37E3708C066629D9DACF66EFC8F8910EFFAE13703769EA717AAB39C0)\""
        //
        // h0w8.: "Fp256 \"(0DBEDB2934AC418D1C1C8E47DEC1A69E66A94BB554BFA6872AFC4F8CA40BAAB9)\""
        // h1w4.: "Fp256 \"(000B4985BCCB79153FCFC78A09DD812C8F4956133E5F9E2AB68AAADAEDB987D2)\""
        // h2w3.: "Fp256 \"(04223E9C7035F035378A054386DDEF799F5EE8291A05E59861D5A022D4F47C95)\""
        // h3w3.: "Fp256 \"(2CB4F280AE2023F789FA8CF12229D101D8DF0232D04F554DCF433A95F85C8C20)\""
        // y.: "Fp256 \"(1CF470047F945B3D32D9181356C6EDAD2FE9D793B43067E662DFC394A89052CF)\""
        // alpha : "Fp256 \"(103021D2C4DFFB3F63489C89C0E19CBD349A4B3257B751B780D5C97DB715AE58)\""
    }

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
        println!("fr actual_bytes: {:?}", actual_bytes);
        let actual = padd_bytes32(actual_bytes);
        println!("fr actual_padd_bytes: {:?}", actual);

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
