use crate::proof::get_proog_bigint;
use crate::{get_omegas, padd_bytes32, vk::VerifierProcessedInputs};
use ark_bn254::Fr;
use ark_ff::{Field, One};
use num_bigint::{BigInt, BigUint};
use std::fmt;

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

    pub fn compute(vpi: VerifierProcessedInputs, pub_signal: Fr) -> (Challenges, Roots) {
        println!("pub_signal: {:?}", pub_signal.to_string());
        println!("pub_signal: {:?}", pub_signal);

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

        println!("y_concatenated: {:?}", concatenated);
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

#[cfg(test)]
mod test {
    use crate::challenge::Challenges;
    use crate::vk::VerifierProcessedInputs;
    use crate::{get_pubSignals, padd_bytes32};
    use ark_bn254::Fr;
    use ark_ff::{BigInteger, PrimeField};
    use num_bigint::{BigInt, BigUint};
    use std::str::FromStr;

    #[test]
    fn test_compute_challenge() {
        let pub_signal = get_pubSignals();

        let vpi = VerifierProcessedInputs::default();

        let (challenges, roots) = Challenges::compute(vpi, pub_signal.clone());

        // println!("challenge.: {:?}", challenges.to_string());
        // println!("");
        // println!("roots: {:?}", roots.to_string());

        // let alpha = Fr::from_str("103021D2C4DFFB3F63489C89C0E19CBD349A4B3257B751B780D5C97DB715AE58").unwrap();
        // println!("alpha: {}", alpha.to_string());
        // let expect_challenge = Challenges{
        //     alpha: Fr::from_str("103021D2C4DFFB3F63489C89C0E19CBD349A4B3257B751B780D5C97DB715AE58").unwrap(),
        //     beta: Fr::from_str("013AA98A5AFBBF2285C69039D7DD67BF087D1132DB842E41AF4E084141611093").unwrap(),
        //     gamma: Fr::from_str("0F61D905AA7AB6431ED37538CE6EBBD8A9BC0ADC26B2E79334897832D4ED7A61").unwrap(),
        //     y: Fr::from_str("1CF470047F945B3D32D9181356C6EDAD2FE9D793B43067E662DFC394A89052CF").unwrap(),
        //     xi_seed: Fr::from_str("11754717ACAD945191E1FF79806878BC9FD858505FDEC854A5A86F5560A9BF60").unwrap(),
        //     xi_seed_2: Fr::from_str("1437DB2A37E3708C066629D9DACF66EFC8F8910EFFAE13703769EA717AAB39C0").unwrap(),
        //     xi: Fr::from_str("16FA559297E6D34B35D901E00A2738B590D3FA0021DE44EC7A5BE1128990CF9A").unwrap(),
        //     zh: Fr::from_str("1327378F00ACD53ADD567D4A3881DFC5B5BBDEB32927E5525FF6185B67335855").unwrap(),
        // };
        // assert_eq!(challenges, expect_challenge);

        // running 1 test
        // y: "Fp256 \"(1CF470047F945B3D32D9181356C6EDAD2FE9D793B43067E662DFC394A89052CF)\""
        // challenge.: "alpha: \"Fp256 \\\"(103021D2C4DFFB3F63489C89C0E19CBD349A4B3257B751B780D5C97DB715AE58)\\\
        // "\"beta: Fp256 \"(013AA98A5AFBBF2285C69039D7DD67BF087D1132DB842E41AF4E084141611093)\
        // "gamma: Fp256 \"(0F61D905AA7AB6431ED37538CE6EBBD8A9BC0ADC26B2E79334897832D4ED7A61)\
        // "y: Fp256 \"(1CF470047F945B3D32D9181356C6EDAD2FE9D793B43067E662DFC394A89052CF)\
        // "xi: Fp256 \"(16FA559297E6D34B35D901E00A2738B590D3FA0021DE44EC7A5BE1128990CF9A)\"xi_seed: Fp256 \"(11754717ACAD945191E1FF79806878BC9FD858505FDEC854A5A86F5560A9BF60)\"xi_seed_2: Fp256 \"(1437DB2A37E3708C066629D9DACF66EFC8F8910EFFAE13703769EA717AAB39C0)\"zh: Fp256 \"(1327378F00ACD53ADD567D4A3881DFC5B5BBDEB32927E5525FF6185B67335855)\""
        //
        // roots: "Roots: [h0w8:[Fp256 \"(0DBEDB2934AC418D1C1C8E47DEC1A69E66A94BB554BFA6872AFC4F8CA40BAAB9)\", Fp256 \"(0E4C760B29A5E4187CE1472F33C29893F7F24D772399C13A9CD4F6E9A68CC495)\", Fp256 \"(25B6D5D784D2A55DA1C28074A7CE58F01DF79C8976D7A7A582007852E0C12688)\", Fp256 \"(2F20E9CC991338002D088E77C566314D95AC6DDE761A48428E61639700A70997)\", Fp256 \"(22A57349AC855E9C9C33B76EA2BFB1BEC18A9C9324F9CA0A18E5A6074BF45548)\", Fp256 \"(2217D867B78BBC113B6EFE874DBEBFC930419AD1561FAF56A70CFEAA49733B6C)\", Fp256 \"(0AAD789B5C5EFACC168DC541D9B2FF6D0A3C4BBF02E1C8EBC1E17D410F3ED979)\", Fp256 \"(014364A6481E68298B47B73EBC1B270F92877A6A039F284EB58091FCEF58F66A)\"], h1w4:[Fp256 \"(000B4985BCCB79153FCFC78A09DD812C8F4956133E5F9E2AB68AAADAEDB987D2)\", Fp256 \"(0D6B92FFC137B85609321C5DB809AB01585AFCCAF0164A61CE8A2CA9CEA7FF60)\", Fp256 \"(305904ED2466271478807E2C77A3D73098EA92353B59D2668D574AB90246782F)\", Fp256 \"(22F8BB731FF9E7D3AF1E2958C977AD5BCFD8EB7D89A3262F7557C8EA215800A1)\"], h2w3:[Fp256 \"(04223E9C7035F035378A054386DDEF799F5EE8291A05E59861D5A022D4F47C95)\", Fp256 \"(1C6BC919795CB7B22F90CE06E0BB83C43ABB610E96022A71CCD908C6C7A69D43)\", Fp256 \"(0FD646BCF79EF8425135726C19E7E51F4E199F10C9B1608715334CAA5364E629)\"], h3w3:[Fp256 \"(2CB4F280AE2023F789FA8CF12229D101D8DF0232D04F554DCF433A95F85C8C20)\", Fp256 \"(0B75162F52D17C750A365B2FDA8098D97CBADA4D015C58416BEFE7EF842CC9C8)\", Fp256 \"(289E9435C1719FE6DC6FA34C065846DEFACDF41121C733934C90C8A26376AA1A)\"] ]"
        // test challenge::test::test_compute_challenge ... ok
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
