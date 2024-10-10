pub mod root;

use crate::vk::VerificationKey;
use ark_bn254::{Fr, G1Affine};
use ark_ff::{BigInteger, Field, One, PrimeField};
use num_bigint::BigInt;
use std::fmt;

use crate::challenge::root::Roots;
use crate::proof::{Evaluations, Proof};
use crate::transcript::TranscriptHash;
use crate::utils::compute_zero_poly_evals;
use ark_ec::CurveGroup;
use std::str::FromStr;

#[derive(Debug, Default, Eq, PartialEq, Copy, Clone)]
pub struct Challenges {
    pub alpha: Fr,
    pub beta: Fr,
    pub gamma: Fr,
    pub y: Fr,
    pub xi: Fr,
    pub zh: Fr,
    pub roots: Roots,
}
impl Challenges {
    // compute challenge, roots and zero_poly_eval zh:
    //  beta, gamma, xi, alpha and y ∈ F, h1w4/h2w3/h3w3 roots, xiN and zh(xi)
    pub fn compute<T: TranscriptHash>(vk: &VerificationKey, proof: &Proof, pub_input: &Fr) -> Self {
        // Compute challenges beta,gamma,xi,alpha,y ∈ 𝐹 as in prover description, from the common inputs, public input, and the elements of 𝜋_SNARK

        // 1 compute beta: keccak_hash with c0, pub_input, c1
        let beta = Self::compute_beta::<T>(&vk.c0, &proof.polynomials.c1.into_affine(), pub_input);
        // 2. compute gamma: keccak_hash with beta
        let gamma = Self::compute_gamma::<T>(&beta);

        // 3. compute xi
        //      compute xi_seed: keccak_hash with gamma,c2
        let xi_seed = Self::compute_xiseed::<T>(&gamma, proof.polynomials.c2.into_affine());
        //      compute xi=xi_seeder^24
        let xi = xi_seed.pow([24]);

        // 4. compute alpha: keccak_hash with xi_seed, eval_lines
        let alpha = Self::compute_alpha::<T>(&xi_seed, &proof.evaluations);

        // 5. compute y: keccak_hash with alpha, w1
        let y = Self::compute_y::<T>(&alpha, &proof.polynomials.w1.into_affine());

        Challenges {
            alpha,
            beta,
            gamma,
            y,
            xi,
            zh: compute_zero_poly_evals(&xi, &vk.n),
            roots: Roots::compute(vk, &xi_seed),
        }
    }

    // compute beta: keccak_hash with c0, pub_input, c1
    pub fn compute_beta<T: TranscriptHash>(c0: &G1Affine, c1: &G1Affine, pub_input: &Fr) -> Fr {
        let concatenated = vec![
            c0.x.into_bigint().to_bytes_be(),
            c0.y.into_bigint().to_bytes_be(),
            pub_input.into_bigint().to_bytes_be(),
            c1.x.into_bigint().to_bytes_be(),
            c1.y.into_bigint().to_bytes_be(),
        ]
        .into_iter()
        .flatten()
        .collect::<Vec<_>>();
        T::hash_to_fr(concatenated)
    }

    // 2. compute gamma: keccak_hash with beta
    pub fn compute_gamma<T: TranscriptHash>(beta: &Fr) -> Fr {
        let concatenated = beta.into_bigint().to_bytes_be();
        T::hash_to_fr(concatenated)
    }

    //  compute xi_seed: hash with gamma,c2
    pub fn compute_xiseed<T: TranscriptHash>(gamma: &Fr, c2: G1Affine) -> Fr {
        let concatenated = vec![
            gamma.into_bigint().to_bytes_be(),
            c2.x.into_bigint().to_bytes_be(),
            c2.y.into_bigint().to_bytes_be(),
        ]
        .into_iter()
        .flatten()
        .collect::<Vec<_>>();
        T::hash_to_fr(concatenated)
    }

    // compute alpha: keccak_hash with xi_seed, eval_lines
    pub fn compute_alpha<T: TranscriptHash>(xi_seed: &Fr, evaluations: &Evaluations) -> Fr {
        let concatenated = vec![
            xi_seed.into_bigint().to_bytes_be(),
            evaluations.ql.into_bigint().to_bytes_be(),
            evaluations.qr.into_bigint().to_bytes_be(),
            evaluations.qm.into_bigint().to_bytes_be(),
            evaluations.qo.into_bigint().to_bytes_be(),
            evaluations.qc.into_bigint().to_bytes_be(),
            evaluations.s1.into_bigint().to_bytes_be(),
            evaluations.s2.into_bigint().to_bytes_be(),
            evaluations.s3.into_bigint().to_bytes_be(),
            evaluations.a.into_bigint().to_bytes_be(),
            evaluations.b.into_bigint().to_bytes_be(),
            evaluations.c.into_bigint().to_bytes_be(),
            evaluations.z.into_bigint().to_bytes_be(),
            evaluations.zw.into_bigint().to_bytes_be(),
            evaluations.t1w.into_bigint().to_bytes_be(),
            evaluations.t2w.into_bigint().to_bytes_be(),
        ]
        .into_iter()
        .flatten()
        .collect::<Vec<_>>();
        T::hash_to_fr(concatenated)
    }

    // compute y: keccak_hash with alpha, w1
    pub fn compute_y<T: TranscriptHash>(alpha: &Fr, w1: &G1Affine) -> Fr {
        let concatenated = vec![
            alpha.into_bigint().to_bytes_be(),
            w1.x.into_bigint().to_bytes_be(),
            w1.y.into_bigint().to_bytes_be(),
        ]
        .into_iter()
        .flatten()
        .collect::<Vec<_>>();
        T::hash_to_fr(concatenated)
    }
}

#[allow(clippy::to_string_in_format_args)]
impl fmt::Display for Challenges {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "alpha: {:?}", self.alpha.to_string())?;
        write!(f, "beta: {}", self.beta.to_string())?;
        write!(f, "gamma: {}", self.gamma.to_string())?;
        write!(f, "y: {}", self.y.to_string())?;
        write!(f, "xi: {}", self.xi.to_string())?;
        write!(f, "zh: {}", self.zh.to_string())
    }
}

// Convert decimal_str to upper_str by fmt macro.
pub fn decimal_to_hex(decimal_str: &str) -> String {
    let decimal_number = BigInt::from_str(decimal_str).expect("Invalid decimal string");
    format!("{:X}", decimal_number)
}

#[cfg(test)]
mod test {
    use super::*;

    use crate::transcript::Blake3TranscriptHash;
    use num_bigint::BigUint;
    use tiny_keccak::{Hasher, Keccak};

    fn keccak_hash(bytes: Vec<u8>) -> Fr {
        println!("keccak_hash ");
        let mut hasher = Keccak::v256();
        hasher.update(&bytes);

        let mut out = [0u8; 32];
        hasher.finalize(&mut out);

        Fr::from_be_bytes_mod_order(&out)
    }

    fn blake3_hash(bytes: Vec<u8>) -> Fr {
        println!("blake3_hash ");

        let mut hasher = blake3::Hasher::new();
        hasher.update(&bytes);
        let output_reader = hasher.finalize();
        let res_bigint = BigInt::from_bytes_be(num_bigint::Sign::Plus, output_reader.as_bytes());

        Fr::from_str(&res_bigint.to_string()).unwrap()
    }

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
    fn test_blake3_gamma() {
        let beta = Fr::from_str(
            "14217054809736064644780466650249611613142182608788581474253500114349716637652",
        )
        .unwrap();

        let bytes = beta.into_bigint().to_bytes_be();

        let actual = blake3_hash(bytes.clone());

        // different hash algorithm should have different output.
        let expect = Fr::from_str(
            "18625893475371571197839289625741174101096563782277458846920976081923622001569",
        )
        .unwrap();
        // 14492412223297911893960987875896571725330441878463898090786262955691738278152
        println!("expect: {:?}", expect.to_string());

        assert_eq!(actual, expect);

        let gamma = Challenges::compute_gamma::<Blake3TranscriptHash>(&beta);
        println!("gamma: {:?}", gamma.to_string());
        assert_eq!(gamma, expect);
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

        let sig_biguint: BigUint = pub_sig.into();
        let actual_biguint_bytes = sig_biguint.to_bytes_be();
        println!("actual_biguint_bytes: {:?}", actual_biguint_bytes);
        let actual_biguint_bytes = padd_bytes32(actual_biguint_bytes);
        println!("actual_biguint_bytes: {:?}", actual_biguint_bytes);

        // assert_eq!(expect_biguint, expect_bigint);

        assert_eq!(actual_biguint_bytes, expect_biguint);
    }

    #[test]
    fn test_compute_beta() {
        let xi_seed = Fr::from_str(
            "12675309311304482509247823029963782393309524866265275290730041635615278736000",
        )
        .unwrap();
        let ql = Fr::from_str(
            "4305584171954448775801758618991977283131671407134816099015723841718827300684",
        )
        .unwrap();
        let qr = Fr::from_str(
            "12383383973686840675128398394454489421896122330596726461131121746926747341189",
        )
        .unwrap();
        let qm = Fr::from_str(
            "84696450614978050680673343346456326547032107368333805624994614151289555853",
        )
        .unwrap();
        let qo = Fr::from_str(
            "3940439340424631873531863239669720717811550024514867065774687720368464792371",
        )
        .unwrap();
        let qc = Fr::from_str(
            "16961785810060156933739931986193776143069216115530808410139185289490606944009",
        )
        .unwrap();
        let s1 = Fr::from_str(
            "12474437127153975801320290893919924661315458586210754316226946498711086665749",
        )
        .unwrap();
        let s2 = Fr::from_str(
            "599434615255095347665395089945860172292558760398201299457995057871688253664",
        )
        .unwrap();
        let s3 = Fr::from_str(
            "16217604511932175446614838218599989473511950977205890369538297955449224727219",
        )
        .unwrap();
        let a = Fr::from_str(
            "7211168621666826182043583595845418959530786367587156242724929610231435505336",
        )
        .unwrap();
        let b = Fr::from_str(
            "848088075173937026388846472327431819307508078325359401333033359624801042",
        )
        .unwrap();
        let c = Fr::from_str(
            "18963734392470978715233675860777231227480937309534365140504133190694875258320",
        )
        .unwrap();
        let z = Fr::from_str(
            "2427313569771756255376235777000596702684056445296844486767054635200432142794",
        )
        .unwrap();
        let zw = Fr::from_str(
            "8690328511114991742730387856275843464438882369629727414507275814599493141660",
        )
        .unwrap();
        let t1w = Fr::from_str(
            "20786626696833495453279531623626288211765949258916047124642669459480728122908",
        )
        .unwrap();
        let t2w = Fr::from_str(
            "12092130080251498309415337127155404037148503145602589831662396526189421234148",
        )
        .unwrap();

        let concatenated = vec![
            xi_seed.into_bigint().to_bytes_be(),
            ql.into_bigint().to_bytes_be(),
            qr.into_bigint().to_bytes_be(),
            qm.into_bigint().to_bytes_be(),
            qo.into_bigint().to_bytes_be(),
            qc.into_bigint().to_bytes_be(),
            s1.into_bigint().to_bytes_be(),
            s2.into_bigint().to_bytes_be(),
            s3.into_bigint().to_bytes_be(),
            a.into_bigint().to_bytes_be(),
            b.into_bigint().to_bytes_be(),
            c.into_bigint().to_bytes_be(),
            z.into_bigint().to_bytes_be(),
            zw.into_bigint().to_bytes_be(),
            t1w.into_bigint().to_bytes_be(),
            t2w.into_bigint().to_bytes_be(),
        ]
        .into_iter()
        .flatten()
        .collect::<Vec<_>>();
        let alpha = Blake3TranscriptHash::hash_to_fr(concatenated);
        println!("alpha: {:?}", alpha.to_string());
    }
}
