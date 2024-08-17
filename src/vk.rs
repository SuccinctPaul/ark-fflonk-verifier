use ark_bn254::{Fq, Fq2, Fr, G1Affine, G1Projective, G2Affine, G2Projective};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::Field;
use num_traits::One;
use serde::{Deserialize, Serialize};
use std::str::FromStr;

#[derive(PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct SnarkJSVK {
    // Domain size
    pub power: u8,

    // Verification Key data
    #[serde(with = "crate::serde::fr")]
    pub k1: Fr,
    #[serde(with = "crate::serde::fr")]
    pub k2: Fr,

    // OMEGAS
    #[serde(with = "crate::serde::fr")]
    pub w: Fr,
    #[serde(with = "crate::serde::fr")]
    pub w3: Fr,
    #[serde(with = "crate::serde::fr")]
    pub w4: Fr,
    #[serde(with = "crate::serde::fr")]
    pub w8: Fr,
    #[serde(with = "crate::serde::fr")]
    pub wr: Fr,

    // Verifier preprocessed input
    // x·[1]_2
    #[serde(with = "crate::serde::g2", rename = "X_2")]
    pub x2: G2Projective,
    // C_0(x)·[1]_1
    #[serde(with = "crate::serde::g1", rename = "C0")]
    pub c0: G1Projective,
}

impl Default for SnarkJSVK {
    fn default() -> Self {
        let k = 24;
        Self {
            power: k,
            k1: Fr::from(2),
            k2: Fr::from(3),
            w: Fr::from_str(
                "5709868443893258075976348696661355716898495876243883251619397131511003808859",
            )
            .unwrap(),
            wr: Fr::from_str(
                "18200100796661656210024324131237448517259556535315737226009542456080026430510",
            )
            .unwrap(),

            w3: Fr::from_str(
                "21888242871839275217838484774961031246154997185409878258781734729429964517155",
            )
            .unwrap(),

            w4: Fr::from_str(
                "21888242871839275217838484774961031246007050428528088939761107053157389710902",
            )
            .unwrap(),

            w8: Fr::from_str(
                "19540430494807482326159819597004422086093766032135589407132600596362845576832",
            )
            .unwrap(),

            x2: {
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
                G2Projective::new(Fq2::new(x2x1, x2x2), Fq2::new(x2y1, x2y2), Fq2::one())
            },
            c0: {
                let x = Fq::from_str(
                    "7005013949998269612234996630658580519456097203281734268590713858661772481668",
                )
                .unwrap();
                let y = Fq::from_str(
                    "869093939501355406318588453775243436758538662501260653214950591532352435323",
                )
                .unwrap();
                G1Projective::new(x, y, Fq::one())
            },
        }
    }
}

#[derive(Debug, Eq, PartialEq, Clone)]
pub struct VerificationKey {
    // Domain size
    pub power: u8,
    pub n: Fr,

    // Verification Key data
    pub k1: Fr,
    pub k2: Fr,

    // Verifier preprocessed input
    // x·[1]_2
    pub x2: G2Affine,
    // C_0(x)·[1]_1
    pub c0: G1Affine,
    // [1]_2
    pub g2: G2Affine,
    // OMEGAS
    pub omega: Omega,
}
impl Default for VerificationKey {
    fn default() -> Self {
        let k = 24;
        Self {
            power: k,
            n: Fr::from(1 << k),
            k1: Fr::from(2),
            k2: Fr::from(3),
            x2: {
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
                G2Affine::new(Fq2::new(x2x1, x2x2), Fq2::new(x2y1, x2y2))
            },
            c0: {
                let x = Fq::from_str(
                    "7005013949998269612234996630658580519456097203281734268590713858661772481668",
                )
                .unwrap();
                let y = Fq::from_str(
                    "869093939501355406318588453775243436758538662501260653214950591532352435323",
                )
                .unwrap();
                G1Affine::new(x, y)
            },
            g2: G2Affine::generator(),
            omega: Omega::default(),
        }
    }
}

impl From<SnarkJSVK> for VerificationKey {
    fn from(origin: SnarkJSVK) -> Self {
        let k = origin.power;

        let omega = Omega {
            w1: origin.w,
            wr: origin.wr,
            w3: origin.w3,
            w4: origin.w4,
            w4_2: origin.w4,
            w8_1: origin.w8,
            ..Default::default()
        };
        let precompute_omega = Omega::precompute(&omega);

        VerificationKey {
            power: k,
            n: Fr::from(1 << k),
            k1: origin.k1,
            k2: origin.k2,
            x2: origin.x2.into_affine(),
            c0: origin.c0.into_affine(),
            g2: G2Affine::generator(),
            omega: precompute_omega,
        }
    }
}

#[derive(Debug, Eq, PartialEq, Clone)]
pub struct Omega {
    pub w1: Fr,
    pub wr: Fr,

    pub w3: Fr,
    pub w3_2: Fr,

    pub w4: Fr,
    pub w4_2: Fr,
    pub w4_3: Fr,

    pub w8_1: Fr,
    pub w8_2: Fr,
    pub w8_3: Fr,
    pub w8_4: Fr,
    pub w8_5: Fr,
    pub w8_6: Fr,
    pub w8_7: Fr,
}

impl Omega {
    pub fn precompute(origin: &Self) -> Self {
        let w3_2 = origin.w3.pow([2]);

        let w4_2 = origin.w4.pow([2]);
        let w4_3 = w4_2 * origin.w4;

        let w8_2 = origin.w8_1.pow([2]);
        let w8_3 = w8_2 * origin.w8_1;
        let w8_4 = w8_3 * origin.w8_1;
        let w8_5 = w8_4 * origin.w8_1;
        let w8_6 = w8_5 * origin.w8_1;
        let w8_7 = w8_6 * origin.w8_1;

        Self {
            w1: origin.w1,
            wr: origin.wr,
            w3: origin.w3,
            w3_2,
            w4: origin.w4,
            w4_2,
            w4_3,
            w8_1: origin.w8_1,
            w8_2,
            w8_3,
            w8_4,
            w8_5,
            w8_6,
            w8_7,
        }
    }
}

impl Default for Omega {
    fn default() -> Self {
        Self {
            w1: Fr::from_str(
                "5709868443893258075976348696661355716898495876243883251619397131511003808859",
            )
            .unwrap(),
            wr: Fr::from_str(
                "18200100796661656210024324131237448517259556535315737226009542456080026430510",
            )
            .unwrap(),

            w3: Fr::from_str(
                "21888242871839275217838484774961031246154997185409878258781734729429964517155",
            )
            .unwrap(),
            w3_2: Fr::from_str("4407920970296243842393367215006156084916469457145843978461")
                .unwrap(),

            w4: Fr::from_str(
                "21888242871839275217838484774961031246007050428528088939761107053157389710902",
            )
            .unwrap(),
            w4_2: Fr::from_str(
                "21888242871839275222246405745257275088548364400416034343698204186575808495616",
            )
            .unwrap(),
            w4_3: Fr::from_str("4407920970296243842541313971887945403937097133418418784715")
                .unwrap(),

            w8_1: Fr::from_str(
                "19540430494807482326159819597004422086093766032135589407132600596362845576832",
            )
            .unwrap(),
            w8_2: Fr::from_str(
                "21888242871839275217838484774961031246007050428528088939761107053157389710902",
            )
            .unwrap(),
            w8_3: Fr::from_str(
                "13274704216607947843011480449124596415239537050559949017414504948711435969894",
            )
            .unwrap(),
            w8_4: Fr::from_str(
                "21888242871839275222246405745257275088548364400416034343698204186575808495616",
            )
            .unwrap(),
            w8_5: Fr::from_str(
                "2347812377031792896086586148252853002454598368280444936565603590212962918785",
            )
            .unwrap(),
            w8_6: Fr::from_str("4407920970296243842541313971887945403937097133418418784715")
                .unwrap(),
            w8_7: Fr::from_str(
                "8613538655231327379234925296132678673308827349856085326283699237864372525723",
            )
            .unwrap(),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_precompute_omega() {
        let expect = Omega::default();

        let actaul = Omega::precompute(&expect);
        assert_eq!(expect.w4, actaul.w4);
        assert_eq!(expect.w4_2, actaul.w4_2);
        assert_eq!(expect.w4_3, actaul.w4_3);
        assert_eq!(expect.w3, actaul.w3);
        assert_eq!(expect.w3_2, actaul.w3_2);
        assert_eq!(expect.w8_1, actaul.w8_1);
        assert_eq!(expect.w8_2, actaul.w8_2);
        assert_eq!(expect.w8_3, actaul.w8_3);
        assert_eq!(expect.w8_4, actaul.w8_4);
        assert_eq!(expect.w8_5, actaul.w8_5);
        assert_eq!(expect.w8_6, actaul.w8_6);
        assert_eq!(expect.w8_7, actaul.w8_7);
        assert_eq!(expect, actaul);
    }

    #[test]
    fn test_convert_between_SnarkJSVK_and_VerificationKey() {
        let snarkjs_vk = SnarkJSVK::default();
        let actual: VerificationKey = snarkjs_vk.into();

        let expect = VerificationKey::default();
        assert_eq!(actual.power, expect.power);
        assert_eq!(actual.k1, expect.k1);
        assert_eq!(actual.k2, expect.k2);
        assert_eq!(actual.n, expect.n);
        assert_eq!(actual.g2, expect.g2);
        assert_eq!(actual.k2, expect.k2);
        assert_eq!(actual.x2, expect.x2);
        assert_eq!(actual.omega, expect.omega);
        // assert_eq!(actual, expect);
    }
}
