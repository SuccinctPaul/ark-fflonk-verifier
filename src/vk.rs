use ark_bn254::{Fq, Fq2, Fr, G1Affine, G1Projective, G2Affine};
use ark_ec::CurveGroup;
use num_bigint::BigInt;
use num_traits::One;
use std::str::FromStr;

pub fn precompute_c0() -> G1Affine {
    G1Projective::new(Fq::one(), Fq::from(2), Fq::one()).into_affine()
}

#[derive(Debug, Eq, PartialEq, Clone)]
pub struct VerificationKey {
    pub power: u8,
    pub k1: Fr,
    pub k2: Fr,
    // pub w1: Fr,
    pub w3: Fr,
    pub w4: Fr,
    pub w8: Fr,
    pub wr: Fr,
    pub x2: G2Affine,
    pub c0: G1Affine,
}
impl Default for VerificationKey {
    fn default() -> Self {
        Self {
            power: 24,
            k1: Fr::from(2),
            k2: Fr::from(3),
            // w: u256!("0c9fabc7845d50d2852e2a0371c6441f145e0db82e8326961c25f1e3e32b045b").into_fr(),
            w3: Fr::from_str("30644e72e131a029048b6e193fd84104cc37a73fec2bc5e9b8ca0b2d36636f23")
                .unwrap(),
            w4: Fr::from_str("30644e72e131a029048b6e193fd841045cea24f6fd736bec231204708f703636")
                .unwrap(),
            w8: Fr::from_str("2b337de1c8c14f22ec9b9e2f96afef3652627366f8170a0a948dad4ac1bd5e80")
                .unwrap(),
            wr: Fr::from_str("283ce45a2e5b8e4e78f9fbaf5f6a348bfcfaf76dd28e5ca7121b74ef68fdec2e")
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
        }
    }
}

#[derive(Debug, Eq, PartialEq, Clone)]
pub struct VerifierProcessedInputs {
    pub c0x: BigInt,
    pub c0y: BigInt,
    pub x2x1: BigInt,
    pub x2x2: BigInt,
    pub x2y1: BigInt,
    pub x2y2: BigInt,
}

impl Default for VerifierProcessedInputs {
    fn default() -> Self {
        let vpi = VerifierProcessedInputs {
            c0x: BigInt::parse_bytes(
                b"7005013949998269612234996630658580519456097203281734268590713858661772481668",
                10,
            )
            .unwrap(),
            c0y: BigInt::parse_bytes(
                b"869093939501355406318588453775243436758538662501260653214950591532352435323",
                10,
            )
            .unwrap(),
            x2x1: BigInt::parse_bytes(
                b"21831381940315734285607113342023901060522397560371972897001948545212302161822",
                10,
            )
            .unwrap(),
            x2x2: BigInt::parse_bytes(
                b"17231025384763736816414546592865244497437017442647097510447326538965263639101",
                10,
            )
            .unwrap(),
            x2y1: BigInt::parse_bytes(
                b"2388026358213174446665280700919698872609886601280537296205114254867301080648",
                10,
            )
            .unwrap(),
            x2y2: BigInt::parse_bytes(
                b"11507326595632554467052522095592665270651932854513688777769618397986436103170",
                10,
            )
            .unwrap(),
        };
        vpi
    }
}

pub struct Omegas {
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

impl Default for Omegas {
    fn default() -> Self {
        // TODO: merge omega into vk_data

        Omegas {
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
