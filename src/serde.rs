#![cfg(feature = "serde")]

pub mod fr {
    use ark_bn254::Fr;
    use std::str::FromStr;

    pub fn serialize<S>(fr: &Fr, s: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        s.serialize_str(&fr.to_string())
    }

    pub fn deserialize<'de, D>(data: D) -> Result<Fr, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        <String as serde::Deserialize>::deserialize(data).map(|s| Fr::from_str(&s).unwrap())
    }
}

pub mod fq {
    use ark_bn254::Fq;
    use std::str::FromStr;

    pub fn serialize<S>(fr: &Fq, s: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        s.serialize_str(&fr.to_string())
    }

    pub fn deserialize<'de, D>(data: D) -> Result<Fq, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        <String as serde::Deserialize>::deserialize(data).map(|s| Fq::from_str(&s).unwrap())
    }
}

mod fq2 {
    use ark_bn254::{Fq, Fq2};
    use serde::{Deserialize, Serialize};

    #[derive(Serialize, Deserialize)]
    struct Fq2Serde(
        #[serde(with = "super::fq")] Fq,
        #[serde(with = "super::fq")] Fq,
    );

    pub fn serialize<S>(fq2: &Fq2, s: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        Fq2Serde(fq2.c0, fq2.c1).serialize(s)
    }

    pub fn deserialize<'de, D>(data: D) -> Result<Fq2, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let fq2 = Fq2Serde::deserialize(data)?;
        Ok(Fq2::new(fq2.0, fq2.1))
    }
}

pub mod g2 {
    use ark_bn254::{Fq2, G2Affine, G2Projective};
    use ark_ec::CurveGroup;
    use ark_serialize::Valid;
    use num_traits::One;
    use serde::{Deserialize, Serialize};

    #[derive(Serialize, Deserialize)]
    struct G2Serde(
        #[serde(with = "super::fq2")] Fq2,
        #[serde(with = "super::fq2")] Fq2,
        #[serde(with = "super::fq2")] Fq2,
    );
    // serde G2Affine from G2Projective.
    pub fn serialize<S>(g2: &G2Projective, s: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        G2Serde(g2.x, g2.y, g2.z).serialize(s)
    }

    // deserde G2Affine into G2Projective.
    pub fn deserialize<'de, D>(data: D) -> Result<G2Projective, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let g2 = G2Serde::deserialize(data)?;
        let candidate = G2Projective::new(g2.0, g2.1, g2.2);
        candidate
            .check()
            .map_err(|_e| serde::de::Error::custom("Invalid G2Projective point"))?;
        Ok(candidate)
    }
}

pub mod g1 {
    use ark_bn254::{Fq, G1Affine, G1Projective};
    use ark_ec::CurveGroup;
    use ark_serialize::Valid;
    use num_traits::One;
    use serde::{Deserialize, Serialize};

    #[derive(Serialize, Deserialize)]
    struct G1Serde(
        #[serde(with = "super::fq")] Fq,
        #[serde(with = "super::fq")] Fq,
        #[serde(with = "super::fq")] Fq,
    );

    pub fn serialize<S>(g1: &G1Projective, s: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        G1Serde(g1.x, g1.y, g1.z).serialize(s)
    }

    pub fn deserialize<'de, D>(data: D) -> Result<G1Projective, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let g1 = G1Serde::deserialize(data)?;
        let candidate = G1Projective::new(g1.0, g1.1, g1.2);
        candidate
            .check()
            .map_err(|_e| serde::de::Error::custom("Invalid G1Projective point"))?;
        Ok(candidate)
    }
}

#[cfg(test)]
mod should {
    use super::super::*;
    use crate::vk::SnarkjsVK;
    use ::serde::Deserialize;
    use ark_bn254::{Fr, G1Projective, G2Projective};
    use pretty_assertions::assert_eq;

    // Just because `json!` macro need `vec!` macro.
    #[cfg(feature = "std")]
    #[test]
    fn serialize_the_valid_json() {
        let vk = SnarkjsVK::default();

        let serialized = serde_json::to_string(&vk).unwrap();

        let v: serde_json::Value = serde_json::from_str(&serialized).unwrap();
        let expected = serde_json::json!({
        "power": 24,
        "k1": "2",
        "k2": "3",
        "w": "5709868443893258075976348696661355716898495876243883251619397131511003808859",
        "w3": "21888242871839275217838484774961031246154997185409878258781734729429964517155",
        "w4": "21888242871839275217838484774961031246007050428528088939761107053157389710902",
        "w8": "19540430494807482326159819597004422086093766032135589407132600596362845576832",
        "wr": "18200100796661656210024324131237448517259556535315737226009542456080026430510",
        "X_2": [
        [
        "21831381940315734285607113342023901060522397560371972897001948545212302161822",
        "17231025384763736816414546592865244497437017442647097510447326538965263639101"
        ],
        [
        "2388026358213174446665280700919698872609886601280537296205114254867301080648",
        "11507326595632554467052522095592665270651932854513688777769618397986436103170"
        ],
        [
        "1",
        "0"
        ]
        ],
        "C0": [
        "7436841426934271843999872946312645822871802402068881571108027575346498207286",
        "18448034242258174646222819724328439025708531082946938915005051387020977719791",
        "1"
        ]
        });
        assert_eq!(expected, v);
    }

    #[test]
    fn deserialize_the_verification_key_json() {
        let json = r#"
        {
            "protocol": "fflonk",
            "curve": "bn128",
            "nPublic": 1,
            "power": 24,
            "k1": "2",
            "k2": "3",
            "w": "5709868443893258075976348696661355716898495876243883251619397131511003808859",
            "w3": "21888242871839275217838484774961031246154997185409878258781734729429964517155",
            "w4": "21888242871839275217838484774961031246007050428528088939761107053157389710902",
            "w8": "19540430494807482326159819597004422086093766032135589407132600596362845576832",
            "wr": "18200100796661656210024324131237448517259556535315737226009542456080026430510",
            "X_2": [
            [
            "21831381940315734285607113342023901060522397560371972897001948545212302161822",
            "17231025384763736816414546592865244497437017442647097510447326538965263639101"
            ],
            [
            "2388026358213174446665280700919698872609886601280537296205114254867301080648",
            "11507326595632554467052522095592665270651932854513688777769618397986436103170"
            ],
            [
            "1",
            "0"
            ]
            ],
            "C0": [
            "7005013949998269612234996630658580519456097203281734268590713858661772481668",
            "869093939501355406318588453775243436758538662501260653214950591532352435323",
            "1"
            ]
        }
        "#;
        let vk: SnarkjsVK = serde_json::from_str(json).unwrap();

        let expect = SnarkjsVK::default();
        assert_eq!(expect, vk);
        // assert_eq!(expect.power, vk.power);
        // assert_eq!(expect.k1, vk.k1);
        // assert_eq!(expect.k2, vk.k2);
        // assert_eq!(expect.w, vk.w);
        // assert_eq!(expect.wr, vk.wr);
        // assert_eq!(expect.w3, vk.w3);
        // assert_eq!(expect.w4, vk.w4);
        // assert_eq!(expect.w8, vk.w8);
        // assert_eq!(expect.x2, vk.x2);
        // assert_eq!(expect.c0, vk.c0);
    }

    #[test]
    fn serialize_deserialize_default_key() {
        let vk = SnarkjsVK::default();
        let json = serde_json::to_string(&vk).unwrap();
        let other = serde_json::from_str(&json).unwrap();

        assert_eq!(vk, other);
    }

    #[test]
    #[should_panic(expected = "Invalid G1 point")]
    fn raise_error_if_try_to_deserialize_an_invalid_g1_point() {
        let json = r#"["1", "2", "3"]"#;
        #[derive(Deserialize)]
        #[allow(dead_code)]
        struct Test(#[cfg_attr(feature = "serde", serde(with = "super::g1"))] G1Projective);

        serde_json::from_str::<Test>(json).unwrap();
    }

    #[test]
    #[should_panic(expected = "Invalid G2 point")]
    fn raise_error_if_try_to_deserialize_an_invalid_g2_point() {
        let json = r#"[["1", "2"], ["3", "4"], ["5", "6"]]"#;
        #[derive(Deserialize)]
        #[allow(dead_code)]
        struct Test(#[cfg_attr(feature = "serde", serde(with = "super::g2"))] G2Projective);

        serde_json::from_str::<Test>(json).unwrap();
    }
}
