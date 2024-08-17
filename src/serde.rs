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
        let a = fr.to_string();
        println!("serde_fr: {:?}", a);
        s.serialize_str(&a)
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

    #[derive(Serialize, Deserialize, Debug, Eq, PartialEq)]
    pub(crate) struct Fq2Serde(
        #[serde(with = "super::fq")] pub(crate) Fq,
        #[serde(with = "super::fq")] pub(crate) Fq,
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

    #[derive(Serialize, Deserialize, Debug, Eq, PartialEq)]
    pub(crate) struct G2Serde(
        #[serde(with = "super::fq2")] pub(crate) Fq2,
        #[serde(with = "super::fq2")] pub(crate) Fq2,
        #[serde(with = "super::fq2")] pub(crate) Fq2,
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

    #[derive(Serialize, Deserialize, Debug, Eq, PartialEq)]
    pub(crate) struct G1Serde(
        #[serde(with = "super::fq")] pub(crate) Fq,
        #[serde(with = "super::fq")] pub(crate) Fq,
        #[serde(with = "super::fq")] pub(crate) Fq,
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
mod test {
    use super::super::*;
    use crate::vk::SnarkJSVK;
    use ark_bn254::{Fq, Fq2, Fr};
    use num_traits::One;
    use pretty_assertions::assert_eq;

    #[test]
    fn deserialize_snarkjs_vk_json() {
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
        let vk: SnarkJSVK = serde_json::from_str(json).unwrap();

        let expect = SnarkJSVK::default();
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
    fn serialize_and_deserialize_default_snarkjs_vk() {
        let vk = SnarkJSVK::default();
        let json = serde_json::to_string_pretty(&vk).unwrap();
        println!("vk: {:?}", vk);
        // let other = serde_json::from_str(&json).unwrap();
        //
        // assert_eq!(vk, other);
    }

    #[test]
    fn serialize_and_deserialize_fr_g1_g2() {
        let expect_fq2 = super::fq2::Fq2Serde(Fq::one(), Fq::one());

        let json = serde_json::to_string(&expect_fq2).unwrap();
        println!("fq2: {:?}", json);
        let actual_fq2: super::fq2::Fq2Serde = serde_json::from_str(&json).unwrap();

        assert_eq!(expect_fq2, actual_fq2);

        let expect_g1 = super::g1::G1Serde(Fq::one(), Fq::one(), Fq::one());

        let json = serde_json::to_string(&expect_g1).unwrap();
        println!("g1: {:?}", json);
        let actual_g1: super::g1::G1Serde = serde_json::from_str(&json).unwrap();

        assert_eq!(expect_g1, actual_g1);

        // TODO: Optimise serde&deserde
        // let expect_g2 = super::g2::G2Serde(Fq2::one(), Fq2::one(), Fq2::one());
        //
        // println!("g2: {:?}", expect_g1.0.to_string());
        // println!("g2: {:?}", expect_g1.1.to_string());
        // println!("g2: {:?}", expect_g1.2.to_string());
        // let json = serde_json::to_string(&expect_g2).unwrap();
        // println!("g2: {:?}", json);
        // let actual_g2: super::g2::G2Serde = serde_json::from_str(&json).unwrap();
        //
        // assert_eq!(expect_g2, actual_g2);
    }
}
