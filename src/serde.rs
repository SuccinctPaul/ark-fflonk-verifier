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
    use crate::mock::MOCK_PROOF_DATA;
    use crate::proof::Proof;
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
    fn deserialize_snarkjs_proof_json() {
        let json = r#"
       {
         "polynomials": {
          "C1": [
           "19512952758028491405934790115790312944649901939821135923885427424035043432523",
           "14556573045681247107321758464038638460236603165915844088653795891137636966580",
           "1"
          ],
          "C2": [
           "18724765532860887462293740304560312103629598712675774059706825360379977966561",
           "14533846076669948037568538427127727867276686064060198244794640904541487914310",
           "1"
          ],
          "W1": [
           "18433064140714518735926988684235687309803035076187502211354351663568191930935",
           "14788057617464302331557630380512402745218864581677826595197645173223539673357",
           "1"
          ],
          "W2": [
           "16578902799151672151956332367598573028719537462531716854255433720543688684250",
           "21622823131302647207265406578951014306163648459064954245545121280505919027356",
           "1"
          ]
         },
         "evaluations": {
          "ql": "18137169988004520649554381379919736533761028898864355980977573474774839426808",
          "qr": "20404082766518508880627958927869090077251470748406210835504197196401842200720",
          "qm": "707461819326729660985337250976599267781706195992934524838013487904784094085",
          "qo": "18963438173828461591436352330653675208295853959010167304990158722672578932373",
          "qc": "0",
          "s1": "13524886271252282626956626393365051655320699188917745152708417704896009650580",
          "s2": "3174783679655029387130611916286066252438878675967458260277093528819580058722",
          "s3": "21577928273077063144453890504595174724360613180856082038860286291422143482499",
          "a": "10974786676655016445248972047105688770512999913871262036359224483296214498183",
          "b": "21083250626163147629372415164899163984499137689834405549506537520836126119194",
          "c": "18485668148010316467769714971633785148294508157898193267298903173050206942624",
          "z": "16553584390052184118636614382976559370280626167659817002054727638080918750406",
          "zw": "4415347360457194011128422992457486517452412864360300524180855069319812783387",
          "t1w": "14054646597435401354125275990480383598795508549938505679628793738166042203625",
          "t2w": "13096655044313949187605874896346306929343048005668253765142398343590307027689",
          "inv": "7456529870837358461413290055129561230845481425037098795678169994084881795519"
         },
         "protocol": "fflonk",
         "curve": "bn128"
        }
        "#;
        let proof: Proof = serde_json::from_str(json).unwrap();

        let expect = Proof::construct(MOCK_PROOF_DATA.to_vec());
        assert_eq!(expect, proof);
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
        let json = serde_json::to_string(&vk).unwrap();
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
