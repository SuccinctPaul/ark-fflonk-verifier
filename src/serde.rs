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
           "12195165594784431822497303968938621279445690754376121387655513728730220550454",
           "19482351300768228183728567743975524187837254971200066453308487514712354412818",
           "1"
          ],
          "C2": [
           "270049702185508019342640204324826241417613526941291105097079886683911146886",
           "8044577183782099118358991257374623532841698893838076750142877485824795072127",
           "1"
          ],
          "W1": [
           "18899554350581376849619715242908819289791150067233598694602356239698407061017",
           "868483199604273061042760252576862685842931472081080113229115026384087738503",
           "1"
          ],
          "W2": [
           "15400234196629481957150851143665757067987965100904384175896686561307554593394",
           "1972554287366869807517068788787992038621302618305780153544292964897315682091",
           "1"
          ]
         },
         "evaluations": {
          "ql": "13012702442141574024514112866712813523553321876510290446303561347565844930654",
          "qr": "6363613431504422665441435540021253583148414748729550612486380209002057984394",
          "qm": "16057866832337652851142304414708366836077577338023656646690877057031251541947",
          "qo": "12177497208173170035464583425607209406245985123797536695060336171641250404407",
          "qc": "1606928575748882874942488864331180511279674792603033713048693169239812670017",
          "s1": "12502690277925689095499239281542937835831064619179570213662273016815222024218",
          "s2": "21714950310348017755786780913378098925832975432250486683702036755613488957178",
          "s3": "7373645520955771058170141217317033724805640797155623483741097103589211150628",
          "a": "10624974841759884514517518996672059640247361745924203600968035963539096078745",
          "b": "12590031312322329503809710776715067780944838760473156014126576247831324341903",
          "c": "17676078410435205056317710999346173532618821076911845052950090109177062725036",
          "z": "13810130824095164415807955516712763121131180676617650812233616232528698737619",
          "zw": "9567903658565551430748252507556148460902008866092926659415720362326593620836",
          "t1w": "17398514793767712415669438995039049448391479578008786242788501594157890722459",
          "t2w": "11804645688707233673914574834599506530652461017683048951953032091830492459803",
          "inv": "6378827379501409574366452872421073840754012879130221505294134572417254316105"
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
