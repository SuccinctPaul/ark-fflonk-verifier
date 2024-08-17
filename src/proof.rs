use ark_bn254::{Fq, Fr, G1Projective};
use ark_ec::*;
use ark_ff::One;
use std::fmt::Debug;
use std::str::FromStr;

/// The Proof data: use the implemented conversion traits `TryFrom` to build it.
#[derive(Debug, Clone, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct Proof {
    pub polynomials: Polynomials,
    pub evaluations: Evaluations,
}

#[derive(Debug, Clone, Eq, PartialEq)]
#[cfg_attr(
    feature = "serde",
    derive(::serde::Serialize, ::serde::Deserialize),
    serde(rename_all = "SCREAMING_SNAKE_CASE")
)]
/// Proof's Polynomial.
pub struct Polynomials {
    #[cfg_attr(feature = "serde", serde(with = "crate::serde::g1"))]
    pub c1: G1Projective,
    #[cfg_attr(feature = "serde", serde(with = "crate::serde::g1"))]
    pub c2: G1Projective,
    #[cfg_attr(feature = "serde", serde(with = "crate::serde::g1"))]
    pub w1: G1Projective,
    #[cfg_attr(feature = "serde", serde(with = "crate::serde::g1"))]
    pub w2: G1Projective,
}

#[derive(Debug, Clone, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
/// Proof's Evaluation values.
pub struct Evaluations {
    #[cfg_attr(feature = "serde", serde(with = "crate::serde::fr"))]
    pub ql: Fr,
    #[cfg_attr(feature = "serde", serde(with = "crate::serde::fr"))]
    pub qr: Fr,
    #[cfg_attr(feature = "serde", serde(with = "crate::serde::fr"))]
    pub qm: Fr,
    #[cfg_attr(feature = "serde", serde(with = "crate::serde::fr"))]
    pub qo: Fr,
    #[cfg_attr(feature = "serde", serde(with = "crate::serde::fr"))]
    pub qc: Fr,
    #[cfg_attr(feature = "serde", serde(with = "crate::serde::fr"))]
    pub s1: Fr,
    #[cfg_attr(feature = "serde", serde(with = "crate::serde::fr"))]
    pub s2: Fr,
    #[cfg_attr(feature = "serde", serde(with = "crate::serde::fr"))]
    pub s3: Fr,
    #[cfg_attr(feature = "serde", serde(with = "crate::serde::fr"))]
    pub a: Fr,
    #[cfg_attr(feature = "serde", serde(with = "crate::serde::fr"))]
    pub b: Fr,
    #[cfg_attr(feature = "serde", serde(with = "crate::serde::fr"))]
    pub c: Fr,
    #[cfg_attr(feature = "serde", serde(with = "crate::serde::fr"))]
    pub z: Fr,
    #[cfg_attr(feature = "serde", serde(with = "crate::serde::fr"))]
    pub zw: Fr,
    #[cfg_attr(feature = "serde", serde(with = "crate::serde::fr"))]
    pub t1w: Fr,
    #[cfg_attr(feature = "serde", serde(with = "crate::serde::fr"))]
    pub t2w: Fr,
    #[cfg_attr(feature = "serde", serde(with = "crate::serde::fr"))]
    pub inv: Fr,
}
impl Proof {
    pub fn construct(proof_values: Vec<&str>) -> Self {
        assert_eq!(proof_values.len(), 24);
        let c1_x = Fq::from_str(proof_values[0]).unwrap();
        let c1_y = Fq::from_str(proof_values[1]).unwrap();
        let c1 = G1Projective::new(c1_x, c1_y, Fq::one());

        let c2_x = Fq::from_str(proof_values[2]).unwrap();
        let c2_y = Fq::from_str(proof_values[3]).unwrap();
        let c2 = G1Projective::new(c2_x, c2_y, Fq::one());

        let w1_x = Fq::from_str(proof_values[4]).unwrap();
        let w1_y = Fq::from_str(proof_values[5]).unwrap();
        let w1 = G1Projective::new(w1_x, w1_y, Fq::one());

        let w2_x = Fq::from_str(proof_values[6]).unwrap();
        let w2_y = Fq::from_str(proof_values[7]).unwrap();
        let w2 = G1Projective::new(w2_x, w2_y, Fq::one());

        let polynomials = Polynomials {
            c1: c1,
            c2: c2,
            w1: w1,
            w2: w2,
        };
        let evaluations = Evaluations {
            ql: Fr::from_str(proof_values[8]).unwrap(),
            qr: Fr::from_str(proof_values[9]).unwrap(),
            qm: Fr::from_str(proof_values[10]).unwrap(),
            qo: Fr::from_str(proof_values[11]).unwrap(),
            qc: Fr::from_str(proof_values[12]).unwrap(),
            s1: Fr::from_str(proof_values[13]).unwrap(),
            s2: Fr::from_str(proof_values[14]).unwrap(),
            s3: Fr::from_str(proof_values[15]).unwrap(),
            a: Fr::from_str(proof_values[16]).unwrap(),
            b: Fr::from_str(proof_values[17]).unwrap(),
            c: Fr::from_str(proof_values[18]).unwrap(),
            z: Fr::from_str(proof_values[19]).unwrap(),
            zw: Fr::from_str(proof_values[20]).unwrap(),
            t1w: Fr::from_str(proof_values[21]).unwrap(),
            t2w: Fr::from_str(proof_values[22]).unwrap(),
            inv: Fr::from_str(proof_values[23]).unwrap(),
        };

        Self {
            polynomials,
            evaluations,
        }
    }
}

#[cfg(test)]
mod test {}
