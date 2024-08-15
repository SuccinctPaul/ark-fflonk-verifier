use ark_bn254::{Fq, Fr, G1Affine, G1Projective};
use ark_ec::*;
use ark_ff::One;
use std::fmt::Debug;
use std::str::FromStr;

#[derive(Debug, Clone)]
pub struct Proof {
    pub c1: G1Affine,
    pub c2: G1Affine,
    pub w1: G1Affine,
    pub w2: G1Affine,

    pub eval_ql: Fr,
    pub eval_qr: Fr,
    pub eval_qm: Fr,
    pub eval_qo: Fr,
    pub eval_qc: Fr,
    pub eval_s1: Fr,
    pub eval_s2: Fr,
    pub eval_s3: Fr,
    pub eval_a: Fr,
    pub eval_b: Fr,
    pub eval_c: Fr,
    pub eval_z: Fr,
    pub eval_zw: Fr,
    pub eval_t1w: Fr,
    pub eval_t2w: Fr,
    pub eval_inv: Fr,
}

#[derive(Debug, Clone)]
pub struct ProofWithPubSignal {
    pub proof: Proof,
    pub pub_input: Fr,
}

impl Proof {
    pub fn construct_proof_with_pubsignal(
        proof_values: Vec<&str>,
        pub_input: Fr,
    ) -> ProofWithPubSignal {
        let proof = Proof::construct(proof_values);

        ProofWithPubSignal { proof, pub_input }
    }

    pub fn construct(proof_values: Vec<&str>) -> Proof {
        let c1_x = Fq::from_str(proof_values[0]).unwrap();
        let c1_y = Fq::from_str(proof_values[1]).unwrap();
        let c1_affine = G1Projective::new(c1_x, c1_y, Fq::one()).into_affine();

        let c2_x = Fq::from_str(proof_values[2]).unwrap();
        let c2_y = Fq::from_str(proof_values[3]).unwrap();
        let c2_affine = G1Projective::new(c2_x, c2_y, Fq::one()).into_affine();

        let w1_x = Fq::from_str(proof_values[4]).unwrap();
        let w1_y = Fq::from_str(proof_values[5]).unwrap();
        let w1_affine = G1Projective::new(w1_x, w1_y, Fq::one()).into_affine();

        let w2_x = Fq::from_str(proof_values[6]).unwrap();
        let w2_y = Fq::from_str(proof_values[7]).unwrap();
        let w2_affine = G1Projective::new(w2_x, w2_y, Fq::one()).into_affine();

        Proof {
            c1: c1_affine,
            c2: c2_affine,
            w1: w1_affine,
            w2: w2_affine,
            eval_ql: Fr::from_str(proof_values[8]).unwrap(),
            eval_qr: Fr::from_str(proof_values[9]).unwrap(),
            eval_qm: Fr::from_str(proof_values[10]).unwrap(),
            eval_qo: Fr::from_str(proof_values[11]).unwrap(),
            eval_qc: Fr::from_str(proof_values[12]).unwrap(),
            eval_s1: Fr::from_str(proof_values[13]).unwrap(),
            eval_s2: Fr::from_str(proof_values[14]).unwrap(),
            eval_s3: Fr::from_str(proof_values[15]).unwrap(),
            eval_a: Fr::from_str(proof_values[16]).unwrap(),
            eval_b: Fr::from_str(proof_values[17]).unwrap(),
            eval_c: Fr::from_str(proof_values[18]).unwrap(),
            eval_z: Fr::from_str(proof_values[19]).unwrap(),
            eval_zw: Fr::from_str(proof_values[20]).unwrap(),
            eval_t1w: Fr::from_str(proof_values[21]).unwrap(),
            eval_t2w: Fr::from_str(proof_values[22]).unwrap(),
            eval_inv: Fr::from_str(proof_values[23]).unwrap(),
        }
    }
}
