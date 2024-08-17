use crate::challenge::Challenges;
use crate::inversion::Inversion;
use crate::proof::Proof;
use crate::vk::VerificationKey;
use ark_bn254::{Fq, Fr, G1Affine, G1Projective};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{BigInteger, PrimeField};
use num_traits::One;

#[derive(Debug, Default, Eq, PartialEq, Copy, Clone)]
pub struct FEJ {
    // [F]_1: full batched polynomial commitment
    pub F: G1Affine,
    // [E]_1: group-encoded batch evaluation
    pub E: G1Affine,
    // [J]_1: the full difference
    pub J: G1Affine,
}

impl FEJ {
    // Compute full batched polynomial commitment [F]_1, group-encoded batch evaluation [E]_1 and the full difference [J]_1
    pub fn compute(
        vk: &VerificationKey,
        proof: &Proof,
        challenge: &Challenges,
        invers_tuple: &Inversion,
        h0w8: Vec<Fr>,
        R0: Fr,
        R1: Fr,
        R2: Fr,
    ) -> Self {
        let polynomials = &proof.polynomials;
        let numerator = h0w8
            .iter()
            .fold(Fr::one(), |acc, h0_w8_i| acc * (challenge.y - *h0_w8_i));
        let quotient1 = challenge.alpha * numerator * invers_tuple.denH1;
        let quotient2 = challenge.alpha * challenge.alpha * numerator * invers_tuple.denH2;
        // println!("numerator: {:?}", numerator.into_bigint().to_bytes_be());
        println!("quotient1: {:?}", quotient1.into_bigint().to_bytes_be());
        println!("quotient2: {:?}", quotient2.into_bigint().to_bytes_be());
        // println!(
        //     "proof.poly.w1: {:?}",
        //     polynomials.w1.x.into_bigint().to_bytes_be()
        // );
        let f = polynomials.c1 * quotient1 + polynomials.c2 * quotient2 + vk.c0;
        println!("vk.c0.x: {:?}", &vk.c0.x.into_bigint().to_bytes_be());
        println!(
            "poly.c1.x: {:?}",
            &polynomials.c1.x.into_bigint().to_bytes_be()
        );
        println!(
            "poly.c2.x: {:?}",
            &polynomials.c2.x.into_bigint().to_bytes_be()
        );
        println!("fej.F: {:?}", &f.x.into_bigint().to_bytes_be());
        println!("");

        let e = G1Affine::generator() * (R0 + quotient1 * R1 + quotient2 * R2);
        let j = polynomials.w1 * numerator;
        // println!("fej.E: {:?}", &e.x.into_bigint().to_bytes_be());
        // println!("fej.J: {:?}", &j.x.into_bigint().to_bytes_be());

        Self {
            F: f.into_affine(),
            E: e.into_affine(),
            J: j.into_affine(),
        }
    }
}

// pi: [35, 49, 152, 5, 150, 183, 109, 117, 249, 192, 93, 165, 74, 251, 17, 83, 101, 0, 105, 13, 155, 27, 195, 253, 27, 177, 174, 103, 20, 23, 66, 197]
// r0: [13, 226, 199, 102, 228, 139, 95, 44, 95, 161, 125, 114, 51, 202, 142, 6, 87, 244, 131, 93, 30, 121, 91, 153, 37, 200, 178, 47, 77, 42, 193, 193]
// r1: [17, 178, 193, 232, 73, 104, 213, 205, 166, 111, 18, 209, 55, 185, 188, 68, 4, 93, 113, 226, 35, 17, 11, 95, 232, 112, 208, 176, 53, 237, 85, 36]
// r2: [26, 243, 238, 87, 48, 20, 79, 8, 76, 190, 27, 57, 129, 114, 215, 120, 143, 201, 200, 72, 76, 49, 149, 231, 120, 215, 220, 55, 70, 99, 36, 22]
// numerator: [4, 121, 183, 144, 97, 48, 213, 117, 230, 252, 140, 104, 63, 115, 164, 109, 194, 109, 218, 62, 36, 92, 68, 186, 37, 160, 224, 159, 51, 47, 194, 60]
// quotient1: [6, 76, 225, 73, 217, 178, 251, 238, 174, 214, 138, 120, 165, 163, 171, 158, 164, 53, 244, 78, 193, 93, 7, 190, 210, 25, 227, 174, 170, 125, 226, 245]
// quotient2: [1, 125, 241, 4, 155, 224, 211, 196, 15, 215, 118, 187, 54, 49, 250, 32, 60, 146, 15, 152, 96, 203, 161, 15, 100, 37, 158, 246, 197, 71, 227, 142]
// proof.poly.w1: [40, 192, 190, 156, 222, 23, 32, 207, 166, 235, 64, 41, 77, 232, 214, 154, 197, 211, 219, 9, 251, 27, 8, 193, 93, 102, 232, 187, 18, 174, 194, 55]
// DEBUG: Here
// poly.c0.x: [31, 35, 1, 129, 123, 151, 67, 201, 19, 114, 28, 223, 9, 167, 253, 128, 218, 157, 41, 57, 7, 37, 222, 64, 50, 194, 89, 216, 69, 238, 166, 138]
// poly.c1.x: [43, 35, 240, 155, 225, 171, 136, 99, 17, 140, 255, 122, 135, 23, 213, 215, 205, 22, 203, 251, 40, 112, 75, 254, 201, 126, 231, 255, 55, 206, 88, 75]
// poly.c2.x: [41, 101, 215, 122, 216, 191, 166, 121, 156, 177, 64, 226, 70, 6, 247, 115, 7, 0, 16, 102, 180, 121, 113, 139, 124, 120, 192, 172, 242, 236, 163, 225]
// TODO: Error data
// fej.F: [33, 102, 199, 89, 114, 209, 57, 14, 232, 253, 127, 226, 211, 250, 156, 218, 145, 204, 50, 218, 107, 132, 117, 206, 97, 100, 231, 68, 197, 76, 239, 4]

// fej.E: [5, 254, 104, 91, 184, 6, 10, 166, 222, 84, 223, 141, 57, 131, 227, 165, 104, 30, 50, 184, 235, 27, 96, 49, 20, 199, 16, 83, 128, 80, 36, 160]
// fej.J: [29, 194, 201, 1, 84, 102, 232, 154, 36, 169, 30, 159, 217, 239, 116, 46, 112, 43, 242, 236, 190, 10, 6, 210, 152, 252, 60, 242, 216, 55, 190, 120]
// test should_verify_snarkjs_proof ... ok
