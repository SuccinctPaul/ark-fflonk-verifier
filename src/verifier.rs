use crate::challenge::Challenges;
use crate::compute_r::compute_r;
use crate::inversion::Inversion;
use crate::pairing::check_pairing;
use crate::{
    compute_fej::compute_fej, compute_lagrange, compute_pi::compute_pi, get_proof, get_pubSignals,
    vk::VerifierProcessedInputs, Proof,
};
use ark_bn254::{Fr, FrParameters, G1Affine, G1Projective};
use ark_ec::{AffineCurve, ProjectiveCurve};
use ark_ff::{Fp256, One, Zero};
use num_bigint::BigInt;
use std::str::FromStr;

/// Use the given verification key `vk` to verify the `proof`` against the given `pubs` public inputs.
/// Can fail if:
/// - the provided inverse in the proof is wrong
/// - the pair checking is wrong
pub fn verifier(mut vpi: VerifierProcessedInputs, proof: Proof, pub_signal: Fr) {
    // NOTE: values of n larger than 186 will overflow the u128 type,
    // resulting in output that doesn't match fibonacci sequence.
    // However, the resulting proof will still be valid!
    println!("cycle-tracker-start: verification");

    // // TODO: remove
    // let pubSignalBigInt = BigInt::parse_bytes(
    //     b"14516932981781041565586298118536599721399535462624815668597272732223874827152",
    //     10,
    // )
    // .unwrap();

    let mut zh: &mut Fr = &mut Fr::zero();
    let mut zhinv: &mut Fr = &mut Fr::zero();

    // 1. compute challenge
    let (challenges, roots) = Challenges::compute(&mut zh, &mut zhinv, vpi, pub_signal.clone());

    // it is similar to zhinv just more updated value
    let zinv = zhinv.clone();

    // 2. compute inversion
    // Compute public input polynomial evaluation PI(xi) = \sum_i^l -public_input_i·L_i(xi)
    let inv_tuple = Inversion::build(challenges.y, challenges.xi, *zhinv, &roots);

    // todo remove it into calculateInversions.
    let eval_l1 = compute_lagrange(*zh, inv_tuple.eval_l1);

    let pi = compute_pi(pub_signal, eval_l1);

    println!("Verifying proof...");

    // Computes r1(y) and r2(y)
    let (R0, R1, R2) = compute_r(
        &proof,
        &challenges,
        &roots,
        &inv_tuple,
        &pi,
        &zinv,
        &eval_l1,
    );

    // Compute full batched polynomial commitment [F]_1, group-encoded batch evaluation [E]_1 and the full difference [J]_1
    let g1_x = <G1Affine as AffineCurve>::BaseField::from_str("1").unwrap();
    let g1_y = <G1Affine as AffineCurve>::BaseField::from_str("2").unwrap();
    let g1_affine = G1Projective::new(
        g1_x,
        g1_y,
        <G1Projective as ProjectiveCurve>::BaseField::one(),
    )
    .into_affine();

    // Compute full batched polynomial commitment [F]_1, group-encoded batch evaluation [E]_1 and the full difference [J]_1
    let points = compute_fej(
        challenges.y,
        roots.h0w8.to_vec(),
        inv_tuple.denH1,
        inv_tuple.denH2,
        challenges.alpha,
        proof.clone(),
        g1_affine,
        R0,
        R1,
        R2,
    );

    // Validate all evaluations
    check_pairing(proof, points, challenges);

    println!("cycle-tracker-end: verification");
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_fflonk_verifier() {
        println!("cycle-tracker-start: loading");
        let proof = get_proof();
        let pub_signal = get_pubSignals();

        let mut vpi = VerifierProcessedInputs {
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

        println!("cycle-tracker-end: loading");
        verifier(vpi, proof, pub_signal);
    }
}
