use crate::challenge::Challenges;
use crate::inversion::calculateInversions;
use crate::pairing::check_pairing;
use crate::{
    calculateR0, calculateR1, calculateR2, computeFEJ, computePi, compute_lagrange, get_proof,
    get_pubSignals, Proof, VerifierProcessedInputs,
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
    // // NOTE: values of n larger than 186 will overflow the u128 type,
    // // resulting in output that doesn't match fibonacci sequence.
    // // However, the resulting proof will still be valid!
    println!("cycle-tracker-start: verification");

    // TODO: remove
    let pubSignalBigInt = BigInt::parse_bytes(
        b"14516932981781041565586298118536599721399535462624815668597272732223874827152",
        10,
    )
    .unwrap();

    let mut zh: &mut Fp256<FrParameters> = &mut Fr::zero();
    let mut zhinv: &mut Fp256<FrParameters> = &mut Fr::zero();

    // 1. compute challenge
    let (challenges, roots) = Challenges::compute(&mut zh, &mut zhinv, vpi, pubSignalBigInt);

    // it is similar to zhinv just more updated value
    let zinv = zhinv.clone();

    // 2. compute inversion
    let mut inv_tuple = calculateInversions(
        challenges.y,
        challenges.xi,
        *zhinv,
        roots.h0w8.to_vec(),
        roots.h1w4.to_vec(),
        roots.h2w3.to_vec(),
        roots.h3w3.to_vec(),
    );
    let mut eval_l1 = inv_tuple.0;
    let lis_values = inv_tuple.1;
    let denH1 = inv_tuple.2;
    let denH2 = inv_tuple.3;

    eval_l1 = compute_lagrange(*zh, eval_l1);

    let pi = computePi(pub_signal, eval_l1);

    println!("Verifying proof...");

    // Computes r1(y) and r2(y)
    let R0 = calculateR0(
        challenges.xi,
        proof.clone(),
        challenges.y,
        roots.h0w8.to_vec(),
        lis_values.li_s0_inv,
    );
    let R1 = calculateR1(
        challenges.xi,
        proof.clone(),
        challenges.y,
        pi,
        roots.h1w4.to_vec(),
        lis_values.li_s1_inv,
        zinv,
    );
    let R2 = calculateR2(
        challenges.xi,
        challenges.gamma,
        challenges.beta,
        proof.clone(),
        challenges.y,
        eval_l1,
        zinv,
        roots.h2w3.to_vec(),
        roots.h3w3.to_vec(),
        lis_values.li_s2_inv,
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

    let points = computeFEJ(
        challenges.y,
        roots.h0w8.to_vec(),
        denH1,
        denH2,
        challenges.alpha,
        proof.clone(),
        g1_affine,
        R0,
        R1,
        R2,
    );

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
