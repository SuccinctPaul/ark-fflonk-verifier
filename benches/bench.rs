use ark_bn254::Fr;
use ark_fflonk_verifier::mock::{MOCK_PROOF_DATA, MOCK_PUB_INPUT};
use ark_fflonk_verifier::proof::Proof;
use ark_fflonk_verifier::verifier::fflonk_verifier;
use ark_fflonk_verifier::vk::VerificationKey;
use criterion::{criterion_group, criterion_main, Criterion};
use std::str::FromStr;

pub fn criterion_benchmark(c: &mut Criterion) {
    let pub_input = Fr::from_str(MOCK_PUB_INPUT).unwrap();

    let proof = Proof::construct(MOCK_PROOF_DATA.to_vec());

    let vk = VerificationKey::default();

    c.bench_function("fflonk_verifier_without_recursive_verifier", |b| {
        b.iter(|| fflonk_verifier(&vk, &proof, &pub_input, false))
    });
    c.bench_function("fflonk_verifier_with_recursive_verifier", |b| {
        b.iter(|| fflonk_verifier(&vk, &proof, &pub_input, true))
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
