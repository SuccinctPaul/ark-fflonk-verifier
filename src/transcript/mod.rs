use ark_bn254::Fr;
use ark_ff::PrimeField;
use tiny_keccak::{Hasher, Keccak};

pub trait TranscriptHash {
    fn hash_to_fr(bytes: Vec<u8>) -> Fr;
}

pub struct Keccak256TranscriptHash;

impl TranscriptHash for Keccak256TranscriptHash {
    fn hash_to_fr(bytes: Vec<u8>) -> Fr {
        println!("keccak_hash ");
        let mut hasher = Keccak::v256();
        hasher.update(&bytes);

        let mut out = [0u8; 32];
        hasher.finalize(&mut out);

        let res = Fr::from_be_bytes_mod_order(&out);

        res
    }
}

pub struct Blake3TranscriptHash;

impl TranscriptHash for Blake3TranscriptHash {
    fn hash_to_fr(bytes: Vec<u8>) -> Fr {
        println!("blake3_hash ");

        let mut hasher = blake3::Hasher::new();
        hasher.update(&bytes);
        let out = hasher.finalize();
        let res = Fr::from_be_bytes_mod_order(out.as_bytes());
        res
    }
}
