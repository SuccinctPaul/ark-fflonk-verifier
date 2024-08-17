use crate::proof::Proof;

#[cfg(test)]
mod test {
    use super::*;
    use std::str::FromStr;

    use crate::mock::{MOCK_PROOF_DATA, MOCK_PUB_INPUT};
    use crate::verifier::fflonk_verifier;
    use crate::vk::{SnarkJSVK, VerificationKey};
    use ark_bn254::{Fr, G1Affine};
    use ark_ec::AffineRepr;

    #[test]
    fn test_fflonk_verifier() {
        let pub_input = Fr::from_str(MOCK_PUB_INPUT).unwrap();

        let proof = Proof::construct(MOCK_PROOF_DATA.to_vec());

        let vk = VerificationKey::default();
        fflonk_verifier(&vk, proof, &pub_input);
    }
    #[test]
    fn test_snarkjs_fflonk_verifier() {
        let pub_input = Fr::from_str(MOCK_PUB_INPUT).unwrap();

        let proof = Proof::construct(MOCK_PROOF_DATA.to_vec());

        let snark_vk = SnarkJSVK::default();
        let vk: VerificationKey = snark_vk.into();
        fflonk_verifier(&vk, proof, &pub_input);
    }
}
