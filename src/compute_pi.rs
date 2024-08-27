use ark_bn254::Fr;
use std::ops::Neg;

// Compute public input polynomial evaluation `PI(xi)`:
// $PI(xi) = -\sum_i^l PublicInput_i·L_i(xi)$
pub fn compute_pi(pub_inputs: &Vec<Fr>, eval_ls: &Vec<Fr>) -> Fr {
    pub_inputs
        .iter()
        .zip(eval_ls.iter())
        .map(|(pub_input_i, eval_li)| pub_input_i * eval_li)
        .sum::<Fr>()
        .neg()
}
