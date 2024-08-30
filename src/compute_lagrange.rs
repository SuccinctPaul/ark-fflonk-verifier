use ark_bn254::Fr;
use std::ops::Mul;

// Compute Lagrange polynomial evaluation L_i(xi)
// Equation:
//      [zh * Li_1, zh * Li_2 * w]
pub fn compute_lagrange(zh: &Fr, Li_inv: &Fr) -> Fr {
    zh * Li_inv
}
