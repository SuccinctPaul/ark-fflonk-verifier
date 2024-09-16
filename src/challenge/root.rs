use ark_bn254::Fr;
use std::fmt;

use crate::vk::VerificationKey;
use std::ops::Mul;

#[derive(Debug, Default, Eq, PartialEq, Copy, Clone)]
pub struct Roots {
    pub h0w8: [Fr; 8],
    pub h1w4: [Fr; 4],
    pub h2w3: [Fr; 3],
    pub h3w3: [Fr; 3],
}

impl Roots {
    pub fn compute(vk: &VerificationKey, xi_seed: &Fr) -> Self {
        // compute xi_seed_2, xi_seed_3
        let xi_seed_2 = xi_seed.mul(xi_seed);
        let xi_seed_3 = xi_seed * &xi_seed_2;

        // compute roots h0w8
        let omegas = &vk.omega;
        let h0w8 = [
            xi_seed_3,
            xi_seed_3 * omegas.w8_1,
            xi_seed_3 * omegas.w8_2,
            xi_seed_3 * omegas.w8_3,
            xi_seed_3 * omegas.w8_4,
            xi_seed_3 * omegas.w8_5,
            xi_seed_3 * omegas.w8_6,
            xi_seed_3 * omegas.w8_7,
        ];

        // compute roots h1w4
        let xi_seed_6 = xi_seed_3 * xi_seed_3;
        let h1w4 = [
            xi_seed_6,
            xi_seed_6 * omegas.w4,
            xi_seed_6 * omegas.w4_2,
            xi_seed_6 * omegas.w4_3,
        ];

        // compute roots h2w3
        let xi_seed_8 = xi_seed_6 * xi_seed_2;
        let h2w3 = [xi_seed_8, xi_seed_8 * omegas.w3, xi_seed_8 * omegas.w3_2];

        // compute roots h3w3
        let h3w3_0 = xi_seed_8 * omegas.wr;
        let h3w3 = [h3w3_0, h3w3_0 * omegas.w3, h3w3_0 * omegas.w3_2];
        Roots {
            h0w8,
            h1w4,
            h2w3,
            h3w3,
        }
    }
}

impl fmt::Display for Roots {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Roots: [")?;
        write!(f, "h0w8:[");
        for (i, v) in self.h0w8.iter().enumerate() {
            if i != 0 {
                write!(f, ", ")?;
            }
            write!(f, "{}", v.to_string())?;
        }
        write!(f, "], ");

        write!(f, "h1w4:[");
        for (i, v) in self.h1w4.iter().enumerate() {
            if i != 0 {
                write!(f, ", ")?;
            }
            write!(f, "{}", v.to_string())?;
        }
        write!(f, "], ");

        write!(f, "h2w3:[");
        for (i, v) in self.h2w3.iter().enumerate() {
            if i != 0 {
                write!(f, ", ")?;
            }
            write!(f, "{}", v.to_string())?;
        }
        write!(f, "], ");

        write!(f, "h3w3:[");
        for (i, v) in self.h3w3.iter().enumerate() {
            if i != 0 {
                write!(f, ", ")?;
            }
            write!(f, "{}", v.to_string())?;
        }
        write!(f, "] ");

        write!(f, "]")
    }
}
