use num_bigint::BigInt;

#[derive(Debug, Default, Eq, PartialEq, Clone)]
pub struct VerifierProcessedInputs {
    pub c0x: BigInt,
    pub c0y: BigInt,
    pub x2x1: BigInt,
    pub x2x2: BigInt,
    pub x2y1: BigInt,
    pub x2y2: BigInt,
}
