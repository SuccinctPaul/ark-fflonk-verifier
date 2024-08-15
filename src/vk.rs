use num_bigint::BigInt;

#[derive(Debug, Eq, PartialEq, Clone)]
pub struct VerifierProcessedInputs {
    pub c0x: BigInt,
    pub c0y: BigInt,
    pub x2x1: BigInt,
    pub x2x2: BigInt,
    pub x2y1: BigInt,
    pub x2y2: BigInt,
}

impl Default for VerifierProcessedInputs {
    fn default() -> Self {
        let vpi = VerifierProcessedInputs {
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
        vpi
    }
}
