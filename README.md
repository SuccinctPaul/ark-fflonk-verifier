# ark-fflonk-verifier

This repo contains polygon-cdk's fflonk_verifier implementation using arkwork-rs(v0.4.0) library, orresponding to their onchain solidity verifier.


## How to use this
Add dependency on Cargo.toml:
```toml
ark-fflonk-verifier = {git="https://github.com/SuccinctPaul/ark-fflonk-verifier.git"}

# As some structs and funcitons are private in arkworks-rs v0.4.0. So needs to use the modified one.
[patch.crates-io]
ark-ff = { git = "https://github.com/SuccinctPaul/arkworks-algebra.git",  branch = "v0.4.2"}
ark-ec = { git = "https://github.com/SuccinctPaul/arkworks-algebra.git",  branch = "v0.4.2"}
ark-serialize = { git = "https://github.com/SuccinctPaul/arkworks-algebra.git",  branch = "v0.4.2"}
ark-poly = { git = "https://github.com/SuccinctPaul/arkworks-algebra.git",  branch = "v0.4.2"}
```


## References
* https://github.com/arielgabizon/fflonk
* https://github.com/0xPolygonHermez/zkevm-contracts/tree/main/contracts/verifiers
* https://github.com/RizeLabs/sp1-verifier
* https://github.com/availproject/Henosis
* https://github.com/HorizenLabs/fflonk_verifier
