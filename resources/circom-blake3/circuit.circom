// Reference: https://docs.circom.io/getting-started/writing-circuits
pragma circom 2.1.0;

template Multiplier2() {
   // Declaration of signals.
   signal input a;
   signal input b;
   signal output c;

   // Constraints.
   c <== a * b;
}

component main = Multiplier2();
