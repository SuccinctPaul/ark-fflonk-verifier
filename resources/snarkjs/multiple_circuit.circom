pragma circom 2.0.0;

/*This circuit template checks that c is the multiplication of a and b.*/

template Multiplier2 () {

   // Declaration of signals.
   signal input a;// Public
   signal input b;// Private
   signal output c;

   // Constraints.
   c <== a * b;
}


component main {public [a]} = Multiplier2();