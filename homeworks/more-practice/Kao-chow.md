# Kao-Chow protocol


## Specification
Let A, B, and S all be principals.
Let symmetric keys be represented as K_{UV} where U and V are the participants who share the key.


1. A -> S: A, B, Na 
2. S -> B: enc(Na, K_{AB}, A, B, K_{AS}), enc(Na, K_{AB},A,B,K_{BS})
3. B -> A: enc(Na, K_{AB}, A, B, K_{AS}), enc(Na, K_{AB}), Nb
4. A -> B: enc(Nb, K_{AB})



## Reference
https://www.cs.cmu.edu/~iliano/projects/MSR/cjl/kaoChow.shtml
