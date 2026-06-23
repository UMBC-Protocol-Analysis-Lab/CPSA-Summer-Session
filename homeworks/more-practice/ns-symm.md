# Needham-Schroeder Symmetric key protocol
**IMPORTANT: This is different from the asymmetric key method you learned during the first meeting.**

## Specification
Let A, B, and S all be principals.
Let symmetric keys be represented as K_{UV} where U and V are the participants who share the key.


1. A -> S: A, B, Na 
2. S -> A: enc(Na, B, K_{AB}, enc(K_{AB}, A, K_{BS}), K_{AS})
3. A -> B: enc(K_{AB}, A, K_{BS})
4. B -> A: enc(Nb, K_{AB})
5. A -> B: enc(cat(Nb, "1"), K_{AB})



## Reference
https://www.cs.utexas.edu/~byoung/cs361/lecture60.pdf
