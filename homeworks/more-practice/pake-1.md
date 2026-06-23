## Protocol: pake1

### Message Flow

1. **A → B:** v
2. **B → A:** v
3. **A → B:** enc("hello", B, "I am", A, k)
4. **B → A:** enc("got it", A, "I am", B, k)


where

* u = g^{alpha}
* v = g^{beta}
* w = u^{beta} = g^{alpha * beta}
* k = hash(pw || a || b || u || v || w)

### Notes

* ( pw ) is a shared password between A and B
* ( a, b ) are identities
* ( alpha, beta ) are fresh random exponents
