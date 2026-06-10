## Definition 1: TLS

We define traces that establish a TLS handshakke between a client C and a server S.
Let the following be terms within the trace
* $C, S, CA \in Name$
* $r_C,r_s \in Nonce$
* $e_S, e_C \in Expt$
* $Cert_S: S||pk(S)||e(h(s, g^{e_S}), sk(CA)))$
* $S_{KE}: g^{e_S}||e(h(r_C || r_S || g^{e_S}), sk(S))$
* $PMS: g^{e_S \times e_C}$
* $C_{WRITE}: h(PMS, r_C, r_S, \text{"client-write"})$
* $S_{WRITE}: h(PMS, r_C, r_S, \text{"server-write"})$
* $C_{FMESG}: r_C || r_S ||Cert_S||S_{KE}$
* $C_{FIN}: e(h(PMS || \text{"client-fin"} || C_{FMESG}),C_{WRITE})$
* $S_{FIN}: e(h(PMS || \text{"server-fin"} ||C_{FMESG} || C_{FIN}), S_{WRITE}$).


Let trace $Tr_{TLS-C}(C, S, CA, r_C, r_S, e_S, e_C) =$
1. $+r_C$
2. $-r_S||Cert_S||S_{KE}$
3. $+g^{ec}||C_{FIN}$
4. $-S_{FIN}$.

Let the complementary trace \\$Tr_{TLS-S}(C, S, CA, r_C, r_S, e_S, e_C) =$
1. $-r_C$
2. $+r_S||Cert_S||S_{KE}$
3. $-g^{ec}||C_{FIN}$
4. $+S_{FIN}$.


## Definition 2: SCEP Token
Let $Tok_{X,Y} = \text{''Token''} ||X||pk(X)||Y||pk(Y)||data$
be the actual token.

We then define the actual SCEP token as:
$T_{X, Y} = Tok_{X,Y}||e(h(Tok_{X,Y}), sk(Y))$


## Definition 3: SCEP
We define traces that carry out SCEP between S and a responding infrastructure server K or H, which we define as W. 
As before, we first define the terms that we use within the traces:

* $\mathcal{S}, \mathcal{W}, M, CA \in Name$
* $r_\mathcal{S}, r_\mathcal{W}, r'_\mathcal{S}, r'_\mathcal{W}, \omega\in Nonce$
* $e_\mathcal{S}, e_\mathcal{W} \in Expt$
* $T_{S,M}$ (Definition 2)
* $T_{\mathcal{W,CA}}$ (Definition 2)
* $\mathcal{S}_{WRITE}: h(g^{e_\mathcal{S} \times e_\mathcal{W}}, r'_\mathcal{S}, r'_\mathcal{W}, \text{"client-write''})$
* $\mathcal{W}_{WRITE}: h(g^{e_\mathcal{S} \times e_\mathcal{W}}, r'_\mathcal{S}, r'_\mathcal{W}, \text{"server-write''})$.


Let $Tr_{SCEP-\mathcal{S}\mathcal{W}}(\mathcal{S}, \mathcal{W}, M, CA, r_\mathcal{S}, r_\mathcal{W}, r'_\mathcal{S}, r'_\mathcal{W}, \omega, e_\mathcal{S}, e_\mathcal{W}):$

1. $Tr_{TLS-C}(\mathcal{S},\mathcal{W},CA,r'_\mathcal{S},r'_\mathcal{W}, e_\mathcal{S}, e_\mathcal{W})$
(Definition 1)
2. $+e(r_\mathcal{S}||T_{S,M}, \mathcal{S}_{WRITE})$
3. $-e(\omega || r_{\mathcal{W}} || T_{\mathcal{W,CA}} \\||e(h(\text{"server-mutauth"}, r_{\mathcal{S}}, r_{\mathcal{W}},T_{\mathcal{W,CA}}), pk(\mathcal{W})),\\\ \mathcal{W}_{WRITE})$
4. $+e(\omega\\||e(h(\text{"client-mutauth"}, r_{\mathcal{S}}, r_{\mathcal{W}},T_{S,M}), pk(\mathcal{S})),\\\ \mathcal{S}_{WRITE})$.

Let $Tr_{SCEP-\mathcal{W}\mathcal{S}}$ be complementary to $Tr_{SCEP-\mathcal{S}\mathcal{W}}$, such that $Tr_{SCEP-\mathcal{W}\mathcal{S}}$ (1) includes $Tr_{TLS-S}$ rather than $Tr_{TLS-C}$, and
(2) inverts the directions of terms 2, 3, and 4.