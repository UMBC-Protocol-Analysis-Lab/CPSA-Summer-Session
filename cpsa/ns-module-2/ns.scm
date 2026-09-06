(herald "PAL Module 2 Needham-Schroeder")

(defprotocol enis basic 

    (defrole alice (vars (a b name) (Na Nb text))
      (trace
		(send (enc Na a (pubk b)))
		(recv (enc Na Nb (pubk a)))
		(send (enc Nb (pubk b)))
      )
    )

    (defrole bob (vars (a b name) (Na Nb text))
      (trace
		(recv (enc Na a (pubk b)))
		(send (enc Na Nb (pubk a)))
		(recv (enc Nb (pubk b)))
      )
    )
)


(defskeleton enis (vars (a_name b_name name) (Na_nonce Nb_nonce text))
	(defstrandmax alice (a a_name) (b b_name) (Na Na_nonce) (Nb Nb_nonce))

	(uniq-orig Na_nonce) ;the first time that Na exists
	(non-orig (privk a_name) (privk b_name)) ;adversary doesn't get the private key
)

(defskeleton enis (vars (a_name b_name name) (Na_nonce Nb_nonce text))
	(defstrandmax bob (a a_name) (b b_name) (Na Na_nonce) (Nb Nb_nonce))

	(uniq-orig Nb_nonce) ;the first time that Na exists
	(non-orig (privk a_name) (privk b_name)) ;adversary doesn't get the private key
)

