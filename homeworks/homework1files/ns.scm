(herald "PAL Summer Session 1 Needham-Schroeder")

(defprotocol enis basic

        (defrole alice (vars (alice bob name) (na nb text))
          (trace
                (send (enc na alice (pubk bob)))
                (recv (enc na nb (pubk alice)))
                (send (enc nb (pubk bob)))
          )
        )

        (defrole bob (vars (alice bob name) (na nb text))
          (trace
                (recv (enc na alice (pubk bob)))
                (send (enc na nb (pubk alice)))
                (recv (enc nb (pubk bob)))
          )
        )
)


(defskeleton enis (vars (alice bob name) (na nb text))
    (defstrandmax alice (alice alice) (bob bob) (na na) (nb nb))

    (uniq-orig na) ;the first time that Na exists
    (non-orig (privk alice) (privk bob)) ;adversary doesn't get the private key
)

(defskeleton enis (vars (alice bob name) (na nb text))
    (defstrandmax bob (alice alice) (bob bob) (na na) (nb nb))

    (uniq-orig nb) ;the first time that Nb exists
    (non-orig (privk alice) (privk bob)) ;adversary doesn't get the private key
)
