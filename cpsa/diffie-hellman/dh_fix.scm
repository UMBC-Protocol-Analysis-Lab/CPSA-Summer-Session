(herald "diffie-hellman" (algebra diffie-hellman))


(defprotocol dh diffie-hellman
        (defrole alice (vars (a b rndx) (alice bob name) (msg1 msg2 text))
          (trace
                (send (enc "message 1" alice bob (exp (gen) a) (privk alice)))
                (recv (enc alice bob (exp (gen) b) (privk bob)))
                (send (enc "msg 1" msg1 (exp (exp (gen) a) b)))
                (recv (enc msg2 (exp (exp (gen) a) b)))
          )

        (uniq-gen a)
        )


        (defrole bob (vars (a b rndx) (alice bob name) (msg1 msg2 text))
          (trace
                (recv (enc "message 1" alice bob (exp (gen) a) (privk alice)))
                (send (enc alice bob (exp (gen) b) (privk bob)))
                (recv (enc "msg 1" msg1 (exp (exp (gen) a) b)))
                (send (enc msg2 (exp (exp (gen) a) b)))
          )

        (uniq-gen b)
        )
)


(defskeleton dh (vars (a b rndx) (alice bob name) (msg1 msg2 text))
        (defstrandmax alice (a a) (b b) (alice alice) (bob bob) (msg1 msg1) (msg2 msg2))

        (uniq-orig msg1)
        (non-orig (privk alice) (privk bob))
)

(defskeleton dh (vars (a b rndx) (alice bob name) (msg1 msg2 text))
        (defstrandmax bob (a a) (b b) (alice alice) (bob bob) (msg1 msg1) (msg2 msg2))

        (uniq-orig msg2)
        (non-orig (privk alice) (privk bob))
)
