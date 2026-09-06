(herald "diffie-hellman" (algebra diffie-hellman))


(defprotocol dh diffie-hellman
        (defrole alice (vars (a b rndx))
          (trace
                (send (exp (gen) a))
                (recv (exp (gen) b))
          )

        )


        (defrole bob (vars (a b rndx))
          (trace
                (recv (exp (gen) a))
                (send (exp (gen) b))
          )
        )
)


(defskeleton dh (vars (a b rndx))
        (defstrandmax alice (a a) (b b))

        (uniq-gen a)
)

(defskeleton dh (vars (a b rndx))
        (defstrandmax bob (a a) (b b))

        (uniq-gen b)
)
