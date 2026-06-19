(herald "Problem 4")

(defprotocol prob_four basic

    (defrole init (vars (a b name) (n1 n2 salt text) (S skey))
      (trace
        (send (enc "salt?" n1 a b (privk b)))
        (recv (enc salt n1 n2 a b (privk a)))
        (send (cat S salt n2 a b))
        (recv (enc "hello" S))
      )
    )

;; Uncomment out the block and fill in the protocol messages
;    (defrole resp (vars (a b name) (n1 n2 salt text) (S skey))
;      (trace
;
;      )
;    )
;)


(defskeleton prob_four (vars (a b name) (n1 n2 salt text) (S skey))
    (defstrandmax init (a a) (b b) (n1 n1) (S S))
    (uniq-gen S)
    (non-orig (privk a))
    (uniq-orig n1)
)

(defskeleton prob_four (vars (a b name) (n1 n2 salt text) (S skey))
    (defstrandmax resp (a a) (b b) (n1 n1) (n2 n2) (S S))
    (uniq-gen S)
    (non-orig (privk a) (privk b))
    (uniq-orig n2)
)