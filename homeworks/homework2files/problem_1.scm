(herald "Problem 1")

(defprotocol prob_one basic

    (defrole party1 (vars (p1 p2 name) (n1 n2 text))
      (trace
        (send (enc p1 p2 n1 (pubk p2)))
        (recv (enc p1 p2 n2 (pubk p1)))
        (send (enc "hello" p2 n2 (pubk p2)))
      )
    )


    (defrole party2 (vars (p1 p2 name) (n1 n2 text))
      (trace
        (recv (enc p1 p2 n1 (pubk p2)))
        (send (enc p1 p2 n2 (pubk p1)))
        (recv (enc "hello" p2 n2 (pubk p2)))
      )
    )
)


(defskeleton prob_one
  (vars (p1 p2 name) (n1 text))
  (defstrand party1 3 (p1 p1) (p2 p2) (n1 n1))
  (non-orig (privk p1) (privk p2))
)

(defskeleton prob_one
  (vars (p1 name) (n2 text))
  (defstrand party2 3 (p1 p1) (n2 n2))
  (non-orig (privk p1))
)