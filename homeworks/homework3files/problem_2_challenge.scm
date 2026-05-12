(herald "Problem 2")

(defprotocol prob_two basic

    (defrole party1 (vars (p1 p2 name) (n1 n2 text))
      (trace
        (send (enc (privk p1) p2 n1 (pubk p2)))
        (recv (enc p1 p2 n2 (pubk p1)))
        (send (enc "hello" p2 n2 (pubk p2)))
      )
    )

    (defrole party2 (vars (p1 p2 name) (n1 n2 text))
      (trace
        (recv (enc (privk p1) p2 n1 (pubk p2)))
        (send (enc p1 p2 n2 (pubk p1)))
        (recv (enc "hello" p2 n2 (pubk p2)))
      )
    )
)


(defskeleton prob_two
  (vars (p1 p2 name) (n1 text))
  (defstrand party1 3 (p1 p1) (p2 p2) (n1 n1))
  (uniq-orig n1)
)


;; Uncomment the below block by removing the semicolons, and then fill in the blank line
; (defskeleton prob_two
;  (vars (p1 name) (n2 text))
;  ;; Fill in the line that should be here
;  (uniq-orig n2)
; )