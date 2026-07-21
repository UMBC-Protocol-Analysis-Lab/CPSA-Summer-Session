(herald "problem5")


(defprotocol prob5 basic

  (defrole init (vars (a b name) (n1 n2 m x y text))
    (trace
     (send a)
     (recv (cat b n1 n2))
     (send (cat a (enc n1 n2 m (pubk b))))
     (recv (cat n1 x (enc x y n1 (pubk b))))
    )
  )

  (defrole resp (vars (b a name) (n1 n2 x y text))
    (trace
     (recv a)
     (send (cat b n1 n2))
     (recv (cat a (enc n1 x y (pubk b))))
     (send (cat n1 x (enc x y n1 (pubk b)))))
    (uniq-orig n1 n2)
  )
)

(defskeleton prob5
  (vars (b name) (n1 n2 m text))
  ; define a strand from the perspective of the init role.
  ; Does the init role actually know anything about n1 and n2?


  ; Look a the shapes and see what the listener tells us
  (deflistener m)
  (uniq-orig m)
  (non-orig (privk b)))
