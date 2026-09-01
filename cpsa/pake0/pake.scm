(herald "pake0")

(defmacro (k) (hash pw alice bob na nb))

(defprotocol pake basic

	(defrole alice (vars (na nb text) (pw data) (alice bob name))
	  (trace
		(send na)
		(recv nb)
		(send (hash (k)))
		(recv (hash (hash (k)) (k)))
	  )
	)

	(defrole bob (vars (na nb text) (pw data) (alice bob name))
	  (trace
		(recv na)
		(send nb)
		(recv (hash (k)))
		(send (hash (hash (k)) (k)))
	  )
	)
)


(defskeleton pake (vars (na nb text) (pw data) (alice bob name))
	(defstrandmax alice (alice alice) (bob bob) (na na) (nb nb) (pw pw))

	(uniq-orig na)
	(pen-non-orig pw)
)

(defskeleton pake (vars (na nb text) (pw data) (alice bob name))
	(defstrandmax bob (alice alice) (bob bob) (na na) (nb nb) (pw pw))

	(uniq-orig nb)
	(pen-non-orig pw)
)
