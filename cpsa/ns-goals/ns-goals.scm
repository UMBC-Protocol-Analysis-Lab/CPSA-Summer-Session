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

(defgoal enis
	 (forall ((alice bob name) (na nb text) (z strd))
		 (implies 
		   	(and 
			  (p "alice" z 3) ;; Define strand of role alice (with full depth)
			  (p "alice" "alice" z alice) ;; Assign variable "alice" to var "alice"
			  (p "alice" "bob" z bob) ;; Assign "bob"
			  (p "alice" "na" z na)
			  (p "alice" "nb" z nb)
			  ;; (p ROLE VARNAME STRAND GOALVAR)
			  (uniq na)
			  (non (privk alice))
			  (non (privk bob))
			)
			(exists ((z-0 strd))
				(and 
				  (p "bob" z-0 2)
				  (p "bob" "alice" z-0 alice)
				  (p "bob" "bob" z-0 bob)
				  (p "bob" "na" z-0 na)
				  (p "bob" "nb" z-0 nb))
			)
		))
	(comment "Agreement goal from the perspective of strands of type Alice."))

;; confidentiality goal
(defgoal enis
	 (forall ((alice bob name) (na nb text) (z eve strd))
		 (implies
		   	;; Hypothesis
		   	(and 
			  (p "bob" z 3)
			  (p "bob" "alice" z alice)
			  (p "bob" "bob" z bob)
			  (p "bob" "na" z na)
			  (p "bob" "nb" z nb)
			  (p "" eve 1)
			  (p "" "x" eve (cat na nb))
			  (uniq nb)
			  (non (privk alice))
			  (non (privk bob)))
			;; Conclusion
			(false) ;; Testing for impossibility!
		)))
			  

