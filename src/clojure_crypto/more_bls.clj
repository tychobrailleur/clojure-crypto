(ns clojure-crypto.more-bls
  (:import [org.apache.tuweni.crypto.mikuli KeyPair BLS12381 Signature SignatureAndPublicKey]))

(defn create-keypair []
  (KeyPair/random))


(defn sign [key-pair message domain]
  (BLS12381/sign key-pair message domain))

(defn verify [^SignatureAndPublicKey key-pair-sig message domain]
  (BLS12381/verify key-pair-sig message domain))

(defn -main [& _args]
  (let [message (.getBytes "Pouet")
        domain 48
        keypair1 (create-keypair)
        keypair2 (create-keypair)
        keypair3 (create-keypair)
        signature1 (sign keypair1 message domain)
        signature2 (sign keypair2 message domain)
        signature3 (sign keypair3 message domain)]
    (println keypair1)
    (println keypair2)
    (let [aggregate (SignatureAndPublicKey/aggregate (list signature1 signature2))]
      (println aggregate)
      (println (verify signature1 message domain))
      (println (verify signature2 message domain))
      (println (verify signature3 message domain)) ;; uh?
      )))
