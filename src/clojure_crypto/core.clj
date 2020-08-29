(ns clojure-crypto.core
  (:import [java.security Signature KeyFactory]
           [java.security.spec EncodedKeySpec X509EncodedKeySpec]
           [java.util Base64]))


(defn sign-payload [payload private-key]
  (let [ecdsa-signature (Signature/getInstance "SHA256withECDSA")]
    (.initSign ecdsa-signature private-key)
    (.update ecdsa-signature payload)
    (.sign ecdsa-signature)))

(defn verify-signature [data signature public-key]
  (let [ecdsa-signature (Signature/getInstance "SHA256withECDSA")
        key-factory (KeyFactory/getInstance "EC")]
    (.initVerify ecdsa-signature public-key)
    (.update ecdsa-signature data)
    (.verify ecdsa-signature signature)))


;; Create a secp256r1 EC key pair, print out private key and address (SHA-1(SHA-256(Pk)))
(defn -main [& _args]
  (let [g (java.security.KeyPairGenerator/getInstance "EC")
        spec (new java.security.spec.ECGenParameterSpec "secp256r1")
        sha256-digest (java.security.MessageDigest/getInstance "SHA-256")
        sha1-digest (java.security.MessageDigest/getInstance "SHA-1")
        base64-encoder (java.util.Base64/getEncoder)]
    (.initialize g spec)
    (let [key-pair (.generateKeyPair g)
          private-key (.getPrivate key-pair)
          public-key (.getPublic key-pair)
          ecdsa-signature (Signature/getInstance "SHA256withECDSA")]
      (println (.toString (new BigInteger (.getEncoded private-key))))
      (println (.encodeToString base64-encoder (.getEncoded private-key)))
      (println (.encodeToString base64-encoder (.digest sha1-digest
                                                        (.digest sha256-digest
                                                                 (.getEncoded public-key)))))
      (println (.encodeToString base64-encoder (sign-payload (.getBytes "pouet") private-key))) ; sign once
      (println (.encodeToString base64-encoder (sign-payload (.getBytes "pouet") private-key))) ; sign second time – ECDSA signature should be different
      (println (verify-signature (.getBytes "pouet")
                                 (sign-payload (.getBytes "pouet") private-key)
                                 public-key)) ; sign and verify
      )))

;; Produces for example:
;; 42400449615825239949034251209721392312410047603504363169820785445001651662277979956410227646910225546770551154371697370495471215219072921185724645690919042347828
;; MEECAQAwEwYHKoZIzj0CAQYIKoZIzj0DAQcEJzAlAgEBBCB7W+q+8JBYknNZ7zEgl8+RIwLhuAhlWOohD51PyabzNA==
;; ze7BvOknFHc8ey0Z47WMPE8Hxvk=
;; MEQCICq0JXJyYEAFjD1xaw9BhxiJcVvXeRbJfgtl6q5+NS8KAiBwX0VhpK+kradUuy4jESkV4rdS8Am9QSJWJAM3AKP3JQ==
;; MEUCIBG5UgArbxNb3iQ6V1ibreJaWD2BGBX93vUlgKOPuz75AiEAr1/2bnA+EngrAMQVQuJUMi5YXE9imyj66hCjF99eaPc=
;; true
;;


(defn create-pair-from-key [key]
  (let [g (java.security.KeyPairGenerator/getInstance "EC")
        spec (new java.security.spec.ECGenParameterSpec "secp256r1")
        sha256-digest (java.security.MessageDigest/getInstance "SHA-256")
        sha1-digest (java.security.MessageDigest/getInstance "SHA-1")
        base64-encoder (java.util.Base64/getEncoder)]
    (.initialize g spec)
    (let [ec-params (.getParams (.getPrivate (.generateKeyPair g))) ;; generate a random key pair to get ecParams
          private-key-spec (new java.security.spec.ECPrivateKeySpec (new BigInteger key) ec-params)
          key-factory (java.security.KeyFactory/getInstance "EC")
          private-key (.generatePrivate key-factory private-key-spec)
          public-key-spec (new java.security.spec.ECPublicKeySpec
                               (.getGenerator ec-params)
                               (.getParams private-key))
          public-key (.generatePublic key-factory public-key-spec)]
      (println (new BigInteger (.getEncoded private-key)))
      (println (.encodeToString base64-encoder (.getEncoded private-key)))
      (println (.encodeToString base64-encoder (.digest sha1-digest
                                                        (.digest sha256-digest
                                                                 (.getEncoded public-key))))))))
