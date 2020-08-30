(ns clojure-crypto.bls-signatures
  (:require [clojure-crypto.utils :as utils])
  (:import [it.unisa.dia.gas.jpbc PairingParametersGenerator PairingParameters]
           [it.unisa.dia.gas.plaf.jpbc.pairing PairingFactory]
           [it.unisa.dia.gas.plaf.jpbc.pairing.a TypeACurveGenerator]
           [org.bouncycastle.crypto CipherParameters]
           [org.bouncycastle.crypto.digests SHA256Digest]
           [it.unisa.dia.gas.crypto.jpbc.signature.bls01.engines BLS01Signer]
           [it.unisa.dia.gas.crypto.jpbc.signature.bls01.generators BLS01KeyPairGenerator BLS01ParametersGenerator]
           [it.unisa.dia.gas.crypto.jpbc.signature.bls01.params BLS01Parameters BLS01KeyGenerationParameters]))

(defn get-pairing []
  "Return Pairing configured in params.properties."
  (PairingFactory/getPairing "params.properties"))

(defn bls01-parameters []
  (let [pairing-parameters (PairingFactory/getPairingParameters "params.properties")
        generator (BLS01ParametersGenerator.)]
      (.init generator pairing-parameters)
      (.generateParameters generator)))

(defn generate-pairing-params []
  "Generate Pairing parameters that can be stored in properties."
  (let [r 160
        q 512
        params-generator (TypeACurveGenerator. r q)]
    (.generate params-generator)))

(defn create-secret-key [pairing]
  (-> pairing
      (.getZr)
      (.newRandomElement)
      (.toBytes)))

;; (defn sign [message pairing private-key]
;;   (let [zr (.getZr pairing) ; Field $\mathbb{Z}_r$
;;         secret-key (.newElementFromBytes zr private-key)
;;         public-key (-> system-parameters
;;                        (.duplicate)
;;                        (.powZn secret-key))]
;;     private-key))

(defn create-signer []
  (BLS01Signer. (SHA256Digest.)))

(defn generate-key [^BLS01Parameters parameters]
  (let [key-generator (BLS01KeyPairGenerator.)]
    (.init key-generator (BLS01KeyGenerationParameters. nil parameters))
    (.generateKeyPair key-generator)))


(defn sign [message ^CipherParameters private-key]
  (let [signer (create-signer)]
    (.init signer true private-key)
    (.update signer message 0 (count message))
    (.generateSignature signer)))

(defn verify [message signature ^CipherParameters public-key]
  (let [signer (create-signer)]
    (.init signer false public-key)
    (.update signer message 0 (count message))
    (.verifySignature signer signature)))

;; (defn hash [message public-key]
;;   (let [h (utils/sha256 message)]
;;     (utils/sha256 (byte-array (concat h (.toBytes public-key))))))

(defn -main [& _args]
  (let [params (bls01-parameters)
        key-pair (generate-key params)
        message "Pouet!"]
    (println (verify (.getBytes message)
                     (sign (.getBytes message) (.getPrivate key-pair))
                     (.getPublic key-pair)))
    (println (verify (.getBytes "Bing")
                     (sign (.getBytes message) (.getPrivate key-pair))
                     (.getPublic key-pair)))))

;; (defn -main [& _args]
;;   (let [pairing (get-pairing)
;;         zr (.getZr pairing)
;;         private-key (create-secret-key pairing)
;;         secret-key (.newElementFromBytes zr private-key)
;;         signatures (map (fn [n] (sign (format "pouet %d" n) pairing (create-secret-key pairing))) (range 10))]
;;     (println signatures)
;;     (println (generate-pairing-params))
;;     (println (sign (.getBytes "pouet") pairing private-key))
;;     (println (hash (.getBytes "pouet") (.powZn (.duplicate system-parameters) secret-key)))))
