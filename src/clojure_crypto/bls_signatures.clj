(ns clojure-crypto.bls-signatures
  (:import [it.unisa.dia.gas.jpbc PairingParametersGenerator PairingParameters]
           [it.unisa.dia.gas.plaf.jpbc.pairing PairingFactory]
           [it.unisa.dia.gas.plaf.jpbc.pairing.a TypeACurveGenerator]))

(defn generate-pairing-params []
  "Generate Pairing parameters that can be stored in properties."
  (let [r 160
        q 512
        params-generator (TypeACurveGenerator. r q)]
    (.generate params-generator)))

(defn get-pairing []
  "Return Pairing configured in params.properties."
  (PairingFactory/getPairing "params.properties"))

(defn sign [message pairing private-key]
  (let [zr (.getZr pairing)
        secret-key (.newElementFromBytes zr private-key)]
    (println secret-key)))

(defn -main [& _args]
  (let [pairing (get-pairing)
        zr (.getZr pairing)
        system-parameters (.newRandomElement (.getG2 pairing))
        private-key (.toBytes (.newRandomElement zr))]
  (println (generate-pairing-params))
  (println (sign (.getBytes "pouet") pairing private-key))))
