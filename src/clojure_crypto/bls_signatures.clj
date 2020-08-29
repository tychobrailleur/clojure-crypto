(ns clojure-crypto.bls-signatures
  (:import [it.unisa.dia.gas.jpbc PairingParametersGenerator PairingParameters]
           [it.unisa.dia.gas.plaf.jpbc.pairing PairingFactory]
           [it.unisa.dia.gas.plaf.jpbc.pairing.a TypeACurveGenerator]))

(def system-parameters (.newRandomElement (.getG2 pairing)))

(defn generate-pairing-params []
  "Generate Pairing parameters that can be stored in properties."
  (let [r 160
        q 512
        params-generator (TypeACurveGenerator. r q)]
    (.generate params-generator)))

(defn get-pairing []
  "Return Pairing configured in params.properties."
  (PairingFactory/getPairing "params.properties"))

(defn create-secret-key [pairing]
  (-> pairing
      (.getZr)
      (.newRandomElement)
      (.toBytes)))

(defn sign [message pairing private-key]
  (let [zr (.getZr pairing)
        secret-key (.newElementFromBytes zr private-key)
        public-key (-> system-parameters
                       (.duplicate)
                       (.powZn secret-key))]
    private-key))

(defn -main [& _args]
  (let [pairing (get-pairing)
        zr (.getZr pairing)
        private-key (create-secret-key pairing)]
    (println (map (fn [n] (sign (format "pouet %d" n) pairing (create-secret-key pairing))) (range 10)))
    (println (generate-pairing-params))
    (println (sign (.getBytes "pouet") pairing private-key))))
