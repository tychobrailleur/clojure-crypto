(ns clojure-crypto.ecdh
  (:require [clojure.core.async :as async :refer [go go-loop chan <! >! <!!]]
            [clojure-crypto.utils :as util])
  (:import [java.security KeyPairGenerator]
           [java.security.spec ECGenParameterSpec]
           [javax.crypto KeyAgreement]))



(defn keypair-generator []
  (let [keypair-generator (KeyPairGenerator/getInstance "EC")
        spec (ECGenParameterSpec. "secp256r1")]
    (.initialize keypair-generator spec)
    keypair-generator))

(def a->b (chan))
(def b->a (chan))
(def control-chan (chan))

(defn create-key-agreement [my-secret-key their-public-key]
  (let [key-agreement (KeyAgreement/getInstance "ECDH")]
    (.init key-agreement my-secret-key)
    (.doPhase key-agreement their-public-key true)
    (.generateSecret key-agreement)))



;; A sends their public key to B
;; B calculates the DH secret, prints it and sends their public back to A
;; A calculates the DH secret, and prints it.  It is identical to the one B calculated.
(defn -main [& args]
  (let [generator (keypair-generator)
        keypair-a (.generateKeyPair generator)
        keypair-b (.generateKeyPair generator)]
    (go (>! a->b {:message :init :key (.getPublic keypair-a)}))
    (go (let [msg (<! a->b)
              {m :message key :key :as all} msg]
          (case m
            :init (do (println (util/base64
                                (create-key-agreement (.getPrivate keypair-b) key)))
                      (>! b->a {:message :response :key (.getPublic keypair-b)})))))
    (go (let [msg (<! b->a)
              {m :message key :key :as all} msg]
          (case m
            :response (do (println (util/base64 (create-key-agreement (.getPrivate keypair-a) key)))
                          (>! control-chan :end))))))
  (<!! control-chan))
