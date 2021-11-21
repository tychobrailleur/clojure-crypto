(ns clojure-crypto.nssk
  (:require [clojure-crypto.utils :as util]
            [clojure.string :as str]
            [clojure.core.async :as async :refer [<! >!! >! <!! go go-loop to-chan chan alts!!]])
  (:import [java.security SecureRandom]
           [javax.crypto KeyGenerator Cipher]
           [javax.crypto.spec SecretKeySpec]))


(def cipher (Cipher/getInstance "AES"))

(defn encrypt [msg key]
  (.init cipher Cipher/ENCRYPT_MODE key)
  (.doFinal cipher msg))

(defn encrypt-list [l key]
  (.init cipher Cipher/ENCRYPT_MODE key)
  (->> l
       (str/join "|")
       (.getBytes)
       (.doFinal cipher)))

(defn decrypt-list [cip key]
  (.init cipher Cipher/DECRYPT_MODE key)
  (let [cleartext (.doFinal cipher cip)]
    (str/split (String. cleartext) #"\|")))


(defn generate-key []
  (let [generator (KeyGenerator/getInstance "AES")]
    (.init generator 256)
    (.generateKey generator)))


(def secret-keys (partition-all 2
                         (interleave ["Alice" "Bob" "Server"]
                                     (repeatedly 3 generate-key))))

(defn get-entity-key [entity]
  (last (first (filter #(= (first %) entity) secret-keys))))

(def state (atom {}))

(let [a->as (chan)
      as->a (chan)
      a->b (chan)
      b->as (chan)
      as->b (chan)
      b->a (chan)]
  ;; Step 1. A -> AS
  (go (>! a->as (list "Alice" "Bob" (util/base64 (util/random-bytes 32)))))

  ;; Step 3. A -> B
  (go (let [msg (<! as->a)
            decrypted-msg (decrypt-list msg (get-entity-key "Alice"))
            [nonce recipient session-key cipher-to-b] decrypted-msg]
        (swap! state assoc :alice session-key)
        (>! a->b cipher-to-b)))

  ;; Step 2. AS -> A
  (go (let [msg (<! a->as)
            [sender recipient nonce] msg
            session-key (util/random-bytes 32)
            ka (get-entity-key sender)
            kb (get-entity-key recipient)
            msb-to-b (encrypt-list (list (util/base64 session-key) sender) kb)
            msg-to-a (encrypt-list (list nonce recipient (util/base64 session-key) (util/base64 msb-to-b)) ka)]
        (>! as->a msg-to-a)))

  ;; Step 4. B -> A
  (go (let [msg (<! a->b)
            decrypted-msg (decrypt-list (util/debase64 msg) (get-entity-key "Bob"))
            [session-key sender] decrypted-msg
            nonce (util/random-bytes 32)]
        (>! b->a (encrypt-list (list (util/base64 nonce)) (SecretKeySpec. (util/debase64 session-key) "AES")))))

  ;; Step 5. A -> B
  (go (let [msg (<! b->a)
            session-key (@state :alice)
            decrypted-msg (decrypt-list msg (SecretKeySpec. (util/debase64 session-key) "AES"))
            nonce (util/debase64 (first decrypted-msg))]

        ;; Just printing last message.
        (println "Will send next"  (.subtract (BigInteger. nonce) BigInteger/ONE) "encrypted with" session-key))))



;; (def my-key (generate-key))
;; (prn (decrypt-list (encrypt-list (list "Alice" "Bob" "Chantal") my-key) my-key))
;; (prn (encrypt-list (list "Alice" "Bob" "Chantal") my-key) my-key)
