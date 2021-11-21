(ns clojure-crypto.utils
  (:import [java.security MessageDigest KeyFactory SecureRandom]
           [org.apache.commons.codec.binary Hex]
           [java.util Base64]))

(def sha1-digest (java.security.MessageDigest/getInstance "SHA-1"))
(def sha256-digest (java.security.MessageDigest/getInstance "SHA-256"))
(def base64-encoder (java.util.Base64/getEncoder))
(def base64-decoder (java.util.Base64/getDecoder))

(defn sha256 [message]
  (.digest sha256-digest message))

(defn sha1 [message]
  (.digest sha1-digest message))

(defn base64 [message]
  (.encodeToString base64-encoder message))

(defn debase64 [message]
  (.decode base64-decoder message))

(defn bytes->hex [bytes]
  (Hex/encodeHexString bytes))

(defn hex->bytes [str]
  (Hex/decodeHex str))

(defn random-bytes
  "Create a byte array with `num` random bytes."
  [num]
  (let [rng (SecureRandom.)
        buf (byte-array num)]
    (.nextBytes rng buf)
    buf))

(defn xor
  "XOR two byte arrays, and returns the resulting byte array."
  [first second]
  (byte-array (map bit-xor first second)))
