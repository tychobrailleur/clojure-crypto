(ns clojure-crypto.utils
  (:import [java.security MessageDigest KeyFactory]
           [org.apache.commons.codec.binary Hex]
           [java.util Base64]))

(def sha1-digest (java.security.MessageDigest/getInstance "SHA-1"))
(def sha256-digest (java.security.MessageDigest/getInstance "SHA-256"))
(def base64-encoder (java.util.Base64/getEncoder))

(defn sha256 [message]
  (.digest sha256-digest message))

(defn sha1 [message]
  (.digest sha1-digest message))

(defn base64 [message]
  (.encodeToString base64-encoder message))

(defn bytes->hex [bytes]
  (Hex/encodeHexString bytes))
