(ns clojure-crypto.nssdb
  (:import [java.security Security KeyStore Signature]
           [java.io File])
  (:require [clojure-crypto.utils :as util]))

(def SIG-ALGO "SHA256withECDSA")

(defn init-pkcs11-provider [conf]
  (let [proto (Security/getProvider "SunPKCS11")
        config-path (.getAbsolutePath (File. conf))
        provider (.configure proto config-path)]
    (println "info:" (.getInfo provider))
    (Security/addProvider provider)
    provider))

(defn load-keystore [provider password]
  (let [ks (KeyStore/getInstance "PKCS11" provider)]
    (.load ks nil (.toCharArray password))
    (println "Count:" (.size ks))
    ks))

(defn get-certificate [keystore alias]
  (.getCertificate keystore alias))

(defn sign-message [msg provider keystore alias password]
  (let [private-key (.getKey keystore alias (.toCharArray password))
        sig (Signature/getInstance SIG-ALGO provider)]
    (.initSign sig private-key)
    (.update sig (.getBytes msg))
    (.sign sig)))

(defn verify-signature [msg signature provider cert]
  (let [public-sig (Signature/getInstance SIG-ALGO provider)]
    (.initVerify public-sig (.getPublicKey cert))
    (.update public-sig (.getBytes msg))
    (.verify public-sig signature)))


;; Uses Mozilla NSS to sign a message, and then to verify the signature.
;; See also https://magnus-k-karlsson.blogspot.com/2019/09/reading-nss-db-from-java-11-with.html
(defn -main [& rest]
  (let [msg "Hello World"
        alias "weblogism - Weblogism"
        provider (init-pkcs11-provider "resources/config.cfg")
        keystore (load-keystore provider "password")
        cert (get-certificate keystore alias)]
    (println cert)
    (let [signature (sign-message msg provider keystore alias "password")]
      (println "Signature:" (util/base64 signature))
      (println (verify-signature msg signature provider cert)))))
