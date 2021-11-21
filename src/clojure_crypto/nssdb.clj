(ns clojure-crypto.nssdb
  (:import [java.security Security KeyStore Signature]
           [java.io File])
  (:require [clojure-crypto.utils :as util]))


;; Uses Mozilla NSS to sign a message, and then to verify the signature.
;; TODO Cleanup, make Clojure-y.
(defn -main [& rest]

  (let [proto (Security/getProvider "SunPKCS11")
        config-path (.getAbsolutePath (File. "resources/config.cfg"))
        provider (.configure proto config-path)]
    (println "info:" (.getInfo provider))
    (Security/addProvider provider)
    (KeyStore/getInstance "PKCS11" provider)

    (let [ks (KeyStore/getInstance "PKCS11" provider)]
      (.load ks nil (.toCharArray "password"))
      (println "Count:" (.size ks))

      (let [aliases (.aliases ks)]
        (while (.hasMoreElements aliases)
          (let [alias (.nextElement aliases)
                cert (.getCertificate ks alias)]
            (println cert)
            (when (= "weblogism - Weblogism" alias)
              (let [private-key (.getKey ks alias (.toCharArray "password"))
                    sig (Signature/getInstance "SHA256withECDSA" provider)]
                (.initSign sig private-key)
                (.update sig (.getBytes "Hello World!"))
                (println (.getEncoded private-key))
                (let [signature (.sign sig)
                      readable-sig (util/base64 signature)
                      public-sig (Signature/getInstance "SHA256withECDSA" provider)]
                  (println "Signature:" readable-sig)
                  (.initVerify public-sig (.getPublicKey cert))
                  (.update public-sig (.getBytes "Hello World!"))
                  (println (.verify public-sig signature)))))))))))
