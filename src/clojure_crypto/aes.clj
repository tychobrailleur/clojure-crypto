(ns clojure-crypto.aes
  (:require [clojure-crypto.utils :as util])
  (:import [javax.crypto Cipher]
           [javax.crypto.spec IvParameterSpec SecretKeySpec]
           [java.security MessageDigest KeyFactory SecureRandom]
           [org.apache.commons.codec.binary Hex]
           [java.util Base64]))




(defn decrypt-ctr [key cipher]
  (let [c (Cipher/getInstance "AES/CTR/NoPadding")
        secret-key (SecretKeySpec. (util/hex->bytes key) "AES")
        nonce-counter (IvParameterSpec.
                       (byte-array (take 16 (util/hex->bytes cipher))))]
    (.init c
           Cipher/DECRYPT_MODE
           secret-key
           nonce-counter)
    (String. (.doFinal c (byte-array (drop 16 (util/hex->bytes cipher)))))))



(defn -main [& _args]
  (println (decrypt-ctr
            "36f18357be4dbd77f050515c73fcf9f2"
            "69dda8455c7dd4254bf353b773304eec0ec7702330098ce7f7520d1cbbb20fc388d1b0adb5054dbd7370849dbf0b88d393f252e764f1f5f7ad97ef79d59ce29f5f51eeca32eabedd9afa9329"))
  (println (decrypt-ctr
            "36f18357be4dbd77f050515c73fcf9f2"
            "770b80259ec33beb2561358a9f2dc617e46218c0a53cbeca695ae45faa8952aa0e311bde9d4e01726d3184c34451")))
