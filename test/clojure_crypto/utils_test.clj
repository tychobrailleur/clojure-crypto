(ns clojure-crypto.utils-test
  (:require [clojure.test :refer :all]
            [clojure-crypto.utils :refer :all]))

(deftest bytes->hex-test
  (testing "Hex"
    (is (= "68656c6c6f" (bytes->hex (.getBytes "hello"))))))

(deftest base64-test
  (testing "Base64 encoded"
    (is (= "aGVsbG8=" (base64 (.getBytes "hello"))))))

(deftest sha1-test
  (testing "SHA-1 hashing"
    (is (= "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d"
           (bytes->hex (sha1 (.getBytes "hello")))))))

(deftest sha256-test
  (testing "SHA-256 hashing"
    (is (= "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
           (bytes->hex (sha256 (.getBytes "hello")))))))

(deftest xor-test
  (testing "XOR byte arrays"
    (is (= (bytes->hex (xor (hex->bytes "e86d2de2")
                            (hex->bytes "1792d21d")))
           "ffffffff"))
    (is (= (bytes->hex (xor (hex->bytes "e86d2de210")
                            (hex->bytes "1792d21d")))
           "ffffffff"))))
