(defproject clojure-crypto "0.1.0-SNAPSHOT"
  :description "FIXME: write description"
  :url "http://example.com/FIXME"
  :license {:name "GNU General Public License v3.0"
            :url "none"
            :year 2020
            :key "gpl-3.0"}
  :dependencies [[org.clojure/clojure "1.10.0"]
                 [it.unisa.dia.gas/jpbc-api "2.0.0"]
                 [it.unisa.dia.gas/jpbc-plaf "2.0.0"]]
  :main clojure-crypto.core
  :repl-options {:init-ns clojure-crypto.core})
