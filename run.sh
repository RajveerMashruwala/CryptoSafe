#!/usr/bin/env bash
# Compile and run CryptoSafe (Linux / macOS). No database server needed.
set -e
cd "$(dirname "$0")"
mkdir -p out
javac -encoding UTF-8 -cp "lib/*" -d out CryptoSafe.java
java -cp "out:lib/*" CryptoSafe
