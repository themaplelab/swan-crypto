# SWAN Crypto

This repository contains work for using [SWAN](https://github.com/themaplelab/swan) to find cryptographic API misuses. This work is experimental.

### Summary

I have extended SWAN to feature hand-crafted analyses for detecting misuses in the popular open-source [SwiftCrypto](https://github.com/krzyzanowskim/CryptoSwift) API. You can find the analysis code [here](https://github.com/themaplelab/swan/blob/crypto/jvm/ca.ualberta.maple.swan.spds/src/scala/ca/ualberta/maple/swan/spds/analysis/crypto/CryptoAnalysis.scala). My analyses follow the classic crypto rules/guidelines as laid out in the following works:

- Modelling Analysis and Auto-detection of Cryptographic Misuse in Android Applications [[link](https://ieeexplore.ieee.org/document/6945307)]
- A Comparative Study of Misapplied Crypto in Android and iOS Applications [[link](https://www.semanticscholar.org/paper/A-Comparative-Study-of-Misapplied-Crypto-in-Android-Feichtner/d3c48ad2e7e67521f5847f596ab8b3ca37f6b5a4)]
- An empirical study of cryptographic misuse in android applications [[link](https://dl.acm.org/doi/10.1145/2508859.2516693)]

My analysis currently supports the following rules:

1. Do Not Use ECB Mode for Encryption

   ```swift
   let blockMode = ECB()
   _ = try AES(key: key, blockMode: blockMode, padding: padding)
   ```

2. No Non-random IVs for Encryption

   ```swift
   let iv = "constant string"
   _ = try AES(key: key, iv: iv)
   ```

3. Do Not Use Constant Encryption Keys

   ```swift
   let key = "constant key".bytes
   _ = try AES(key: key, blockMode: blockMode, padding: padding)
   ```

4. Do Not Use Constant Salts for PBE

   ```swift
   let salt = "constant salt".bytes
   _ = try HKDF(password: pwd, salt: salt, info: i, keyLength: 128, variant: .sha2(.sha256))
   ```

5. Do Not Use < 1000 Iterations for PBE

   ```swift
   let iterations = 500
   _ = try PKCS5.PBKDF1(password: pwd, salt: salt, iterations: iterations, keyLength: 128)
   ```

6. Do Not Use Constant Password for PBE

   ```swift
   let password = "constant password".bytes
   _ = try HKDF(password: password, salt: salt, info: i, keyLength: 128, variant: .sha2(.sha256))
   ```

## Instructions

Clone SWAN using the `crypto` branch.

```shell
git clone https://github.com/themaplelab/swan.git -b crypto
```

Follow the instructions located in the README of SWAN to build SWAN. The `lib/` directory will contain the executables you need to run SWAN. I recommend putting the `lib/` directory onto your `$PATH`.

### Running tests

`CryptoSwiftTests/` contains an Xcode project with code that exhibits API misuses for use with the crypto analysis. You can run the analysis on the project using the following series of commands

```shell
cd CryptoSwiftTests/
```

Build the project

```shell
swan-xcodebuild -- -project CryptoSwiftTests.xcodeproj -scheme CryptoSwiftTests
```

Now you should see a `swan-dir/` containing the SIL files to analyze. Due to an issue with parsing, you need to copy  the `CryptoSwift.CryptoSwift.sil` file located in `sil/` into the ` swan-dir/`.

```shell
cp ../sil/CryptoSwift.CryptoSwift.sil swan-dir/
```

Run the SWAN analysis.

```
java -jar driver.jar --crypto swan-dir/
```

The analysis results will be available in `swan-dir/crypto-results.json`. Now, we use the annotation checker to make sure the analysis found the correct violations. You should see no output (and exit 0) if the violations are correct.

```
java -jar annotation.jar swan-dir/
```
