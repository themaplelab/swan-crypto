import Foundation
import CryptoSwift

// *** UTILITIES ***

func getRandomArray() -> Array<UInt8> {
  AES.randomIV(10)
}

func getUnknownArray() -> Array<UInt8> {
  [0x2a, 0x3a, 0x80, 0x05, 0xaf, 0x46, 0x58, 0x2d, 0x66, 0x52, 0x10, 0xae, 0x86, 0xd3, 0x8e, 0x8f]
}

func unknownCondition() -> Bool {
  Bool.random()
}

func getConstantString() -> String {
  "constant string"
}

func getConstantArray() -> Array<UInt8> {
  Array<UInt8>(hex: "constant hex string")
}

func getLowIterationCount() -> Int { return 999 }

func getGoodIterationCount() -> Int { return 1000 }

// *** RULE 1: USING ECB BLOCK MODE FOR ENCRYPTION ***

func test_r1_simple_violation() throws {
  let key = getRandomArray()
  let padding = Padding.noPadding
  let blockMode = ECB()
  
  // Violation SHOULD be detected only for blockMode argument
  _ = try AES(key: key, blockMode: blockMode, padding: padding) //$ECB$error
  _ = try AES(key: key, blockMode: blockMode) //$ECB$error
  _ = try Blowfish(key: key, blockMode: blockMode, padding: padding) //$ECB$error
}

func test_r1_simple_no_violation() throws {
  let key = getRandomArray()
  let padding = Padding.noPadding
  let blockMode = CBC(iv: getRandomArray())
  
  // Violation SHOULD NOT be detected
  _ = try AES(key: key, blockMode: blockMode, padding: padding)
  _ = try AES(key: key, blockMode: blockMode)
  _ = try Blowfish(key: key, blockMode: blockMode, padding: padding)
}

// *** RULE 2: NO NON-RANDOM IVS ***

func test_r2_simple_violation() throws {
  let iv = getConstantArray()
  let ivString = iv.toHexString()
  let key = getRandomArray()
  let keyString = key.toHexString()
  let randomArray = getRandomArray()
  
  // Violation SHOULD be detected only for iv argument
  
  // BlockModes
  _ = CBC(iv: iv) //$IV$error
  _ = CFB(iv: iv) //$IV$error
  _ = CFB(iv: iv, segmentSize: CFB.SegmentSize.cfb8) //$IV$error
  _ = CCM(iv: iv, tagLength: 0, messageLength: 0, additionalAuthenticatedData: randomArray) //$IV$error
  _ = CCM(iv: iv, tagLength: 0, messageLength: 0, authenticationTag: randomArray, additionalAuthenticatedData: randomArray) //$IV$error
  _ = OFB(iv: iv) //$IV$error
  _ = CTR(iv: iv) //$IV$error
  _ = CTR(iv: iv, counter: 0) //$IV$error
  _ = PCBC(iv: iv) //$IV$error
  
  // Cryptors
  _ = try AES(key: keyString, iv: ivString) //$IV$error
  _ = try ChaCha20(key: key, iv: iv) //$IV$error
  _ = try ChaCha20(key: keyString, iv: ivString) //$IV$error
  _ = try Blowfish(key: keyString, iv: ivString) //$IV$error
  _ = try Blowfish(key: keyString, iv: ivString, padding: Padding.noPadding) //$IV$error
  _ = try Rabbit(key: key, iv: iv) //$IV$error
  _ = try Rabbit(key: keyString, iv: ivString) //$IV$error
}

func test_r2_simple_no_violation() throws {
  let iv = getRandomArray()
  let ivString = iv.toHexString()
  let key = getRandomArray()
  let keyString = key.toHexString()
  let randomArray = getRandomArray()
  
  // Violation SHOULD NOT be detected
  
  // BlockModes
  _ = CBC(iv: iv)
  _ = CFB(iv: iv)
  _ = CFB(iv: iv, segmentSize: CFB.SegmentSize.cfb8)
  _ = CCM(iv: iv, tagLength: 0, messageLength: 0, additionalAuthenticatedData: randomArray)
  _ = CCM(iv: iv, tagLength: 0, messageLength: 0, authenticationTag: randomArray, additionalAuthenticatedData: randomArray)
  _ = OFB(iv: iv)
  _ = CTR(iv: iv)
  _ = CTR(iv: iv, counter: 0)
  _ = PCBC(iv: iv)
  
  // Cryptors, also test the different *.randomIV options
  let aesIV = AES.randomIV(10)
  _ = try AES(key: keyString, iv: aesIV.toHexString())
  let chachaIV = ChaCha20.randomIV(10)
  _ = try ChaCha20(key: key, iv: chachaIV)
  _ = try ChaCha20(key: keyString, iv: chachaIV.toHexString())
  _ = try Blowfish(key: keyString, iv: ivString)
  _ = try Blowfish(key: keyString, iv: ivString, padding: Padding.noPadding)
  _ = try Rabbit(key: key, iv: iv)
  _ = try Rabbit(key: keyString, iv: ivString)
}

func test_r2_non_random_but_not_constant_violation() {
  let iv = getUnknownArray()
  // Violation SHOULD be detected only for iv argument
  _ = CBC(iv: iv) //$IV$error
}

// *** RULE 3: DO NOT USE CONSTANT ENCRYPTION KEYS ***

func test_r3_simple_violation() throws {
  let key = getConstantArray()
  let randomArray = getRandomArray()
  let keyString = getConstantString()
  let blockMode = CBC(iv: randomArray)
  let padding = Padding.noPadding
  let variant = HMAC.Variant.sha2(.sha256)
  let iv = AES.randomIV(10)
  let ivString = iv.toHexString()
  
  // Violation SHOULD be detected only for key argument
  
  // AES
  _ = try AES(key: key, blockMode: blockMode, padding: padding) //$KEY$error
  _ = try AES(key: key, blockMode: blockMode) //$KEY$error
  _ = try AES(key: keyString, iv: ivString) //$KEY$error
  _ = try AES(key: keyString, iv: ivString, padding: padding) //$KEY$error

  // HMAC
  _ = HMAC(key: key) //$KEY$error
  _ = HMAC(key: key, variant: variant) //$KEY$error
  _ = try HMAC(key: keyString) //$KEY$error
  _ = try HMAC(key: keyString, variant: variant) //$KEY$error
  
  // ChaCha20
  _ = try ChaCha20(key: key, iv: iv) //$KEY$error
  _ = try ChaCha20(key: keyString, iv: ivString) //$KEY$error
  
  // CBCMAC
  _ = try CBCMAC(key: key) //$KEY$error
  
  // CMAC
  _ = try CMAC(key: key) //$KEY$error

  // Poly1305
  _ = Poly1305(key: key) //$KEY$error
  
  // Blowfish
  _ = try Blowfish(key: keyString, iv: ivString) //$KEY$error
  _ = try Blowfish(key: keyString, iv: ivString, padding: padding) //$KEY$error
  _ = try Blowfish(key: key, blockMode: blockMode, padding: padding) //$KEY$error
  _ = try Blowfish(key: key, padding: padding) //$KEY$error
  
  // Rabbit
  _ = try Rabbit(key: key) //$KEY$error
  _ = try Rabbit(key: keyString) //$KEY$error
  _ = try Rabbit(key: key, iv: iv) //$KEY$error
  _ = try Rabbit(key: keyString, iv: ivString) //$KEY$error
}

func test_r3_simple_no_violation() throws {
  let key = getRandomArray()
  let randomArray = getRandomArray()
  let keyString = AES.randomIV(10).toHexString()
  let blockMode = CBC(iv: randomArray)
  let padding = Padding.noPadding
  let variant = HMAC.Variant.sha2(.sha256)
  let iv = AES.randomIV(10)
  let ivString = iv.toHexString()
  
  // Violation SHOULD NOT be detected
  
  // AES
  _ = try AES(key: key, blockMode: blockMode, padding: padding)
  _ = try AES(key: key, blockMode: blockMode)
  _ = try AES(key: keyString, iv: ivString)
  _ = try AES(key: keyString, iv: ivString, padding: padding)
  
  // HMAC
  _ = HMAC(key: key, variant: variant)
  _ = try HMAC(key: keyString)
  _ = try HMAC(key: keyString, variant: variant)
  _ = HMAC(key: key)
  
  // ChaCha20
  _ = try ChaCha20(key: key, iv: iv)
  _ = try ChaCha20(key: keyString, iv: ivString)
  
  // CBCMAC
  _ = try CBCMAC(key: key)
  
  // CMAC
  _ = try CMAC(key: key)

  // Poly1305
  _ = Poly1305(key: key)
  
  // Blowfish
  _ = try Blowfish(key: keyString, iv: ivString)
  _ = try Blowfish(key: keyString, iv: ivString, padding: padding)
  _ = try Blowfish(key: key, blockMode: blockMode, padding: padding)
  _ = try Blowfish(key: key, padding: padding)
  
  // Rabbit
  _ = try Rabbit(key: key)
  _ = try Rabbit(key: keyString)
  _ = try Rabbit(key: key, iv: iv)
  _ = try Rabbit(key: keyString, iv: ivString)
}

// *** RULE 4: CONSTANT SALT ***

func test_r4_simple_violation() throws {
  let salt = getConstantArray()
  let iterations = getGoodIterationCount()
  let randomArray = getRandomArray()

  // Violation SHOULD be detected only for password argument
  
  _ = try HKDF(password: randomArray, salt: salt, info: randomArray, keyLength: 0, variant: HMAC.Variant.sha2(.sha256)) //$SALT$error
  _ = try PKCS5.PBKDF1(password: randomArray, salt: salt, iterations: iterations, keyLength: 0) //$SALT$error
  _ = try PKCS5.PBKDF2(password: randomArray, salt: salt, iterations: iterations, keyLength: 0) //$SALT$error
  _ = try Scrypt(password: randomArray, salt: salt, dkLen: 64, N: 16384, r: 8, p: 1) //$SALT$error
}

func test_r4_from_string_violation() throws {
  let constantString = getConstantString()
  let salt = constantString.bytes
  let randomArray = getRandomArray()

  // Violation SHOULD be detected only for salt argument
  _ = try HKDF(password: randomArray, salt: salt, info: randomArray, keyLength: 0, variant: HMAC.Variant.sha2(.sha256)) //$SALT$error
}

func test_r4_from_string_md5_violation() throws {
  let constantString = getConstantString()
  let salt = constantString.bytes.md5()
  let randomArray = getRandomArray()
  
  // Violation SHOULD be detected only for salt argument
  _ = try HKDF(password: randomArray, salt: salt, info: randomArray, keyLength: 0, variant: HMAC.Variant.sha2(.sha256)) //$SALT$error
}

func test_r4_multiple_values_violation() throws {
  let salt = unknownCondition() ? getConstantString().bytes : getRandomArray()
  let randomArray = getRandomArray()
  
  // Violation SHOULD be detected only for salt argument
  _ = try HKDF(password: randomArray, salt: salt, info: randomArray, keyLength: 0, variant: HMAC.Variant.sha2(.sha256)) //$SALT$error
}

func test_r4_simple_no_violation() throws {
  let salt = getRandomArray()
  let iterations = getGoodIterationCount()
  let randomArray = getRandomArray()
  
  // Violation SHOULD NOT be detected
  
  _ = try HKDF(password: randomArray, salt: salt, info: randomArray, keyLength: 0, variant: HMAC.Variant.sha2(.sha256))
  _ = try PKCS5.PBKDF1(password: randomArray, salt: salt, iterations: iterations, keyLength: 0)
  _ = try PKCS5.PBKDF2(password: randomArray, salt: salt, iterations: iterations, keyLength: 0)
  _ = try Scrypt(password: randomArray, salt: salt, dkLen: 64, N: 16384, r: 8, p: 1)
}


// *** RULE 5: DO NOT USE < 1000 ITERATIONS FOR PBE ***

func test_r5_simple_violation() throws {
  let iterations = getLowIterationCount()
  let randomArray = getRandomArray()
  
  // Violation SHOULD be detected only for iterations argument
  _ = try PKCS5.PBKDF1(password: randomArray, salt: randomArray, iterations: iterations, keyLength: 0) //$ITERATION$error
  _ = try PKCS5.PBKDF2(password: randomArray, salt: randomArray, iterations: iterations, keyLength: 0) //$ITERATION$error
}

func test_r5_multiple_values_violation() throws {
  let iterations = unknownCondition() ? getLowIterationCount() : getGoodIterationCount()
  let randomArray = getRandomArray()
    
  // Violation SHOULD be detected only for iterations argument
  _ = try PKCS5.PBKDF1(password: randomArray, salt: randomArray, iterations: iterations, keyLength: 0) //$ITERATION$error
}

func test_r5_simple_no_violation() throws {
  let iterations = getGoodIterationCount()
  let randomArray = getRandomArray()
  
  // Violation SHOULD NOT be detected
  _ = try PKCS5.PBKDF1(password: randomArray, salt: randomArray, iterations: iterations, keyLength: 0)
  _ = try PKCS5.PBKDF2(password: randomArray, salt: randomArray, iterations: iterations, keyLength: 0)
}

// *** RULE 7: CONSTANT PASSWORD ***

func test_r7_simple_violation() throws {
  let password = getConstantArray()
  let iterations = getGoodIterationCount()
  let randomArray = getRandomArray()

  // Violation SHOULD be detected only for password argument
  
  _ = try HKDF(password: password, salt: randomArray, info: randomArray, keyLength: 0, variant: HMAC.Variant.sha2(.sha256)) //$PASSWORD$error
  _ = try PKCS5.PBKDF1(password: password, salt: randomArray, iterations: iterations, keyLength: 0) //$PASSWORD$error
  _ = try PKCS5.PBKDF2(password: password, salt: randomArray, iterations: iterations, keyLength: 0) //$PASSWORD$error
  _ = try Scrypt(password: password, salt: randomArray, dkLen: 64, N: 16384, r: 8, p: 1) //$PASSWORD$error
}

func test_r7_from_string_violation() throws {
  let constantString = getConstantString()
  let password = constantString.bytes
  let randomArray = getRandomArray()

  // Violation SHOULD be detected only for password argument
  _ = try HKDF(password: password, salt: randomArray, info: randomArray, keyLength: 0, variant: HMAC.Variant.sha2(.sha256)) //$PASSWORD$error
}

func test_r7_from_string_md5_violation() throws {
  let constantString = getConstantString()
  let password = constantString.bytes.md5()
  let randomArray = getRandomArray()

  // Violation SHOULD be detected only for password argument
  _ = try HKDF(password: password, salt: randomArray, info: randomArray, keyLength: 0, variant: HMAC.Variant.sha2(.sha256)) //$PASSWORD$error
}

func test_r7_multiple_values_violation() throws {
  let constantString = getConstantString()
  let password = unknownCondition() ? constantString.bytes : getRandomArray()
  let randomArray = getRandomArray()

  // Violation SHOULD be detected only for password argument
  _ = try HKDF(password: password, salt: randomArray, info: randomArray, keyLength: 0, variant: HMAC.Variant.sha2(.sha256)) //$PASSWORD$error
}

func test_r7_simple_no_violation() throws {
  let password = getRandomArray()
  let iterations = getGoodIterationCount()
  let randomArray = getRandomArray()
  
  // Violation SHOULD NOT be detected
  _ = try HKDF(password: password, salt: randomArray, info: randomArray, keyLength: 0, variant: HMAC.Variant.sha2(.sha256))
  _ = try PKCS5.PBKDF1(password: password, salt: randomArray, iterations: iterations, keyLength: 0)
  _ = try PKCS5.PBKDF2(password: password, salt: randomArray, iterations: iterations, keyLength: 0)
  _ = try Scrypt(password: password, salt: randomArray, dkLen: 64, N: 16384, r: 8, p: 1)
}
