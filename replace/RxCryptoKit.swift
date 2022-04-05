import UIKit
import BFKit.Swift
import HandyJSON.Swift
import CryptoSwift.Swift

fileprivate let RxCryptoKey = ("app"+".guan_ce_sen").md5()
/// 加密管理库
public struct RxCryptoKit {
    
    /// AES-128-ECB加密模式
    public static func aesEncrypt(str: String) -> String? {
        do {
            let aes = try AES(key: Padding.zeroPadding.add(to: RxCryptoKey.bytes, blockSize: 128), blockMode: ECB()) //$ECB$error
            let encrypted = try aes.encrypt(str.bytes)
            return encrypted.toBase64()
        } catch let error {
            BFLog.debug("error: \(error.localizedDescription)")
        }
        return nil
    }
    /// AES-128-ECB解密模式
    public static func aesDecrypt(data: Data) -> String? {
        do {
            let aes = try AES(key: Padding.zeroPadding.add(to: RxCryptoKey.bytes, blockSize: 128), blockMode: ECB()) //$ECB$error
            let decrypted = try data.decrypt(cipher: aes)
            return try decrypted.json()
        } catch let error {
            BFLog.debug("error: \(error.localizedDescription)")
        }
        return nil
    }
    /// AES-128-ECB解密模式
    public static func aesDecrypt(str: String) -> String? {
        do {
            let aes = try AES(key: Padding.zeroPadding.add(to: RxCryptoKey.bytes, blockSize: 128), blockMode: ECB()) //$ECB$error
            let decrypted = try str.decryptBase64ToString(cipher: aes)
            return decrypted
        } catch let error {
            BFLog.debug("error: \(error.localizedDescription)")
        }
        return nil
    }
}
