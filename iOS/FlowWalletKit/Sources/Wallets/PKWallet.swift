//
//  File.swift
//  
//
//  Created by Hao Fu on 16/1/2024.
//

import CryptoKit
import Foundation
import Flow
import KeychainAccess
import WalletCore

public class PKWallet: WalletProtocol {
    let pk: PrivateKey
    
    init(pk: PrivateKey) {
        self.pk = pk
    }
    
    public static func create() throws -> PKWallet {
        let pk = PrivateKey()
        return PKWallet(pk: pk)
    }
    
    public static func create(id: String, password: String, sync: Bool) throws -> PKWallet {
        let pk = PrivateKey()
        guard let cipher = ChaChaPolyCipher(key: password) else {
            throw WalletError.initChaChapolyFailed
        }
        
        let encrypted = try cipher.encrypt(data: pk.data)
        try keychain.set(encrypted, key: id, ignoringAttributeSynchronizable: !sync)
        return PKWallet(pk: pk)
    }
    
    public static func get(id: String, password: String) throws -> PKWallet {
        guard let data = try keychain.getData(id) else {
            throw WalletError.emptyKeychain
        }
        
        guard let cipher = ChaChaPolyCipher(key: password) else {
            throw WalletError.initChaChapolyFailed
        }
        
        let pkData = try cipher.decrypt(combinedData: data)
        
        guard let pk = PrivateKey(data: pkData) else {
            throw WalletError.initPrivateKeyFailed
        }
        
        return PKWallet(pk: pk)
    }
    
    public static func restore(secret: Data) throws -> PKWallet {
        guard let pk = PrivateKey(data: secret) else {
            throw WalletError.restoreWalletFailed
        }
        return PKWallet(pk: pk)
    }
    
    public static func restore(json: String, password: String) throws -> PKWallet {
        guard let jsonData = json.data(using: .utf8), let passwordData = password.data(using: .utf8) else {
            throw WalletError.restoreWalletFailed
        }
        
        let storedKey = StoredKey.importJSON(json: jsonData)
        
        guard let pkData = storedKey?.decryptPrivateKey(password: passwordData) else {
            throw WalletError.invaildKeyStorePassword
        }
        
        guard let pk = PrivateKey(data: pkData) else {
            throw WalletError.restoreWalletFailed
        }
        return PKWallet(pk: pk)
    }
    
    public func store(id: String, password: String, sync: Bool) throws {
        guard let cipher = ChaChaPolyCipher(key: password) else {
            throw WalletError.initChaChapolyFailed
        }
        
        let encrypted = try cipher.encrypt(data: pk.data)
        try keychain.set(encrypted, key: id, ignoringAttributeSynchronizable: !sync)
    }
    
    public func isValidSignature(signature: Data, message: Data, signAlgo: Flow.SignatureAlgorithm) -> Bool {
        guard let pubK = try? getPublicKey(signAlgo: signAlgo) else {
            return false
        }
        return pubK.verify(signature: signature, message: message)
    }
    
    public func publicKey(signAlgo: Flow.SignatureAlgorithm) throws -> Data {
        let pubK = try getPublicKey(signAlgo: signAlgo)
        return pubK.uncompressed.data.dropFirst()
    }
    
    public func sign(data: Data, signAlgo: Flow.SignatureAlgorithm, hashAlgo: Flow.HashAlgorithm) throws -> Data {
        let hashed = try hashAlgo.hash(data: data)
        guard let curve = signAlgo.WCCurve else {
            throw WalletError.unsupportSignatureAlgorithm
        }
        guard let signature = pk.sign(digest: hashed, curve: curve) else {
            throw WalletError.signError
        }
        
        return signature.dropLast()
    }
    
    private func getPublicKey(signAlgo: Flow.SignatureAlgorithm) throws -> PublicKey {
        switch signAlgo {
        case .ECDSA_P256:
            return pk.getPublicKeyNist256p1()
        case .ECDSA_SECP256k1:
            return pk.getPublicKeySecp256k1(compressed: false)
        case .unknown:
            throw WalletError.unsupportSignatureAlgorithm
        }
    }
}
