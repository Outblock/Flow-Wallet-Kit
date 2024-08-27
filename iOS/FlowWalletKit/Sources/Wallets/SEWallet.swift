//
//  SecureEnclave.swift
//  FRW
//
//  Created by cat on 2023/11/6.
//

import CryptoKit
import Foundation
import Flow
import KeychainAccess
import WalletCore

public class SEWallet: WalletProtocol {
    public var walletType: WalletType = .secureEnclave
    public let key: SecureEnclave.P256.Signing.PrivateKey
    
    public init(key: SecureEnclave.P256.Signing.PrivateKey) {
        self.key = key
    }
    
    public static func create() throws -> SEWallet {
        let key = try SecureEnclave.P256.Signing.PrivateKey()
        return SEWallet(key: key)
    }
    
    public static func create(id: String, password: String, sync: Bool = false) throws -> SEWallet {
        guard let cipher = ChaChaPolyCipher(key: password) else {
            throw WalletError.initChaChapolyFailed
        }
        let key = try SecureEnclave.P256.Signing.PrivateKey()
        let encrypted = try cipher.encrypt(data: key.dataRepresentation)
        try FlowWalletKit.shared.storage.set(id, value: encrypted)
        return SEWallet(key: key)
    }
    
    public static func get(id: String, password: String) throws -> SEWallet {
        guard let data = try FlowWalletKit.shared.storage.get(id) else {
            throw WalletError.emptyKeychain
        }
        
        guard let cipher = ChaChaPolyCipher(key: password) else {
            throw WalletError.initChaChapolyFailed
        }
        
        let pk = try cipher.decrypt(combinedData: data)
        let key = try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: pk)
        return SEWallet(key: key)
    }
    
    public static func restore(secret: Data) throws -> SEWallet {
        let key = try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: secret)
        return SEWallet(key: key)
    }
    
    public func store(id: String, password: String, sync: Bool) throws {
        guard let cipher = ChaChaPolyCipher(key: password) else {
            throw WalletError.initChaChapolyFailed
        }
        let encrypted = try cipher.encrypt(data: key.dataRepresentation)
        try FlowWalletKit.shared.storage.set(id, value: encrypted)
    }
    
    public func publicKey(signAlgo: Flow.SignatureAlgorithm = .ECDSA_P256) throws -> Data? {
        if signAlgo != .ECDSA_P256 {
            return nil
        }
        return key.publicKey.rawRepresentation
    }
    
    public func isValidSignature(signature: Data, message: Data, signAlgo: Flow.SignatureAlgorithm = .ECDSA_P256) -> Bool {
        if signAlgo != .ECDSA_P256 {
            return false
        }
        guard let result = try? key.publicKey.isValidSignature(.init(rawRepresentation: signature), for: message) else {
            return false
        }
        return result
    }
    
    public func sign(data: Data, 
                     signAlgo: Flow.SignatureAlgorithm = .ECDSA_P256,
                     hashAlgo: Flow.HashAlgorithm) throws -> Data {
        let hashed = try hashAlgo.hash(data: data)
        return try key.signature(for: hashed).rawRepresentation
    }
    
    public func rawSign(data: Data, signAlgo: Flow.SignatureAlgorithm = .ECDSA_P256) throws -> Data {
        return try key.signature(for: data).rawRepresentation
    }
}
