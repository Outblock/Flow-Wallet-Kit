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

public class SPWallet: WalletProtocol {
    static let derivationPath = "m/44'/539'/0'/0/0"
    static let strength: Int32 = 128
    static let passphrase: String = ""
    
    let hdWallet: HDWallet
    
    init(hdWallet: HDWallet) {
        self.hdWallet = hdWallet
    }
    
    public static func create() throws -> SPWallet {
        guard let hdWallet = HDWallet(strength: SPWallet.strength, passphrase: "") else {
            throw WalletError.initHDWalletFailed
        }
        return SPWallet(hdWallet: hdWallet)
    }
    
    public static func create(id: String, password: String, sync: Bool = true) throws -> SPWallet {
        guard let hdWallet = HDWallet(strength: SPWallet.strength, passphrase: "") else {
            throw WalletError.initHDWalletFailed
        }
        
        guard let cipher = ChaChaPolyCipher(key: password) else {
            throw WalletError.initChaChapolyFailed
        }
        
        let encrypted = try cipher.encrypt(data: hdWallet.entropy)
        try keychain.set(encrypted, key: id, ignoringAttributeSynchronizable: !sync)
        return SPWallet(hdWallet: hdWallet)
    }
    
    public static func get(id: String, password: String) throws -> SPWallet {
        guard let data = try keychain.getData(id) else {
            throw WalletError.emptyKeychain
        }
        
        guard let cipher = ChaChaPolyCipher(key: password) else {
            throw WalletError.initChaChapolyFailed
        }
        
        let entropy = try cipher.decrypt(combinedData: data)
        guard let hdWallet = HDWallet(entropy: entropy, passphrase: "") else {
            throw WalletError.initHDWalletFailed
        }
        return SPWallet(hdWallet: hdWallet)
    }
    
    public func isValidSignature(signature: Data, message: Data, signAlgo: Flow.SignatureAlgorithm) -> Bool {
        guard let pubK = try? getPublicKey(signAlgo: signAlgo) else {
            return false
        }
        return pubK.verify(signature: signature, message: message)
    }
    
    public func store(id: String, password: String, sync: Bool) throws {
        guard let cipher = ChaChaPolyCipher(key: password) else {
            throw WalletError.initChaChapolyFailed
        }
        
        let encrypted = try cipher.encrypt(data: hdWallet.entropy)
        try keychain.set(encrypted, key: id, ignoringAttributeSynchronizable: !sync)
    }
    
    public static func restore(secret: String) throws -> SPWallet {
        guard let wallet = HDWallet(mnemonic: secret, passphrase: SPWallet.passphrase) else {
            throw WalletError.restoreWalletFailed
        }
        return SPWallet(hdWallet: wallet)
    }
    
    public func publicKey(signAlgo: Flow.SignatureAlgorithm) throws -> Data {
        let pubK = try getPublicKey(signAlgo: signAlgo)
        return pubK.uncompressed.data.dropFirst()
    }
    
    public func sign(data: Data, signAlgo: Flow.SignatureAlgorithm, hashAlgo: Flow.HashAlgorithm) throws -> Data {
        let hashed = try hashAlgo.hash(data: data)
        
        guard let curve = signAlgo.HDCurve else {
            throw WalletError.unsupportSignatureAlgorithm
        }
    
        var pk = hdWallet.getKeyByCurve(curve: curve, derivationPath: SPWallet.derivationPath)
        defer { pk = PrivateKey() }
        guard let signature = pk.sign(digest: hashed, curve: curve) else {
            throw WalletError.signError
        }
        return signature.dropLast()
    }
    
    private func getPublicKey(signAlgo: Flow.SignatureAlgorithm) throws -> PublicKey {
        switch signAlgo {
        case .ECDSA_P256:
            var pk = hdWallet.getKeyByCurve(curve: .nist256p1, derivationPath: SPWallet.derivationPath)
            defer { pk = PrivateKey() }
            return pk.getPublicKeyNist256p1()
        case .ECDSA_SECP256k1:
            var pk = hdWallet.getKeyByCurve(curve: .secp256k1, derivationPath: SPWallet.derivationPath)
            defer { pk = PrivateKey() }
            return pk.getPublicKeySecp256k1(compressed: false)
        case .unknown:
            throw WalletError.unsupportSignatureAlgorithm
        }
    }
}
