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
    public var storage: any StorageProtocol
    public var walletType: WalletType = .seedPhrase
    static let derivationPath = "m/44'/539'/0'/0/0"
    static let seedPhraseLength: BIP39.SeedPhraseLength = .twelve
    static let passphrase: String = ""
    
    let hdWallet: HDWallet
    
    init(hdWallet: HDWallet, storage: any StorageProtocol) {
        self.hdWallet = hdWallet
        self.storage = storage
    }
    
    public static func create(storage: any StorageProtocol) throws -> SPWallet {
        guard let hdWallet = HDWallet(strength: SPWallet.seedPhraseLength.strength, passphrase: "") else {
            throw WalletError.initHDWalletFailed
        }
        return SPWallet(hdWallet: hdWallet, storage: storage)
    }
    
    public static func create(id: String, password: String, storage: any StorageProtocol) throws -> SPWallet {
        guard let hdWallet = HDWallet(strength: SPWallet.seedPhraseLength.strength, passphrase: "") else {
            throw WalletError.initHDWalletFailed
        }
        
        guard let cipher = ChaChaPolyCipher(key: password) else {
            throw WalletError.initChaChapolyFailed
        }
        
        let encrypted = try cipher.encrypt(data: hdWallet.entropy)
        try storage.set(id, value: encrypted)
        return SPWallet(hdWallet: hdWallet, storage: storage)
    }
    
    public static func get(id: String, password: String, storage: any StorageProtocol) throws -> SPWallet {
        guard let data = try storage.get(id) else {
            throw WalletError.emptyKeychain
        }
        
        guard let cipher = ChaChaPolyCipher(key: password) else {
            throw WalletError.initChaChapolyFailed
        }
        
        let entropy = try cipher.decrypt(combinedData: data)
        guard let hdWallet = HDWallet(entropy: entropy, passphrase: "") else {
            throw WalletError.initHDWalletFailed
        }
        return SPWallet(hdWallet: hdWallet, storage: storage)
    }
    
    public func isValidSignature(signature: Data, message: Data, signAlgo: Flow.SignatureAlgorithm) -> Bool {
        guard let pubK = try? getPublicKey(signAlgo: signAlgo) else {
            return false
        }
        return pubK.verify(signature: signature, message: message)
    }
    
    public func store(id: String, password: String) throws {
        guard let cipher = ChaChaPolyCipher(key: password) else {
            throw WalletError.initChaChapolyFailed
        }
        
        let encrypted = try cipher.encrypt(data: hdWallet.entropy)
        try storage.set(id, value: encrypted)
    }
    
    public static func restore(secret: String, storage: any StorageProtocol) throws -> SPWallet {
        guard let wallet = HDWallet(mnemonic: secret, passphrase: SPWallet.passphrase) else {
            throw WalletError.restoreWalletFailed
        }
        return SPWallet(hdWallet: wallet, storage: storage)
    }
    
    public func publicKey(signAlgo: Flow.SignatureAlgorithm) throws -> Data? {
        let pubK = try getPublicKey(signAlgo: signAlgo)
        return pubK.uncompressed.data.dropFirst()
    }
    
    public func sign(data: Data, signAlgo: Flow.SignatureAlgorithm, hashAlgo: Flow.HashAlgorithm) throws -> Data {
        let hashed = try hashAlgo.hash(data: data)
        
        guard let curve = signAlgo.WCCurve else {
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
