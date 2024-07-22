//
//  File.swift
//  
//
//  Created by Hao Fu on 16/1/2024.
//

import Foundation
import Flow
import KeychainAccess

public protocol WalletProtocol {
    associatedtype Wallet
    associatedtype Secret
    
    var storage: StorageProtocol { get }
    
    static func create() throws -> Wallet
    static func create(id: String, password: String, sync: Bool) throws -> Wallet
    static func get(id: String, password: String) throws -> Wallet
    static func restore(secret: Secret) throws -> Wallet
    
    func store(id: String, password: String, sync: Bool) throws
    func isValidSignature(signature: Data, message: Data, signAlgo: Flow.SignatureAlgorithm) -> Bool
    func publicKey(signAlgo: Flow.SignatureAlgorithm) throws -> Data
    func sign(data: Data, signAlgo: Flow.SignatureAlgorithm, hashAlgo: Flow.HashAlgorithm) throws -> Data
    func remove(id: String) throws
    
    func allKeys() -> [String]
}


extension WalletProtocol {
    public var storage: StorageProtocol {
        FlowWalletKit.shared.storage
    }
    
    public func remove(id: String) throws {
        try storage.remove(id)
    }
    
    public func allKeys() -> [String] {
        storage.allKeys
    }
    
}
