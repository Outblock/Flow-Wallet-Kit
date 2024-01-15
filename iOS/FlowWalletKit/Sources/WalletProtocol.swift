//
//  File.swift
//  
//
//  Created by Hao Fu on 16/1/2024.
//

import Foundation
import Flow

public protocol WalletProtocol {
    associatedtype Wallet
    associatedtype Secret
    static func create() throws -> Wallet
    static func create(id: String, password: String, sync: Bool) throws -> Wallet
    static func get(id: String, password: String) throws -> Wallet
    static func restore(secret: Secret) throws -> Wallet
    
    func store(id: String, password: String, sync: Bool) throws
    func isValidSignature(signature: Data, message: Data, signAlgo: Flow.SignatureAlgorithm) -> Bool
    func publicKey(signAlgo: Flow.SignatureAlgorithm) throws -> Data
    func sign(data: Data, signAlgo: Flow.SignatureAlgorithm, hashAlgo: Flow.HashAlgorithm) throws -> Data
}
