//
//  File.swift
//  
//
//  Created by Hao Fu on 18/7/2024.
//

import Foundation
import Flow

public protocol ProxyProtocol {
    associatedtype Wallet
    
    static func get(id: String) throws -> Wallet
    
    func store(id: String, password: String, sync: Bool) throws
    func isValidSignature(signature: Data, message: Data, signAlgo: Flow.SignatureAlgorithm) -> Bool
    func publicKey(signAlgo: Flow.SignatureAlgorithm) throws -> Data
    func sign(data: Data, signAlgo: Flow.SignatureAlgorithm, hashAlgo: Flow.HashAlgorithm) throws -> Data
    func remove(id: String) throws
}

class FlowAccount {
    enum `Type` {
        case key(any WalletProtocol)
        case proxy(any ProxyProtocol)
        case watch(Flow.Address)
    }
}
