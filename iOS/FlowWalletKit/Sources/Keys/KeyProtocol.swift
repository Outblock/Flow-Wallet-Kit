//
//  File.swift
//
//
//  Created by Hao Fu on 16/1/2024.
//

import Flow
import Foundation
import KeychainAccess

public enum KeyType {
    case secureEnclave
    case seedPhrase
    case privateKey
    case keyStore
}

public protocol KeyProtocol {
    associatedtype Key
    associatedtype Secret
    associatedtype Advance

    var keyType: KeyType { get }

    var storage: StorageProtocol { set get }

    static func create(_ advance: Advance, storage: StorageProtocol) throws -> Key
    static func create(storage: StorageProtocol) throws -> Key
    static func createAndStore(id: String, password: String, storage: StorageProtocol) throws -> Key
    static func get(id: String, password: String, storage: StorageProtocol) throws -> Key
    static func restore(secret: Secret, storage: StorageProtocol) throws -> Key

    func store(id: String, password: String) throws
    func isValidSignature(signature: Data, message: Data, signAlgo: Flow.SignatureAlgorithm) -> Bool
    func publicKey(signAlgo: Flow.SignatureAlgorithm) throws -> Data?
    func sign(data: Data, signAlgo: Flow.SignatureAlgorithm, hashAlgo: Flow.HashAlgorithm) throws -> Data
    func remove(id: String) throws

    func allKeys() -> [String]
}

public extension KeyProtocol {
    var storage: StorageProtocol {
        FWKManager.shared.storage
    }

    func remove(id: String) throws {
        try storage.remove(id)
    }

    func allKeys() -> [String] {
        storage.allKeys
    }

    static func create(_: Advance, storage _: any StorageProtocol) throws -> Key {
        throw WalletError.noImplement
    }
}
