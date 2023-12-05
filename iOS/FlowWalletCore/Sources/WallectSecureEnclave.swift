//
//  SecureEnclave.swift
//  FRW
//
//  Created by cat on 2023/11/6.
//

import CryptoKit
import Foundation
import Flow

public enum SignError: Error, LocalizedError {
    case unknown
    case privateKeyEmpty
    case emptyContent
    
    public var errorDescription: String? {
        switch self {
        case .privateKeyEmpty:
                return "[Sign] private key is empty,check `init(privateKey:)`"
        
        default:
            return "[Sign] There was an error. Please try again."
        }
    }
}

public struct WallectSecureEnclave {
    public let key: WallectSecureEnclave.PrivateKey
    
    public init(privateKey data: Data) throws {
        do {
            key = try PrivateKey(data: data)
        }catch {
            debugPrint("[Wallet Core] init private key failed")
            throw error
        }
        
    }
    
    public init() throws {
        key = try PrivateKey()
    }
    
    public func sign(data: Data) throws -> Data {
        guard let privateKey = key.privateKey else {
            throw SignError.privateKeyEmpty
        }
        do {
            let hashed = SHA256.hash(data: data)
            return try privateKey.signature(for: hashed).rawRepresentation
        } catch {
            debugPrint(error)
            throw error
        }
    }
    
    public func sign(text: String) throws -> String {
        guard let textData = text.data(using: .utf8) else {
            throw SignError.emptyContent
        }
        return try sign(data: textData).hexValue
    }
}

extension WallectSecureEnclave {
    public enum SignAlgo {
        case P256
    }
    
    public func accountKey(sign: SignAlgo = .P256) throws -> Flow.AccountKey {
        guard let publickeyValue = key.publickeyValue else {
            print(" generate private key empty")
            throw SignError.privateKeyEmpty
        }
        switch sign {
        case .P256:
            return try accountKeyForP256(publicKeyValue: publickeyValue)
        }
    }
    
    func accountKeyForP256(publicKeyValue: String) throws -> Flow.AccountKey {
        let publicKey = Flow.PublicKey(hex: publicKeyValue)
        let key = Flow.AccountKey(publicKey: publicKey, signAlgo: .ECDSA_P256, hashAlgo: .SHA2_256, weight: 1000)
        return key
    }
    
}

extension Data {
    public func signUserMessage() -> Data {
        return Flow.DomainTag.user.normalize + self
    }
}

extension String {
    public func AddUserMessage() -> Data? {
        guard let textData = self.data(using: .utf8) else {
            return nil
        }
        return Flow.DomainTag.user.normalize + textData
    }
}
