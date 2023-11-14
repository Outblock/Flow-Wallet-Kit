//
//  WallectSecureEnclavePrivateKey.swift
//  FRW
//
//  Created by cat on 2023/11/7.
//

import CryptoKit
import Foundation

public extension WallectSecureEnclave {
    struct PrivateKey {
        public var privateKey: SecureEnclave.P256.Signing.PrivateKey?
        
        public var publicKey: P256.Signing.PublicKey? {
            return privateKey?.publicKey
        }
        
        public var publickeyValue: String? {
            return publicKey?.rawRepresentation.hexValue
        }
        
        public init(data: Data) throws {
            
            privateKey = try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: data)
        }
        
        public init() throws {
            privateKey = try PrivateKey.generate()
        }
        
        public static func generate() throws -> SecureEnclave.P256.Signing.PrivateKey {
            return try SecureEnclave.P256.Signing.PrivateKey()
        }
    }
}
