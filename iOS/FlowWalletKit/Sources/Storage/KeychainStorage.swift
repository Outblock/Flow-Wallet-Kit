//
//  File.swift
//
//
//  Created by Hao Fu on 22/7/2024.
//

import Foundation
import KeychainAccess

public class KeychainStorage: StorageProtocol {
    let service: String
    let label: String
    let synchronizable: Bool
    let accessGroup: String?
    var keychain: Keychain

    public init(service: String, label: String, synchronizable: Bool, accessGroup: String? = nil) {
        self.service = service
        self.label = label
        self.synchronizable = synchronizable
        self.accessGroup = accessGroup
        if let accessGroup {
            keychain = Keychain(service: service, accessGroup: accessGroup)
                .label(label)
                .accessibility(.afterFirstUnlock)
                .synchronizable(synchronizable)
        } else {
            keychain = Keychain(service: service)
                .label(label)
                .synchronizable(synchronizable)
                .accessibility(.afterFirstUnlock)
        }
    }

    public var allKeys: [String] {
        keychain.allKeys()
    }

    public func get(_ key: String) throws -> Data? {
        try keychain.getData(key)
    }

    public func remove(_ key: String) throws {
        try keychain.remove(key)
    }

    public func removeAll() throws {
        try keychain.removeAll()
    }

    public func set(_ key: String, value: Data) throws {
        try keychain.set(value, key: key, ignoringAttributeSynchronizable: !synchronizable)
    }
}
