//
//  File.swift
//
//
//  Created by Hao Fu on 18/7/2024.
//

import Flow
import Foundation

public protocol ProxyProtocol {
    associatedtype Wallet

    static func get(id: String) throws -> Wallet
    func sign(data: Data, signAlgo: Flow.SignatureAlgorithm, hashAlgo: Flow.HashAlgorithm) throws -> Data
}

@MainActor
public class Account {
    var childs: [Account]?

    var hasChild: Bool {
        !(childs?.isEmpty ?? true)
    }

    var vm: [Account]?

    var hasVM: Bool {
        !(vm?.isEmpty ?? true)
    }

    var canSign: Bool {
        !(key == nil)
    }

    let account: Flow.Account
    let key: (any KeyProtocol)?

    init(account: Flow.Account, key: (any KeyProtocol)?) {
        self.account = account
        self.key = key
    }

    func findKeyInAccount() -> [Flow.AccountKey]? {
        guard let key else {
            return nil
        }

        do {
            var keys: [Flow.AccountKey] = []
            if let p256 = try key.publicKey(signAlgo: .ECDSA_P256) {
                let p256Keys = account.keys.filter { $0.weight > 1000 }.filter { $0.publicKey.data == p256 }
                keys += p256Keys
            }

            if let secpKey = try key.publicKey(signAlgo: .ECDSA_SECP256k1) {
                let secpKeys = account.keys.filter { $0.weight > 1000 }.filter { $0.publicKey.data == secpKey }
                keys += secpKeys
            }

            return keys

        } catch {
            // TODO: Add error handling
            return nil
        }
    }

    func fetchChild() {
        // TODO:
    }

    func fetchVM() {
        // TODO:
    }
}

extension Account: FlowSigner {
    public var address: Flow.Address {
        account.address
    }

    public var keyIndex: Int {
        findKeyInAccount()?.first?.index ?? 0
    }

    public func sign(transaction _: Flow.Transaction, signableData: Data) async throws -> Data {
        guard let key, let signKey = findKeyInAccount()?.first else {
            throw WalletError.emptySignKey
        }

        return try key.sign(data: signableData, signAlgo: signKey.signAlgo, hashAlgo: signKey.hashAlgo)
    }
}
