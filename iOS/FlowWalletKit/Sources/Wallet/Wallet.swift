//
//  File.swift
//
//
//  Created by Hao Fu on 12/9/2024.
//

import Flow
import Foundation

public enum WalletType {
    case key(any KeyProtocol)
//    case proxy(any ProxyProtocol)
    case watch(Flow.Address)

    var idPrefix: String {
        switch self {
        case .key:
            return "Key"
        case .watch:
            return "Watch"
        }
    }

    var id: String {
        switch self {
        case let .key(key):
            return [idPrefix, key.id].joined(separator: "/")
        case let .watch(address):
            return [idPrefix, address.hex].joined(separator: "/")
        }
    }

    var key: (any KeyProtocol)? {
        switch self {
        case let .key(key):
            return key
        default:
            return nil
        }
    }
}

@MainActor
public class Wallet: ObservableObject {
    static let cachePrefix: String = "Accounts"
    public let type: WalletType
    public var networks: Set<Flow.ChainID>

    @Published
    public var accounts: [Flow.ChainID: [Account]]? = nil

    var flowAccounts: [Flow.ChainID: [Flow.Account]]?

    var cacheId: String {
        [Wallet.cachePrefix, type.id].joined(separator: "/")
    }

    init(type: WalletType, networks: Set<Flow.ChainID> = [.mainnet, .testnet]) {
        self.type = type
        self.networks = networks
        fetchAccount()
    }

    public func fetchAccount() {
        Task {
            do {
                try loadCahe()
                try await _ = fetchAllNetworkAccounts()
                try cache()
            } catch {
                // TODO: Handle Error
            }
        }
    }

    public func addNetwork(_ network: Flow.ChainID) {
        networks.insert(network)
    }

    public func fetchAllNetworkAccounts() async throws -> [Flow.ChainID: [Account]] {
        var flowAccounts = [Flow.ChainID: [Flow.Account]]()
        var networkAccounts = [Flow.ChainID: [Account]]()
        // TODO: Improve this to parallel fetch
        for network in networks {
            guard let accounts = try? await account(chainID: network) else {
                continue
            }
            flowAccounts[network] = accounts
            networkAccounts[network] = accounts.compactMap { Account(account: $0, key: type.key) }
        }
        accounts = networkAccounts
        self.flowAccounts = flowAccounts
        return networkAccounts
    }

    public func account(chainID: Flow.ChainID) async throws -> [Flow.Account] {
        guard case let .key(key) = type else {
            if case let .watch(address) = type {
                return [try await flow.getAccountAtLatestBlock(address: address)]
            }
            throw WalletError.invaildWalletType
        }

        var accounts: [Flow.Account] = []
        if let p256Key = try key.publicKey(signAlgo: .ECDSA_P256)?.hexString {
            async let p256KeyRequest = Network.findFlowAccountByKey(publicKey: p256Key, chainID: chainID)
            try await accounts += p256KeyRequest
        }

        if let secp256k1Key = try key.publicKey(signAlgo: .ECDSA_SECP256k1)?.hexString {
            async let secp256k1KeyRequest = Network.findFlowAccountByKey(publicKey: secp256k1Key, chainID: chainID)
            try await accounts += secp256k1KeyRequest
        }

        return accounts
    }

    public func fullAccount(chainID: Flow.ChainID) async throws -> [Flow.Account] {
        guard case let .key(key) = type else {
            if case let .watch(address) = type {
                return [try await flow.getAccountAtLatestBlock(address: address)]
            }
            throw WalletError.invaildWalletType
        }

        var accounts: [KeyIndexerResponse.Account] = []
        if let p256Key = try key.publicKey(signAlgo: .ECDSA_P256)?.hexString {
            async let p256KeyRequest = Network.findAccountByKey(publicKey: p256Key, chainID: chainID)
            try await accounts += p256KeyRequest
        }

        if let secp256k1Key = try key.publicKey(signAlgo: .ECDSA_SECP256k1)?.hexString {
            async let secp256k1KeyRequest = Network.findAccountByKey(publicKey: secp256k1Key, chainID: chainID)
            try await accounts += secp256k1KeyRequest
        }

        let addresses = Set(accounts).compactMap { Flow.Address(hex: $0.address) }
        return try await fetchAccounts(addresses: addresses)
    }

    public func fetchAccounts(addresses: [Flow.Address]) async throws -> [Flow.Account] {
        try await withThrowingTaskGroup(of: Flow.Account.self) { group in

            addresses.forEach { address in
                group.addTask { try await Flow.shared.accessAPI.getAccountAtLatestBlock(address: address) }
            }

            var result = [Flow.Account]()

            for try await image in group {
                result.append(image)
            }

            return result
        }
    }

    // MARK: - Cache

    public func cache() throws {
        // TODO: Handle other type
        guard let flowAccounts, case let .key(key) = type else {
            return
        }

        let data = try JSONEncoder().encode(flowAccounts)
        try key.storage.set(cacheId, value: data)
    }

    public func loadCahe() throws {
        // TODO: Handle other type
        guard case let .key(key) = type, let data = try key.storage.get(cacheId) else {
            throw WalletError.loadCacheFailed
        }
        let model = try JSONDecoder().decode([Flow.ChainID: [Flow.Account]].self, from: data)
        flowAccounts = model

        accounts = [Flow.ChainID: [Account]]()
        for network in model.keys {
            if let acc = model[network] {
                accounts?[network] = acc.compactMap { Account(account: $0, key: type.key) }
            }
        }
    }
}
