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

    func store(id: String, password: String, sync: Bool) throws
    func isValidSignature(signature: Data, message: Data, signAlgo: Flow.SignatureAlgorithm) -> Bool
    func publicKey(signAlgo: Flow.SignatureAlgorithm) throws -> Data
    func sign(data: Data, signAlgo: Flow.SignatureAlgorithm, hashAlgo: Flow.HashAlgorithm) throws -> Data
    func remove(id: String) throws
}

enum FlowAccountType {
    case key(any KeyProtocol)
    case proxy(any ProxyProtocol)
    case watch(Flow.Address)
    case child(Flow.Address)
    case vm(FlowVM)
}

@MainActor
public class FlowAccount {
    var childs: [FlowAccount]?

    var hasChild: Bool {
        !(childs?.isEmpty ?? true)
    }

    var vm: [FlowAccount]?

    var hasVM: Bool {
        !(vm?.isEmpty ?? true)
    }
    
    public let key: any KeyProtocol
    public var networks: Set<Flow.ChainID>
    public var accounts: [Flow.ChainID: [Flow.Account]]? = nil
    
    init(key: any KeyProtocol, networks: Set<Flow.ChainID> = [.mainnet, .testnet]) {
        self.key = key
        self.networks = networks
    }
    
    func addNetwork(_ network: Flow.ChainID) {
        networks.insert(network)
    }
    
    func fetchAllNetworkAccounts() async throws -> [Flow.ChainID: [Flow.Account]] {
        var networkAccounts =  [Flow.ChainID: [Flow.Account]]()
        // TODO: Improve this to parallel fetch
        for network in networks {
            guard let accounts = try? await account(chainID: network) else {
                continue
            }
            networkAccounts[network] = accounts
        }
        accounts = networkAccounts
        return networkAccounts
    }
    
    func account(chainID: Flow.ChainID) async throws -> [Flow.Account] {
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

    func fetchAccounts(addresses: [Flow.Address]) async throws -> [Flow.Account] {
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
}
