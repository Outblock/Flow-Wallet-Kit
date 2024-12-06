//
//  File.swift
//
//
//  Created by Hao Fu on 27/8/2024.
//

import Flow
import Foundation

public struct KeyIndexerResponse: Codable {
    public let publicKey: String
    public let accounts: [Account]

    public struct Account: Codable, Hashable {
        public let address: String
        public let keyId: Int
        public let weight: Int
        public let sigAlgo: Int
        public let hashAlgo: Int
        public let signing: Flow.SignatureAlgorithm
        public let hashing: Flow.HashAlgorithm
    }
}

extension KeyIndexerResponse {
    var accountResponse: [Flow.Account] {
        var response: [Flow.Account] = []
        for account in accounts {
            let index = response.firstIndex { a in
                a.address.hex == account.address
            }
            if let index {
                response[index].keys.append(
                    .init(index: account.keyId,
                          publicKey: .init(hex: publicKey),
                          signAlgo: account.signing,
                          hashAlgo: account.hashing,
                          weight: account.weight)
                )

            } else {
                response.append(
                    Flow.Account(address: Flow.Address(hex: account.address),
                                 keys: [Flow.AccountKey(
                                     index: account.keyId,
                                     publicKey: .init(hex: publicKey),
                                     signAlgo: account.signing,
                                     hashAlgo: account.hashing,
                                     weight: account.weight
                                 )])
                )
            }
        }

        return response
    }
}

public enum Network {
    public static func findAccount(publicKey: String, chainID: Flow.ChainID) async throws -> KeyIndexerResponse {
        guard let url = chainID.keyIndexer(with: publicKey) else {
            throw WalletError.incorrectKeyIndexerURL
        }
        let urlRequest = URLRequest(url: url)
        let (data, response) = try await URLSession.shared.data(for: urlRequest)

        guard (response as? HTTPURLResponse)?.statusCode == 200 else {
            throw WalletError.keyIndexerRequestFailed
        }

        return try JSONDecoder().decode(KeyIndexerResponse.self, from: data)
    }

    public static func findAccountByKey(publicKey: String, chainID: Flow.ChainID) async throws -> [KeyIndexerResponse.Account] {
        let model = try await findAccount(publicKey: publicKey, chainID: chainID)
        return model.accounts
    }

    public static func findFlowAccountByKey(publicKey: String, chainID: Flow.ChainID) async throws -> [Flow.Account] {
        let model = try await findAccount(publicKey: publicKey, chainID: chainID)
        return model.accountResponse
    }
}
