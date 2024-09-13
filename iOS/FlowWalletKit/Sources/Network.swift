//
//  File.swift
//
//
//  Created by Hao Fu on 27/8/2024.
//

import Flow
import Foundation

public struct KeyIndexerResponse: Codable {
    let publicKey: String
    let accounts: [Account]

    public struct Account: Codable, Hashable {
        public let address: String
        public let keyId: Int
        public let weight: Int
    }
}

public enum Network {
    public static func findAccountByKey(publicKey: String, chainID: Flow.ChainID) async throws -> [KeyIndexerResponse.Account] {
        guard let host = chainID.keyIndexer?.absoluteString, let url = URL(string: host + publicKey) else {
            throw WalletError.incorrectKeyIndexerURL
        }
        let urlRequest = URLRequest(url: url)
        let (data, response) = try await URLSession.shared.data(for: urlRequest)

        guard (response as? HTTPURLResponse)?.statusCode == 200 else {
            throw WalletError.keyIndexerRequestFailed
        }

        let decodedModel = try JSONDecoder().decode(KeyIndexerResponse.self, from: data)
        return decodedModel.accounts
    }
}
