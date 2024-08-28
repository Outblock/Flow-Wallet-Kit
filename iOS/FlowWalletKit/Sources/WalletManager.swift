// The Swift Programming Language
// https://docs.swift.org/swift-book

import Flow
import KeychainAccess
import WalletCore

public class FWKManager {
    static let shared = FWKManager()
    private static var config: Config?

    public let storage: any StorageProtocol

    public class func setup(_ config: Config) {
        FWKManager.config = config
    }

    private init() {
        guard let config = FWKManager.config else {
            fatalError("Error - you must call setup before accessing FlowWalletKit.shared")
        }
        storage = config.storage
    }
}

public extension FWKManager {
    struct Config {
        let storage: any StorageProtocol
    }
}
