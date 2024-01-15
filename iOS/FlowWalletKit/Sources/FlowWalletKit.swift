// The Swift Programming Language
// https://docs.swift.org/swift-book

import WalletCore
import Flow
import KeychainAccess

let keychain = Keychain()
    .label("Flow Wallet Kit")
    .synchronizable(true)

class FlowWalletKit {
    enum WalletType {
        case secureEnclave
        case seedPhrase
        case privateKey
        case keyStore
    }
}
