//
//  File.swift
//
//
//  Created by Hao Fu on 16/1/2024.
//

import Flow
import Foundation

public enum WalletError: String, Error, CaseIterable, CustomStringConvertible {
    case noImplement
    case emptyKeychain
    case emptyKey
    case emptySignKey
    case unsupportHashAlgorithm
    case unsupportSignatureAlgorithm
    case initChaChapolyFailed
    case initHDWalletFailed
    case initPrivateKeyFailed
    case restoreWalletFailed
    case invaildSignatureAlgorithm
    case invaildPassword
    case invaildPrivateKey
    case invaildKeyStorePassword
    case signError
    case initPublicKeyFailed
    case incorrectKeyIndexerURL
    case keyIndexerRequestFailed
    case decodeKeyIndexerFailed
    case loadCacheFailed
    case invaildWalletType

    var errorCode: Int {
        WalletError.allCases.firstIndex(of: self) ?? -1
    }

    public var description: String {
        "\(type(of: self)) Code: \(errorCode) - \(self)"
    }
}
