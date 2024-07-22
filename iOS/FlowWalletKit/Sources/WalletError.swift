//
//  File.swift
//  
//
//  Created by Hao Fu on 16/1/2024.
//

import Foundation

public enum WalletError: Error {
    case emptyKeychain
    case emptyKey
    case unsupportHashAlgorithm
    case unsupportSignatureAlgorithm
    case initChaChapolyFailed
    case initHDWalletFailed
    case initPrivateKeyFailed
    case restoreWalletFailed
    case invaildSignatureAlgorithm
    case invaildPassword
    case invaildKeyStorePassword
    case signError
}
