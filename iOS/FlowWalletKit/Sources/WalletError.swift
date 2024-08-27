//
//  File.swift
//  
//
//  Created by Hao Fu on 16/1/2024.
//

import Foundation
import Flow

public enum WalletError: String, Error, CaseIterable, CustomStringConvertible {
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
    case initPublicKeyFailed
    case incorrectKeyIndexerURL
    case keyIndexerRequestFailed
    case decodeKeyIndexerFailed
    
    var errorCode: Int {
        WalletError.allCases.firstIndex(of: self) ?? -1
    }
    
    public var description: String {
        "\(type(of: self)) Code: \(errorCode) - \(self)"
    }
}
