//
//  WalletCoreSigner.swift
//  WalletDemoTests
//
//  Created by Hao Fu on 9/12/21.
//

import Flow
import Foundation
import WalletCore

struct WalletCoreSigner: FlowSigner {
    func sign(transaction: Flow.Transaction, signableData: Data) async throws -> Data {
        var data = signableData
        if hashAlgo == .SHA2_256 {
            data = Hash.sha256(data: data)
        } else {
            data = Hash.sha3_256(data: data)
        }

        let curve: Curve = signatureAlgo == .ECDSA_SECP256k1 ? .secp256k1 : .nist256p1
        let signedData = privateKey.sign(digest: data, curve: curve) ?? Data()
        return signedData.dropLast()
    }
    
    var address: Flow.Address
    var keyIndex: Int
    var hashAlgo: Flow.HashAlgorithm
    var signatureAlgo: Flow.SignatureAlgorithm
    var privateKey: WalletCore.PrivateKey

    init(address: Flow.Address, keyIndex: Int,
         hashAlgo: Flow.HashAlgorithm,
         signatureAlgo: Flow.SignatureAlgorithm,
         privateKey: WalletCore.PrivateKey)
    {
        self.address = address
        self.keyIndex = keyIndex
        self.hashAlgo = hashAlgo
        self.signatureAlgo = signatureAlgo
        self.privateKey = privateKey
    }

    func sign(signableData: Data) throws -> Data {
        var data = signableData
        if hashAlgo == .SHA2_256 {
            data = Hash.sha256(data: data)
        } else {
            data = Hash.sha3_256(data: data)
        }

        let curve: Curve = signatureAlgo == .ECDSA_SECP256k1 ? .secp256k1 : .nist256p1
        let signedData = privateKey.sign(digest: data, curve: curve) ?? Data()
        return signedData.dropLast()
    }
}
