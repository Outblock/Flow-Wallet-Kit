//
//  FWKDemoTests.swift
//  FWKDemoTests
//
//  Created by Hao Fu on 1/5/2024.
//

import CryptoKit
import FlowWalletKit
@testable import FWKDemo
import XCTest

final class FWKDemoTests: XCTestCase {
    let id = "userId"
    let password = "password"
    let wrongPassword = "wrong_password"
    var storage = KeychainStorage(service: "io.outblock.FWKDemo", label: "FWKDemo Unit Test", synchronizable: false)
    
    func testSEWalletCreate() throws {
        let wallet = try SEWallet.create(id: id, password: password, storage: storage)
        let reWallet = try SEWallet.get(id: id, password: password, storage: storage)
        XCTAssertEqual(try wallet.publicKey(), try reWallet.publicKey())
    }

    func testSEWalletStore() throws {
        let wallet = try SEWallet.create(storage: storage)
        try wallet.store(id: id, password: password)
        let reWallet = try SEWallet.get(id: id, password: password, storage: storage)
        XCTAssertEqual(try wallet.publicKey(), try reWallet.publicKey())
    }

    func testExample() throws {
        let reWallet = try SEWallet.get(id: id, password: wrongPassword, storage: storage)

//        let key = try P256.Signing.PublicKey.init(rawRepresentation: "7a57837de0f3f67903c8de330e1453e13ea3f6fc99805d8fb55e20594198df17290fdab23ffad68648dbae309c7f0fe6b9f77ce42710637b0e89ef236dda58ca".hexValue)

//        print(key)
    }
}
