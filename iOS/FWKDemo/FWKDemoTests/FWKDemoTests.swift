//
//  FWKDemoTests.swift
//  FWKDemoTests
//
//  Created by Hao Fu on 1/5/2024.
//

import XCTest
@testable import FWKDemo
import FlowWalletKit

final class FWKDemoTests: XCTestCase {
    
    let id = "userId"
    let password = "password"
    let wrongPassword = "wrong_password"
    
    func testSEWalletCreate() throws {
        let wallet = try SEWallet.create(id: id, password: password, sync: false)
        let reWallet = try SEWallet.get(id: id, password: password)
        XCTAssertEqual(try wallet.publicKey(), try reWallet.publicKey())
    }
    
    func testSEWalletStore() throws {
        let wallet = try SEWallet.create()
        try wallet.store(id: id, password: password, sync: false)
        let reWallet = try SEWallet.get(id: id, password: password)
        XCTAssertEqual(try wallet.publicKey(), try reWallet.publicKey())
    }

    func testExample() throws {
        let reWallet = try SEWallet.get(id: id, password: wrongPassword)
    }
}
