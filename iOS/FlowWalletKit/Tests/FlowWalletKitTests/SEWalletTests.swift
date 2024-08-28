@testable import FlowWalletKit
import XCTest

final class FlowWalletCoreTests: XCTestCase {
    let id = "userId"
    let password = "password"

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
}
