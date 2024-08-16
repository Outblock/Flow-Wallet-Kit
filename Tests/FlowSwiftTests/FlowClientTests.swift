import CryptoKit
import Flow
@testable import FlowWalletKit
import WalletCore
import XCTest

final class FlowClientTests: XCTestCase {
    let mnemonic = "normal dune pole key case cradle unfold require tornado mercy hospital buyer"
    let derivationPath = "m/44'/539'/0'/0/0"

    func testHDWallet() {
        let wallet = HDWallet(mnemonic: mnemonic, passphrase: "")!
        XCTAssertTrue(Mnemonic.isValid(mnemonic: wallet.mnemonic))
    }

    func testP256Key() {
        let wallet = HDWallet(mnemonic: mnemonic, passphrase: "")!
        let privateKey = wallet.getCurveKey(curve: .nist256p1, derivationPath: derivationPath)

        XCTAssertEqual("638dc9ad0eee91d09249f0fd7c5323a11600e20d5b9105b66b782a96236e74cf", privateKey.data.hexValue)

        let unsignData = "hello schnorr".data(using: .utf8)!
    }
}
