//
//  WalletDemoTests.swift
//  WalletDemoTests
//
//  Created by Hao Fu on 9/12/21.
//

import CryptoKit
import Flow
import WalletCore
@testable import WalletDemo
import XCTest
import FlowKeygen

class WalletDemoTests: XCTestCase {
    let mnemonic = "normal dune pole key case cradle unfold require tornado mercy hospital buyer"
    let mnemonic2 = "ripple scissors kick mammal hire column oak again sun offer wealth tomorrow wagon turn fatal"

    // Why it's this path? Check here
    // https://github.com/satoshilabs/slips/blob/master/slip-0044.md
    let derivationPath = "m/44'/539'/0'/0/0"

    let script = """
    import Crypto
    pub fun main(
      publicKey: String,
      signature: String,
      message: String,
      signAlgo: UInt8,
      hashAlgo: UInt8
    ): Bool {

        let signatureBytes = signature.decodeHex()
        let messageBytes = message.utf8

        let pk = PublicKey(
                publicKey: publicKey.decodeHex(),
                signatureAlgorithm: SignatureAlgorithm(rawValue: signAlgo)!
        )

        return pk.verify(
            signature: signatureBytes,
            signedData: messageBytes,
            domainSeparationTag: "",
            hashAlgorithm: HashAlgorithm(rawValue: hashAlgo)!)
    }
    """
    
    func testCreateMainnetAccount2() async {
        let wallet = HDWallet(mnemonic: mnemonic2, passphrase: "")!
        print(wallet.mnemonic)
        let privateKey1 = wallet.getCurveKey(curve: .secp256k1, derivationPath: derivationPath)
        print(privateKey1.data.hexValue)
        
        let privateKey2 = wallet.getCurveKey(curve: .nist256p1, derivationPath: derivationPath)
        print(privateKey2.data.hexValue)
        
        let privateKey3 = wallet.getCurveKey(curve: .curve25519, derivationPath: derivationPath)
        print(privateKey3.data.hexValue)
        
        let privateKey4 = wallet.getCurveKey(curve: .ed25519, derivationPath: derivationPath)
        print(privateKey4.data.hexValue)
    }
    
    func testEthSign() {
        
        let pubK = PublicKey(data: "04a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd5b8dec5235a0fa8722476c7709c02559e3aa73aa03918ba2d492eea75abea235".hexValue.data,
                             type: .secp256k1Extended)!
        
        let message = "0x179b6b1cb6755e31"
        let rawMessage = ["\u{19}Ethereum Signed Message:\n", String(message.count), message].joined(separator: "").data(using: .utf8)!
        let hashed = Hash.keccak256(data: rawMessage)
        
        print(hashed.hexValue)
        
        let result = pubK.verify(signature: "727b958012620a3543b500d4411a7f0fac551bc4285382501cf298e49c6621430148a590b23a1301c319f82a386c97fff9f2cc583bb441572939e83de51488b71c".hexValue.data,
                                  message: hashed)
        
        XCTAssertEqual(result, true)
        
    }
    
    func testCreateMainnetAccount() async {
        let wallet = HDWallet(strength: 128, passphrase: "")!
//        let wallet = HDWallet(mnemonic: "deposit purchase jewel rhythm name gossip enhance beyond sponsor fashion walnut quiz", passphrase: "")!
        print(wallet.mnemonic)
        let privateKey = wallet.getCurveKey(curve: .nist256p1, derivationPath: derivationPath)
        let publickKey = privateKey.getPublicKeyNist256p1().uncompressed
        print(wallet.mnemonic)
        print(privateKey.data.hexValue)
        print(publickKey.data.hexValue)
        
        let formatedKey = String(publickKey.data.hexValue.dropFirst(2))
        print("formatedKey --> \(formatedKey)")
        
        let payerAddress = Flow.Address(hex: "0xc7efa8c33fceee03")
//        let payerKey = PrivateKey(data: Data(hexString: "")!)!
        
        let outblockKey = HDWallet(mnemonic: "elder letter trophy lamp today intact picture shallow search magic pepper whip", passphrase: "")!
        let payerKey = outblockKey.getCurveKey(curve: .secp256k1, derivationPath: derivationPath)
        
        let signer = WalletCoreSigner(address: payerAddress,
                                      keyIndex: 0,
                                      hashAlgo: .SHA2_256,
                                      signatureAlgo: .ECDSA_SECP256k1,
                                      privateKey: payerKey)

        
        // User publick key
        let accountKey = Flow.AccountKey(publicKey: Flow.PublicKey(hex: formatedKey),
                                         signAlgo: .ECDSA_P256,
                                         hashAlgo: .SHA2_256,
                                         weight: 1000)

        
        flow.configure(chainID: .mainnet)
        do {
            var unsignedTx = try await flow.buildTransaction {
                cadence {
                """
                    transaction(publicKey: String) {
                        prepare(signer: AuthAccount) {
                            let account = AuthAccount(payer: signer)
                            account.addPublicKey(publicKey.decodeHex())
                        }
                    }
                """
                }
                
                proposer {
                    Flow.TransactionProposalKey(address: payerAddress, keyIndex: 0)
                }
                
                authorizers {
                    payerAddress
                }
                
                arguments {
                    [.string(accountKey.encoded!.hexValue)]
                }
                
                // optional
                gasLimit {
                    1000
                }
            }
            
            let signedTx = try! await unsignedTx.sign(signers: [signer])
            let txId = try! await flow.sendTransaction(signedTransaction: signedTx)
            XCTAssertNotNil(txId)
            print("txid --> \(txId.hex)")
        } catch {
            print(error)
            XCTAssertTrue(false)
        }
        
    }
    
    func testCreateMainnetAccount21() async {
        let wallet = HDWallet(mnemonic: mnemonic2, passphrase: "")!
        print(wallet.mnemonic)
        let privateKey1 = wallet.getCurveKey(curve: .secp256k1, derivationPath: derivationPath)
        print(privateKey1.data.hexValue)
        
        let privateKey2 = wallet.getCurveKey(curve: .nist256p1, derivationPath: derivationPath)
        print(privateKey2.data.hexValue)
        
        let privateKey3 = wallet.getCurveKey(curve: .curve25519, derivationPath: derivationPath)
        print(privateKey3.data.hexValue)
        
        let privateKey4 = wallet.getCurveKey(curve: .ed25519, derivationPath: derivationPath)
        print(privateKey4.data.hexValue)
    }
    
    
    func testCreateMainnetAccount3() async {
        let wallet = HDWallet(strength: 128, passphrase: "")!
        let privateKey = wallet.getCurveKey(curve: .secp256k1, derivationPath: derivationPath)
        let publickKey = privateKey.getPublicKeySecp256k1(compressed: false).uncompressed
        print(wallet.mnemonic)
        print(privateKey.data.hexValue)
        print(publickKey.data.dropFirst().hexValue)
        
        flow.configure(chainID: .mainnet)
        
        let userKey = publickKey.data.dropFirst().compactMap{ Flow.Cadence.FValue.uint8($0) }
        
        let list = "6e4f43f79d3c1d8cacb3d5f3e7aeedb29feaeb4559fdb71a97e2fd0438565310e87670035d83bc10fe67fe314dba5363c81654595d64884b1ecad1512a64e65e"
        let listKey = list.hexValue.compactMap{ Flow.Cadence.FValue.uint8($0) }
        
        let formatedKey = String(publickKey.data.hexValue.dropFirst(2))
        print("formatedKey --> \(formatedKey)")
        
        let payerAddress = Flow.Address(hex: "0xc7efa8c33fceee03")
//        let payerKey = PrivateKey(data: Data(hexString: "")!)!
        
        let outblockWallet = HDWallet(mnemonic: "elder letter trophy lamp today intact picture shallow search magic pepper whip", passphrase: "")!
        let payerKey = outblockWallet.getCurveKey(curve: .secp256k1, derivationPath: derivationPath)
        
        print("payerKey => \(payerKey.data.hexValue)")
        
//        let signer = WalletCoreSigner(address: payerAddress,
//                                      keyIndex: 0,
//                                      hashAlgo: .SHA2_256,
//                                      signatureAlgo: .ECDSA_SECP256k1,
//                                      privateKey: payerKey)
//
//        // User publick key
////        let accountKey = Flow.AccountKey(publicKey: Flow.PublicKey(hex: formatedKey),
////                                         signAlgo: .ECDSA_P256,
////                                         hashAlgo: .SHA2_256,
////                                         weight: 1000)
//
//        var unsignedTx = try! await flow.buildTransaction {
//            cadence {
//                """
//                import Crypto
//                import FlowToken from 0x1654653399040a61
//                import FungibleToken from 0xf233dcee88fe0abe
//                import LockedTokens from 0x8d0e87b65159ae63
//
//                /// Transaction that a custody provider would sign
//                /// to create a shared account and an unlocked
//                /// account for a user
//                transaction(
//                    fullAdminPublicKey: Crypto.KeyListEntry, // Weight: 1000
//                    fullUserPublicKey: Crypto.KeyListEntry, // Weight: 1000
//                )  {
//
//                    prepare(custodyProvider: AuthAccount) {
//
//                        let sharedAccount = AuthAccount(payer: custodyProvider)
//                        let userAccount = AuthAccount(payer: custodyProvider)
//
//                        sharedAccount.keys.add(publicKey: fullAdminPublicKey.publicKey, hashAlgorithm: fullAdminPublicKey.hashAlgorithm, weight: fullAdminPublicKey.weight)
//
//                        userAccount.keys.add(publicKey: fullUserPublicKey.publicKey, hashAlgorithm: fullUserPublicKey.hashAlgorithm, weight: fullUserPublicKey.weight)
//
//                        let vaultCapability = sharedAccount
//                            .link<&FlowToken.Vault>(/private/flowTokenVault, target: /storage/flowTokenVault)
//                            ?? panic("Could not link Flow Token Vault capability")
//
//                        let lockedTokenManager <- LockedTokens.createLockedTokenManager(vault: vaultCapability)
//
//                        sharedAccount.save(<-lockedTokenManager, to: LockedTokens.LockedTokenManagerStoragePath)
//
//                        let tokenManagerCapability = sharedAccount
//                            .link<&LockedTokens.LockedTokenManager>(
//                                LockedTokens.LockedTokenManagerPrivatePath,
//                                target: LockedTokens.LockedTokenManagerStoragePath
//                        )   ?? panic("Could not link token manager capability")
//
//                        let tokenHolder <- LockedTokens.createTokenHolder(lockedAddress: sharedAccount.address, tokenManager: tokenManagerCapability)
//
//                        userAccount.save(
//                            <-tokenHolder,
//                            to: LockedTokens.TokenHolderStoragePath,
//                        )
//
//                        userAccount.link<&LockedTokens.TokenHolder{LockedTokens.LockedAccountInfo}>(LockedTokens.LockedAccountInfoPublicPath, target: LockedTokens.TokenHolderStoragePath)
//
//                        let tokenAdminCapability = sharedAccount
//                            .link<&LockedTokens.LockedTokenManager>(
//                                LockedTokens.LockedTokenAdminPrivatePath,
//                                target: LockedTokens.LockedTokenManagerStoragePath)
//                            ?? panic("Could not link token custodyProvider to token manager")
//
//                        let lockedAccountCreator = custodyProvider
//                            .borrow<&LockedTokens.LockedAccountCreator>(from: LockedTokens.LockedAccountCreatorStoragePath)
//                            ?? panic("Could not borrow reference to LockedAccountCreator")
//
//                        lockedAccountCreator.addAccount(sharedAccountAddress: sharedAccount.address, unlockedAccountAddress: userAccount.address, tokenAdmin: tokenAdminCapability)
//
//                        // Override the default FlowToken receiver
//                        sharedAccount.unlink(/public/flowTokenReceiver)
//
//                        // create new receiver that marks received tokens as unlocked
//                        sharedAccount.link<&AnyResource{FungibleToken.Receiver}>(
//                            /public/flowTokenReceiver,
//                            target: LockedTokens.LockedTokenManagerStoragePath
//                        )
//
//                        // pub normal receiver in a separate unique path
//                        sharedAccount.link<&AnyResource{FungibleToken.Receiver}>(
//                            /public/lockedFlowTokenReceiver,
//                            target: /storage/flowTokenVault
//                        )
//                    }
//                }
//                """
//            }
//
//            proposer {
//                Flow.TransactionProposalKey(address: payerAddress, keyIndex: 0)
//            }
//
//            authorizers {
//                payerAddress
//            }
//
//            arguments {
//                [
//                    .struct(.init(id: "I.Crypto.Crypto.KeyListEntry",
//                                   fields: [.init(name: "keyIndex", value: .int(1000)),
//                                            .init(name: "publicKey",
//                                                  value: .struct(.init(id: "PublicKey",
//                                                                       fields: [.init(name: "publicKey",
//                                                                                      value: .array(listKey.toArguments())),
//                                                                                .init(name: "signatureAlgorithm",
//                                                                                      value: .enum(.init(id: "SignatureAlgorithm",
//                                                                                                         fields: [.init(name: "rawValue", value: .uint8(UInt8(Flow.SignatureAlgorithm.ECDSA_P256.index)))])))
//                                                                               ]
//                                                                      )
//                                                                )
//                                                 ),
//                                            .init(name: "hashAlgorithm", value: .enum(.init(id: "HashAlgorithm",
//                                                                                            fields: [.init(name: "rawValue", value: .uint8(UInt8(Flow.HashAlgorithm.SHA2_256.code)))]))),
//                                            .init(name: "weight", value: .ufix64(1000.0)),
//                                            .init(name: "isRevoked", value: .bool(false))
//                                            ]
//                                  )
//                            ),
//
//                    .struct(.init(id: "I.Crypto.Crypto.KeyListEntry",
//                               fields: [.init(name: "keyIndex", value: .int(1000)),
//                                        .init(name: "publicKey",
//                                              value: .struct(.init(id: "PublicKey",
//                                                                   fields: [.init(name: "publicKey",
//                                                                                  value: .array(userKey.toArguments())),
//                                                                            .init(name: "signatureAlgorithm",
//                                                                                  value: .enum(.init(id: "SignatureAlgorithm",
//                                                                                                     fields: [.init(name: "rawValue", value: .uint8(UInt8(Flow.SignatureAlgorithm.ECDSA_SECP256k1.index)))])))
//                                                                           ]
//                                                                  )
//                                                            )
//                                             ),
//                                        .init(name: "hashAlgorithm", value: .enum(.init(id: "HashAlgorithm",
//                                                                                        fields: [.init(name: "rawValue", value: .uint8(UInt8(Flow.HashAlgorithm.SHA2_256.code)))]))),
//                                        .init(name: "weight", value: .ufix64(1000.0)),
//                                        .init(name: "isRevoked", value: .bool(false))
//                                        ]
//                              )
//                        ),
//                ]
//            }
//
//            // optional
//            gasLimit {
//                9999
//            }
//        }
//
//        let signedTx = try! await unsignedTx.sign(signers: [signer])
//        let txId = try! await flow.sendTransaction(signedTransaction: signedTx)
//        XCTAssertNotNil(txId)
//        print("txid --> \(txId.hex)")
        
    }

    func testHDWallet() {
        let wallet = HDWallet(mnemonic: mnemonic, passphrase: "")!
        XCTAssertTrue(Mnemonic.isValid(mnemonic: wallet.mnemonic))
    }

    func testCreateHDWallet() {
        let wallet = HDWallet(strength: 128, passphrase: "")!
        XCTAssertTrue(Mnemonic.isValid(mnemonic: wallet.mnemonic))
        let privateKey = wallet.getCurveKey(curve: .nist256p1, derivationPath: derivationPath)
        let publickKey = privateKey.getPublicKeyNist256p1().uncompressed
        print(wallet.mnemonic)
        print(publickKey.data.hexValue)
        
        let result = PublicKey.isValid(data: Data(hexString: "047fabe5ad2f98156b63a651e616e4259ab88e74adb1604a964370517022fc266519e17cf8797d81ad20c21d54a50737a141679b6c4fb8ce251c7d40302bb6a829")!, type: .secp256k1)
        
        XCTAssertTrue(result)
    }

    func testVerifyUserSignature() async {
        let wallet = HDWallet(mnemonic: "kiwi erosion weather slam harvest move crumble zero juice steel start hotel", passphrase: "")!
        let privateKey = wallet.getCurveKey(curve: .nist256p1, derivationPath: derivationPath)
        let publickKey = privateKey.getPublicKeyNist256p1().uncompressed

        print("publickKey -> \(String(publickKey.data.hexValue.dropFirst(2)))")

        let message = "q0qHq9ehLIgupkXUnF7Ey4954q33"
        let unsignData = Flow.DomainTag.user.normalize + message.data(using: .utf8)!
//        let address = Flow.Address(hex: "0x4f05d22690e07938")

        // Use SHA256 here
        let hashedData = Hash.sha256(data: unsignData)
        let signedData = privateKey.sign(digest: hashedData, curve: .nist256p1)
        let formatSignature = signedData!.dropLast()

        print("formatSignature -> \(formatSignature.hexValue)")

        flow.configure(chainID: .testnet)

        let result = try! await flow.accessAPI.executeScriptAtLatestBlock(script: .init(text: script),
                                                                    arguments: [
                                                                        .init(value: .string(String(publickKey.data.hexValue.dropFirst(2)))),
                                                                        .init(value: .string(formatSignature.hexValue)),
                                                                        .init(value: .string(message)),
                                                                        .init(value: .uint8(UInt8(Flow.SignatureAlgorithm.ECDSA_P256.index))),
                                                                        .init(value: .uint8(1)),
                                                                    ])

//        XCTAssertEqual(result, true)
        print(result)
    }

    func testVerify256K1UserSignature() async {
        let wallet = HDWallet(mnemonic: mnemonic, passphrase: "")!
        let privateKey = wallet.getCurveKey(curve: .secp256k1, derivationPath: derivationPath)
        let publickKey = privateKey.getPublicKeySecp256k1(compressed: false)

        print("publickKey -> \(String(publickKey.data.hexValue.dropFirst(2)))")

        let message = "q0qHq9ehLIgupkXUnF7Ey4954q33"
        let unsignData = Flow.DomainTag.user.normalize + message.data(using: .utf8)!
//        let address = Flow.Address(hex: "0x4f05d22690e07938")

        print("unsignData -> \(unsignData.hexValue)")

        // Use SHA256 here
        let hashedData = Hash.sha256(data: unsignData)
        print("hashedData -> \(hashedData.hexValue)")

        let signedData = privateKey.sign(digest: hashedData, curve: .secp256k1)
        let formatSignature = signedData!.dropLast()

        print("formatSignature -> \(formatSignature.hexValue)")

        flow.configure(chainID: .testnet)

        let result = try! await flow.accessAPI.executeScriptAtLatestBlock(script: .init(text: script),
                                                                    arguments: [
                                                                        .init(value: .string(String(publickKey.data.hexValue.dropFirst(2)))),
                                                                        .init(value: .string("914cf7cc77f05501451dc67732d264122de680229a1135261bbb6f0d09916b947c1a26a40fb0113695282110e843314d626d9096a8a7214adb58764233d51f39")),
                                                                        .init(value: .string(message)),
                                                                        .init(value: .uint8(UInt8(Flow.SignatureAlgorithm.ECDSA_SECP256k1.index))),
                                                                        .init(value: .uint8(1)),
                                                                    ])

//        XCTAssertEqual(result, true)
        print(result)
    }
    
    func testVerify256K1UserSignature22() async {
        let wallet = HDWallet(mnemonic: mnemonic, passphrase: "")!
        let privateKey = wallet.getCurveKey(curve: .secp256k1, derivationPath: derivationPath)
        let publickKey = privateKey.getPublicKeySecp256k1(compressed: false)

        print("publickKey -> \(String(publickKey.data.hexValue.dropFirst(2)))")

        let message = "q0qHq9ehLIgupkXUnF7Ey4954q33"
        let unsignData = message.data(using: .utf8)!
//        let address = Flow.Address(hex: "0x4f05d22690e07938")

        print("unsignData -> \(unsignData.hexValue)")

        // Use SHA256 here
        let hashedData = Hash.sha256(data: unsignData)
        print("hashedData -> \(hashedData.hexValue)")

        let signedData = privateKey.sign(digest: hashedData, curve: .secp256k1)
        let formatSignature = signedData!.dropLast()

        print("formatSignature -> \(formatSignature.hexValue)")

        flow.configure(chainID: .testnet)

        let result = try! await flow.accessAPI.executeScriptAtLatestBlock(script: .init(text: script),
                                                                    arguments: [
                                                                        .init(value: .string(String(publickKey.data.hexValue.dropFirst(2)))),
                                                                        .init(value: .string(formatSignature.hexValue)),
                                                                        .init(value: .string(message)),
                                                                        .init(value: .uint8(UInt8(Flow.SignatureAlgorithm.ECDSA_SECP256k1.index))),
                                                                        .init(value: .uint8(1)),
                                                                    ])

//        XCTAssertEqual(result, true)
        print(result)
    }

    // MARK: - P256 Test

    func testP256_SHA256() {
//        let wallet = HDWallet(mnemonic: mnemonic, passphrase: "")!
        let wallet = HDWallet(strength: 128, passphrase: "")!
        print("mnemonic ->", wallet.mnemonic)
        let privateKey = wallet.getCurveKey(curve: .nist256p1, derivationPath: derivationPath)
        let publickKey = privateKey.getPublicKeyNist256p1().uncompressed
        
//        let secKey = try! SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: privateKey.data)
        
//        let keygen = FlowKeygenSdk()
//        let key = try! keygen.recoverKeys(wallet.mnemonic)
//        print("privateKey 1 ->", key.privateKey)
//        print("publickKey 1 ->", key.publicKey)
        
        print("privateKey ->", privateKey.data.hexValue)
        print("publickKey ->", publickKey.data.hexValue)

        // Test Private key and public key
//        XCTAssertTrue(PrivateKey.isValid(data: privateKey.data, curve: .nist256p1))
//        XCTAssertEqual("638dc9ad0eee91d09249f0fd7c5323a11600e20d5b9105b66b782a96236e74cf", privateKey.data.hexValue)

        // Important!!! wallet core using x963 format for public key
        // which will have `04` prefix, we need drop prefix to 128 length hex string
//        XCTAssertEqual("04dbe5b4b4416ad9158339dd692002ceddab895e11bd87d90ce7e3e745efef28d2ad6e736fe3d57d52213f397a7ba9f0bc8c65620a872aefedbc1ddd74c605cf58", publickKey.data.hexValue)

        let unsignData = Flow.DomainTag.user.normalize + "hello schnorr".data(using: .utf8)!

        // Use SHA256 here
        let hashedData = Hash.sha256(data: unsignData)
        let signedData = privateKey.sign(digest: hashedData, curve: .nist256p1)

        // Important!!! wallet core use (32 + 32 + 1) which is ( r + s + v)
        // However, flow verify signature using (r + s), hence we need drop v
        let formatSignature = signedData!.dropLast()
        print("formatSignature -> \(formatSignature.hexValue)")
        XCTAssertTrue(publickKey.verify(signature: formatSignature, message: hashedData))

        // Cross validation for private and public key
        let privateKey_CK = try! SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: privateKey.data)
        let publicKey_CK = privateKey_CK.publicKey

        XCTAssertEqual("dbe5b4b4416ad9158339dd692002ceddab895e11bd87d90ce7e3e745efef28d2ad6e736fe3d57d52213f397a7ba9f0bc8c65620a872aefedbc1ddd74c605cf58", publicKey_CK.rawRepresentation.hexValue)

        XCTAssertEqual("04dbe5b4b4416ad9158339dd692002ceddab895e11bd87d90ce7e3e745efef28d2ad6e736fe3d57d52213f397a7ba9f0bc8c65620a872aefedbc1ddd74c605cf58", publicKey_CK.x963Representation.hexValue)

        // Cross validation for signature
        let ECDSASignature = try! P256.Signing.ECDSASignature(rawRepresentation: formatSignature)
        XCTAssertTrue(privateKey_CK.publicKey.isValidSignature(ECDSASignature, for: unsignData))

        XCTAssertEqual("0cd37adf53dc353eeb07321c765d81aedd11f34a6393de31bb15e2c5a07793c96ac54369d71a7e769dced55fc941d2f723538e1b31bf587e7f435e911222068b01", signedData!.hexValue)
    }

    func testP256_SHA3_256() {
        let wallet = HDWallet(mnemonic: mnemonic, passphrase: "")!
        let privateKey = wallet.getCurveKey(curve: .nist256p1, derivationPath: derivationPath)
        let publickKey = privateKey.getPublicKeyNist256p1().uncompressed

        // Test Private key and public key
        XCTAssertTrue(PrivateKey.isValid(data: privateKey.data, curve: .nist256p1))
        XCTAssertEqual("638dc9ad0eee91d09249f0fd7c5323a11600e20d5b9105b66b782a96236e74cf", privateKey.data.hexValue)

        // Important!!! wallet core using x963 format for public key
        // which will have `04` prefix, we need drop prefix to 128 length hex string
        XCTAssertEqual("04dbe5b4b4416ad9158339dd692002ceddab895e11bd87d90ce7e3e745efef28d2ad6e736fe3d57d52213f397a7ba9f0bc8c65620a872aefedbc1ddd74c605cf58", publickKey.data.hexValue)

        let unsignData = "hello schnorr".data(using: .utf8)!

        // Use SHA3_256 here
        let hashedData = Hash.sha3_256(data: unsignData)
        let signedData = privateKey.sign(digest: hashedData, curve: .nist256p1)

        // Important!!! wallet core use (32 + 32 + 1) which is ( r + s + v)
        // However, flow verify signature using (r + s), hence we need drop v
        let formatSignature = signedData!.dropLast()
        XCTAssertTrue(publickKey.verify(signature: formatSignature, message: hashedData))
        XCTAssertEqual("74bae2badfff9e8193292978b07acb703ffafee2b81b551ab6dffa1135a144fd68e352ec7057eca55f5deac2307b8919797d0a7417cc4da983c5608a861afe9500", signedData!.hexValue)
    }

    // MARK: - Secp256k1 Test

    func testSecp256k1_SHA256() {
        let testmnemonic = "motion roof require label swing direct million alarm memory bridge torch kitchen"
        let wallet = HDWallet(mnemonic: testmnemonic, passphrase: "")!
        let privateKey = wallet.getCurveKey(curve: .secp256k1, derivationPath: derivationPath)
        let publickKey = privateKey.getPublicKeySecp256k1(compressed: false)

        print("privateKey.data.hexValue -> \(privateKey.data.hexValue)")
        print("publickKey.data.hexValue -> \(publickKey.data.hexValue)")

        // Test Private key and public key
//        XCTAssertTrue(PrivateKey.isValid(data: privateKey.data, curve: .nist256p1))
//        XCTAssertEqual("9c33a65806715a537d7f67cf7bf8a020cbdac8a1019664a2fa34da42d1ddbc7d", privateKey.data.hexValue)

        // Important!!! wallet core using x963 format for public key
        // which will have `04` prefix, we need drop prefix to 128 length hex string
//        XCTAssertEqual("04ad94008dea1505863fc92bd2db5b9fbf52a57f2a05d34fedb693c714bdc731cca57be95775517a9df788a564f2d7491d2c9716d1c0411a5a64155895749d47bc", publickKey.data.hexValue)

        let signable = "464c4f572d56302e302d7472616e73616374696f6e0000000000000000000000f8a6f8a3b8670a2020202020207472616e73616374696f6e207b0a202020202020202065786563757465207b0a202020202020202020206c6f67282241207472616e73616374696f6e2068617070656e656422290a20202020202020207d0a2020202020207d0a202020202020c0a04d34ca87d345f560fe47d8fa0002b23a0580cf852d4f28025083cd01d259545f82270f8821b02c958f39fbd180808821b02c958f39fbd1c0c0"

        let unsignData = Data(hexString: signable)!
        let hashedData = Hash.sha256(data: unsignData)

        print("hashedData -> \(hashedData.hexValue)")
        let signedData = privateKey.sign(digest: hashedData, curve: .secp256k1)

        // Important!!! wallet core use (32 + 32 + 1) which is ( r + s + v)
        // However, flow verify signature using (r + s), hence we need drop v
        let formatSignature = signedData!.dropLast()

        print("formatSignature -> \(formatSignature.hexValue)")

        XCTAssertTrue(publickKey.verify(signature: formatSignature, message: hashedData))
//        XCTAssertEqual("7c2e835850eee7375fa9540ddb7828c786338c84a6424b592be2388b1663a5fd27862167e21fd4a771c54abcc5ed3a23371265072129315aab93022e35f77ebe01", signedData!.hexValue)
    }

    func testSecp256k1_SHA3_256() {
        let wallet = HDWallet(mnemonic: mnemonic, passphrase: "")!
        let privateKey = wallet.getCurveKey(curve: .secp256k1, derivationPath: derivationPath)
        let publickKey = privateKey.getPublicKeySecp256k1(compressed: false)

        // Test Private key and public key
        XCTAssertTrue(PrivateKey.isValid(data: privateKey.data, curve: .nist256p1))
        XCTAssertEqual("9c33a65806715a537d7f67cf7bf8a020cbdac8a1019664a2fa34da42d1ddbc7d", privateKey.data.hexValue)

        // Important!!! wallet core using x963 format for public key
        // which will have `04` prefix, we need drop prefix to 128 length hex string
        XCTAssertEqual("04ad94008dea1505863fc92bd2db5b9fbf52a57f2a05d34fedb693c714bdc731cca57be95775517a9df788a564f2d7491d2c9716d1c0411a5a64155895749d47bc", publickKey.data.hexValue)

        let unsignData = "hello schnorr".data(using: .utf8)!
        let hashedData = Hash.sha3_256(data: unsignData)
        let signedData = privateKey.sign(digest: hashedData, curve: .secp256k1)

        // Important!!! wallet core use (32 + 32 + 1) which is ( r + s + v)
        // However, flow verify signature using (r + s), hence we need drop v
        let formatSignature = signedData!.dropLast()
        XCTAssertTrue(publickKey.verify(signature: formatSignature, message: hashedData))

        XCTAssertEqual("88271aaa67c0f66b9591b8706056a2f46876ceb8e3400ee95b0d32a4bcd99de9168b28f5e74cd561602fb36c035adccf4329001dc5ee42c32ae2fc0038cbc20301", signedData!.hexValue)
    }
}
