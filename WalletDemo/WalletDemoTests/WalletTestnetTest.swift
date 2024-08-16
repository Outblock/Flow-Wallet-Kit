//
//  WalletTestnetTest.swift
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

struct ECDSA_P256_Signer: FlowSigner {
    func sign(transaction: Flow.Transaction, signableData: Data) async throws -> Data {
        do {
            return try privateKey.signature(for: signableData).rawRepresentation
        } catch {
            throw error
        }
    }
    
    var address: Flow.Address
    var keyIndex: Int
    var hashAlgo: Flow.HashAlgorithm = .SHA2_256
    var signatureAlgo: Flow.SignatureAlgorithm = .ECDSA_P256

    var privateKey: P256.Signing.PrivateKey

    init(address: Flow.Address, keyIndex: Int, privateKey: P256.Signing.PrivateKey) {
        self.address = address
        self.keyIndex = keyIndex
        self.privateKey = privateKey
    }
}


extension String {
    /// Convert hex string to bytes
    var hexValue: [UInt8] {
        var startIndex = self.startIndex
        return (0 ..< count / 2).compactMap { _ in
            let endIndex = index(after: startIndex)
            defer { startIndex = index(after: endIndex) }
            return UInt8(self[startIndex ... endIndex], radix: 16)
        }
    }
}


class WalletTestnetTests: XCTestCase {
    let mnemonic = "normal dune pole key case cradle unfold require tornado mercy hospital buyer"
    // Why it's this path? Check here
    // https://github.com/satoshilabs/slips/blob/master/slip-0044.md
    let derivationPath = "m/44'/539'/0'/0/0"

    // Testnet address with 4 different type of key
    // Key 1 --> ECDSA_SECP256k1 - SHA3_256
    // Key 2 --> ECDSA_P256 - SHA2_256
    // Key 3 --> ECDSA_P256 - SHA3_256
    // Key 4 --> ECDSA_SECP256k1 - SHA2_256
    let address = Flow.Address(hex: "0x4f05d22690e07938")
    
    // Mainnet!!
    let address2 = Flow.Address(hex: "0x33f75ff0b830dcec")

    var wallet: HDWallet!
    var privateKey: PrivateKey!
    var P256PrivateKey: PrivateKey!

    override func setUp() {
        super.setUp()
        flow.configure(chainID: .testnet)
        wallet = HDWallet(mnemonic: mnemonic, passphrase: "")
        privateKey = wallet.getCurveKey(curve: .secp256k1, derivationPath: derivationPath)
        P256PrivateKey = wallet.getCurveKey(curve: .nist256p1, derivationPath: derivationPath)
        print("P256PrivateKey --> \(P256PrivateKey.data.hexValue)")
    }
    
    struct AddKeyModel: Codable {
        let mnemonic: String
        let network: String
        let address: String
        let signAlgo: String
        let hashAlgo: String
        var keys: [KeyModel]
    }
    
    struct KeyModel: Codable {
        let derivationPath: String
        let privateKey: String
        let publicKey: String
        let keyIndex: Int
        let txId: String
    }
    
    func testApp() {
//        let new = "shuffle book stereo author wisdom hour bind danger scrap honey label tank"
//        let testWallet = HDWallet(mnemonic: new, passphrase: "")!
        let testWallet = HDWallet(strength: 128, passphrase: "")!
        print("Mn: \(testWallet.mnemonic)")
//            let path = DerivationPath(purpose: .bip44, coin: 539, account: 0, change: 0, address: 1)
//            print("DerivationPath: \(path.description)")
        let privateKey = testWallet.getCurveKey(curve: .nist256p1, derivationPath: derivationPath)
        let publicKey = privateKey.getPublicKeyNist256p1().uncompressed.data.hexValue.dropFirst(2)
        print("privateKey: \(privateKey.data.hexValue)")
        print("publicKey: \(publicKey)")
    }
    
    func testMultipleKey() async {
        let new = "shuffle book stereo author wisdom hour bind danger scrap honey label tank"
        let testWallet = HDWallet(mnemonic: new, passphrase: "")!

        let address = "0x3d2b4d1b51f3a4cd"
        var keys: [KeyModel] = []

        flow.configure(chainID: .testnet)
        print(testWallet.mnemonic)
        for i in 101...500 {
            let path = DerivationPath(purpose: .bip44, coin: 539, account: 0, change: 0, address: UInt32(i))
            print("DerivationPath: \(path.description)")
            let privateKey = testWallet.getCurveKey(curve: .nist256p1, derivationPath: path.description)
            let publicKey = privateKey.getPublicKeyNist256p1().uncompressed.data.hexValue.dropFirst(2)
            print("privateKey: \(privateKey.data.hexValue)")
            print("publicKey: \(publicKey)")

            let privateKeyC = try! P256.Signing.PrivateKey(rawRepresentation: "e2237854a5f1f8e450c7c8a6fc965af27fdb0909cff34950e6a7e9b2dae6c64c".hexValue)


            let flowAddress: Flow.Address = .init(hex: address)
            let signer = ECDSA_P256_Signer(address: .init(hex: address),
                                           keyIndex: 0,
                                           privateKey: privateKeyC)

//            let txID = try! flow.addKeyToAccount(address: .init(hex: address),
         let accountKey: Flow.AccountKey = .init(publicKey: .init(hex: String(publicKey)),
                           signAlgo: .ECDSA_P256,
                           hashAlgo: .SHA2_256,
                           weight: 1000)
//                                      signers: [signer]).wait()


            let txID = try! await flow.sendTransaction(signers: [signer]) {
                cadence {
                    """
                    import Crypto
                    transaction(publicKey: String, signatureAlgorithm: UInt8, hashAlgorithm: UInt8, weight: UFix64) {
                        prepare(signer: AuthAccount) {
                            let key = PublicKey(
                                publicKey: publicKey.decodeHex(),
                                signatureAlgorithm: SignatureAlgorithm(rawValue: signatureAlgorithm)!
                            )
                            let account = AuthAccount(payer: signer)
                            account.keys.add(
                                publicKey: key,
                                hashAlgorithm: HashAlgorithm(rawValue: hashAlgorithm)!,
                                weight: weight
                            )
                        }
                    }
                    """
                }
                arguments {
                    [
                        .string(accountKey.publicKey.hex),
                        .uint8(UInt8(accountKey.signAlgo.index)),
                        .uint8(UInt8(accountKey.hashAlgo.code)),
                        .ufix64(1000),
                    ]
                }
                proposer {
                    Flow.TransactionProposalKey(address: flowAddress, keyIndex: 1)
                }
                authorizers {
                    flowAddress
                }
            }


            print("txID: \(txID.hex)")
            let result = try! await txID.onceSealed()
            print("-------------------")

            keys.append(KeyModel(derivationPath: path.description,
                              privateKey: privateKey.data.hexValue,
                                 publicKey: String(publicKey),
                                 keyIndex: i+1,
                                 txId: txID.hex))
        }

        let model = AddKeyModel(mnemonic: new,
                                network: "testnet",
                                address: address,
                                signAlgo: Flow.SignatureAlgorithm.ECDSA_P256.id,
                                hashAlgo: Flow.HashAlgorithm.SHA2_256.algorithm,
                                keys: keys)
        print("---------------")
        let jsonEncoder = JSONEncoder()
        let jsonData = try! jsonEncoder.encode(model)
        let json = String(data: jsonData, encoding: .utf8)!
        print(print(json))
        print("---------------")
    }
    
    
    func testCheckKey() async {
        
        let decoder = JSONDecoder()
        let url = Bundle.main.url(forResource: "keys", withExtension: "json")!
        guard let data = try? Data(contentsOf: url),
             let model = try? decoder.decode(AddKeyModel.self, from: data)
        else {
             return
        }
        
        print(model)
        
        for (index, key) in model.keys.enumerated() {
            let result = await verifyUserSignature(privateKey: key.privateKey, publickKey: key.publicKey)
            print("\(index) - \(result)")
        }
    }
    
    func verifyUserSignature(privateKey: String, publickKey: String) async -> Bool {
        
        let script = """
           import Crypto

            pub fun main(rawPublicKeys: [String], weights: [UFix64], signatures: [String], signedData: String): Bool {
              let keyList = Crypto.KeyList()
              var i = 0
              for rawPublicKey in rawPublicKeys {
                keyList.add(
                  PublicKey(
                    publicKey: rawPublicKey.decodeHex(),
                    signatureAlgorithm: SignatureAlgorithm.ECDSA_P256 // or SignatureAlgorithm.ECDSA_Secp256k1
                  ),
                  hashAlgorithm: HashAlgorithm.SHA3_256,
                  weight: weights[i],
                )
                i = i + 1
              }
            
              let signatureSet: [Crypto.KeyListSignature] = []
              var j = 0
              for signature in signatures {
                signatureSet.append(
                  Crypto.KeyListSignature(
                    keyIndex: j,
                    signature: signature.decodeHex()
                  )
                )
                j = j + 1
              }
            
              return keyList.verify(
                signatureSet: signatureSet,
                signedData: signedData.decodeHex(),
              )
            }
        """
        
//        let wallet = HDWallet(mnemonic: "person general flat put rough hat metal antenna noise insect beauty wrist", passphrase: "")!
//        let privateKey = wallet.getCurveKey(curve: .nist256p1, derivationPath: derivationPath)
//        let publickKey = privateKey.getPublicKeyNist256p1().uncompressed
        

//        print("publickKey -> \(String(publickKey.data.hexValue.dropFirst(2)))")

        let addPrefix = "04"+publickKey
        
        let privateKey = PrivateKey(data: Data(privateKey.hexValue))!
        let publickKey = privateKey.getPublicKeyNist256p1().uncompressed
//        PublicKey(data: Data(addPrefix.hexValue), type: .nist256p1)!
        
        print("publickKey -> \(publickKey.data.hexValue)")
        print("addPrefix -> \(addPrefix)")
        
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
                                                                        .init(value: .array([.string(String(publickKey.data.hexValue.dropFirst(2)))])),
                                                                        .init(value: .array([.ufix64(1000.0)])),
                                                                        .init(value: .array([.string(formatSignature.hexValue)])),
                                                                        .init(value: .string(message)),
                                                                    ])

//        XCTAssertEqual(result, true)
        print(result)
        
        return result.fields!.value.toBool() ?? false
    }
    
    
    func formatJsonString(jsonString: String) -> Data? {
        let jsonData = jsonString.data(using: .utf8)!
        let object = try! JSONSerialization.jsonObject(with: jsonData)
        return try! JSONSerialization.data(withJSONObject: object, options: [])
    }

    func testSecp256k1_SHA256() async {
        let signer = WalletCoreSigner(address: address,
                                      keyIndex: 3,
                                      hashAlgo: .SHA2_256,
                                      signatureAlgo: .ECDSA_SECP256k1,
                                      privateKey: privateKey)
        await sendSimpleTransaction(signers: [signer])
    }

    func testSecp256k1_SHA3_256() async {
        let signer = WalletCoreSigner(address: address,
                                      keyIndex: 0,
                                      hashAlgo: .SHA3_256,
                                      signatureAlgo: .ECDSA_SECP256k1,
                                      privateKey: privateKey)
        await sendSimpleTransaction(signers: [signer])
    }

    func testP256_SHA256() async {
        let signer = WalletCoreSigner(address: address2,
                                      keyIndex: 0,
                                      hashAlgo: .SHA2_256,
                                      signatureAlgo: .ECDSA_P256,
                                      privateKey: PrivateKey(data: Data(hexString: "b9e452a92cdfc4857b6b6dd499f28e310c314818b7fd5f05c34736c0a7eb1255")!)!)

        let unsignData = "hello schnorr".data(using: .utf8)!
        let signedData = try! signer.sign(signableData: unsignData)

        print("signedData --> \(signedData.hexValue)")

        await sendSimpleTransaction(signers: [signer])
    }

    func testP256_SHA3_256() async {
        let signer = WalletCoreSigner(address: address2,
                                      keyIndex: 0,
                                      hashAlgo: .SHA2_256,
                                      signatureAlgo: .ECDSA_P256,
                                      privateKey: P256PrivateKey)
        await sendSimpleTransaction(signers: [signer])
    }

    func sendSimpleTransaction(signers: [FlowSigner]) async {
        flow.configure(chainID: .testnet)
        var unsignedTx = try! await flow.buildTransaction(chainID: .testnet) {
            cadence {
                """
                transaction {
                  execute {
                    log("A transaction happened")
                  }
                }
                """
            }

            proposer {
                Flow.TransactionProposalKey(address: address,
                                            keyIndex: signers.first!.keyIndex,
                                            sequenceNumber: -1)
            }

            gasLimit {
                1000
            }
        }

        let signedTx = try! await unsignedTx.sign(signers: signers)
//        print("encodedEnvelope --> \(signedTx.encodedEnvelope?.hexValue)")
//        print("signedTx --> \(signedTx.envelopeSignatures.first!.signature.hexValue)")
//        print("signedTx count --> \(signedTx.envelopeSignatures.first!.signature.hexValue.count)")
        let txId = try! await flow.sendTransaction(signedTransaction: signedTx)
        print("txId --> \(txId.hex)")
        let result = try! await txId.onceSealed()
        print("result --> \(result.status)")
        print("errorMessage --> \(result.errorMessage)")
        
    }

    // MARK: - Util

    func testAddKey() async {
        let P256PublicKey = P256PrivateKey.getPublicKeyNist256p1().uncompressed.data.hexValue.dropFirst(2)
        print("P256PublicKey --> \(P256PublicKey)")
        let secondKey = Flow.AccountKey(publicKey: .init(hex: String(P256PublicKey)),
                                        signAlgo: .ECDSA_P256,
                                        hashAlgo: .SHA2_256,
                                        weight: 1000)

        let thirdKey = Flow.AccountKey(publicKey: .init(hex: String(P256PublicKey)),
                                       signAlgo: .ECDSA_P256,
                                       hashAlgo: .SHA3_256,
                                       weight: 1000)

        let publicKey_secp256k1 = privateKey.getPublicKeySecp256k1(compressed: false).data.hexValue.dropFirst(2)
        print("secp256k1 PublicKey --> \(publicKey_secp256k1)")
        let forthKey = Flow.AccountKey(publicKey: .init(hex: String(publicKey_secp256k1)),
                                       signAlgo: .ECDSA_SECP256k1,
                                       hashAlgo: .SHA2_256,
                                       weight: 1000)

        await addKeyToAddress(accountKey: forthKey)
    }

    func addKeyToAddress(accountKey: Flow.AccountKey) async {
        let signer = WalletCoreSigner(address: address, keyIndex: 0, hashAlgo: .SHA3_256,
                                      signatureAlgo: .ECDSA_SECP256k1, privateKey: privateKey)
        let txId = try! await flow.addKeyToAccount(address: address, accountKey: accountKey, signers: [signer])
        print("txId --> \(txId.hex)")
        _ = try! await txId.onceSealed()
    }
    
    
    func testMultiplePartySign() async throws {
        // Example in Testnet
        
        let addressA = Flow.Address(hex: "0xc6de0d94160377cd")
        let publicKeyA = try! P256.KeyAgreement.PublicKey(rawRepresentation: "d487802b66e5c0498ead1c3f576b718949a3500218e97a6a4a62bf69a8b0019789639bc7acaca63f5889c1e7251c19066abb09fcd6b273e394a8ac4ee1a3372f".hexValue)
        let privateKeyA = try! P256.Signing.PrivateKey(rawRepresentation: "c9c0f04adddf7674d265c395de300a65a777d3ec412bba5bfdfd12cffbbb78d9".hexValue)

        var addressB = Flow.Address(hex: "0x10711015c370a95c")
        let publicKeyB = try! P256.KeyAgreement.PublicKey(rawRepresentation: "6278ff9fdf75c5830e4aafbb8cc25af50b62869d7bc9b249e76aae31490199732b769d1df627d36e5e336aeb4cb06b0fad80ae13a25aca37ec0017e5d8f1d8a5".hexValue)
        let privateKeyB = try! P256.Signing.PrivateKey(rawRepresentation: "38ebd09b83e221e406b176044a65350333b3a5280ed3f67227bd80d55ac91a0f".hexValue)

        var addressC = Flow.Address(hex: "0xe242ccfb4b8ea3e2")
        let publicKeyC = try! P256.KeyAgreement.PublicKey(rawRepresentation: "adbf18dae6671e6b6a92edf00c79166faba6babf6ec19bd83eabf690f386a9b13c8e48da67973b9cf369f56e92ec25ede5359539f687041d27d0143afd14bca9".hexValue)
        let privateKeyC = try! P256.Signing.PrivateKey(rawRepresentation: "1eb79c40023143821983dc79b4e639789ea42452e904fda719f5677a1f144208".hexValue)

        var addressD = Flow.Address(hex: "0xb05b2abb42335e88")
        
        let privateKeyD = try! P256.Signing.PrivateKey(rawRepresentation: "dbf01310a3f2fe3a244fc95aa624a865b8367fc2b93bb5edd3293c1cc2d1e006".hexValue)
        
        // Admin key
        let signers: [FlowSigner] = [
            // Address A
//            ECDSA_P256_Signer(address: addressA, keyIndex: 5, privateKey: privateKeyB), // weight: 500
            ECDSA_P256_Signer(address: addressA, keyIndex: 0, privateKey: privateKeyA), // weight: 1000
            // Address B
            ECDSA_P256_Signer(address: addressB, keyIndex: 2, privateKey: privateKeyA), // weight: 800
            ECDSA_P256_Signer(address: addressB, keyIndex: 1, privateKey: privateKeyC), // weight: 500
            // Address C
//            ECDSA_P256_Signer(address: addressC, keyIndex: 3, privateKey: privateKeyB), // weight: 300
//            ECDSA_P256_Signer(address: addressC, keyIndex: 2, privateKey: privateKeyB), // weight: 500
            ECDSA_P256_Signer(address: addressC, keyIndex: 0, privateKey: privateKeyC), // weight: 1000
            
//            ECDSA_P256_Signer(address: addressC, keyIndex: 0, privateKey: privateKeyC),
            
            WalletCoreSigner(address: addressD,
                             keyIndex: 0,
                             hashAlgo: .SHA3_256,
                             signatureAlgo: .ECDSA_P256,
                             privateKey: PrivateKey(data: Data(hexString: "dbf01310a3f2fe3a244fc95aa624a865b8367fc2b93bb5edd3293c1cc2d1e006")!)!)
        ]

        var unsignedTx = try! await flow.buildTransaction {
            cadence {
                """
                import Domains from 0xb05b2abb42335e88
                import Flowns from 0xb05b2abb42335e88
                import NonFungibleToken from 0x631e88ae7f1d7c20
                import FungibleToken from 0x9a0766d93b6608b7

                transaction(name: String) {
                 let client: &{Flowns.AdminPrivate}
                 let receiver: Capability<&{NonFungibleToken.Receiver}>
                 prepare(user: AuthAccount, lilico: AuthAccount, flowns: AuthAccount) {
                   let userAcc = getAccount(user.address)
                    // check user balance
                   let userBalRef = userAcc.getCapability(/public/flowTokenBalance).borrow<&{FungibleToken.Balance}>()
                   if balanceRef.balance < 0.001 {
                     let vaultRef = flowns.borrow<&FungibleToken.Vault>(from: /storage/flowTokenVault)
                     let userReceiverRef =  userAcc.getCapability(/public/flowTokenReceiver).borrow<&{FungibleToken.Receiver}>()
                     userReceiverRef.deposit(from: <- vaultRef.withdraw(amount: 0.001))
                   }
                 
                   // init user's domain collection
                   if user.getCapability<&{NonFungibleToken.Receiver}>(Domains.CollectionPublicPath).check() == false {
                     if user.borrow<&Domains.Collection>(from: Domains.CollectionStoragePath) != nil {
                       user.unlink(Domains.CollectionPublicPath)
                       user.link<&Domains.Collection{NonFungibleToken.CollectionPublic, NonFungibleToken.Receiver, Domains.CollectionPublic}>(Domains.CollectionPublicPath, target: Domains.CollectionStoragePath)
                     } else {
                       user.save(<- Domains.createEmptyCollection(), to: Domains.CollectionStoragePath)
                       user.link<&Domains.Collection{NonFungibleToken.CollectionPublic, NonFungibleToken.Receiver, Domains.CollectionPublic}>(Domains.CollectionPublicPath, target: Domains.CollectionStoragePath)
                     }
                   }

                   self.receiver = userAcc.getCapability<&{NonFungibleToken.Receiver}>(Domains.CollectionPublicPath)
                   
                   self.client = flowns.borrow<&{Flowns.AdminPrivate}>(from: Flowns.FlownsAdminStoragePath) ?? panic("Could not borrow admin client")
                 }
                 execute {
                   self.client.mintDomain(domainId: 1, name: name, duration: 3153600000.00, receiver: self.receiver)
                 }
                }
                """
            }

            proposer {
                Flow.TransactionProposalKey(address: addressC, keyIndex: 0)
            }

            authorizers {
                [addressC, addressA, addressD]
            }
            
            payer {
                addressA
            }

            arguments {
                [.string("Test")]
            }

            // optional
            gasLimit {
                1000
            }
        }

//        let notFinishedTx = try! unsignedTx.signPayload(signers: signers)
        
//        let model = TestModel(transaction: notFinishedTx, message: notFinishedTx.signablePlayload?.hexValue ?? "")
//        let encoder = JSONEncoder()
//        encoder.outputFormatting = .prettyPrinted
//        let jsonData = try! encoder.encode(model)
//        let jsonString = String(data: jsonData, encoding: .utf8)!
//
//        print("<-------------  RAW TRANSACTION  ------------->")
//        print(jsonString)
//        print("<-------------  RAW TRANSACTION END  ------------->")
//
//
////      Replace me
//        var unpaidTx:Flow.Transaction = try await API.fetch(url: URL(string: "https://739c-118-113-135-6.ap.ngrok.io/api/auth/sign")!, method: .post, data: jsonData)
//        let signedTx = try! unpaidTx.signEnvelope(signers: signers)
//
//
//        let jsonData2 = try! encoder.encode(signedTx)
//        let jsonString2 = String(data: jsonData2, encoding: .utf8)!
//
//        print("<-------------  SIGNED TRANSACTION  ------------->")
//        print(jsonString2)
//        print("<-------------  SIGNED TRANSACTION END  ------------->")
        
        let signedTx = try! await unsignedTx.sign(signers: signers)
        let txId = try! await flow.sendTransaction(signedTransaction: signedTx)
        XCTAssertNotNil(txId)
        print("txid --> \(txId.hex)")
    }

}
