//
//  WallectSecureEnclaveStore.swift
//  FRW
//
//  Created by cat on 2023/11/7.
//

import Foundation
import KeychainAccess
import CryptoTokenKit
import CryptoKit
import QuartzCore

public extension WallectSecureEnclave {
    enum StoreError: Error {
        case unowned
        case encode
        case decode
        case emptyKeychain
    }

    enum Store {
        private static var service: String = "com.flowfoundation.wallet.securekey"
        private static var userKey: String = "user.keystore"

        public static func config(service: String) throws {
            if !service.isEmpty {
                Store.service = service
            }
        }

        public static func store(key: String, value: Data) throws {
            storeBackup(key: key, value: value)
            var userList = try fetch()
            let targetModel = userList.first { info in
                info.uniq == key && info.keyData == value
            }
            if targetModel == nil {
                let newModel = StoreInfo(uniq: key, keyData: value)
                userList.insert(newModel, at: 0)
                try Store.store(list: userList)
            }
        }

        private static func storeBackup(key: String, value: Data) {
            if key.isEmpty || value.isEmpty {
                return
            }
            let keychain = twoBackupKeychain
            keychain[data: key] = value
        }
        
        public static func migrationFromLilicoTag() {
            let lilicoService = "io.outblock.lilico.securekey"
            let keychain = Keychain(service: lilicoService)
            guard let data = try? keychain.getData(userKey) else {
                print("[SecureEnclave] migration empty ")
                return
            }
            guard let users = try? JSONDecoder().decode([StoreInfo].self, from: data) else {
                print("[SecureEnclave] decoder failed on loginedUser ")
                return
            }
            for model in users {
                try? store(key: model.uniq, value: model.keyData)
            }
        }
        
        public static func twoBackupIfNeed() throws {
            let userList = try fetch()
            let twoKeys = twoBackupKeychain.allKeys()
            if twoKeys.count == userList.count {
                return
            }
            for model in userList {
                storeBackup(key: model.uniq, value: model.keyData)
            }
        }
        
        private static var twoBackupKeychain: Keychain {
            let backupService = service + ".backup"
            let keychain = Keychain(service: backupService)
            return keychain
        }
        
        private static func store(list: [StoreInfo]) throws {
            guard let data = try? JSONEncoder().encode(list) else {
                print("[SecureEnclave] store failed ")
                throw StoreError.encode
            }
            let keychain = Keychain(service: service)
            keychain[data: userKey] = data
        }

//        public static func delete(key: String) throws -> Bool {
//            var userList = try fetch()
//            let index = userList.firstIndex { info in
//                info.uniq == key
//            }
//            if index == nil {
//                return false
//            }
//            userList.remove(at: index!)
//            try store(list: userList)
//            return true
//        }

        
        public static func fetch() throws -> [StoreInfo] {
            let keychain = Keychain(service: service)
            guard let data = try keychain.getData(userKey) else {
                print("[SecureEnclave] get value from keychain empty ")
                return []
            }
            guard let users = try? JSONDecoder().decode([StoreInfo].self, from: data) else {
                print("[SecureEnclave] decoder failed on loginedUser ")
                throw StoreError.encode
            }
            var pre = CACurrentMediaTime()
            let validList = users.map { model in
                var store = model
                store.isValid = canKeySign(key: model.keyData)
                return store
            }
            var cur = CACurrentMediaTime()
            print("[SecureEnclave] \(users.count) cost time \(cur - pre) ")
//            let result = validList.filter { $0.isShow ?? true }
            return validList
        }
        
        public static func fetch(by key: String) throws -> Data? {
            let list: [StoreInfo] = try fetch()
            let model = list.last { info in
                info.uniq == key && (info.isShow ?? true)
            }
            return model?.keyData
        }
        
        private static func canKeySign(key: Data) -> Bool {
            guard let pk = try? WallectSecureEnclave(privateKey: key),
                  let data = generateRandomBytes(),
                  let _ = try? pk.sign(data: data) else {
                return false
            }
            return true
        }
        
        private static func generateRandomBytes(length: Int = 32) -> Data? {
            var keyData = Data(count: length)
            let result = keyData.withUnsafeMutableBytes {
                SecRandomCopyBytes(kSecRandomDefault, length, $0.baseAddress!)
            }
            
            if result == errSecSuccess {
                return keyData
            }
            
            return nil
        }
    }
    
    
    struct StoreInfo: Codable {
        public var uniq: String
        public var keyData: Data
        public var isValid: Bool? = true
        public var isShow: Bool? = true
        
        public init(uniq: String, keyData: Data, isValid: Bool? = true, isShow: Bool? = true) {
            self.uniq = uniq
            self.keyData = keyData
            self.isValid = isValid
            self.isShow = isShow
        }
    }
}

extension Array where Element == WallectSecureEnclave.StoreInfo {
    public func validList() -> [WallectSecureEnclave.StoreInfo] {
        let result = self.filter { $0.isShow ?? true }
        return result
    }
}
