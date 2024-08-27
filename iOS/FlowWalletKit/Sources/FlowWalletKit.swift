// The Swift Programming Language
// https://docs.swift.org/swift-book

import WalletCore
import Flow
import KeychainAccess

class FlowWalletKit {
    static let shared = FlowWalletKit()
    private static var config: Config?
    
    let storage: any StorageProtocol
    
    class func setup(_ config: Config){
         FlowWalletKit.config = config
     }
     
     private init() {
         guard let config = FlowWalletKit.config else {
             fatalError("Error - you must call setup before accessing FlowWalletKit.shared")
         }
         self.storage = config.storage
     }
}


extension FlowWalletKit {
    
    struct Config {
        let storage: any StorageProtocol
    }
}
