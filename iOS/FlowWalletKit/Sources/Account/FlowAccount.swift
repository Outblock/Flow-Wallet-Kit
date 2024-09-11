//
//  File.swift
//
//
//  Created by Hao Fu on 18/7/2024.
//

import Flow
import Foundation

public protocol ProxyProtocol {
    associatedtype Wallet

    static func get(id: String) throws -> Wallet

    func store(id: String, password: String, sync: Bool) throws
    func isValidSignature(signature: Data, message: Data, signAlgo: Flow.SignatureAlgorithm) -> Bool
    func publicKey(signAlgo: Flow.SignatureAlgorithm) throws -> Data
    func sign(data: Data, signAlgo: Flow.SignatureAlgorithm, hashAlgo: Flow.HashAlgorithm) throws -> Data
    func remove(id: String) throws
}

enum FlowAccountType {
    case key(any KeyProtocol)
    case proxy(any ProxyProtocol)
    case watch(Flow.Address)
    case child(Flow.Address)
    case vm(FlowVM)
}

@MainActor
struct FlowAccount {
    var childs: [FlowAccount]?

    var hasChild: Bool {
        !(childs?.isEmpty ?? true)
    }

    var vm: [FlowAccount]?

    var hasVM: Bool {
        !(vm?.isEmpty ?? true)
    }

    var address: Flow.Address

    init(address: Flow.Address) {
        self.address = address
        fetchChild()
        fetchVM()
    }

    func fetchChild() {
        // TODO: add fetch child accounts logic
        // Task {
        // flow.accessAPI.executeScriptAtLatestBlock(cadence: "").decode()
    }

    func fetchVM() {
        // TODO: add fetch VM accounts logic
        // Task {
        // flow.accessAPI.executeScriptAtLatestBlock(cadence: "").decode()
    }
}
