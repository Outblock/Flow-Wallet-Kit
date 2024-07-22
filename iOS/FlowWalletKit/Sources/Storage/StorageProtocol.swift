//
//  File.swift
//  
//
//  Created by Hao Fu on 22/7/2024.
//

import Foundation

public protocol StorageProtocol {
//    associatedtype Key
//    associatedtype Value
    
    var allKeys: [String] { get }
    func get(_ key: String) throws -> Data?
    func set(_ key: String, value: Data) throws
    func remove(_ key: String) throws
    func removeAll() throws
}
