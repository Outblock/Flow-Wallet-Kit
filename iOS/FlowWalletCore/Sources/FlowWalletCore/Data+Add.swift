//
//  File.swift
//  
//
//  Created by cat on 2023/11/14.
//

import Foundation

public extension Data {
    
    var hexValue: String {
        return reduce("") { $0 + String(format: "%02x", $1) }
    }
}
