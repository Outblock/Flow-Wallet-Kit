//
//  Item.swift
//  FWKDemo
//
//  Created by Hao Fu on 1/5/2024.
//

import Foundation
import SwiftData

@Model
final class Item {
    var timestamp: Date
    
    init(timestamp: Date) {
        self.timestamp = timestamp
    }
}
