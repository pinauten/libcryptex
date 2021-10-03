//
//  Hashing.swift
//  libcryptex
//
//  Created by Linus Henze on 2021-09-29.
//  Copyright © 2021 Pinauten GmbH. All rights reserved.
//  

import Foundation
import CommonCrypto

public func getSHA384Digest(of data: Data) -> Data {
    var hash = Array<UInt8>(repeating: 0, count: Int(CC_SHA384_DIGEST_LENGTH))
    data.withUnsafeBytes { ptr in
        _ = CC_SHA384(ptr.baseAddress, CC_LONG(data.count), &hash)
    }
    
    return Data(hash)
}
