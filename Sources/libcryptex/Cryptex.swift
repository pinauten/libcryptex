//
//  Cryptex.swift
//  libcryptex
//
//  Created by Linus Henze on 2021-09-29.
//  Copyright © 2021 Pinauten GmbH. All rights reserved.
//  

import Foundation

public struct CryptexInfo {
    public let identifier: String
    public let version: String
    public let infoPlist: Data?
    public let infoPlistDigest: Data
    public let dmgDigest: Data
    public let trustCacheDigest: Data
    
    public init(identifier: String, version: String, infoPlistDigest: Data, dmgDigest: Data, trustCacheDigest: Data) {
        self.identifier = identifier
        self.version = version
        self.infoPlist = nil
        self.infoPlistDigest = infoPlistDigest
        self.dmgDigest = dmgDigest
        self.trustCacheDigest = trustCacheDigest
    }
    
    public init(identifier: String, version: String, dmg: Data, trustCache: Data) {
        let plist = createCryptexInfoPlist(identifier: identifier, version: version)
        
        self.identifier = identifier
        self.version = version
        self.infoPlist = plist
        self.infoPlistDigest = getSHA384Digest(of: plist)
        self.dmgDigest = getSHA384Digest(of: dmg)
        self.trustCacheDigest = getSHA384Digest(of: trustCache)
    }
}

public func createCryptexInfoPlist(identifier: String, version: String) -> Data {
    return try! PropertyListSerialization.data(fromPropertyList: ["CFBundleIdentifier": identifier, "CFBundleVersion": version], format: .xml, options: .zero)
}
