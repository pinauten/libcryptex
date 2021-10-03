//
//  Install.swift
//  libcryptex
//
//  Created by Linus Henze on 2021-09-29.
//  Copyright © 2021 Pinauten GmbH. All rights reserved.
//  

import Foundation
import Swift_libimobiledevice

public enum CPTXError: Error {
    case dirDoesNotExist
}

public extension MobileImageMounter {
    @discardableResult
    func installCryptex(cptxPath: String) throws -> [String: Any] {
        var isDir = ObjCBool(false)
        guard FileManager.default.fileExists(atPath: cptxPath, isDirectory: &isDir),
        isDir.boolValue else {
            throw CPTXError.dirDoesNotExist
        }
        
        let basePath = URL(fileURLWithPath: cptxPath)
        
        let trustCache = try Data(contentsOf: basePath.appendingPathComponent("ltrs"))
        let infoPlist  = try Data(contentsOf: basePath.appendingPathComponent("c411"))
        let signature  = try Data(contentsOf: basePath.appendingPathComponent("im4m"))
        let cryptex    = try Data(contentsOf: basePath.appendingPathComponent("cpxd"))
        
        return try installCryptex(trustCache: trustCache, infoPlist: infoPlist, signature: signature, cryptex: cryptex)
    }
}
