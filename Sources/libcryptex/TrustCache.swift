//
//  TrustCache.swift
//  libcryptex
//
//  Created by Linus Henze on 2021-10-01.
//  Copyright © 2021 Pinauten GmbH. All rights reserved.
//  

import Foundation
import SwiftUtils
import Security

public func getCDHash(ofFile path: String) -> Data? {
    var staticCode: SecStaticCode?
    guard SecStaticCodeCreateWithPath(URL(fileURLWithPath: path) as CFURL, .init(), &staticCode) == errSecSuccess else {
        return nil
    }
    
    var infos: CFDictionary?
    guard SecCodeCopySigningInformation(staticCode!, .init(), &infos) == errSecSuccess else {
        return nil
    }
    
    guard let sInfos = infos as? [String: Any] else {
        return nil
    }
    
    guard let cdHashes = sInfos["cdhashes"] as? [Data] else {
        return nil
    }
    
    guard cdHashes.count >= 1 else {
        return nil
    }
    
    return cdHashes[0]
}

public func buildTrustCache(hashes: [Data], wrapInIM4P: Bool = false) -> Data {
    var hashes = hashes
    
    // First remove all duplicates
    var hashDupl: [Data] = []
    hashes.removeAll { dat in
        if hashDupl.contains(dat) {
            return true
        }
        
        hashDupl.append(dat)
        
        return false
    }
    
    // Then sort
    hashes.sort { a, b in
        assert(a.count == 20)
        assert(b.count == 20)
        
        for i in 0..<20 {
            if a[i] < b[i] {
                return true
            } else if a[i] > b[i] {
                return false
            }
        }
        
        return false
    }
    
    // Generate a random trust cache UUID
    var randUUID = UUID().uuid
    
    // Trust Cache Format
    // 0x0  -> Version
    // 0x4  -> UUID (16 bytes)
    // 0x14 -> Number of entries
    var tc = Data(fromObject: 1 as UInt32)        // Version
    tc.append(Data(bytes: &randUUID, count: 16))  // UUID
    tc.appendGeneric(value: UInt32(hashes.count)) // Count
    for i in 0..<hashes.count {
        tc.append(hashes[i])
    }
    
    if wrapInIM4P {
        // Wrap in IM4P
        func countBytes(ofNumber n: UInt32) -> Int {
            if (n >> 24) != 0 {
                return 4
            } else if (n >> 16) != 0 {
                return 3
            } else if (n >> 8) != 0 {
                return 2
            } else {
                return 1
            }
        }
        
        let countInner = countBytes(ofNumber: UInt32(tc.count))
        let countOuter = countBytes(ofNumber: UInt32(tc.count + 20 + countInner))
        
        var im4p = Data(fromObject: ((0x3080 as UInt16) | UInt16(countOuter)).bigEndian)
        im4p.append(contentsOf: Data(fromObject: UInt32(tc.count + 20 + countInner))[..<countOuter].reversed())
        im4p.append(Data([0x16, 0x04, 0x49, 0x4D, 0x34, 0x50, 0x16, 0x04, 0x6C, 0x74, 0x72, 0x73, 0x16, 0x04, 0x63, 0x70, 0x74, 0x78, 0x04, 0x80 + UInt8(countInner)] as [UInt8]))
        im4p.append(contentsOf: Data(fromObject: UInt32(tc.count))[..<countInner].reversed())
        im4p.append(tc)
        
        return im4p
    } else {
        return tc
    }
}

public enum TrustCacheCreateError: Error {
    case folderDoesNotExist
    case notAFolder
    case cannotReadFolder
}

public func buildTrustCache(fromPath cryptexPath: String, wrapInIM4P: Bool = false) throws -> Data {
    var isDir: ObjCBool = false
    guard FileManager.default.fileExists(atPath: cryptexPath, isDirectory: &isDir) else {
        throw TrustCacheCreateError.folderDoesNotExist
    }
    
    guard isDir.boolValue else {
        throw TrustCacheCreateError.notAFolder
    }
    
    guard let enumerator = FileManager.default.enumerator(atPath: cryptexPath) else {
        throw TrustCacheCreateError.cannotReadFolder
    }
    
    var hashes: [Data] = []
    
    for entry in enumerator {
        let path = cryptexPath + "/" + (entry as! String)
        
        var isDir: ObjCBool = false
        if FileManager.default.fileExists(atPath: path, isDirectory: &isDir),
           !isDir.boolValue {
            if let cdHash = getCDHash(ofFile: path) {
                hashes.append(cdHash[..<20] + Data(fromObject: 2 as UInt16))
            }
        }
    }
    
    return buildTrustCache(hashes: hashes, wrapInIM4P: wrapInIM4P)
}
