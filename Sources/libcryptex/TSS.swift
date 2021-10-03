//
//  TSS.swift
//  libcryptex
//
//  Created by Linus Henze on 2021-09-29.
//  Copyright © 2021 Pinauten GmbH. All rights reserved.
//  

import Foundation
import Swift_libimobiledevice

public enum TSSDeviceInfoError: Error {
    case noApBoardID
    case noApChipID
    case noApECID
}

public struct TSSDeviceInfo {
    public let EPRO: Bool            // = true
    public let ESEC: Bool            // = true
    public let ApBoardID: Int
    public let ApChipID: Int
    public let ApECID: Int
    public let ApSecurityDomain: Int // = 1
    public let CryptexNonce: Data
    
    public init(EPRO: Bool, ESEC: Bool, ApBoardID: Int, ApChipID: Int, ApECID: Int, ApSecurityDomain: Int, CryptexNonce: Data) {
        self.EPRO             = EPRO
        self.ESEC             = ESEC
        self.ApBoardID        = ApBoardID
        self.ApChipID         = ApChipID
        self.ApECID           = ApECID
        self.ApSecurityDomain = ApSecurityDomain
        self.CryptexNonce     = CryptexNonce
    }
    
    public init(device: iDevice) throws {
        let props = try device.getProperties()
        
        guard let ApBoardID = props["BoardId"] as? Int else {
            throw TSSDeviceInfoError.noApBoardID
        }
        guard let ApChipID = props["ChipID"] as? Int else {
            throw TSSDeviceInfoError.noApChipID
        }
        guard let ApECID = props["UniqueChipID"] as? Int else {
            throw TSSDeviceInfoError.noApECID
        }
        
        let mounter = try MobileImageMounter(device: device)
        let nonce   = try mounter.getCryptexNonce()
        
        self.init(EPRO: true, ESEC: true, ApBoardID: ApBoardID, ApChipID: ApChipID, ApECID: ApECID, ApSecurityDomain: 1, CryptexNonce: nonce)
    }
}

public enum TSSSignError: Error {
    case emptyReply
    case failedToDecodeReply
    case badReplyStart
    case invalidReplyStatus
    case badReplyStatus(statusCode: Int, message: String)
    case noBody
    case replyNotAPlist
    case noSignatureInReply
}

public func TSSSign(cryptex: CryptexInfo, forDevice device: TSSDeviceInfo) throws -> Data {
    let request = [
        "@ApImg4Ticket": true,
        "@BBTicket": true,
        "@HostPlatformInfo": "mac",
        "@VersionInfo": "libauthinstall-850.0.1.0.1",
        "Ap,CryptexInfoPlist": [
            "Digest": cryptex.infoPlistDigest,
            "EPRO": device.EPRO,
            "ESEC": device.ESEC,
            "Trusted": true
        ],
        "ApBoardID": device.ApBoardID,
        "ApChipID": device.ApChipID,
        "ApECID": device.ApECID,
        "ApNonce": device.CryptexNonce,
        "ApProductionMode": device.EPRO,
        "ApSecurityDomain": device.ApSecurityDomain,
        "ApSecurityMode": device.ESEC,
        "CryptexDMG": [
            "Digest": cryptex.dmgDigest,
            "Name": cryptex.identifier,
            "EPRO": device.EPRO,
            "ESEC": device.ESEC,
            "Trusted": true
        ],
        "LoadableTrustCache": [
            "Digest": cryptex.trustCacheDigest,
            "EPRO": device.EPRO,
            "ESEC": device.ESEC,
            "Trusted": true
        ],
        "SepNonce": Data(repeating: 0, count: 20)
    ] as [String: Any]
    
    let requestPlist = try PropertyListSerialization.data(fromPropertyList: request, format: .xml, options: .zero)
    
    var urlRequest = URLRequest(url: URL(string: "http://gs.apple.com/TSS/controller?action=2")!)
    urlRequest.httpMethod = "POST"
    urlRequest.setValue(#"text/xml; charset="utf-8""#, forHTTPHeaderField: "Content-Type")
    urlRequest.setValue("libcryptex/0.0.1 (Pinauten GmbH)", forHTTPHeaderField: "User-Agent")
    urlRequest.httpBody = requestPlist
    
    let requestLock = NSLock()
    requestLock.lock()
    
    var resultSig: Data?
    var resultError: Error?
    
    URLSession.shared.dataTask(with: urlRequest) { data, result, error in
        defer { requestLock.unlock() }
        
        guard data != nil && data!.count > 0 else {
            resultError = TSSSignError.emptyReply
            return
        }
        
        guard let res = String(data: data!, encoding: .utf8) else {
            resultError = TSSSignError.failedToDecodeReply
            return
        }
        
        let resultPattern = #"^STATUS=(\d+)&MESSAGE=([A-Za-z0-9_\-%]*)(?:&REQUEST_STRING=(.*))?$"#
        
        let expr = try! NSRegularExpression(pattern: resultPattern, options: .dotMatchesLineSeparators)
        let range = NSRange(res.startIndex..<res.endIndex, in: res)
        let match = expr.firstMatch(in: res, options: [], range: range)
        
        guard match != nil else {
            resultError = TSSSignError.badReplyStart
            return
        }
        
        guard let status = Int(String(res[Range(match!.range(at: 1), in: res)!])) else {
            resultError = TSSSignError.invalidReplyStatus
            return
        }
        
        guard status == 0 else {
            let message = String(res[Range(match!.range(at: 2), in: res)!])
            
            resultError = TSSSignError.badReplyStatus(statusCode: status, message: message)
            return
        }
        
        guard match!.numberOfRanges == 4 else {
            resultError = TSSSignError.noBody
            return
        }
        
        let body = String(res[Range(match!.range(at: 3), in: res)!])
        
        guard let parsed = try? PropertyListSerialization.propertyList(from: body.data(using: .utf8)!, options: [], format: nil) as? [String: Any] else {
            resultError = TSSSignError.replyNotAPlist
            return
        }
        
        guard let signature = parsed["ApImg4Ticket"] as? Data else {
            resultError = TSSSignError.noSignatureInReply
            return
        }
        
        resultSig = signature
    }.resume()
    
    // Wait for the download to finish
    requestLock.lock()
    
    guard resultSig != nil else {
        throw resultError!
    }
    
    return resultSig.unsafelyUnwrapped
}
