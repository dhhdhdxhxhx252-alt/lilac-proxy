//
//  Obfs2.swift
//  AES-256-CTR потоки и вывод ключей из MTProto-секрета.
//  Порт Kotlin-версии dev.lilac.proxy.Obfs2 — окна байтов и порядок хешей совпадают.
//

import Foundation
import CommonCrypto

/// Один поток ключей AES-CTR. XOR симметричен, поэтому режим всегда «шифрование».
final class AesCtrStream {
    private let key: Data
    private let iv: Data
    private var cryptor: CCCryptorRef?
    private(set) var processed: UInt64 = 0

    init?(key: Data, iv: Data) {
        guard key.count == 32, iv.count == 16 else { return nil }
        self.key = key
        self.iv = iv

        var status = CCCryptorStatus(kCCParamError)
        key.withUnsafeBytes { keyPointer in
            iv.withUnsafeBytes { ivPointer in
                status = CCCryptorCreateWithMode(
                    CCEncrypt,
                    CCMode(kCCModeCTR),
                    CCAlgorithm(kCCAlgorithmAES),
                    CCPadding(ccNoPadding),
                    ivPointer.baseAddress,
                    keyPointer.baseAddress,
                    keyPointer.count,
                    nil,
                    0,
                    CCModeOptions(kCCModeOptionCTR_BE),
                    &cryptor
                )
            }
        }
        guard status == kCCSuccess, cryptor != nil else { return nil }
    }

    deinit {
        if let cryptor { CCCryptorRelease(cryptor) }
    }

    /// XOR байтов на месте. false — CommonCrypto отказался обрабатывать кусок.
    @discardableResult
    func xor(_ data: inout Data) -> Bool {
        guard !data.isEmpty else { return true }
        let length = data.count
        var moved = 0
        let status = data.withUnsafeMutableBytes { buffer in
            CCCryptorUpdate(cryptor, buffer.baseAddress, length,
                            buffer.baseAddress, length, &moved)
        }
        guard status == kCCSuccess, moved == length else { return false }
        processed += UInt64(length)
        return true
    }

    /// Поток с тем же состоянием: CommonCrypto нельзя скопировать, поэтому проматываем keystream.
    func copy() -> AesCtrStream? {
        guard let clone = AesCtrStream(key: key, iv: iv) else { return nil }
        clone.advance(processed)
        return clone
    }

    private func advance(_ bytes: UInt64) {
        var rest = bytes
        while rest > 0 {
            let chunk = Int(min(rest, 8192))
            var buffer = Data(count: chunk)
            _ = xor(&buffer)
            rest -= UInt64(chunk)
        }
    }
}

enum Obfs2 {
    static let handshakeSize = 64

    static func sha256(_ parts: Data...) -> Data {
        var context = CC_SHA256_CTX()
        CC_SHA256_Init(&context)
        for part in parts {
            part.withUnsafeBytes { buffer in
                _ = CC_SHA256_Update(&context, buffer.baseAddress, CC_LONG(buffer.count))
            }
        }
        var digest = Data(count: Int(CC_SHA256_DIGEST_LENGTH))
        digest.withUnsafeMutableBytes { buffer in
            _ = CC_SHA256_Final(buffer.bindMemory(to: UInt8.self).baseAddress, &context)
        }
        return digest
    }

    /// Секрет прокси — 32 hex-символа (16 байт), как в простой схеме obfs2.
    static func parseSecret(_ hex: String) -> Data? {
        let clean = hex.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        guard clean.count == 32 else { return nil }
        return Data(hexString: clean)
    }

    static func hex(_ data: Data) -> String {
        data.map { String(format: "%02x", $0) }.joined()
    }

    static func randomBytes(_ count: Int) -> Data {
        var data = Data(count: count)
        _ = data.withUnsafeMutableBytes { buffer in
            SecRandomCopyBytes(kSecRandomDefault, count, buffer.baseAddress!)
        }
        return data
    }

    /// Ключи потока, которым расшифровывается то, что прислал Telegram.
    static func clientDecryptor(_ init: Data, secret: Data) -> AesCtrStream? {
        AesCtrStream(key: sha256(slice(init, 8, 40), secret), iv: slice(init, 40, 56))
    }

    /// Ключи потока, которым отвечает клиенту: перевёрнутое окно init + секрет.
    static func clientEncryptor(_ init: Data, secret: Data) -> AesCtrStream? {
        let reversed = reversedWindow(init)
        return AesCtrStream(key: sha256(slice(reversed, 0, 32), secret), iv: slice(reversed, 32, 48))
    }

    /// Поток шифрования на сторону DC: секрета нет, ключи берутся из relay-init напрямую.
    static func relayEncryptor(_ relayInit: Data) -> AesCtrStream? {
        AesCtrStream(key: slice(relayInit, 8, 40), iv: slice(relayInit, 40, 56))
    }

    static func relayDecryptor(_ relayInit: Data) -> AesCtrStream? {
        let reversed = reversedWindow(relayInit)
        return AesCtrStream(key: slice(reversed, 0, 32), iv: slice(reversed, 32, 48))
    }

    private static func reversedWindow(_ source: Data) -> Data {
        Data(slice(source, 8, 56).reversed())
    }

    static func slice(_ data: Data, _ from: Int, _ to: Int) -> Data {
        data.subdata(in: data.startIndex + from ..< data.startIndex + to)
    }
}

extension Data {
    init?(hexString: String) {
        guard hexString.count % 2 == 0 else { return nil }
        var bytes = [UInt8]()
        bytes.reserveCapacity(hexString.count / 2)
        var index = hexString.startIndex
        while index < hexString.endIndex {
            let next = hexString.index(index, offsetBy: 2)
            guard let byte = UInt8(hexString[index ..< next], radix: 16) else { return nil }
            bytes.append(byte)
            index = next
        }
        self = Data(bytes)
    }

    func leInt(at offset: Int) -> Int32 {
        let base = startIndex + offset
        return Int32(bitPattern:
            UInt32(self[base]) | UInt32(self[base + 1]) << 8 |
                UInt32(self[base + 2]) << 16 | UInt32(self[base + 3]) << 24)
    }

    func leShort(at offset: Int) -> Int16 {
        let base = startIndex + offset
        return Int16(bitPattern: UInt16(UInt16(self[base]) | UInt16(self[base + 1]) << 8))
    }

    mutating func writeLeInt(_ value: Int32, at offset: Int) {
        let base = startIndex + offset
        let raw = UInt32(bitPattern: value)
        self[base] = UInt8(raw & 0xFF)
        self[base + 1] = UInt8((raw >> 8) & 0xFF)
        self[base + 2] = UInt8((raw >> 16) & 0xFF)
        self[base + 3] = UInt8((raw >> 24) & 0xFF)
    }

    mutating func writeLeShort(_ value: Int16, at offset: Int) {
        let base = startIndex + offset
        let raw = UInt16(bitPattern: value)
        self[base] = UInt8(raw & 0xFF)
        self[base + 1] = UInt8((raw >> 8) & 0xFF)
    }
}
