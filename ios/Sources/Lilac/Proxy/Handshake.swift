//
//  Handshake.swift
//  64-байтный init: разбор клиентского и генерация relay-init для стороны DC.
//

import Foundation

let protoAbridged: Int32 = Int32(bitPattern: 0xEFEFEFEF)
let protoIntermediate: Int32 = Int32(bitPattern: 0xEEEEEEEE)
let protoPaddedIntermediate: Int32 = Int32(bitPattern: 0xDDDDDDDD)

let protoTypeAbridged = 0
let protoTypeIntermediate = 1
let protoTypePaddedIntermediate = 2

func validProto(_ proto: Int32) -> Bool {
    proto == protoAbridged || proto == protoIntermediate || proto == protoPaddedIntermediate
}

func protoTagToType(_ proto: Int32) -> Int {
    switch proto {
    case protoIntermediate: return protoTypeIntermediate
    case protoPaddedIntermediate: return protoTypePaddedIntermediate
    default: return protoTypeAbridged
    }
}

/// Что прокси вычитал из 64-байтного init клиента.
struct ClientInit {
    let proto: Int32
    let dc: Int
    let isMedia: Bool

    var tag: String { isMedia ? " DC\(dc)-M" : " DC\(dc)" }
}

enum Handshake {
    /// Разбирает уже расшифрованный init. Поток остаётся у вызывающей стороны.
    static func clientInit(_ plain: Data) -> ClientInit? {
        guard plain.count >= Obfs2.handshakeSize else { return nil }
        let proto = plain.leInt(at: 56)
        guard validProto(proto) else { return nil }
        let rawDc = plain.leShort(at: 60)
        return ClientInit(proto: proto, dc: abs(Int(rawDc)), isMedia: rawDc < 0)
    }

    static func isHttpTransport(_ data: Data) -> Bool {
        guard data.count >= 4 else { return false }
        let prefixes = ["POST", "GET ", "HEAD", "OPTIO"]
        let head = String(decoding: data.prefix(5), as: UTF8.self)
        return prefixes.contains { head.hasPrefix($0) }
    }

    /// init не должен напоминать HTTP, TLS hello или известный тег протокола.
    private static func usableRelayInit(_ init_: Data) -> Bool {
        guard init_[init_.startIndex] != 0xEF else { return false }
        let head = Array(init_.prefix(4))
        let banned: [[UInt8]] = [
            Array("HEAD".utf8), Array("POST".utf8), Array("GET ".utf8),
            [0xEE, 0xEE, 0xEE, 0xEE], [0xDD, 0xDD, 0xDD, 0xDD], [0x16, 0x03, 0x01, 0x02],
        ]
        if banned.contains { $0 == head } { return false }
        return Array(init_.prefix(8).dropFirst(4)).contains { $0 != 0 }
    }

    /// 64-байтный init на сторону DC: хвост подгоняется так, чтобы после шифрования
    /// там прочитались нужный proto tag и номер DC.
    static func relayInit(proto: Int32, dc: Int, isMedia: Bool) -> Data? {
        var init_ = Data()
        while true {
            let candidate = Obfs2.randomBytes(Obfs2.handshakeSize)
            if usableRelayInit(candidate) { init_ = candidate; break }
        }

        var tail = Data(count: 8)
        tail.writeLeInt(proto, at: 0)
        tail.writeLeShort(Int16(dc * (isMedia ? -1 : 1)), at: 4)
        tail.replaceSubrange(6 ..< 8, with: Obfs2.randomBytes(2))

        guard let encryptor = Obfs2.relayEncryptor(init_) else { return nil }
        var encrypted = init_
        guard encryptor.xor(&encrypted) else { return nil }

        for index in 0 ..< 8 {
            let keystream = encrypted[encrypted.startIndex + 56 + index] ^ init_[init_.startIndex + 56 + index]
            init_[init_.startIndex + 56 + index] = tail[tail.startIndex + index] ^ keystream
        }
        return init_
    }
}
