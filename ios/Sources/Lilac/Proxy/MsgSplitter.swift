//
//  MsgSplitter.swift
//  Нарезка восходящего потока на цельные MTProto-сообщения для WebSocket-фреймов.
//

import Foundation

final class MsgSplitter {
    private let stream: AesCtrStream
    private let protoType: Int
    private var cipherBuf = Data()
    private var plainBuf = Data()
    private var disabled = false

    init?(relayInit: Data, proto: Int32) {
        guard let stream = Obfs2.relayEncryptor(relayInit) else { return nil }
        var skip = Data(count: Obfs2.handshakeSize)
        guard stream.xor(&skip) else { return nil }
        self.stream = stream
        self.protoType = protoTagToType(proto)
    }

    func split(_ chunk: Data) -> [Data] {
        if chunk.isEmpty { return [] }
        if disabled { return [chunk] }

        cipherBuf.append(chunk)
        var decrypted = chunk
        guard stream.xor(&decrypted) else { return [cipherBuf] }
        plainBuf.append(decrypted)

        var parts = [Data]()
        while !cipherBuf.isEmpty {
            let packetLen = nextPacketLen()
            if packetLen < 0 { break }
            if packetLen == 0 {
                parts.append(cipherBuf)
                cipherBuf.removeAll(keepingCapacity: false)
                plainBuf.removeAll(keepingCapacity: false)
                disabled = true
                break
            }
            if cipherBuf.count < packetLen { break }
            parts.append(take(from: &cipherBuf, packetLen))
            plainBuf.removeFirst(packetLen)
        }
        if cipherBuf.isEmpty {
            cipherBuf.removeAll(keepingCapacity: false)
            plainBuf.removeAll(keepingCapacity: false)
        }
        return parts
    }

    /// Хвост при закрытии соединения: недобранное сообщение отправляем как есть.
    func flush() -> [Data] {
        guard !cipherBuf.isEmpty else { return [] }
        let tail = cipherBuf
        cipherBuf.removeAll(keepingCapacity: false)
        plainBuf.removeAll(keepingCapacity: false)
        return [tail]
    }

    /// -1 — данных пока мало, 0 — поток больше не похож на MTProto.
    private func nextPacketLen() -> Int {
        guard !plainBuf.isEmpty else { return -1 }
        switch protoType {
        case protoTypeAbridged:
            let first = Int(plainBuf[plainBuf.startIndex]) & 0x7F
            let headerLen: Int
            let payloadLen: Int
            if first == 0x7F {
                guard plainBuf.count >= 4 else { return -1 }
                payloadLen = (Int(plainBuf[plainBuf.startIndex + 1])
                    | Int(plainBuf[plainBuf.startIndex + 2]) << 8
                    | Int(plainBuf[plainBuf.startIndex + 3]) << 16) * 4
                headerLen = 4
            } else {
                payloadLen = first * 4
                headerLen = 1
            }
            if payloadLen <= 0 { return 0 }
            let packetLen = headerLen + payloadLen
            return plainBuf.count < packetLen ? -1 : packetLen

        case protoTypeIntermediate, protoTypePaddedIntermediate:
            guard plainBuf.count >= 4 else { return -1 }
            let payloadLen = Int(plainBuf.leInt(at: 0) & 0x7FFFFFFF)
            if payloadLen <= 0 { return 0 }
            let packetLen = 4 + payloadLen
            return plainBuf.count < packetLen ? -1 : packetLen

        default:
            return 0
        }
    }

    private func take(from buffer: inout Data, _ count: Int) -> Data {
        let piece = buffer.subdata(in: buffer.startIndex ..< buffer.startIndex + count)
        buffer.removeFirst(count)
        return piece
    }
}
