//
//  Targets.swift
//  Адреса дата-центров и домены WebSocket-шлюза Telegram Web.
//

import Foundation

enum Targets {
    static let dcDefaultIPs: [Int: String] = [
        1: "149.154.175.50",
        2: "149.154.167.51",
        3: "149.154.175.100",
        4: "149.154.167.91",
        5: "149.154.171.5",
        203: "91.105.192.100",
    ]

    static let dcTitles: [Int: String] = [
        1: "DC1 · Амстердам",
        2: "DC2 · Амстердам",
        3: "DC3 · Лондон",
        4: "DC4 · Майами",
        5: "DC5 · Сингапур",
        203: "DC203 · Амстердам (медиа → DC2)",
    ]

    /// DC, у которого нет своего WS-шлюза: пул берёт домен другого.
    private static let dcOverrides: [Int: Int] = [203: 2]

    static func wsDomains(dc: Int, isMedia: Bool) -> [String] {
        let effective = dcOverrides[dc] ?? dc
        let primary = "kws\(effective).web.telegram.org"
        let secondary = "kws\(effective)-1.web.telegram.org"
        return isMedia ? [secondary, primary] : [primary, secondary]
    }

    static func fallbackIp(dc: Int) -> String? { dcDefaultIPs[dc] }

    /// Пользовательский адрес DC: для медиа ключ хранится как -dc.
    static func configuredTarget(_ overrides: [Int: String], dc: Int, isMedia: Bool) -> String? {
        if isMedia, let media = overrides[-dc], !media.isEmpty { return media }
        guard let value = overrides[dc] else { return nil }
        return value.isEmpty ? nil : value
    }

    static func telegramLink(port: Int, secretHex: String) -> String {
        "tg://proxy?server=127.0.0.1&port=\(port)&secret=\(secretHex.lowercased())"
    }
}
