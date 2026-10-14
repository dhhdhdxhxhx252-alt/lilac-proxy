//
//  ProxyStats.swift + LogStore.swift
//  Счётчики для экрана статистики и кольцевой буфер журнала.
//

import Foundation

final class ProxyStats {
    private let state = NSLock()
    private var values: [String: Int64] = [:]

    enum Key {
        static let connectionsTotal = "connections_total"
        static let connectionsActive = "connections_active"
        static let connectionsWs = "connections_ws"
        static let connectionsTcp = "connections_tcp"
        static let connectionsBad = "connections_bad"
        static let bytesUp = "bytes_up"
        static let bytesDown = "bytes_down"
    }

    func add(_ key: String, _ delta: Int64) {
        state.lock()
        values[key, default: 0] += delta
        state.unlock()
    }

    func set(_ key: String, _ value: Int64) {
        state.lock()
        values[key] = value
        state.unlock()
    }

    func value(_ key: String) -> Int64 {
        state.lock()
        defer { state.unlock() }
        return values[key] ?? 0
    }

    var lastError: String?

    func reset() {
        state.lock()
        values.removeAll()
        state.unlock()
        lastError = nil
    }
}

/// Кольцевой буфер строк для экрана логов.
final class LogStore: ObservableObject {
    static let maxLines = 400

    @Published private(set) var lines: [String] = []
    private let formatter: DateFormatter = {
        let formatter = DateFormatter()
        formatter.dateFormat = "HH:mm:ss"
        return formatter
    }()

    func add(_ message: String) {
        let line = "\(formatter.string(from: Date())) \(message)"
        DispatchQueue.main.async {
            self.lines.append(line)
            if self.lines.count > LogStore.maxLines {
                self.lines.removeFirst(self.lines.count - LogStore.maxLines)
            }
        }
    }

    func clear() {
        DispatchQueue.main.async { self.lines = [] }
    }
}

func humanBytes(_ bytes: Int64) -> String {
    let units = ["Б", "КБ", "МБ", "ГБ", "ТБ"]
    var value = Double(bytes)
    var index = 0
    while value >= 1024 && index < units.count - 1 {
        value /= 1024
        index += 1
    }
    return index == 0 ? "\(bytes) \(units[0])" : String(format: "%.1f %@", value, units[index])
}
