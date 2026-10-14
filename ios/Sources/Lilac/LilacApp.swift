//
//  LilacApp.swift + ContentView.swift
//  Экраны приложения. Палитра совпадает с Android-версией: фон #0C0B0E, акцент #A578FF.
//

import SwiftUI

extension Color {
    static let lilacBackground = Color(red: 0x0C / 255, green: 0x0B / 255, blue: 0x0E / 255)
    static let lilacSurface = Color(red: 0x15 / 255, green: 0x14 / 255, blue: 0x19 / 255)
    static let lilacAccent = Color(red: 0xA5 / 255, green: 0x78 / 255, blue: 0xFF / 255)
    static let lilacText = Color(red: 0xF2 / 255, green: 0xEF / 255, blue: 0xFA / 255)
    static let lilacMuted = Color(red: 0x8B / 255, green: 0x85 / 255, blue: 0x98 / 255)
    static let lilacLine = Color(red: 0x26 / 255, green: 0x23 / 255, blue: 0x2E / 255)
}

@main
struct LilacApp: App {
    @StateObject private var settings = Settings()
    @StateObject private var controller = ProxyController()

    var body: some Scene {
        WindowGroup {
            ContentView()
                .environmentObject(settings)
                .environmentObject(controller)
                .preferredColorScheme(.dark)
                .onOpenURL { url in
                    // tg://proxy?server=127.0.0.1&port=1443&secret=… — Telegram может открыть ответную ссылку
                    if url.scheme == "lilac" { url.queryValue(for: "secret").map { settings.secretHex = $0 } }
                }
        }
    }
}

extension URL {
    func queryValue(for key: String) -> String? {
        URLComponents(url: self, resolvingAgainstBaseURL: false)?.queryItems?
            .first { $0.name == key }?.value
    }
}

struct SectionCard<Content: View>: View {
    let title: String
    @ViewBuilder var content: Content

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text(title.uppercased())
                .font(.system(size: 11, weight: .semibold))
                .tracking(1.2)
                .foregroundColor(.lilacAccent)
            content
        }
        .padding(16)
        .background(RoundedRectangle(cornerRadius: 16).fill(Color.lilacSurface))
        .overlay(RoundedRectangle(cornerRadius: 16).stroke(Color.lilacLine, lineWidth: 1))
    }
}

struct ContentView: View {
    @EnvironmentObject private var settings: Settings
    @EnvironmentObject private var controller: ProxyController
    @State private var copied: String?

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(spacing: 14) {
                    statusCard
                    accessCard
                    transportCard
                    dcCard
                    statsCard
                    logsCard
                }
                .padding(16)
            }
            .background(Color.lilacBackground.ignoresSafeArea())
            .navigationTitle("Lilac")
            .toolbarColorScheme(.dark, for: .navigationBar)
        }
        .tint(.lilacAccent)
    }

    private var statusCard: some View {
        SectionCard(title: "Статус") {
            HStack {
                Circle()
                    .fill(controller.running ? Color.lilacAccent : Color.lilacMuted)
                    .frame(width: 10, height: 10)
                Text(controller.running
                    ? "Работает на порту \(settings.port)"
                    : "Остановлен")
                    .foregroundColor(.lilacText)
                Spacer()
            }
            Button {
                controller.toggle(settings: settings)
            } label: {
                Text(controller.running ? "Остановить" : "Запустить прокси")
                    .font(.system(size: 16, weight: .semibold))
                    .frame(maxWidth: .infinity)
                    .padding(.vertical, 12)
                    .background(controller.running ? Color.lilacSurface : Color.lilacAccent)
                    .foregroundColor(controller.running ? .lilacAccent : .lilacBackground)
                    .cornerRadius(14)
            }
            if let message = controller.errorMessage {
                Text(message).foregroundColor(.red).font(.system(size: 12))
            }
            Text("iOS приостанавливает приложение через несколько секунд — прокси живёт только пока приложение активно. Включите удержание по геопозиции и не сворачивайте экран.")
                .font(.system(size: 12))
                .foregroundColor(.lilacMuted)
        }
    }

    private var accessCard: some View {
        SectionCard(title: "Доступ") {
            VStack(alignment: .leading, spacing: 8) {
                Text("Секрет прокси (32 hex)").font(.system(size: 12)).foregroundColor(.lilacMuted)
                HStack {
                    TextField("0000…", text: $settings.secretHex)
                        .font(.system(.body, design: .monospaced))
                        .autocorrectionDisabled()
                        .textInputAutocapitalization(.never)
                    Button("Новый") { settings.secretHex = Settings.randomSecretHex() }
                }
                HStack {
                    Button("Скопировать ссылку") {
                        copied = Targets.telegramLink(port: settings.port, secretHex: settings.secretHex)
                    }
                    Link("Открыть в Telegram",
                         destination: URL(string: Targets.telegramLink(port: settings.port,
                                                                       secretHex: settings.secretHex))!)
                }
                .font(.system(size: 13))
                if let copied {
                    Text(copied).font(.system(size: 11, design: .monospaced)).foregroundColor(.lilacMuted)
                }
            }
        }
    }

    private var transportCard: some View {
        SectionCard(title: "Транспорт") {
            VStack(spacing: 8) {
                HStack {
                    Text("Порт на 127.0.0.1").foregroundColor(.lilacText)
                    Spacer()
                    TextField("", value: $settings.port, format: .number)
                        .multilineTextAlignment(.trailing)
                        .frame(width: 90)
                        .keyboardType(.numberPad)
                }
                Toggle("Сначала WebSocket (kws*.web.telegram.org)", isOn: $settings.preferWs)
                Toggle("Разрешить прямой TCP к DC", isOn: $settings.tcpFallback)
            }
            .font(.system(size: 13))
        }
    }

    private var dcCard: some View {
        SectionCard(title: "Дата-центры") {
            ForEach(Targets.dcDefaultIPs.keys.sorted(), id: \.self) { dc in
                VStack(alignment: .leading, spacing: 4) {
                    HStack {
                        Text(Targets.dcTitles[dc] ?? "DC\(dc)").foregroundColor(.lilacText)
                        Spacer()
                        Text(Targets.dcDefaultIPs[dc] ?? "")
                            .font(.system(size: 11, design: .monospaced))
                            .foregroundColor(.lilacMuted)
                    }
                    TextField("свой адрес для TCP", text: binding(for: dc))
                        .font(.system(size: 12, design: .monospaced))
                        .textInputAutocapitalization(.never)
                }
                .padding(.vertical, 4)
                Divider().overlay(Color.lilacLine)
            }
        }
    }

    private var statsCard: some View {
        SectionCard(title: "Статистика") {
            VStack(spacing: 6) {
                row("Соединений всего", "\(controller.stat(ProxyStats.Key.connectionsTotal))")
                row("Активных", "\(controller.stat(ProxyStats.Key.connectionsActive))")
                row("Через WS", "\(controller.stat(ProxyStats.Key.connectionsWs))")
                row("Через TCP", "\(controller.stat(ProxyStats.Key.connectionsTcp))")
                row("Отклонено", "\(controller.stat(ProxyStats.Key.connectionsBad))")
                row("Отправлено", humanBytes(controller.stat(ProxyStats.Key.bytesUp)))
                row("Получено", humanBytes(controller.stat(ProxyStats.Key.bytesDown)))
            }
        }
    }

    private var logsCard: some View {
        SectionCard(title: "Журнал") {
            VStack(alignment: .leading, spacing: 6) {
                ScrollView {
                    VStack(alignment: .leading, spacing: 2) {
                        ForEach(Array(controller.log.lines.enumerated()), id: \.offset) { _, line in
                            Text(line).font(.system(size: 10, design: .monospaced))
                                .foregroundColor(.lilacMuted)
                        }
                    }
                }
                .frame(maxHeight: 220)
                Button("Очистить") { controller.log.clear() }.font(.system(size: 12))
            }
        }
    }

    private func row(_ title: String, _ value: String) -> some View {
        HStack {
            Text(title).foregroundColor(.lilacMuted)
            Spacer()
            Text(value).foregroundColor(.lilacText)
        }
        .font(.system(size: 13))
    }

    private func binding(for dc: Int) -> Binding<String> {
        Binding(
            get: { settings.dcTargets[dc] ?? "" },
            set: { value in
                var current = settings.dcTargets
                if value.isEmpty { current.removeValue(forKey: dc) } else { current[dc] = value }
                settings.dcTargets = current
            }
        )
    }
}
