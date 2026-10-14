<h1 align="center">Lilac Proxy</h1>

<h4 align="center">Локальный MTProto-прокси для Telegram на Android (и исходники для iOS): транспорт через WebSocket, Cloudflare-front и raw TCP к дата-центрам.</h4>

<p align="center">
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-GPLv3-blue?style=for-the-badge&logo=gnu&logoColor=white" alt="GPLv3"></a>
  <img src="https://img.shields.io/badge/Android-8.0%2B-3DDC84?style=for-the-badge&logo=android&logoColor=white" alt="Android 8.0+">
  <img src="https://img.shields.io/badge/Kotlin-1.9.22-7F52FF?style=for-the-badge&logo=kotlin&logoColor=white" alt="Kotlin">
  <img src="https://img.shields.io/badge/iOS-16.0%2B%20(исходники)-000000?style=for-the-badge&logo=apple&logoColor=white" alt="iOS sources">
</p>

---

**Lilac Proxy** поднимает MTProto-прокси прямо на телефоне и отдаёт Telegram локальный адрес. Приложение слушает `127.0.0.1`, а дальше ведёт трафик к серверам Telegram по выбранному транспорту:

```text
Telegram → 127.0.0.1:1443 → локальное ядро → WSS / Cloudflare / TCP → Telegram DC
```

Прокси работает в фоне как foreground-сервис, сам генерирует obfs2-секрет и собирает ссылку `tg://proxy?...` для импорта в Telegram.

> [!CAUTION]
> Это экспериментальный сетевой инструмент, а не средство анонимности. Он не шифрует трафик Telegram дополнительно и не проходил аудит безопасности. Используйте на свой риск и только там, где это разрешено законом.

---

## Что это и чей это код

Это **не** оригинальный проект. Lilac Proxy — производная работа, переписанная с Rust-ядра на Kotlin (Android) и Swift (iOS):

- **[IMDelewer/tg-ws-proxy-ios](https://github.com/IMDelewer/tg-ws-proxy-ios)** — приложение-оригинал для iOS, распространяется под **GPL-3.0**. Протокольная логика, порядок рукопожатий и обфускации взяты оттуда.
- **[Flowseal/tg-ws-proxy](https://github.com/Flowseal/tg-ws-proxy)** — Rust-ядро, которое оборачивал оригинал, под **MIT** (см. [`LICENSE-flowseal`](LICENSE-flowseal)).

Весь код этого репозитория распространяется под **GPL-3.0** ([`LICENSE`](LICENSE)) — это требование лицензии исходного проекта. Полный текст протокольных решений описан в [`docs/ARCHITECTURE.ru.md`](docs/ARCHITECTURE.ru.md).

### Что изменено по сравнению с оригиналом

- **Ядро переписано с Rust на чистый Kotlin** для Android — без Rust, без NDK, без cross-compile. Криптография на `javax.crypto` (AES-256-CTR) и `MessageDigest` (SHA-256).
- **Добавлено Android-приложение**: `MainActivity` с настройками, foreground-сервис, статистика соединений и живые логи, импорт прокси в Telegram одной кнопкой.
- **iOS оставлен как исходники** (`ios/Sources/…`, SwiftUI + `Network.framework` + CommonCrypto). Проект собирается в Xcode — готового `.ipa` здесь нет.
- **Транспортный слой**: WebSocket через OkHttp (Android) и `URLSessionWebSocketTask` (iOS); Cloudflare-front и raw-TCP fallback к IP дата-центров.
- Рендер и палитра интерфейса — тёмная тема с акцентом `#A578FF`.

---

## Возможности

- Три транспорта с авто-фолбэком: **WSS** на `kws{N}[-1].web.telegram.org`, **Cloudflare-front** домены, **raw TCP** к `149.154.x.x:443`.
- Obfs2-обфускация MTProto-потока (AES-256-CTR с ключами из handshake + секрет).
- Поддержка протоколов `Abridged`, `Intermediate`, `Padded` — одно сообщение на один WS-фрейм.
- Дата-центры DC1–DC5 и DC203 (медиа), с пользовательскими переопределениями адресов.
- Локально сгенерированный 16-байтный секрет; ссылка для импорта в Telegram формируется автоматически.

---

## Сборка Android

Требуются JDK 17+ и Android SDK (build-tools 34). `minSdk 26`, `targetSdk 34`.

```bash
cd android
./gradlew assembleDebug        # app-debug.apk
./gradlew testDebugUnitTest    # юнит-тесты рукопожатия и сплиттера
```

Готовый `app-debug.apk` лежит на [странице релизов](../../releases/latest).

## Сборка iOS (исходники)

`ios/Sources/…` — это Swift-код приложения и прокси-ядра. Откройте папку в Xcode 15+, создайте таргет iOS 16.0+ и подключите файлы. Сборка `.ipa` требует подписи Apple — готового файла в релизах нет.

---

## Как пользоваться

1. Установите APK и откройте Lilac Proxy.
2. Нажмите **Запустить** — поднимется локальный прокси на `127.0.0.1:1443`.
3. Нажмите **«Открыть в Telegram»** (или скопируйте ссылку) и подтвердите добавление прокси.
4. Telegram подключится через локальное ядро; в приложении видна статистика и лог транспортов.

---

## Лицензия

GPL-3.0-only. см. [`LICENSE`](LICENSE). Часть протокольной кодовой базы происходит из Flowseal/tg-ws-proxy под MIT — [`LICENSE-flowseal`](LICENSE-flowseal).
