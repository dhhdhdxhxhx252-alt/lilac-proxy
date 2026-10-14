# Архитектура Lilac Proxy

Документ описывает, **как** устроено локальное MTProto-ядро в этом порте. Протокольные решения воспроизводят поведение Rust-ядра оригинала ([IMDelewer/tg-ws-proxy-ios](https://github.com/IMDelewer/tg-ws-proxy-ios) → [Flowseal/tg-ws-proxy](https://github.com/Flowseal/tg-ws-proxy)), но реализованы на Kotlin (Android) и Swift (iOS).

## Общая схема

```text
Telegram-клиент
      │  TCP 127.0.0.1:<port>
      ▼
ProxyServer (локальное ядро)
      │  читает 64-байтный инициализатор клиента
      │  выводит DC и протокол из tail-байтов
      ▼
Transport (WSS / Cloudflare-front / raw TCP)
      ▼
Telegram DC (149.154.x.x:443 или kws{N}.web.telegram.org)
```

Ядро поднимает `ServerSocket` только на loopback-адресе. Принятые соединения проверяются на адрес пира `127.0.0.1` — извне прокси недоступен.

## Транспорты

1. **WebSocket (основной).** Запрос `GET /apiws HTTP/1.1` на `kws{N}[-1].web.telegram.org` с заголовками `Upgrade: websocket`, `Connection: Upgrade`, `Sec-WebSocket-Key`, `Sec-WebSocket-Version: 13`, `Sec-WebSocket-Protocol: binary`. `User-Agent` не отправляется. На Android — OkHttp `wss://`, на iOS — `URLSessionWebSocketTask`.
2. **Cloudflare-front.** При недоступности WS используются front-домены (`kws{DC}.<base-domain>`), за которыми стоит Cloudflare. Домены с 429 уходят в cooldown.
3. **Raw TCP fallback.** Прямое соединение к IP дата-центра на `:443`. Таблица DC: `1→149.154.175.50`, `2→149.154.167.51`, `3→149.154.175.100`, `4→149.154.167.91`, `5→149.154.171.5`, `203→91.105.192.100`. Для DC203 (медиа) применяется override `203→2`.

Fallback выбирается автоматически: WS → Cloudflare → TCP. Решение фиксируется на уровне одного соединения.

## Obfs2

Поток MTProto оборачивается в AES-256-CTR со смещением (stream cipher, без выравнивания). Ключи выводятся из инициализатора клиента и локального секрета (16 байт / 32 hex-символа).

Выводы ключей (точное соответствие оригиналу):

- `clientDecryptor = AES-256-CTR( sha256(init[8..40] + secret), init[40..56] )`
- `clientEncryptor = AES-256-CTR( sha256(reversed(init[8..56])[0..32] + secret), reversed[32..48] )`
- Сторона DC — без хеширования:
  - `relayEncryptor = AES-CTR( relayInit[8..40], relayInit[40..56] )`
  - `relayDecryptor = AES-CTR( reversed[0..32], reversed[32..48] )`

Здесь `reversed(...)` — это те же байты окна `[8..56]`, развёрнутые задом наперёд.

## Инициализаторы и хвост

Клиентский init — 64 байта. Из него ядро читает DC и протокол. Чтобы upstream получил нужный DC, хвост relay-init переписывается так, чтобы ключевые байты (окно 8..56) остались нетронутыми:

```text
ks[i]        = encrypted[56+i] XOR init[56+i]
init[56+i]   = tail_plain[i] XOR ks[i]
tail_plain   = proto(4, LE) + dcIdx(2, LE; отрицательный = медиа) + 2 случайных байта
```

relay-init обязан **не** начинаться с `0xEF`, не совпадать с `HEAD`/`POST`/`GET `/`0xEEEEEEEE`/`0xDDDDDDDD`, не выглядеть как TLS (`16 03 01 02`) и иметь ненулевые байты в позиции 4..8.

## Сплиттер сообщений (MsgSplitter)

Одно MTProto-сообщение — один WS-фрейм. Формат заголовка зависит от протокола:

- **Abridged**: 1-байтный заголовок, длина = `plain[0] & 0x7F`, умножить на 4; значение `0x7F` → 4-байтный заголовок длины.
- **Intermediate / Padded**: `payload = LE u32 & 0x7FFFFFFF`.

Если `payload <= 0` — сбрасывается всё буферное и сплиттер отключается. На EOF вызывается `flush()`. `MsgSplitter` «сжигает» 64 нулевых байта на старте. Валидные протоколы: `0xEFEFEFEF`, `0xEEEEEEEE`, `0xDDDDDDDD`.

## Инварианты смещений потоков (важно)

Это самое хрупкое место — любой сдвиг ломает дешифровку:

- `clt_dec` продвинут на 64 байта клиентского init;
- `tg_enc` продвинут на 64, потому что upstream переиспользует его для формирования хвоста relay-init;
- `tg_dec` и `clt_enc` стартуют с 0 — 64-байтный ответ DC пере-ключуется и форвардится, а relay-init клиенту не отдаётся.

## Фоновая работа

- **Android**: foreground-сервис с типом `specialUse` (выбран вместо `dataSync`, потому что Android 14 ограничивает dataSync-сервис 6 часами в сутки). Уведомение показывает состояние и статистику.
- **iOS**: режим loopback удерживается через `BackgroundKeeper` (CoreLocation). `PacketTunnel` с `includedRoutes=[]`, `excludedRoutes=default` нужен только чтобы держать процесс резидентным; если туннель не доходит до `.connected` за 8 секунд, происходит авто-фолбэк на loopback.

## Структура кода

Android (`android/app/src/main/java/dev/lilac/proxy/`):

- `Obfs2.kt` — AES-CTR-поток, выводы ключей, SHA-256, разбор секрета.
- `Handshake.kt` — протоколы, клиентский/relay-init, крафт хвоста.
- `MsgSplitter.kt` — сплиттер + `ByteQueue`.
- `Targets.kt` — таблицы DC, WS-домены, формирование `tg://proxy`-ссылки.
- `Transport.kt` — `TcpTransport`, `WsTransport` (OkHttp).
- `ProxyServer.kt` — loopback-сервер, диспатч транспорта, мост.
- `ProxyService.kt` — foreground-сервис + глобальный `ProxyState`.
- `ProxyStats.kt` — атомарные счётчики + кольцо логов `LogStore`.
- `Settings.kt` — `ProxyConfig` поверх SharedPreferences.
- `MainActivity.kt` — UI.

iOS (`ios/Sources/Lilac/`): `LilacApp.swift` + `Proxy/*.swift` — те же модули на Swift (CommonCrypto, `Network.framework`, `URLSessionWebSocketTask`).

## Тесты

`android/app/src/test/` содержит юнит-тесты `Obfs2RoundTripTest` (шифрование/дешифрование туда-обратно на контрольных байтах) и `MsgSplitterTest` (границы фреймов по всем трём протоколам).
