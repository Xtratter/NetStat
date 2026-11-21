# Synthetic fixtures / Синтетические образцы

`dns-http.pcap` was generated from literal packet fields and payloads by
`python tools/generate-fixtures.py`. It contains nine IPv4 packets with a raw IP
link type (101), using addresses from RFC 5737. The generated file is deterministic.

Файл создан командой `python tools/generate-fixtures.py` из заданных вручную полей
и полезной нагрузки. Это девять IPv4-пакетов, тип канального уровня Raw IP (101).
Использованы адреса RFC 5737. Повторный запуск создаёт файл с идентичным содержимым.

| Packets / Пакеты | Expected / Ожидаемый результат |
| --- | --- |
| 1–2 | UDP `192.0.2.10:53530` ↔ `203.0.113.53:53`. DNS ID `0x4321`, `example.test` A `198.51.100.20`. |
| 3–5 | TCP handshake / рукопожатие `192.0.2.10:49152` ↔ `198.51.100.20:80`. |
| 6–7 | `GET /network-night HTTP/1.1`, `Host: example.test`. The text `network-night` spans two segments / текст разбит на два сегмента. |
| 8–9 | `HTTP/1.1 200 OK`, `Content-Length: 5`, body / тело `hello`, client ACK / подтверждение клиента. |

SHA-256 `7c37ff91dc0f381c377ec5cbe92eac49e28d092f25ae9ecfec355ec6e6772d5a`

The generator uses the Python standard library. The APK packages
`libandroidx.graphics.path.so` from Google Maven
(`androidx.graphics:graphics-path:1.0.1`) through Compose. It has arm64-v8a,
armeabi-v7a, x86 and x86_64 variants under Apache License 2.0. The license is
included in the APK at `assets/licenses/apache-2.0.txt`. The binaries are shipped
prebuilt. The arm64-v8a ELF identifies NDK r25c (9519653) as its build toolchain.

Генератор использует стандартную библиотеку Python. В APK через Compose входит
`libandroidx.graphics.path.so` из Google Maven
(`androidx.graphics:graphics-path:1.0.1`) для arm64-v8a, armeabi-v7a, x86 и x86_64.
Текст лицензии Apache 2.0 находится в APK по пути
`assets/licenses/apache-2.0.txt`. Для сборки используются готовые бинарные файлы. В ELF для arm64-v8a указан NDK r25c (9519653).

[AndroidX Graphics Path 1.0.1 release notes](https://developer.android.com/jetpack/androidx/releases/graphics#graphics-path) ·
[Google Maven metadata](https://dl.google.com/dl/android/maven2/androidx/graphics/graphics-path/1.0.1/graphics-path-1.0.1.pom)

`app/src/test/resources/pcapd-sample.events` is the Unix socket stream emitted
by the pinned arm64 helper (pcapd-bin 6b545346) when replaying this synthetic
PCAP. The two padding bytes in each native header have been cleared.
RecordedPcapdTest reads the stream and compares the SHA-256 of the restored
PCAP with the value above. It runs without root or Android networking.

JVM-тест читает события arm64-версии pcapd с синтетической записи. Два байта
выравнивания в заголовке каждого события обнулены. Контрольная сумма
восстановленного PCAP должна совпасть с опубликованной выше.
