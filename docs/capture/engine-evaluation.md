# Root capture evaluation / Проверка root-захвата

The release APK uses Android usage history. This evaluation runs separately from the APK. The engine for live capture is provisional pending on-device UID measurements.

В опубликованном APK работает системная статистика. Ниже результаты проверки кандидата для ручной записи. Привязка сокетов к приложениям зависит от прошивки и времени жизни сокета.

| Item / Параметр | Result / Результат |
| --- | --- |
| Binary distribution | [emanuele-f/pcapd-bin at 6b545346](https://github.com/emanuele-f/pcapd-bin/tree/6b54534635b53a0bcb62d8dbe788425a319b5611), arm64-v8a/libpcapd.so |
| Origin | Upstream identifies source revision [dbfaab6](https://github.com/emanuele-f/PCAPdroid/tree/dbfaab6/app/src/main/jni/pcapd). The binary repository permits bundling its binaries with attribution to PCAPdroid. Credit Emanuele Faranda and PCAPdroid when distributing. |
| arm64 SHA-256 | `4cc86aa41502882ec3a6ad4dab0d6c64aea3ee5d0efa23a7bdc208da646c3697` |
| ABI | Android arm64 ELF, interpreter /system/bin/linker64. IPC header 32 bytes on this ABI. A 32-bit helper uses a different timeval layout. |
| Offline input | fixtures/dns-http.pcap, nine synthetic raw IPv4 packets over two flows |
| Socket verification | 9/9 packet timestamps, lengths and payloads matched. DNS-only filter 2/2. TCP port 443 filter 0/0. Offline UID unknown for all packets, as expected. Re-encoding all socket events using the benchmark writer produced a byte-identical PCAP. |

## Offline check / Проверка без root

Run in Termux on arm64 from the repository root. The commands use a file as input. No live capture, installation or permissions prompt is needed.

Из корня репозитория в Termux на arm64 можно повторить проверку. Она сравнивает события из Unix-сокета с исходным файлом и проверяет два фильтра.

```sh
git clone https://github.com/emanuele-f/pcapd-bin.git .superpowers/pcapd-bin
git -C .superpowers/pcapd-bin checkout --detach 6b54534635b53a0bcb62d8dbe788425a319b5611
python tools/verify-pcapd-fixture.py .superpowers/pcapd-bin/dist/arm64-v8a/libpcapd.so
```

## Device results / Результаты на устройстве

| Source / Источник | Known UID / Атрибуция | Drops / Потери | Observation / Наблюдение |
| --- | --- | --- | --- |
| Offline fixture | n/a | n/a | TCP 7, UDP 2. File playback exercises decoding only. |
| Current network | Pending | Pending | The Termux wrapper in the Codex execution session returned 127 when executing /system/bin/su. No privileged capture started. |
| Other transports | Pending | Pending | Repeat separately on Wi-Fi, mobile and the VPN tunnel when each is available. |

Код 127 описывает среду запуска стенда. Для измерения нужен успешный запуск su из той же сессии, в которой запускается стенд. Прочерк в этих измерениях нельзя интерпретировать как ноль потерянных пакетов.

## Engine decision / Выбор движка

Prefer pcapd for the first device trial. It includes libpcap, socket-owner lookup through inet_diag with a fallback, a flow cache, packet direction and a local IPC format. A standalone libpcap capture would require NetStat to implement and validate ownership separately. The published binary is from 2022. Adopt it for the APK only after measuring known-UID TCP and short UDP flows on a real device. The raw recording and measured flows belong to a single interface per run.

Для испытаний выбран pcapd. В проекте без него пришлось бы отдельно реализовать поиск владельца соединения и проверить его на тех же коротких потоках. Доступность UID, видимость трафика внутри VPN и фактические потери ещё нужно измерить по каждому интерфейсу. Счётчик ядра и пропущенные тестовые пакеты — разные показатели. В файле PCAP сведений о UID нет; измерения сохраняются отдельно.
