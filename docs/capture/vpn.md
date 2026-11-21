# Local VPN capture

The arm64 APK can record IPv4 and IPv6 TCP and UDP through Android VpnService.
NetStat opens protected direct sockets on the network that was active at
the start. It uses that network's DNS servers. Losing that network ends
the recording. The same selectable 3- or 30-minute duration and 8 MiB file cap apply as in root mode.

Selecting an app constrains the VPN to the app's UID through Android's
allowed-application list. Packets with a confirmed different UID are excluded.
Android's per-connection UID API can return an unknown owner, including for a
short-lived socket. The journal displays that outcome. NetStat's own UID is
excluded in all-app mode.

## Native source and rebuild

The APK dynamically links zdtun by Emanuele Faranda under LGPL-3.0-or-later.
The [pinned upstream source](https://github.com/emanuele-f/zdtun/tree/4a53fbbbfc16ed012af676a871dd989f3583a5e6)
is vendored at `app/src/main/cpp/zdtun` with its notices. NetStat adds checked
socket setup and suppresses SIGPIPE on TCP socket writes. The library and JNI bridge
are separate shared objects. To replace or modify the library, rebuild the
shared objects and assemble and sign the debug APK with your own key.

```sh
bash tools/build-vpn-native.sh arm64-v8a
./gradlew testDebugUnitTest lintDebug assembleDebug
```

Use arm64 Termux clang or set `NETSTAT_VPN_CC` to the Android NDK's
`aarch64-linux-android29-clang`. The normal Gradle build packages the checked-in
shared objects. Both are built with 16 KiB ELF segment alignment.

## Verification

The JNI bridge was exercised with a synthetic TUN socket pair against local
TCP and UDP echo servers. TCP and UDP passed over both IPv4 and IPv6. A simulated
socket-protection failure prevented the probe from reaching the server.
UID filtering is covered by JVM tests. The Android consent flow, DNS from an
ordinary app, VPN revocation and physical network changes require device testing.
[Android VpnService](https://developer.android.com/develop/connectivity/vpn) ·
[zdtun](https://github.com/emanuele-f/zdtun)

## Русский

Режим **VPN без root** работает на Android arm64 и использует локальную пересылку
IPv4/IPv6. NetStat открывает защищённые сокеты в сети, активной на момент старта,
и использует её DNS. При потере этой сети запись завершится. Можно выбрать
длительность до 3 или 30 минут, лимит файла составляет 8 МиБ. Для запуска нужен системный запрос Android. При обнаружении
другого VPN приложение предложит открыть настройки.

Если выбрано приложение, Android направляет в туннель его UID. Пакеты с
подтверждённым чужим UID отбрасываются. Для коротких соединений Android иногда
не определяет владельца, что видно в журнале. Когда выбраны все приложения,
трафик самого NetStat исключён.

Движок zdtun подключён как отдельная библиотека по LGPL-3.0-or-later.
Его исходники и тексты лицензий лежат в `app/src/main/cpp/zdtun`. Скрипт
`bash tools/build-vpn-native.sh arm64-v8a` пересобирает библиотеку и JNI-мост.

На стенде проверены TCP и UDP по IPv4 и IPv6, а также отказ защиты сокета.
Системное разрешение VPN, обычный DNS-запрос, отзыв VPN и смена сети остаются
отдельными проверками на телефоне.
