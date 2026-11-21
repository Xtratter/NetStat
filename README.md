# NetStat

[Русский](README.ru.md)

[Download the Android APK (v0.5.0 debug)](https://github.com/Xtratter/NetStat/releases/download/v0.5.0/NetStat-0.5.0-debug.apk)

NetStat shows Android’s Wi-Fi and mobile data history by app. The first build runs on
Android 10 (API 29) and later. Usage access is available on a standard device.

1. Open NetStat and enable usage access in Android settings.
2. Choose **Today**, **Last night**, or a custom start and end, then choose **Wi-Fi**
   or **Mobile**. Mobile shows all subscriptions counted by Android for the current user.
3. Compare received and sent bytes. Apps sharing an Android UID appear together. If Android
   reports a system category or the installed package cannot be resolved, the row keeps its
   category or UID.

**Last night** means the last completed local 00:00–07:00 period. Before 07:00 it refers
to the previous day. A saved custom selection keeps its start and end instants across
time-zone changes. For a repeated local time the picker offers both occurrences.

Android provides history in coarse intervals and can update it with a delay. NetStat
adds complete intervals inside the selected period and shows their size, observed ranges
and gaps. Coverage at the top combines intervals across apps. Each app shows its own coverage.
An empty result means Android returned no usable intervals, while zero means Android
returned intervals with zero recorded bytes.

## Root capture

On an arm64 phone, open **Capture**, choose the current Android network or pick an interface from the list, choose an app or all UIDs, and start recording. Grant root to NetStat. Stop using the app or notification. Sessions are capped at three minutes or 8 MiB.

The journal shows IPs, ports, protocol and available owner information. The per-app filter keeps packets confirmed for the selected UID. NetStat keeps the latest recording in private storage. After a process interruption it recovers complete packets and byte counts. The UID index is available for normally completed sessions. [Capture bench instructions](docs/pcapd-bench.md).

## Packet inspector

Stop the recording and open **Packets** for the entire session, or tap a connection in the completed journal for its packets. Select a packet and a protocol field to highlight the corresponding hex bytes. **Export full PCAPNG** writes the entire session through the system file picker, including other connections in the session. Completed recordings from 0.2.0 are readable after updating. Deleting the session removes its packets and journal after confirmation.

## HTTP conversations

Open **Packets → HTTP conversations** for a completed session or a TCP connection. NetStat reconstructs cleartext HTTP/1.x requests and responses from captured TCP segments and marks incomplete exchanges. Search includes URLs, headers and decoded text in both directions. Chunked bodies and gzip are decoded, with up to 256 KiB of preview per body and 4 MiB of retained HTTP headers and bodies per analysis. Binary previews show hex.

## HTTPS diagnostics

Open a local explicit-proxy session from **Capture → HTTPS**. [Setup and report import](docs/capture/https.md).

## Build and check

Use JDK 17, Android SDK 35 and Build Tools 35.0.0. The wrapper pins Gradle 8.10.2,
the project pins Android Gradle Plugin 8.7.3, Kotlin 2.0.21, Compose Material 3 1.3.1 and
Activity Compose 1.10.1. Compose includes the prebuilt native library
`androidx.graphics:graphics-path:1.0.1` under Apache License 2.0. The build
requires only the Android SDK. See the [dependency record](fixtures/README.md).

```sh
./gradlew clean testDebugUnitTest lintDebug assembleDebug
```

The debug APK is at `app/build/outputs/apk/debug/app-debug.apk`. In Termux, Gradle
needs the ARM64 `aapt2` provided by Termux. Set the local Gradle property
`android.aapt2FromMavenOverride` to its executable path.

For device acceptance, grant usage access on Android 16, transfer a known quantity of
data on each network and compare the ranking and bytes after Android updates its counters.
Compare only the same time range and observe the reported coverage. Revoke usage access,
return to NetStat and confirm that the history is hidden. Check the period boundaries
around local midnight and 07:00, then change the phone’s time zone and repeat.

[Synthetic capture](fixtures/README.md) ·
[Android network statistics API](https://developer.android.com/reference/android/app/usage/NetworkStatsManager)
