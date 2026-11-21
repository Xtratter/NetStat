# Android acceptance

Record the phone model, Android version, NetStat version, network and result
for each check. Use a controlled client and synthetic traffic or a server
you operate.

| Check | Expected result |
| --- | --- |
| Clean install | The usage screen opens and reports the current usage-access state. |
| Denied or revoked access | The usage screen prompts for access, and resumes reading history once it is granted. |
| Day and overnight usage | After Android refreshes its counters, the test download appears under the expected app and network. Compare received and sent bytes for the same time window. |
| Root and VPN capture | Visit a test page and run a DNS query from a selected app. Stop, inspect the connection and packet data, and verify the PCAPNG export. Unknown UIDs are marked. |
| VPN denial and revocation | The consent denial leaves capture stopped. Revoking a running VPN ends the session. A test page opens on the ordinary network afterward. |
| Wi-Fi to mobile | Losing the initial Wi-Fi network ends VPN capture and preserves available packets. Starting again uses the mobile network. |
| Upgrade | Save a test session in the previous APK and install the update in place. Open the session and compare packet count and connection fields. |
| Screen off | Select **Up to 30 min**. At low traffic, the session should end at the time limit. The 8 MiB cap may end it earlier. |
| HTTPS | The configured test client generates a searchable response through the local diagnostic proxy. [Setup](../capture/https.md). |

Compare two 30-minute runs with the same workload, network, screen state and
charging state, one with capture off and one with capture on. Record the
change in charge, transferred bytes, capture duration and exported PCAPNG
size. Reduce the workload for both runs if the size cap ends capture early.
Measure Wi-Fi and mobile separately.

## Emulator checks

Run **Android emulator acceptance** from the repository’s Actions tab. The
workflow uses a fresh Android 15 (API 35) x86_64 emulator. It installs the
published 0.6.0 APK and the current build with a temporary key shared by
both APKs. It opens the same synthetic recording before and after updating.
The VPN check uses a test app and local HTTP and DNS endpoints on the runner.
Root capture, mobile handover and battery measurements require a physical
device.

## APK verification

GitHub Actions runs JVM and Python tests, Android lint and the APK build.
Its artifact uses a runner-generated debug key. Use the GitHub Release APK
for in-place updates. Verify the release APK with the accompanying checksum
file using `sha256sum -c SHA256SUMS.txt`.
