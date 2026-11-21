# pcapd bench on Android arm64

[Русский](pcapd-bench.ru.md)

This stage 3 bench uses Python 3.10+ in Termux. Run from the NetStat directory as
the ordinary Termux user. The script records that user’s UID as ground truth and
starts the official pcapd under `su`. Android’s `timeout` limits the helper to 24
seconds, with a two-second grace period. It uses one interface and leaves the
existing network configuration in place.

## Run

Prepare the official arm64-v8a binary in the local ignored directory.

```sh
git clone https://github.com/emanuele-f/pcapd-bin .superpowers/pcapd-bin
git -C .superpowers/pcapd-bin checkout --detach 6b54534635b53a0bcb62d8dbe788425a319b5611
```

The script verifies SHA-256
`4cc86aa41502882ec3a6ad4dab0d6c64aea3ee5d0efa23a7bdc208da646c3697`.
The ELF uses the Android 21 arm64 ABI and was built with NDK r20b. The official
binary repository grants redistribution with PCAPdroid attribution. The pinned
PCAPdroid source file states GPL-3.0-or-later. [Binary and attribution terms](https://github.com/emanuele-f/pcapd-bin/tree/6b54534635b53a0bcb62d8dbe788425a319b5611) · [Corresponding source](https://github.com/emanuele-f/PCAPdroid/blob/dbfaab61647893fc0b1f4ae9b15e857dcdcb8337/app/src/main/jni/pcapd/pcapd.c)

Loopback exercises the socket protocol and export. The test client and its echo
server share the Termux UID, so it cannot establish accuracy across two UIDs.

```sh
python tools/pcapd_bench.py loopback \
  --pcapd .superpowers/pcapd-bin/dist/arm64-v8a/libpcapd.so \
  --output .superpowers/pcapd-lo
```

For the active IPv4 interface, replace `wlan0` and `192.168.1.23` with its actual
interface name and assigned IPv4 address. The example sends three TCP and four
UDP requests for the A record of `example.com` to `1.1.1.1:53`. A known IPv4 DNS
resolver can be passed with `--peer`. Use a new output directory for each run.

```sh
python tools/pcapd_bench.py dns \
  --pcapd .superpowers/pcapd-bin/dist/arm64-v8a/libpcapd.so \
  --output .superpowers/pcapd-dns --interface wlan0 \
  --local-ip 192.168.1.23 --peer 1.1.1.1
```

## Read the results

- Open `probe.pcap` in Wireshark. The input uses the pinned 32-byte little-endian
  arm64 header and pcapd DLT_RAW 12. The classic PCAP uses LINKTYPE_RAW 101 and
  microsecond timestamps. The protocol provides the captured length.
- The capture filter uses the two addresses and the client and peer ports
  reserved for each protocol before capture. UDP client sockets close immediately
  after each exchange. The exporter checks the exact flow again and retains UDP
  datagrams only when their payload and direction match the sent request or the
  validated reply. The retained capture is capped at 1,500 packets and 2 MiB of
  packet data.
- In `report.json`, `correct` means every retained packet for the flow had the
  expected UID. `partial` mixes the expected UID and unknown UID. `wrong` includes
  an unexpected known UID. `unknown` and `unseen` identify flows with only unknown
  UID packets and flows without retained packets, respectively.
- `udp_missing_messages` counts sent requests and validated replies missing from
  the recorded UDP packets. TCP reports the observed payload directions.
  `final_stats` contains libpcap drop counters from the helper’s shutdown log.
  `dns_unavailable` means the probe received no validated replies. For
  `incomplete`, inspect `pcapd.log` for startup, permission or interface errors.

```sh
python -m unittest discover -s tools -p 'test_pcapd_bench.py'
```
