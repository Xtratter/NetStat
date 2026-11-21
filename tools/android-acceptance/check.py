#!/usr/bin/env python3
"""Exercise NetStat on a fresh API 35 x86_64 Android emulator."""
import hashlib
import http.server
import json
from pathlib import Path
import re
import socket
import struct
import subprocess
import sys
import threading
import time
import xml.etree.ElementTree as ET

NETSTAT = "io.github.xtratter.netstat"
PROBE = NETSTAT + ".probe"
ARCHIVE = "no_backup/capture"
SESSION = "f1f0df53-ffac-4f5c-b3bc-72bc49fb17dc"
OPEN_CAPTURE = NETSTAT + ".OPEN_CAPTURE"
CONTROL = b"netstat-acceptance"
TCP_PORT = 18780
DNS_PORT = 18781
ROOT = Path(__file__).resolve().parents[2]
UI_DUMP = "/sdcard/netstat-acceptance.xml"


def adb(*args, payload=None, timeout=25):
    command = ["adb", *args]
    result = subprocess.run(command, input=payload, capture_output=True, timeout=timeout)
    if result.returncode != 0:
        raise RuntimeError(f"{' '.join(command)} failed: {result.stderr.decode(errors='replace')}")
    return result.stdout


def activity(name, *extra, restart=False):
    options = ["-S"] if restart else []
    response = adb("shell", "am", "start", "-W", *options, "-n", name, *extra)
    if b"Error" in response:
        raise RuntimeError(response.decode(errors="replace"))


def netstat(capture=False, restart=False):
    activity(f"{NETSTAT}/.MainActivity", "--activity-single-top",
             "--ez", OPEN_CAPTURE, str(capture).lower(), restart=restart)


def screen():
    result = adb("shell", "uiautomator", "dump", UI_DUMP)
    if UI_DUMP.encode() not in result:
        raise RuntimeError(f"UI hierarchy unavailable: {result.decode(errors='replace')}")
    return ET.fromstring(adb("exec-out", "cat", UI_DUMP))


def find_label(text, present=True):
    deadline = time.monotonic() + 30
    last_error = None
    while time.monotonic() < deadline:
        try:
            tree = screen()
        except (RuntimeError, ET.ParseError) as error:
            last_error = error
            time.sleep(0.25)
            continue
        node = next((item for item in tree.iter("node")
                     if text.casefold() in item.get("text", "").casefold().splitlines()), None)
        if present and node is not None:
            return node
        if not present and node is None:
            return None
        time.sleep(0.25)
    raise AssertionError(f"{text!r} did not become {'visible' if present else 'hidden'}") from last_error


def tap(text):
    node = find_label(text)
    left, top, right, bottom = map(int, re.findall(r"\d+", node.attrib["bounds"]))
    adb("shell", "input", "tap", str((left + right) // 2), str((top + bottom) // 2))


def archive_file(name):
    return adb("exec-out", "run-as", NETSTAT, "cat", f"{ARCHIVE}/{name}")


def seed_recording():
    packet_file = (ROOT / "fixtures/dns-http.pcap").read_bytes()
    payload_bytes = len(packet_file) - 24 - 9 * 16
    report = dict(
        config=dict(interface="tun0", uid=None, label=None, mode="ROOT", package=None),
        id=SESSION, started=1795219200000, ended=1795219200250, reason="USER_STOPPED",
        detail=None, packets=9, bytes=payload_bytes, uidExcluded=0, malformed=0,
        unlisted=0, drops=0, connections=[],
    )
    adb("shell", "run-as", NETSTAT, "mkdir", "-p", ARCHIVE)
    for name, data in (("latest.json", json.dumps(report).encode()), (f"capture-{SESSION}.pcap", packet_file)):
        adb("shell", "-T", f"run-as {NETSTAT} sh -c 'cat > {ARCHIVE}/{name}'", payload=data)
    return hashlib.sha256(packet_file).digest()


def check_saved_packets(expected):
    netstat(capture=True, restart=True)
    tap("Packets")
    find_label("Packets: 9")
    packet = archive_file(f"capture-{SESSION}.pcap")
    assert hashlib.sha256(packet).digest() == expected, "Stored packet bytes changed"
    adb("shell", "input", "keyevent", "KEYCODE_BACK")


class Origin(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Length", str(len(CONTROL)))
        self.end_headers()
        self.wfile.write(CONTROL)

    def log_message(self, *_):
        pass


def dns_echo(server, stopped):
    server.settimeout(0.5)
    while not stopped.is_set():
        try:
            data, peer = server.recvfrom(4096)
        except TimeoutError:
            continue
        if len(data) >= 12:
            reply = data[:2] + b"\x81\x80" + data[4:6] + bytes(6) + data[12:]
            server.sendto(reply, peer)


def run_probe(phase):
    activity(f"{PROBE}/.ProbeActivity", "--es", "phase", phase, restart=True)
    deadline = time.monotonic() + 12
    while time.monotonic() < deadline:
        log = adb("logcat", "-d", "-s", "NetStatProbe:I").decode(errors="replace")
        if f"OK {phase}" in log:
            return
        if f"FAILED {phase}" in log:
            raise AssertionError(log)
        time.sleep(0.3)
    raise AssertionError(f"No probe response for {phase!r}")


def start_vpn():
    tap("Start VPN capture")
    tap("OK")
    find_label("Recording")


def check_vpn():
    netstat(capture=True, restart=True)
    tap("All UIDs")
    tap("Search apps")
    adb("shell", "input", "text", "NetStat%sProbe")
    tap("NetStat Probe")

    tap("Start VPN capture")
    tap("Cancel")
    find_label("Start VPN capture")
    assert json.loads(archive_file("latest.json"))["id"] == SESSION
    print("System VPN consent denial preserved the prior recording.", flush=True)

    start_vpn()
    run_probe("tunnel")
    netstat(capture=True)
    tap("Stop recording")
    find_label("Recording finished")
    report = json.loads(archive_file("latest.json"))
    packages = adb("shell", "pm", "list", "packages", "-U", PROBE)
    uid = int(re.search(rb"uid:(\d+)", packages).group(1))
    assert report["config"]["mode"] == "VPN" and report["config"]["uid"] == uid
    for protocol, port in ((6, TCP_PORT), (17, DNS_PORT)):
        connections = [item for item in report["connections"] if item["protocol"] == protocol and
                       port in (item["first"]["port"], item["second"]["port"])]
        assert connections, f"Expected protocol {protocol} flow on port {port}"
        assert all(item["uid"] in (None, uid) for item in connections)
        assert any(item["rx"] > 0 and item["tx"] > 0 for item in connections)
    assert any(item["uid"] == uid for item in report["connections"]), "No flow had the probe's resolved UID"
    packet = archive_file(f'capture-{report["id"]}.pcap')
    header = struct.unpack_from("<IHHIIII", packet)
    assert header[0] == 0xA1B2C3D4 and header[-1] == 101
    assert CONTROL in packet and b"example\x04test" in packet
    print("IPv4 HTTP and DNS completed through VPN. PCAP and UID scope checked.", flush=True)

    run_probe("after-stop")
    netstat(capture=True)
    tap("Start VPN capture")
    find_label("Recording")
    activity(f"{PROBE}/.ProbeActivity", "--ez", "takeVpn", "true", restart=True)
    tap("OK")
    netstat(capture=True)
    find_label("Recording interrupted")
    assert json.loads(archive_file("latest.json"))["reason"] == "INTERRUPTED"
    run_probe("after-revoke")
    print("Android revoked NetStat VPN and ordinary networking resumed.", flush=True)


def check(previous, candidate, probe):
    if adb("shell", "getprop", "ro.kernel.qemu").strip() != b"1":
        raise RuntimeError("This acceptance test requires a dedicated emulator")
    assert adb("shell", "id", "-u").strip() == b"2000", "Expected ordinary non-root ADB shell"
    adb("shell", "input", "keyevent", "KEYCODE_WAKEUP")
    adb("shell", "wm", "dismiss-keyguard")
    adb("shell", "wm", "size", "1080x1920")
    adb("shell", "wm", "density", "320")
    adb("install", previous)
    adb("install", probe)
    netstat()
    find_label("Allow usage access")
    adb("shell", "cmd", "appops", "set", NETSTAT, "GET_USAGE_STATS", "allow")
    netstat(restart=True)
    find_label("Today")
    find_label("Allow usage access", present=False)
    adb("shell", "cmd", "appops", "set", NETSTAT, "GET_USAGE_STATS", "ignore")
    netstat(restart=True)
    find_label("Allow usage access")
    print("Clean install and usage-access grant/revocation checked.", flush=True)

    expected = seed_recording()
    check_saved_packets(expected)
    adb("install", "-r", candidate)
    check_saved_packets(expected)
    print("In-place upgrade retained and opened the same nine packet recording.", flush=True)

    with http.server.ThreadingHTTPServer(("127.0.0.1", TCP_PORT), Origin) as httpd, \
            socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as dns:
        dns.bind(("127.0.0.1", DNS_PORT))
        stopped = threading.Event()
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
        threading.Thread(target=dns_echo, args=(dns, stopped), daemon=True).start()
        try:
            check_vpn()
        finally:
            stopped.set()
            httpd.shutdown()


if __name__ == "__main__":
    try:
        check(*sys.argv[1:])
    except Exception:
        try:
            last = screen()
            print(ET.tostring(last, encoding="unicode"), file=sys.stderr)
            print(adb("logcat", "-d", "-s", "AndroidRuntime:E", "NetStat:W", "NetStatProbe:I").decode(errors="replace"),
                  file=sys.stderr)
        except Exception:
            pass
        raise
