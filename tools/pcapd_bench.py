"""Bounded Android arm64 pcapd test for individually reserved IPv4 TCP/UDP flows."""

import argparse
from collections import Counter
from contextlib import ExitStack
from dataclasses import asdict, dataclass, field
import hashlib
from ipaddress import IPv4Address
import json
import os
from pathlib import Path
import platform
import re
import secrets
import shlex
import socket
import struct
import subprocess
import tempfile
import time

PIN = "6b54534635b53a0bcb62d8dbe788425a319b5611"
ARM64_BYTES = 788968
ARM64_SHA256 = "4cc86aa41502882ec3a6ad4dab0d6c64aea3ee5d0efa23a7bdc208da646c3697"
HEADER = struct.Struct("<qqIIHHBB2x")
PROTOCOL = {6: "tcp", 17: "udp"}
START_SECONDS = 7
TRAFFIC_SECONDS = 11
DRAIN_SECONDS = 2
ROOT_SECONDS = 24
MAX_PACKETS = 1500
MAX_PCAP_BYTES = 2 * 1024 * 1024

FINAL_STATS = re.compile(r"Pkts: (\d+) rcvd, (\d+) drops \([^)]*\), (\d+) iface_drops")
DNS_QUESTION = b"\x07example\x03com\x00\x00\x01\x00\x01"


@dataclass(frozen=True)
class Frame:
    seconds: int
    microseconds: int
    drops: int
    uid: int | None
    is_tx: bool
    packet: bytes


class FrameReader:
    def __init__(self):
        self.buffer = bytearray()

    def feed(self, data):
        self.buffer.extend(data)
        offset = 0
        while len(self.buffer) - offset >= HEADER.size:
            seconds, usec, drops, uid, length, link, flags, iface = HEADER.unpack_from(self.buffer, offset)
            if link != 12 or iface != 0 or flags & ~1:
                raise ValueError("unexpected pcapd datalink, interface or flags")
            if not 0 <= seconds <= 0xFFFFFFFF or not 0 <= usec < 1_000_000 or not length:
                raise ValueError("invalid pcapd timestamp or packet length")
            start = offset + HEADER.size
            end = start + length
            if len(self.buffer) < end:
                break
            packet = bytes(self.buffer[start:end])
            yield Frame(seconds, usec, drops, None if uid == 0xFFFFFFFF else uid, bool(flags), packet)
            offset = end
        del self.buffer[:offset]

    def finish(self):
        if self.buffer:
            raise ValueError("incomplete pcapd stream record")


def write_pcap(stream, frames):
    # libpcap's DLT_RAW value on Android (12) differs from its savefile LINKTYPE_RAW (101).
    stream.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 101))
    for frame in frames:
        size = len(frame.packet)
        stream.write(struct.pack("<IIII", frame.seconds, frame.microseconds, size, size))
        stream.write(frame.packet)


@dataclass(frozen=True)
class Flow:
    protocol: int
    local_ip: str
    local_port: int
    peer_ip: str
    peer_port: int

    def tuple(self, outgoing):
        local = (self.local_ip, self.local_port)
        peer = (self.peer_ip, self.peer_port)
        return (self.protocol, *(local + peer if outgoing else peer + local))


def build_filter(flows):
    if not flows:
        raise ValueError("reserve at least one test flow")
    local_ip, peer_ip = flows[0].local_ip, flows[0].peer_ip
    IPv4Address(local_ip)
    IPv4Address(peer_ip)
    ports_by_protocol = {}
    for flow in flows:
        if (flow.local_ip, flow.peer_ip) != (local_ip, peer_ip):
            raise ValueError("all test flows must use the same pair of addresses")
        if flow.protocol not in PROTOCOL or not all(1 <= port <= 65535 for port in (flow.peer_port, flow.local_port)):
            raise ValueError("invalid test protocol or port")
        ports_by_protocol.setdefault((flow.protocol, flow.peer_port), set()).add(flow.local_port)

    def direction(src, dst, client, server):
        rules = []
        for (protocol, peer_port), ports in sorted(ports_by_protocol.items()):
            first, *rest = sorted(ports)
            client_port = f"{client} port {first}"
            if rest:
                client_port = "(" + " or ".join([client_port, *map(str, rest)]) + ")"
            rules.append(f"({PROTOCOL[protocol]} and {server} port {peer_port} and {client_port})")
        joined = " or ".join(rules)
        return f"(src host {src} and dst host {dst} and ({joined}))"

    outgoing = direction(local_ip, peer_ip, "src", "dst")
    incoming = direction(peer_ip, local_ip, "dst", "src")
    bpf = f"ip and ({outgoing} or {incoming})"
    # The pinned executable appends this to a 512-byte snprintf buffer, including NUL.
    if len(f"ip or ip6 and ({bpf})".encode("ascii")) >= 512:
        raise ValueError("pcapd BPF would exceed its 512-byte buffer")
    return bpf


def packet_tuple(packet):
    if len(packet) < 20 or packet[0] >> 4 != 4:
        return None
    offset = (packet[0] & 15) * 4
    length, _, fragment = struct.unpack_from("!HHH", packet, 2)
    protocol = packet[9]
    if offset < 20 or length > len(packet) or fragment & 0x3FFF:
        return None
    if protocol == 17 and offset + 8 <= length:
        sport, dport, udp_size = struct.unpack_from("!HHH", packet, offset)
        if not 8 <= udp_size <= length - offset:
            return None
        payload = packet[offset + 8:offset + udp_size]
    elif protocol == 6 and offset + 20 <= length:
        sport, dport = struct.unpack_from("!HH", packet, offset)
        data_offset = (packet[offset + 12] >> 4) * 4
        if not 20 <= data_offset <= length - offset:
            return None
        payload = packet[offset + data_offset:length]
    else:
        return None
    source = socket.inet_ntoa(packet[12:16])
    destination = socket.inet_ntoa(packet[16:20])
    return (protocol, source, sport, destination, dport), payload


@dataclass
class Observation:
    uids: Counter = field(default_factory=Counter)
    udp_expected: set = field(default_factory=set)
    udp_seen: set = field(default_factory=set)
    tcp_directions: set = field(default_factory=set)
    tx_flags: int = 0
    exchange: str = "not attempted"

    def attribution(self, expected_uid):
        if not self.uids:
            return "unseen"
        if any(uid is not None and uid != expected_uid for uid in self.uids):
            return "wrong"
        if expected_uid not in self.uids:
            return "unknown"
        return "partial" if None in self.uids else "correct"


class Capture:
    def __init__(self, flows, uid):
        self.uid = uid
        self.observations = {flow: Observation() for flow in flows}
        self.match = {
            flow.tuple(outgoing): (flow, outgoing)
            for flow in flows for outgoing in (True, False)
        }
        self.frames = []
        self.excluded = 0
        self.bytes = 0
        self.max_reported_drops = None

    def expect_udp(self, flow, outgoing, payload):
        self.observations[flow].udp_expected.add((outgoing, payload))

    def add(self, frame):
        parsed = packet_tuple(frame.packet)
        match = parsed and self.match.get(parsed[0])
        if not match:
            self.excluded += 1
            return
        flow, outgoing = match
        observation = self.observations[flow]
        payload = parsed[1]
        if flow.protocol == 17:
            # Another socket can reuse the port after the short probe closes.
            message = (outgoing, payload)
            if message not in observation.udp_expected:
                self.excluded += 1
                return
            observation.udp_seen.add(message)
        self.bytes += len(frame.packet)
        if len(self.frames) == MAX_PACKETS or self.bytes > MAX_PCAP_BYTES:
            raise ValueError("test capture exceeded its packet or byte limit")
        self.frames.append(frame)
        self.max_reported_drops = max(self.max_reported_drops or 0, frame.drops)

        observation.uids[frame.uid] += 1
        observation.tx_flags += frame.is_tx
        if flow.protocol == 6 and payload:
            observation.tcp_directions.add("request" if outgoing else "response")

    def report(self):
        rows = []
        for flow, observation in self.observations.items():
            rows.append({
                **asdict(flow),
                "protocol": PROTOCOL[flow.protocol],
                "exchange": observation.exchange,
                "packet_count": observation.uids.total(),
                "packet_uids": {"unknown" if uid is None else str(uid): count
                                for uid, count in observation.uids.items()},
                "attribution": observation.attribution(self.uid),
                "pcapd_tx_flags": observation.tx_flags,
                "tcp_payload_directions": sorted(observation.tcp_directions),
                "udp_expected_messages": len(observation.udp_expected),
                "udp_missing_messages": len(observation.udp_expected - observation.udp_seen),
            })
        return {
            "expected_uid": self.uid,
            "retained_records": len(self.frames),
            "excluded_records": self.excluded,
            "max_packet_header_drops": self.max_reported_drops,
            "flow_counts": dict(Counter(row["attribution"] for row in rows)),
            "completed_exchanges": sum(row["exchange"] == "ok" for row in rows),
            "udp_expected_messages": sum(row["udp_expected_messages"] for row in rows),
            "udp_missing_messages": sum(row["udp_missing_messages"] for row in rows),
            "flows": rows,
        }


def remaining(deadline, limit=None):
    seconds = deadline - time.monotonic()
    if seconds <= 0:
        raise TimeoutError("test deadline reached")
    return min(seconds, limit) if limit is not None else seconds


def receive_exact(connection, size, deadline):
    data = bytearray()
    while len(data) < size:
        connection.settimeout(remaining(deadline))
        part = connection.recv(size - len(data))
        if not part:
            raise OSError("peer closed before sending the complete reply")
        data.extend(part)
    return bytes(data)


def prepare_flows(stack, options):
    clients, peers = {}, {}
    for protocol, kind, count in ((6, socket.SOCK_STREAM, options.tcp), (17, socket.SOCK_DGRAM, options.udp)):
        if options.mode == "loopback":
            peer = stack.enter_context(socket.socket(socket.AF_INET, kind))
            peer.bind((options.local_ip, 0))
            if protocol == 6:
                peer.listen(1)
            peers[protocol] = peer
            peer_port = peer.getsockname()[1]
        else:
            peer_port = 53
        for _ in range(count):
            client = stack.enter_context(socket.socket(socket.AF_INET, kind))
            client.bind((options.local_ip, 0))
            flow = Flow(protocol, options.local_ip, client.getsockname()[1], options.peer, peer_port)
            clients[flow] = client
    return clients, peers


def dns_request(transaction_id):
    return struct.pack("!6H", transaction_id, 0x0100, 1, 0, 0, 0) + DNS_QUESTION


def require_dns_reply(query, reply):
    if (len(reply) < len(query) or reply[:2] != query[:2] or reply[2] & 0x80 == 0
            or reply[4:6] != b"\x00\x01" or reply[12:len(query)] != DNS_QUESTION):
        raise ValueError("peer returned an unrelated DNS response")


def traffic_exchange(flow, client, peer, capture, stack, global_deadline):
    deadline = time.monotonic() + remaining(global_deadline, 1.4)
    client.settimeout(remaining(deadline))
    client.connect((flow.peer_ip, flow.peer_port))
    payload = (dns_request(secrets.randbits(16)) if peer is None
               else b"netstat-pcapd-" + secrets.token_bytes(16))
    if flow.protocol == 6:
        request = struct.pack("!H", len(payload)) + payload if peer is None else payload
        if peer is not None:
            peer.settimeout(remaining(deadline))
            accepted, client_address = peer.accept()
            stack.enter_context(accepted)
            if client_address != (flow.local_ip, flow.local_port):
                raise ValueError("local listener accepted an unrelated connection")
        client.settimeout(remaining(deadline))
        client.sendall(request)
        if peer is not None:
            incoming = receive_exact(accepted, len(request), deadline)
            if incoming != request:
                raise ValueError("local listener received an unrelated payload")
            accepted.settimeout(remaining(deadline))
            accepted.sendall(incoming)
            reply = receive_exact(client, len(incoming), deadline)
        else:
            length = struct.unpack("!H", receive_exact(client, 2, deadline))[0]
            reply = receive_exact(client, length, deadline)
    else:
        client.settimeout(remaining(deadline))
        client.send(payload)
        capture.expect_udp(flow, True, payload)
        if peer is not None:
            peer.settimeout(remaining(deadline))
            received, address = peer.recvfrom(2048)
            if received != payload or address != (flow.local_ip, flow.local_port):
                raise ValueError("local listener received an unrelated datagram")
            peer.settimeout(remaining(deadline))
            peer.sendto(received, address)
        client.settimeout(remaining(deadline))
        reply = client.recv(65535)
    if peer is None:
        require_dns_reply(payload, reply)
    elif reply != payload:
        raise ValueError("local echo reply did not match the probe")
    if flow.protocol == 17:
        capture.expect_udp(flow, False, reply)


def exercise_flows(clients, peers, capture, stack):
    deadline = time.monotonic() + TRAFFIC_SECONDS
    for flow, client in clients.items():
        try:
            traffic_exchange(flow, client, peers.get(flow.protocol), capture, stack, deadline)
            capture.observations[flow].exchange = "ok"
        except (ValueError, OSError) as error:
            capture.observations[flow].exchange = f"{type(error).__name__}: {error}"
        finally:
            if flow.protocol == 17:
                client.close()


def verified_binary(path):
    with path.open("rb") as candidate:
        image = candidate.read(ARM64_BYTES + 1)
    if len(image) != ARM64_BYTES or hashlib.sha256(image).hexdigest() != ARM64_SHA256:
        raise ValueError(f"use the official arm64-v8a binary from pcapd-bin {PIN}")
    return image


def helper_command(directory, interface, bpf):
    args = ["/system/bin/timeout", "-k", "2", str(ROOT_SECONDS), "./libpcapd.so", "-i", interface, "-b", bpf]
    return ["su", "-c", f"cd {shlex.quote(str(directory))} && exec {shlex.join(args)}"]


def accept_helper(listener, helper, log_path, interface):
    deadline = time.monotonic() + START_SECONDS
    while True:
        if helper.poll() is not None:
            raise RuntimeError(f"pcapd exited before connecting (exit {helper.returncode})")
        listener.settimeout(remaining(deadline, 0.2))
        try:
            connection, _ = listener.accept()
            break
        except TimeoutError:
            continue
    try:
        credentials = connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)
        _, uid, _ = struct.unpack("=3i", credentials)
        if uid != 0:
            raise RuntimeError("pcapd socket peer does not have root UID")
        ready = re.compile(rf"\b{re.escape(interface)}\(\d+\): datalink=")
        while not ready.search(log_path.read_text(errors="replace")):
            if helper.poll() is not None:
                raise RuntimeError(f"pcapd could not activate {interface} (exit {helper.returncode})")
            time.sleep(remaining(deadline, 0.05))
        return connection
    except BaseException:
        connection.close()
        raise


def drain_capture(connection, capture):
    reader = FrameReader()
    deadline = time.monotonic() + DRAIN_SECONDS
    while True:
        try:
            connection.settimeout(remaining(deadline))
            data = connection.recv(65536)
        except TimeoutError:
            reader.finish()
            return
        if not data:
            reader.finish()
            raise RuntimeError("pcapd closed the socket before the test finished")
        for record in reader.feed(data):
            capture.add(record)


def stop_helper(helper):
    try:
        return helper.wait(timeout=3)
    except subprocess.TimeoutExpired:
        # The root-side timeout remains in force if the su frontend cannot be stopped here.
        try:
            helper.terminate()
            return helper.wait(timeout=1)
        except (PermissionError, subprocess.TimeoutExpired):
            return None


def read_final_stats(log_path):
    sample = FINAL_STATS.search(log_path.read_text(errors="replace"))
    if not sample:
        return None
    received, dropped, iface_dropped = map(int, sample.groups())
    return {"libpcap_received": received, "libpcap_dropped": dropped, "interface_dropped": iface_dropped}


def run_bench(options):
    if os.geteuid() == 0:
        raise ValueError("run the bench as the ordinary Termux user to measure its UID")
    if platform.machine() not in ("aarch64", "arm64"):
        raise ValueError("the pinned bench requires an arm64-v8a device")
    image = verified_binary(options.pcapd)
    os.umask(0o077)
    options.output.mkdir(mode=0o700)
    log = options.output / "pcapd.log"
    result = {"pcapd_commit": PIN, "pcapd_sha256": ARM64_SHA256, "mode": options.mode,
              "interface": options.interface, "expected_uid": os.getuid()}
    capture = None
    try:
        with ExitStack() as stack:
            directory = Path(stack.enter_context(tempfile.TemporaryDirectory(prefix="np-")))
            binary = directory / "libpcapd.so"
            binary.write_bytes(image)
            binary.chmod(0o700)
            path = directory / "pcapsock"
            if len(os.fsencode(path)) > 107:
                raise ValueError("use a shorter Termux TMPDIR for the pcapd UNIX socket")
            clients, peers = prepare_flows(stack, options)
            capture = Capture(clients, os.getuid())
            bpf = build_filter(list(clients))
            result["bpf"] = bpf

            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener, log.open("wb") as helper_log:
                listener.bind(str(path))
                listener.listen(1)
                helper = subprocess.Popen(helper_command(directory, options.interface, bpf),
                                          stdin=subprocess.DEVNULL, stdout=helper_log, stderr=subprocess.STDOUT)
                try:
                    with accept_helper(listener, helper, log, options.interface) as connection:
                        exercise_flows(clients, peers, capture, stack)
                        drain_capture(connection, capture)
                finally:
                    listener.close()
                    result["pcapd_exit"] = stop_helper(helper)
    except (OSError, RuntimeError, ValueError) as error:
        result["error"] = f"{type(error).__name__}: {error}"
    if log.is_file():
        result["final_stats"] = read_final_stats(log)
    if capture is not None:
        result.update(capture.report())
        with (options.output / "probe.pcap").open("wb") as stream:
            write_pcap(stream, capture.frames)
    if "error" in result or result.get("pcapd_exit") != 0:
        result["status"] = "incomplete"
    elif options.mode == "dns" and not result["completed_exchanges"]:
        result["status"] = "dns_unavailable"
    elif not result["retained_records"]:
        result["status"] = "no_matching_packets"
    elif result["completed_exchanges"] != len(result["flows"]):
        result["status"] = "partial_exchange"
    else:
        result["status"] = "complete"
    with (options.output / "report.json").open("w", encoding="utf-8") as stream:
        json.dump(result, stream, indent=2)
        stream.write("\n")
    print(f"{result['status']}: {options.output / 'report.json'}")
    return 0 if result["status"] == "complete" else 1


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("loopback", "dns"))
    parser.add_argument("--pcapd", type=Path, required=True, help="official pinned arm64-v8a libpcapd.so")
    parser.add_argument("--output", type=Path, required=True, help="new private directory for PCAP and reports")
    parser.add_argument("--interface", help="one specific interface, for example wlan0 or tun0")
    parser.add_argument("--local-ip", help="IPv4 assigned to the specified interface")
    parser.add_argument("--peer", help="IPv4 DNS resolver (default 1.1.1.1)")
    parser.add_argument("--tcp", type=int, default=3, choices=range(1, 6))
    parser.add_argument("--udp", type=int, default=4, choices=range(1, 6))
    options = parser.parse_args(argv)
    if options.mode == "loopback":
        if options.interface not in (None, "lo") or options.local_ip is not None or options.peer is not None:
            parser.error("loopback uses lo and 127.0.0.1 for both endpoints")
        options.interface = "lo"
        options.local_ip = options.peer = "127.0.0.1"
    else:
        if (not options.interface or re.fullmatch(r"[A-Za-z0-9_.-]{1,15}", options.interface) is None
                or options.interface in ("lo", "any", ".", "..") or options.interface.startswith("-")):
            parser.error("specify one concrete non-loopback --interface")
        if not options.local_ip:
            parser.error("provide --local-ip for that interface")
        try:
            local = IPv4Address(options.local_ip)
            peer = IPv4Address(options.peer or "1.1.1.1")
        except ValueError:
            parser.error("the endpoints must be numeric IPv4 addresses")
        for address in (local, peer):
            if (address.is_unspecified or address.is_loopback or address.is_multicast or address.is_reserved
                    or address.is_link_local):
                parser.error("the endpoints must be usable non-loopback unicast IPv4 addresses")
        if local == peer:
            parser.error("the local and peer IPs must differ")
        options.local_ip, options.peer = str(local), str(peer)
    return options


def main():
    options = parse_args()
    try:
        return run_bench(options)
    except (OSError, ValueError) as error:
        print(f"pcapd-bench: {error}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
