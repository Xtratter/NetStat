"""Verify a pinned arm64 pcapd against NetStat's synthetic PCAP, without root."""
import argparse
import hashlib
import io
from pathlib import Path
import socket
import struct
import subprocess
import tempfile

from pcapd_bench import FrameReader, write_pcap

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "fixtures/dns-http.pcap"
ARM64_SHA256 = "4cc86aa41502882ec3a6ad4dab0d6c64aea3ee5d0efa23a7bdc208da646c3697"
PACKET = struct.Struct("<IIII")
EVENT = struct.Struct("<qqIIHHBB2x")  # timeval, drops, UID, length, DLT, flags, interface


def expected_records():
    data = FIXTURE.read_bytes()
    magic, major, minor, _, _, _, link = struct.unpack_from("<IHHIIII", data)
    assert (magic, major, minor, link) == (0xA1B2C3D4, 2, 4, 101)
    records = []
    offset = 24
    while offset < len(data):
        sec, usec, size, original = PACKET.unpack_from(data, offset)
        offset += PACKET.size
        payload = data[offset:offset + size]
        assert len(payload) == size == original
        records.append((sec, usec, payload))
        offset += size
    assert len(records) == 9
    return records


def verify(binary, expression, expected):
    with tempfile.TemporaryDirectory() as tmp, socket.socket(socket.AF_UNIX) as server:
        server.settimeout(5)
        server.bind(str(Path(tmp) / "pcapsock"))
        server.listen(1)
        proc = subprocess.Popen([binary, "-i", FIXTURE, "-b", expression], cwd=tmp,
                                stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        try:
            conn, _ = server.accept()
            with conn:
                conn.settimeout(5)
                with conn.makefile("rb") as stream:
                    reader = FrameReader()
                    frames = []
                    for sec, usec, payload in expected:
                        header = stream.read(EVENT.size)
                        assert len(header) == EVENT.size, "incomplete event"
                        s, us, _, uid, size, link, _, iface = EVENT.unpack(header)
                        assert (s, us, uid, size, link, iface) == (
                            sec, usec, 0xffffffff, len(payload), 12, 0)
                        raw = stream.read(size)
                        assert raw == payload, "payload mismatch"
                        frames.extend(reader.feed(header + raw))
                    assert not stream.read(1), "unexpected packet"
                    reader.finish()
                    assert len(frames) == len(expected)
                    if len(expected) == 9:
                        output = io.BytesIO()
                        write_pcap(output, frames)
                        assert output.getvalue() == FIXTURE.read_bytes(), "PCAP round trip failed"
            _, log = proc.communicate(timeout=5)
            # Pinned pcapd returns -1 on pcap_next_ex offline EOF.
            assert proc.returncode in (0, 255) and b"Terminating..." in log, log
        finally:
            if proc.poll() is None:
                proc.kill()
            proc.communicate()
        print(f"{expression}: {len(expected)} matching packets")


def main():
    if not __debug__:
        raise SystemExit("Run without -O so fixture checks remain enabled")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    binary = parser.parse_args().binary.resolve()
    if hashlib.sha256(binary.read_bytes()).hexdigest() != ARM64_SHA256:
        parser.error("expected the pinned arm64-v8a binary (pcapd-bin 6b54534)")
    records = expected_records()
    verify(binary, "tcp or udp", records)
    verify(binary, "udp and port 53", [r for r in records if r[2][9] == 17])
    verify(binary, "tcp and port 443", [])


if __name__ == "__main__":
    main()
