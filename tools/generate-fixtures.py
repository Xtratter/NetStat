from ipaddress import IPv4Address
from pathlib import Path
from struct import pack, unpack

CLIENT = IPv4Address("192.0.2.10").packed
WEB = IPv4Address("198.51.100.20").packed
DNS = IPv4Address("203.0.113.53").packed


def checksum(data):
    if len(data) % 2:
        data += b"\x00"
    value = sum(unpack(f"!{len(data) // 2}H", data))
    while value >> 16:
        value = (value & 0xFFFF) + (value >> 16)
    return ~value & 0xFFFF


def ipv4(source, target, protocol, payload):
    header = pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), 0, 0x4000, 64,
                  protocol, 0, source, target)
    return header[:10] + pack("!H", checksum(header)) + header[12:] + payload


def tcp(source, target, ports, seq, ack, flags, payload=b""):
    header = pack("!HHIIHHHH", *ports, seq, ack, 0x5000 | flags, 8192, 0, 0)
    pseudo_header = pack("!4s4sBBH", source, target, 0, 6, len(header) + len(payload))
    check = pack("!H", checksum(pseudo_header + header + payload))
    return ipv4(source, target, 6, header[:16] + check + header[18:] + payload)


def udp(source, target, ports, payload):
    header = pack("!HHHH", *ports, 8 + len(payload), 0)
    return ipv4(source, target, 17, header + payload)


def write_capture(output):
    out = (49152, 80)
    reply = (80, 49152)
    request_start = b"GET /network-"
    request_end = b"night HTTP/1.1\r\nHost: example.test\r\n\r\n"
    response = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello"
    request_next = 101 + len(request_start) + len(request_end)

    question = b"\x07example\x04test\x00" + pack("!HH", 1, 1)
    dns_query = pack("!6H", 0x4321, 0x0100, 1, 0, 0, 0) + question
    answer = pack("!HHHIH", 0xC00C, 1, 1, 60, 4) + WEB
    dns_response = pack("!6H", 0x4321, 0x8180, 1, 1, 0, 0) + question + answer

    packets = [
        udp(CLIENT, DNS, (53530, 53), dns_query),
        udp(DNS, CLIENT, (53, 53530), dns_response),
        tcp(CLIENT, WEB, out, 100, 0, 0x02),
        tcp(WEB, CLIENT, reply, 200, 101, 0x12),
        tcp(CLIENT, WEB, out, 101, 201, 0x10),
        tcp(CLIENT, WEB, out, 101, 201, 0x18, request_start),
        tcp(CLIENT, WEB, out, 101 + len(request_start), 201, 0x18, request_end),
        tcp(WEB, CLIENT, reply, 201, request_next, 0x18, response),
        tcp(CLIENT, WEB, out, request_next, 201 + len(response), 0x10),
    ]

    with output.open("wb") as stream:
        stream.write(pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 101))
        for index, packet in enumerate(packets):
            stream.write(pack("<IIII", 1795219200, index * 25000, len(packet), len(packet)))
            stream.write(packet)


if __name__ == "__main__":
    write_capture(Path(__file__).resolve().parents[1] / "fixtures" / "dns-http.pcap")
