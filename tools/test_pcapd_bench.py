import io
import struct
import unittest
from unittest.mock import patch

from pcapd_bench import Capture, Flow, Frame, FrameReader, build_filter, exercise_flows, write_pcap


def frame_bytes(payload, uid=10345, link=12, flags=1, iface=0):
    # From the pinned pcapd.h arm64 layout. Padding may be nonzero.
    return struct.pack("<qqIIHHBBBB", 1795219200, 25, 3, uid, len(payload), link,
                       flags, iface, 0xA1, 0xB2) + payload


def udp(source, destination, source_port, destination_port, payload=b"probe"):
    return (
        struct.pack("!BBHHHBBH4s4s", 0x45, 0, 28 + len(payload), 0, 0, 64, 17, 0,
                    bytes(map(int, source.split("."))), bytes(map(int, destination.split("."))))
        + struct.pack("!HHHH", source_port, destination_port, 8 + len(payload), 0)
        + payload
    )


class ProtocolTests(unittest.TestCase):
    def test_partial_stream_reads_keep_packet_metadata_and_unsigned_unknown_uid(self):
        raw_ip = b"example"
        stream = frame_bytes(raw_ip) + frame_bytes(raw_ip, uid=0xFFFFFFFF, flags=0)
        reader = FrameReader()
        frames = []
        for end in range(0, len(stream), 7):
            frames.extend(reader.feed(stream[end:end + 7]))
        reader.finish()

        self.assertEqual(frames, [
            Frame(1795219200, 25, 3, 10345, True, raw_ip),
            Frame(1795219200, 25, 3, None, False, raw_ip),
        ])

    def test_incomplete_stream_is_distinct_from_no_packets(self):
        reader = FrameReader()
        self.assertEqual(list(reader.feed(frame_bytes(b"example")[:-1])), [])
        with self.assertRaisesRegex(ValueError, "incomplete"):
            reader.finish()
        FrameReader().finish()

    def test_rejects_different_datalink_or_unexpected_interface(self):
        for data in [frame_bytes(b"example", link=1), frame_bytes(b"example", iface=1)]:
            with self.subTest(data=data), self.assertRaises(ValueError):
                list(FrameReader().feed(data))

    def test_classic_pcap_uses_savefile_raw_linktype_not_pcapd_dlt(self):
        output = io.BytesIO()
        write_pcap(output, [Frame(1795219200, 25, 3, 10345, True, b"example")])
        self.assertEqual(
            output.getvalue(),
            bytes.fromhex("d4c3b2a1020004000000000000000000ffff000065000000")
            + struct.pack("<4I", 1795219200, 25, 7, 7)
            + b"example",
        )


class MeasurementTests(unittest.TestCase):
    def test_capture_stores_only_exact_five_tuples_and_counts_expected_udp_payloads(self):
        first = Flow(17, "192.0.2.8", 50001, "198.51.100.4", 53)
        second = Flow(17, "192.0.2.8", 50002, "198.51.100.4", 53)
        capture = Capture([first, second], 10345)
        capture.expect_udp(first, True, b"query")
        capture.expect_udp(first, False, b"response")
        capture.expect_udp(second, True, b"query")
        capture.expect_udp(second, False, b"response")
        packets = [
            (10345, udp(first.local_ip, first.peer_ip, 50001, 53, b"query")),
            (None, udp(first.peer_ip, first.local_ip, 53, 50001, b"response")),
            (10346, udp(second.local_ip, second.peer_ip, 50002, 53, b"query")),
            (10345, udp(second.peer_ip, second.local_ip, 53, 50002, b"wrong")),
            (10345, udp(first.peer_ip, first.local_ip, 53, 50001, b"query")),
            (10345, udp(first.local_ip, "198.51.100.5", 50001, 53, b"query")),
            (10345, udp(first.peer_ip, first.local_ip, 54, 50001, b"response")),
            (10345, udp(first.local_ip, first.peer_ip, 50001, 53, b"query")),
        ]
        for uid, packet in packets:
            capture.add(Frame(1, 2, 0, uid, False, packet))

        report = capture.report()
        self.assertEqual(len(capture.frames), 4)
        self.assertEqual(report["excluded_records"], 4)
        self.assertEqual(report["udp_expected_messages"], 4)
        self.assertEqual(report["udp_missing_messages"], 1)
        self.assertEqual([row["attribution"] for row in report["flows"]], ["partial", "wrong"])

    def test_udp_socket_is_closed_on_success_and_error_before_next_flow(self):
        class Client:
            closed = False

            def close(self):
                self.closed = True

        first = Flow(17, "127.0.0.1", 50001, "127.0.0.1", 50000)
        second = Flow(17, "127.0.0.1", 50002, "127.0.0.1", 50000)
        third = Flow(6, "127.0.0.1", 50003, "127.0.0.1", 50000)
        clients = {first: Client(), second: Client(), third: Client()}
        capture = Capture(clients, 10345)
        entered = []

        def exchange(flow, client, peer, capture, stack, deadline):
            self.assertFalse(client.closed)
            if entered:
                self.assertTrue(clients[entered[-1]].closed)
            entered.append(flow)
            if flow == second:
                raise TimeoutError("synthetic timeout")

        with patch("pcapd_bench.traffic_exchange", side_effect=exchange):
            exercise_flows(clients, {}, capture, None)

        self.assertEqual(entered, [first, second, third])
        self.assertEqual([client.closed for client in clients.values()], [True, True, False])
        self.assertEqual(capture.observations[second].exchange, "TimeoutError: synthetic timeout")

    def test_bpf_matches_only_reserved_ports_and_rejects_truncation(self):
        first = Flow(6, "192.0.2.8", 50001, "198.51.100.4", 53)
        second = Flow(17, "192.0.2.8", 50002, "198.51.100.4", 5300)
        bpf = build_filter([first, second])
        self.assertEqual(
            bpf,
            "ip and ((src host 192.0.2.8 and dst host 198.51.100.4 and "
            "((tcp and dst port 53 and src port 50001) or (udp and dst port 5300 and src port 50002))) or "
            "(src host 198.51.100.4 and dst host 192.0.2.8 and "
            "((tcp and src port 53 and dst port 50001) or (udp and src port 5300 and dst port 50002))))",
        )
        too_many = [Flow(17, first.local_ip, port, first.peer_ip, 53) for port in range(50000, 50050)]
        with self.assertRaisesRegex(ValueError, "512"):
            build_filter(too_many)


if __name__ == "__main__":
    unittest.main()
