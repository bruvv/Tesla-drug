import io
import json
from pathlib import Path
import socket
import struct
import tempfile
import unittest

from tesla_netlab.cli import main, _html
from tesla_netlab.pcap import PcapError, _sni, _dns_question, analyze


def pcap(frames, magic=b"\xd4\xc3\xb2\xa1", network=1):
    header = magic + struct.pack("<HHIIII", 2, 4, 0, 0, 65535, network)
    return header + b"".join(struct.pack("<IIII", 1, 1, len(f), len(f)) + f for f in frames)


def ethernet_ipv4(transport, proto):
    ip = (b"\x45\x00" + struct.pack("!H", 20 + len(transport)) + b"\x00\x01\x00\x00\x40"
          + bytes([proto]) + b"\x00\x00" + socket.inet_aton("192.0.2.10")
          + socket.inet_aton("198.51.100.20"))
    return b"\x00" * 12 + b"\x08\x00" + ip + transport


def dns():
    question = b"\x03api\x05tesla\x03com\x00\x00\x01\x00\x01"
    payload = b"\x00\x01\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00" + question
    udp = struct.pack("!HHHH", 54000, 53, 8 + len(payload), 0) + payload
    return ethernet_ipv4(udp, 17)


def tls():
    name = b"example.org"
    sni_name = b"\x00" + struct.pack("!H", len(name)) + name
    sni_ext = struct.pack("!HHH", 0, len(sni_name) + 2, len(sni_name)) + sni_name
    hello = (b"\x03\x03" + b"\x00" * 32 + b"\x00" + b"\x00\x02\x13\x01"
             + b"\x01\x00" + struct.pack("!H", len(sni_ext)) + sni_ext)
    handshake = b"\x01" + len(hello).to_bytes(3, "big") + hello
    record = b"\x16\x03\x03" + struct.pack("!H", len(handshake)) + handshake
    tcp = struct.pack("!HHIIHHHH", 54000, 443, 0, 0, 0x5018, 65535, 0, 0) + record
    return ethernet_ipv4(tcp, 6)


class PcapTests(unittest.TestCase):
    def test_dns_query(self):
        self.assertEqual(_dns_question(dns()[14 + 20 + 8:]), "api.tesla.com")

    def test_dns_malformed(self):
        self.assertIsNone(_dns_question(b"\x00"))
        self.assertIsNone(_dns_question(b"\x00" * 12 + b"\xc0\x0c"))

    def test_tls_sni(self):
        self.assertEqual(_sni(tls()[14 + 20 + 20:]), "example.org")
        self.assertIsNone(_sni(b"\x16\x03\x03\x10\x00"))

    def test_complete_capture(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "test.pcap"
            path.write_bytes(pcap([dns(), tls()]))
            report = analyze(path).as_dict()
            self.assertEqual(report["packets"], 2)
            self.assertEqual(report["dns_queries"], {"api.tesla.com": 1})
            self.assertEqual(report["tls_sni"], {"example.org": 1})
            self.assertEqual(report["destinations"], {"198.51.100.20": 2})
            self.assertEqual(main(["analyze", str(path), "--json"]), 0)

    def test_invalid_and_truncated_capture(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "test.pcap"
            path.write_bytes(b"pcapng")
            with self.assertRaises(PcapError):
                analyze(path)
            path.write_bytes(pcap([dns()])[:-1])
            with self.assertRaises(PcapError):
                analyze(path)

    def test_xss_escaped_html(self):
        html = _html({"packets": 1, "ipv4": 1, "ipv6": 0, "dns_queries": {"<script>": 1},
                      "tls_sni": {}, "destinations": {}})
        self.assertIn("&lt;script&gt;", html)
        self.assertNotIn("<script>", html)


if __name__ == "__main__":
    unittest.main()
