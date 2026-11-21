"""Offline classic-PCAP parser. Never opens sockets or transmits packets."""
from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
import ipaddress
from pathlib import Path
import socket
import struct


class PcapError(ValueError):
    """Invalid or unsupported capture."""


@dataclass
class Summary:
    packets: int = 0
    ipv4: int = 0
    ipv6: int = 0
    dns_queries: Counter[str] = field(default_factory=Counter)
    tls_sni: Counter[str] = field(default_factory=Counter)
    destinations: Counter[str] = field(default_factory=Counter)

    def as_dict(self) -> dict:
        return {
            "packets": self.packets,
            "ipv4": self.ipv4,
            "ipv6": self.ipv6,
            "dns_queries": dict(sorted(self.dns_queries.items())),
            "tls_sni": dict(sorted(self.tls_sni.items())),
            "destinations": dict(sorted(self.destinations.items())),
            "limitations": [
                "DNS-over-HTTPS, encrypted ClientHello (ECH), and QUIC names are not decoded.",
                "TLS ClientHello spanning multiple TCP segments may not be detected.",
                "Observed network metadata does not establish feature entitlement.",
            ],
        }


def _name(buf: bytes, pos: int) -> str | None:
    labels = []
    visited = set()
    for _ in range(128):
        if pos >= len(buf) or pos in visited:
            return None
        visited.add(pos)
        size = buf[pos]
        if size == 0:
            return ".".join(labels).lower()
        if size & 0xC0 == 0xC0:
            if pos + 1 >= len(buf):
                return None
            pos = ((size & 0x3F) << 8) | buf[pos + 1]
            continue
        if size & 0xC0 or size > 63 or pos + 1 + size > len(buf):
            return None
        label = buf[pos + 1 : pos + 1 + size].decode("ascii", "replace")
        labels.append(label)
        pos += 1 + size
    return None


def _dns_question(data: bytes) -> str | None:
    if len(data) < 12:
        return None
    flags, questions = struct.unpack_from("!HH", data, 2)
    if flags & 0x8000 or not questions:
        return None
    return _name(data, 12)


def _sni(data: bytes) -> str | None:
    """Get SNI only when a TLS ClientHello fits inside one TCP payload."""
    if len(data) < 9 or data[0] != 22:
        return None
    rec_size = int.from_bytes(data[3:5], "big")
    if rec_size + 5 > len(data) or data[5] != 1:
        return None
    handshake_len = int.from_bytes(data[6:9], "big")
    if handshake_len + 4 > rec_size:
        return None
    end = 9 + handshake_len
    pos = 9 + 2 + 32
    if pos >= end:
        return None
    pos += 1 + data[pos]
    if pos + 2 > end:
        return None
    pos += 2 + int.from_bytes(data[pos : pos + 2], "big")
    if pos >= end:
        return None
    pos += 1 + data[pos]
    if pos + 2 > end:
        return None
    extensions_end = pos + 2 + int.from_bytes(data[pos : pos + 2], "big")
    pos += 2
    if extensions_end > end:
        return None
    while pos + 4 <= extensions_end:
        kind, length = struct.unpack_from("!HH", data, pos)
        pos += 4
        if pos + length > extensions_end:
            return None
        if kind == 0 and length >= 5:
            # ServerNameList len(2), name_type(1), name_len(2), name.
            list_len = int.from_bytes(data[pos : pos + 2], "big")
            if list_len + 2 > length or data[pos + 2] != 0:
                return None
            n = int.from_bytes(data[pos + 3 : pos + 5], "big")
            if n > list_len - 3 or pos + 5 + n > pos + length:
                return None
            return data[pos + 5 : pos + 5 + n].decode("ascii", "replace").lower()
        pos += length
    return None


def _network_frame(frame: bytes, linktype: int) -> bytes | None:
    if linktype == 1:  # Ethernet, optionally 802.1Q VLAN tagged
        if len(frame) < 14:
            return None
        etype = int.from_bytes(frame[12:14], "big")
        pos = 14
        for _ in range(2):
            if etype not in (0x8100, 0x88A8) or len(frame) < pos + 4:
                break
            etype = int.from_bytes(frame[pos + 2 : pos + 4], "big")
            pos += 4
        return frame[pos:] if etype in (0x0800, 0x86DD) else None
    if linktype == 101:  # Raw IP
        return frame
    if linktype == 0 and len(frame) >= 4:  # BSD loopback
        family = int.from_bytes(frame[:4], "little")
        if family in (2, 30):
            return frame[4:]
    return None


def _inspect_packet(frame: bytes, linktype: int, summary: Summary) -> None:
    raw = _network_frame(frame, linktype)
    if not raw:
        return
    version = raw[0] >> 4
    if version == 4 and len(raw) >= 20:
        ihl = (raw[0] & 15) * 4
        if ihl < 20 or len(raw) < ihl:
            return
        total = int.from_bytes(raw[2:4], "big")
        if total < ihl:
            return
        # Ignore non-first fragments; they have no transport header.
        if int.from_bytes(raw[6:8], "big") & 0x1FFF:
            return
        proto, dest = raw[9], str(ipaddress.IPv4Address(raw[16:20]))
        data = raw[ihl : min(total, len(raw))]
        summary.ipv4 += 1
    elif version == 6 and len(raw) >= 40:
        proto = raw[6]
        dest = str(ipaddress.IPv6Address(raw[24:40]))
        data = raw[40 : min(40 + int.from_bytes(raw[4:6], "big"), len(raw))]
        summary.ipv6 += 1
    else:
        return
    summary.destinations[dest] += 1
    if proto == 17 and len(data) >= 8:  # UDP
        src_port, dst_port, length = struct.unpack_from("!HHH", data)
        if 53 in (src_port, dst_port) and length >= 8:
            name = _dns_question(data[8 : min(length, len(data))])
            if name:
                summary.dns_queries[name] += 1
    elif proto == 6 and len(data) >= 20:  # TCP
        src_port, dst_port = struct.unpack_from("!HH", data)
        header_size = (data[12] >> 4) * 4
        if header_size >= 20 and header_size <= len(data) and 443 in (src_port, dst_port):
            name = _sni(data[header_size:])
            if name:
                summary.tls_sni[name] += 1


def analyze(path: str | Path, max_bytes: int = 500_000_000) -> Summary:
    """Analyze a bounded classic .pcap file (not pcapng)."""
    path = Path(path)
    if path.stat().st_size > max_bytes:
        raise PcapError(f"Capture exceeds the {max_bytes} byte size limit")
    result = Summary()
    with path.open("rb") as stream:
        header = stream.read(24)
        if len(header) != 24:
            raise PcapError("File is too short for a PCAP header")
        magic = header[:4]
        endian = {b"\xd4\xc3\xb2\xa1": "<", b"\xa1\xb2\xc3\xd4": ">",
                  b"\x4d\x3c\xb2\xa1": "<", b"\xa1\xb2\x3c\x4d": ">"}.get(magic)
        if endian is None:
            raise PcapError("Expected a classic .pcap file; PCAPNG is not supported")
        linktype = struct.unpack_from(endian + "I", header, 20)[0] & 0xFFFF
        if linktype not in (0, 1, 101):
            raise PcapError(f"Unsupported link type {linktype}; use an Ethernet capture")
        while True:
            record = stream.read(16)
            if not record:
                break
            if len(record) != 16:
                raise PcapError("Truncated packet header")
            _, _, caplen, _ = struct.unpack(endian + "IIII", record)
            if caplen > 10_000_000:
                raise PcapError("Unreasonably large packet")
            payload = stream.read(caplen)
            if len(payload) != caplen:
                raise PcapError("Truncated packet data")
            result.packets += 1
            _inspect_packet(payload, linktype, result)
    return result
