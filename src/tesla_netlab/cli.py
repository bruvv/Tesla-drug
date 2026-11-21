"""CLI entry point for macOS 27. No packet injection or network reconfiguration."""
from __future__ import annotations

import argparse
from html import escape
import ipaddress
import json
import platform
from pathlib import Path
import re
import shutil
import subprocess
import sys

from tesla_netlab.pcap import PcapError, analyze


SAFE_INTERFACE = re.compile(r"^[a-zA-Z][a-zA-Z0-9_.-]{0,30}$")


def doctor() -> int:
    mac = sys.platform == "darwin"
    version = platform.mac_ver()[0] if mac else "unavailable"
    major = int(version.split(".")[0]) if version and version[0].isdigit() else 0
    arm = platform.machine() == "arm64"
    print(f"Operating system: {platform.system()} {version}")
    print(f"CPU: {platform.machine()}")
    print(f"Python: {platform.python_version()}")
    print(f"Homebrew: {shutil.which('brew') or 'not found'}")
    print(f"tcpdump: {shutil.which('tcpdump') or 'not found'}")
    if mac and shutil.which("networksetup"):
        result = subprocess.run(["networksetup", "-listallhardwareports"],
                                text=True, capture_output=True, check=False)
        if result.returncode == 0:
            print("\nNetwork interfaces:\n" + result.stdout.strip())
    compatible = mac and major >= 27 and arm and shutil.which("tcpdump") is not None
    print("\nmacOS 27 Apple Silicon prerequisites: " + ("OK" if compatible else "NOT VERIFIED"))
    return 0 if compatible else 1


def capture(args: argparse.Namespace) -> int:
    if sys.platform != "darwin":
        raise ValueError("Live capture is supported on macOS only")
    if not SAFE_INTERFACE.fullmatch(args.interface):
        raise ValueError("Invalid interface name")
    target = ipaddress.ip_address(args.host)
    if target.is_unspecified or target.is_multicast:
        raise ValueError("Specify a unicast device IP address")
    output = Path(args.output).expanduser().resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    if output.exists() and not args.overwrite:
        raise ValueError(f"Capture already exists: {output} (use --overwrite)")
    cmd = ["tcpdump", "-i", args.interface, "-n", "-s", "1024", "-U", "-w", str(output),
           "host", str(target), "and", "(", "udp", "port", "53", "or", "tcp", "port", "53",
           "or", "tcp", "port", "443", "or", "udp", "port", "443", ")"]
    print("Read-only capture. Nothing is redirected or modified.", flush=True)
    print("Stop with Ctrl+C. PCAP files can contain sensitive information.", flush=True)
    print("Command: " + " ".join(cmd), flush=True)
    try:
        return subprocess.call(cmd)
    except KeyboardInterrupt:
        return 130
    except FileNotFoundError as exc:
        raise ValueError("tcpdump is missing") from exc


def _html(data: dict) -> str:
    def table(title: str, values: dict) -> str:
        rows = "".join(f"<tr><td>{escape(k)}</td><td>{n}</td></tr>" for k, n in values.items())
        return f"<h2>{escape(title)}</h2><table><tr><th>Value</th><th>Packets</th></tr>{rows}</table>"
    return ("<!doctype html><html lang='en'><meta charset='utf-8'>"
            "<meta name='viewport' content='width=device-width,initial-scale=1'>"
            "<meta http-equiv='Content-Security-Policy' content=\"default-src 'none'; style-src 'unsafe-inline'\">"
            "<title>Tesla Netlab - Offline report</title><style>body{font:16px system-ui;margin:3rem auto;"
            "max-width:800px;padding:0 1rem;background:#10151c;color:#e4eaf0}table{width:100%;border-collapse:collapse}"
            "td,th{text-align:left;padding:.7rem;border-bottom:1px solid #455}td:last-child{text-align:right}"
            "p{color:#afbac8}</style><h1>Tesla Netlab - Offline report</h1>"
            f"<p>Packets: {data['packets']}; IPv4: {data['ipv4']}; IPv6: {data['ipv6']}</p>"
            + table("DNS queries", data["dns_queries"]) + table("TLS SNI", data["tls_sni"])
            + table("Destination IPs", data["destinations"])
            + "<p>Read-only metadata; not evidence of FSD activation or eligibility.</p></html>")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="tesla-netlab", description="Read-only macOS vehicle network diagnostics")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("doctor", help="Check macOS 27, Apple Silicon and tooling")
    cap = sub.add_parser("capture", help="Capture traffic already visible on a chosen interface")
    cap.add_argument("--interface", required=True, help="e.g. en0; discover with doctor")
    cap.add_argument("--host", required=True, help="IP address of the device you own")
    cap.add_argument("--output", default="captures/vehicle.pcap", help="Local classic PCAP filename")
    cap.add_argument("--overwrite", action="store_true")
    report = sub.add_parser("analyze", help="Analyze offline classic PCAP; never sends traffic")
    report.add_argument("pcap", help="Path to existing .pcap")
    report.add_argument("--json", action="store_true", help="Print machine-readable summary")
    html = sub.add_parser("report", help="Generate a static local HTML report")
    html.add_argument("pcap", help="Path to existing .pcap")
    html.add_argument("--output", default="report.html")
    args = parser.parse_args(argv)
    try:
        if args.command == "doctor":
            return doctor()
        if args.command == "capture":
            return capture(args)
        summary = analyze(args.pcap).as_dict()
        if args.command == "report":
            path = Path(args.output)
            if path.exists():
                raise ValueError(f"Will not overwrite existing report: {path}")
            path.write_text(_html(summary), encoding="utf-8")
            print(f"Wrote {path}")
        elif args.json:
            print(json.dumps(summary, indent=2))
        else:
            print(f"Packets: {summary['packets']}; IPv4: {summary['ipv4']}; IPv6: {summary['ipv6']}")
            for kind in ("dns_queries", "tls_sni", "destinations"):
                print(f"{kind}:")
                for value, count in summary[kind].items():
                    print(f"  {value}: {count}")
            print("Limitations: " + "; ".join(summary["limitations"]))
        return 0
    except (OSError, PcapError, ValueError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
