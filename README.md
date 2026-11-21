# Tesla Netlab for macOS 27

A **command-line**, read-only network diagnostics toolkit for macOS Golden Gate 27 on Apple Silicon. Rebuilt from the Windows-only Tesla-drug fork. No desktop app, injected configurations, traffic redirection, or background services.

**What changed:** This is an intentional safe rebuild, **not an FSD unlocker**. It does not override FSD entitlements, interfere with TLS validation, spoof Tesla servers, install certificate authorities, poison ARP, modify DNS, or change vehicle settings. Nothing here can grant FSD or prove FSD availability.

## Install on an M-series Mac running macOS 27

Prerequisite: [Homebrew](https://brew.sh). Python 3.13 is installed through Homebrew.

```bash
git clone https://github.com/bruvv/Tesla-drug.git
cd Tesla-drug
bash scripts/install.sh
.venv/bin/tesla-netlab doctor
```

The installer makes a local Python virtual environment; it does **not** require `sudo`, create a login item, or configure your Mac's network.

## Commands

```bash
# Check the macOS version, architecture and network interfaces
.venv/bin/tesla-netlab doctor

# Capture only already-visible traffic for a device you own.
# Replace the IP and network interface with your actual values.
# May require running the command with sudo for tcpdump permissions.
.venv/bin/tesla-netlab capture --interface en0 --host 192.168.1.42 \
  --output captures/vehicle.pcap

# Read an existing local capture (no network access)
.venv/bin/tesla-netlab analyze captures/vehicle.pcap
.venv/bin/tesla-netlab analyze captures/vehicle.pcap --json

# Generate a static HTML file, not a hosted app
.venv/bin/tesla-netlab report captures/vehicle.pcap --output report.html
open report.html
```

On macOS, Apple provides `tcpdump` for packet traces. Capture requires suitable permission to access an interface. If permission is denied, run `sudo .venv/bin/tesla-netlab capture ...` or run the displayed tcpdump command with sudo. Press Ctrl+C to stop. `--overwrite` is required if the capture filename exists.

**Important network limitation:** A Wi-Fi client and your Tesla on the same UniFi LAN do **not** automatically see each other's unicast traffic. Use an authorized mirrored/monitored interface or an existing capture. This tool does not change UniFi routing, create a hotspot, or redirect the Tesla's traffic.

## Data and parser limits

- Reports DNS queries, TLS ClientHello SNI hostnames when visible, and destination IP addresses.
- Reads classic `.pcap` files with Ethernet, raw IP or BSD loopback link types (not `.pcapng`).
- IPv4, basic IPv6, VLAN-tagged Ethernet, UDP DNS and single-segment TCP TLS ClientHello are supported.
- Encrypted DNS, ECH, QUIC server names and fragmented ClientHello are not decoded.
- Default capture snap length is 1024 bytes. Captures can contain private network metadata. Do not upload them publicly.
- The analyzer has a 500 MB input limit and never makes network requests.

## Tests

```bash
.venv/bin/python -m unittest discover -s tests -v
```

CI targets macOS 27 Apple Silicon using GitHub's `xcode-27` runner plus Ubuntu for parser portability. A green CI status proves test success, not live functionality with a vehicle.

## History and security

The exact original Windows repository remains preserved in [`backup`](https://github.com/bruvv/Tesla-drug/tree/backup). The previous tree contained TLS certificate/private-key material and vehicle-configuration payloads. Those files are intentionally excluded from the new `main`; because `backup` and Git history remain public, **do not trust or reuse those historical keys**. Removing a file from `main` does not erase it from Git history.

This project is for diagnostics on networks and vehicles you own or administer. Do not use it to make safety-critical driving features available outside their authorized configuration.

Documentation: [Apple packet traces](https://developer.apple.com/documentation/network/recording-a-packet-trace), [Homebrew Python](https://formulae.brew.sh/formula/python@3.13), [GitHub macOS 27 runner](https://github.blog/changelog/2026-10-15-xcode-27-runner-image-generally-available/).
