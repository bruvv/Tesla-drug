# Architecture

`tesla-netlab` is a Python 3.11+ standard-library package. It runs natively on macOS 27 Apple Silicon with Python 3.13 from Homebrew. The CLI and PCAP analyzer also run on Linux for offline tests.

`doctor`: read-only system discovery (`platform`, `networksetup`, executable paths).

`capture`: invokes Apple's `tcpdump` with an exact device IP and network interface; never creates a proxy or changes the network. Permission errors are handled by `tcpdump`. There are no background daemons or launch agents.

`analyze`: parses bounded classic-PCAP records and extracts passive DNS queries, single-packet TLS ClientHello SNI and destination IPs. No decryption is performed and all data remains local.

`report`: produces a static HTML report with HTML-escaped names and an restrictive CSP. There is no web server, JavaScript, or hosted service.

Windows components intentionally not migrated: PowerShell installer/hotspot orchestration, `pydivert`, ARP poisoning, DNS spoofing, TLS interception, FSD payload rewriting and bundled CA/private keys. These are not required for the safe diagnostic workflow and should not be reintroduced as part of a macOS port.

Security considerations: PCAPs can contain sensitive data; they are ignored by Git. File size and packet-length bounds protect the parser against malformed captures. The analyzer does not reconstruct multi-packet TCP streams and therefore cannot be used to infer that absent hostnames imply no communication.
