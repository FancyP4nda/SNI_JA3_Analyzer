<div align="center">

# SNI & JA3 PCAP Analyzer

**A lightning-fast, extensible Python CLI for extracting TLS metadata (SNI, JA3, JA3S, ESNI/ECH) from large-scale packet captures.**

[![Python Version](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

</div>

---

## Overview

The SNI & JA3 PCAP Analyzer is a high-performance forensic tool engineered specifically for Threat Hunters and SOC Analysts. It processes massive PCAP and PCAPNG files to extract critical Transport Layer Security (TLS) intelligence, including ClientHello and ServerHello fingerprints, Server Name Indications (SNI), and encrypted SNI/ECH flags.

Built with scale in mind, this tool leverages streaming execution and C-level BPF (Berkeley Packet Filter) offloading to analyze gigabytes of traffic efficiently without memory bloat.

## Key Features

- **Streaming Execution**: Analyze 50GB+ rolling packet captures seamlessly using Python's lazy-evaluated generators.
- **BPF Filtering**: Drastically increase processing speed by dropping irrelevant packets at the C-level (`libpcap`) before they ever reach the Python interpreter.
- **Comprehensive TLS Extraction**: Accurately computes JA3 (Client) and JA3S (Server) fingerprints while ignoring GREASE values to ensure signature consistency across your threat intelligence platforms. ESNI (Encrypted SNI) and ECH (Encrypted Client Hello) extensions are strictly monitored.
- **Flexible Data Pipelines**: Choose between beautiful, human-readable terminal tables (powered by `rich`) for ad-hoc investigations, or stream output in `jsonl` format directly into Splunk or `jq` pipelines.
- **Standalone Binaries**: Easily distribute the tool across diverse environments by compiling it into a single executable—no Python runtime required.

---

## Installation

### Option 1: Source (Development & Python Environments)

*Requires Python 3.8 or higher.*

```bash
git clone https://github.com/FancyP4nda/SNI_JA3_Analyzer.git
cd SNI_JA3_Analyzer

# Install the package and its dependencies
pip install -e .
```

### Option 2: Pre-compiled Binary (Standalone)

For deployment to environments without Python, simply download the latest standalone binary from the [Releases](#) page. No dependencies required.

If you wish to build the binary yourself, run the included build script:
```bash
./build.sh
```
*(Executables and SHA256 checksums will be placed in the `dist/` directory).*

---

## Quick Start

Invoke the CLI via the `tls-analyzer` command.

### Basic Forensic Analysis 
Output results in a formatted, rich terminal table:
```bash
tls-analyzer --pcap capture.pcap
```

### SIEM Ingestion (Streaming JSONL)
Pipe structured JSON lines directly to `jq` or an enterprise log forwarder:
```bash
tls-analyzer --pcap capture.pcap --output jsonl > results.jsonl
```

### High-Speed BPF Filtering (Recommended for Large Files)
Leverage C-level filtering to exclusively process TLS traffic (port 443) from a specific subnet, dropping all other packets instantly:
```bash
tls-analyzer --pcap capture.pcap --bpf "tcp port 443 and net 192.168.1.0/24"
```

### Simple IP Filtering
Filter by source and destination IPs seamlessly:
```bash
tls-analyzer --pcap capture.pcap --source 192.0.2.10 --dest 198.51.100.20
```

*For a full list of commands, including record caps and routing configurations, run `tls-analyzer --help`.*

---

## Output Data Model

When streaming to JSONL or SIEMs, the tool outputs the following strictly typed fields:

| Field | Description |
| :--- | :--- |
| `timestamp` | UTC ISO8601 packet timestamp |
| `src_ip` / `dst_ip` | Source and Destination IP Addresses |
| `dst_port` | TCP Destination Port |
| `message_type` | `ClientHello` or `ServerHello` indicator |
| `sni` | Server Name Indication plaintext (if present) |
| `ja3` | MD5 hash of the TLS Fingerprint |
| `ja3_string` | The raw, unhashed fingerprint string |
| `esni_ech` | Flag indicating if Encrypted SNI/ECH was detected |

---

## Security Notes

1. Raw shell injection vectors are prevented via strict, explicit `subprocess` routing.
2. GREASE values are automatically stripped during fingerprinting.
3. Passwords, API keys, and external tokens should never be hardcoded into this repository's configurations.
