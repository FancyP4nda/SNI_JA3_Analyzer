# High-Performance TLS Forensic CLI

A lightning-fast, extensible Python Command Line Interface for extracting TLS metadata (SNI, JA3, JA3S, ESNI/ECH) from PCAP and PCAPNG files. Designed for Threat Hunters and SOC Analysts.

## Key Features
- **Streaming Execution:** Analyzes files of any size (50GB+) without memory bloat using lazy-evaluated generators.
- **BPF Filtering:** Drop irrelevant packets at the C-level (`libpcap`) before they hit Python for massive speed increases.
- **Rich Output:** Beautiful terminal tables that gracefully degrade when piped, or JSONL streaming for SIEM ingestion.
- **JA3 & JA3S:** Extracts both ClientHello and ServerHello fingerprints.
- **Standalone Binaries:** Compile the tool into a single executable without requiring a Python environment using the included build script.

## Installation

### Option 1: Development Environment
Requires Python 3.8+
```bash
git clone <repo_url>
cd SNI_JA3_Analyzer
pip install -e .
```

### Option 2: Pre-compiled Binary
*Download the latest binary from the Releases page.* No dependencies required.

---

## Usage
The CLI is invoked via the `tls-analyzer` command.

### Basic Analysis (Rich Table Output)
```bash
tls-analyzer --pcap capture.pcap
```

### Stream to JSONL (For jq or Splunk Ingestion)
```bash
tls-analyzer --pcap capture.pcap --output jsonl > results.jsonl
```

### Blazing Fast C-Level BPF Filtering
Only process TLS traffic on port 443 originating from a specific host. This is significantly faster than analyzing all traffic.
```bash
tls-analyzer --pcap capture.pcap --bpf "tcp port 443 and host 192.168.1.50"
```

### Simple IP Filtering
```bash
tls-analyzer --pcap capture.pcap --source 192.0.2.10 --dest 198.51.100.20
```

### Help Menu
View all options, including record limits and explicit routing:
```bash
tls-analyzer --help
```

---

## Output Data Model
- `timestamp`: UTC ISO8601
- `src_ip`: Source IP Address
- `dst_ip`: Destination IP Address
- `dst_port`: TCP Destination Port
- `message_type`: `ClientHello` or `ServerHello`
- `sni`: Server Name Indication (if present)
- `ja3`: MD5 hash of the TLS Fingerprint
- `ja3_string`: Raw fingerprint string before hashing
- `esni_ech`: Flag indicating if encrypted SNI was detected (`ENCRYPTED_SNI_DETECTED`)

## Security & Architecture Notes
- ESNI extension type `0xffce` and ECH extension type `0xfe0d` are strictly monitored.
- GREASE values are automatically stripped from JA3/JA3S calculations to ensure signature consistency.
- Raw shell injection is prevented via explicit `subprocess` structures where applicable.
- Passwords, API Keys, or external tokens should **never** be hardcoded into this repository.

## Building Standalone Binaries
To generate a standalone executable for distribution:
```bash
./build.sh
```
Executables and SHA256 checksums will be placed in the `dist/` tracking folder (which is ignored by Git to prevent bloat).
