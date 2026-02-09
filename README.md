# TLS ClientHello PCAP Analyzer

Parses TLS ClientHello records from a PCAP using Scapy and prints a table with SNI, JA3 hash, and ESNI/ECH detection. Uses `PcapReader` to stream large files.

## Requirements
- Python 3.8+
- scapy
- tabulate (default table output)
- pandas (optional alternative output)
- cryptography (recommended to avoid TLS cipher warnings)

Install:
```bash
pip install scapy tabulate pandas cryptography
```

## Usage
```bash
python tls_pcap_analyzer.py --pcap path/to/capture.pcap
```

PCAPNG is supported:
```bash
python tls_pcap_analyzer.py --pcap path/to/capture.pcapng
```

Filter by source IP:
```bash
python tls_pcap_analyzer.py --pcap capture.pcap --source 192.0.2.10
```

Filter by destination IP:
```bash
python tls_pcap_analyzer.py --pcap capture.pcap --dest 198.51.100.20
```

Limit output rows:
```bash
python tls_pcap_analyzer.py --pcap capture.pcap --limit 25
```

Use pandas output:
```bash
python tls_pcap_analyzer.py --pcap capture.pcap --output pandas
```

## Output Columns
- `timestamp` (UTC ISO8601)
- `src_ip`
- `dst_ip`
- `dst_port`
- `sni` (if present)
- `ja3` (MD5 hash)
- `ja3_string` (raw JA3 string)
- `esni_ech` (flag if ESNI/ECH extension detected)

## Notes
- ESNI extension type `0xffce` (65486) and ECH extension type `0xfe0d` (65037) are detected in ClientHello extensions.
- JA3 uses the ClientHello version, ciphers, extensions, supported groups, and EC point formats with GREASE values stripped.
- TLS 1.3 ClientHello is supported through Scapy’s TLS layer parsing.
