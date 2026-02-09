#!/usr/bin/env python3
"""
TLS ClientHello forensic parser using Scapy.
- Filters by source IP
- Extracts SNI, JA3 hash, ESNI/ECH detection
- Streams PCAP with PcapReader for large files
"""

import argparse
import hashlib
import sys
from datetime import datetime, timezone

from scapy.all import PcapReader, PcapNgReader, IP, IPv6, TCP, load_layer

# Load TLS layer support
load_layer('tls')

try:
    from scapy.layers.tls.all import TLS, TLSClientHello
    from scapy.layers.tls.extensions import (
        TLS_Ext_ServerName,
        TLS_Ext_SupportedGroups,
        TLS_Ext_SupportedPointFormat,
    )
except Exception:
    # Fallback import path for older scapy versions
    from scapy.layers.tls.all import TLS, TLSClientHello, TLS_Ext_ServerName, TLS_Ext_SupportedGroups, TLS_Ext_SupportedPointFormat


GREASE_VALUES = {
    0x0A0A, 0x1A1A, 0x2A2A, 0x3A3A, 0x4A4A, 0x5A5A, 0x6A6A, 0x7A7A,
    0x8A8A, 0x9A9A, 0xAAAA, 0xBABA, 0xCACA, 0xDADA, 0xEAEA, 0xFAFA,
}

ESNI_EXT = 0xFFCE  # 65486
ECH_EXT = 0xFE0D   # 65037


def is_grease(val):
    return val in GREASE_VALUES


def get_ip(packet):
    if IP in packet:
        return packet[IP].src, packet[IP].dst
    if IPv6 in packet:
        return packet[IPv6].src, packet[IPv6].dst
    return None, None


def get_ext_type(ext):
    # scapy versions vary: .type or .ext_type
    if hasattr(ext, "type"):
        return int(ext.type)
    if hasattr(ext, "ext_type"):
        return int(ext.ext_type)
    return None


def extract_sni(ch):
    for ext in ch.ext or []:
        if isinstance(ext, TLS_Ext_ServerName):
            # ext.servernames: list of ServerName objects
            names = []
            for sn in getattr(ext, "servernames", []) or []:
                name = getattr(sn, "servername", None)
                if name:
                    try:
                        names.append(name.decode("utf-8") if isinstance(name, (bytes, bytearray)) else str(name))
                    except Exception:
                        names.append(str(name))
            return names[0] if names else None
    return None


def get_supported_groups(ch):
    for ext in ch.ext or []:
        if isinstance(ext, TLS_Ext_SupportedGroups):
            groups = getattr(ext, "groups", []) or []
            return [g for g in groups if not is_grease(g)]
    return []


def get_ec_point_formats(ch):
    for ext in ch.ext or []:
        if isinstance(ext, TLS_Ext_SupportedPointFormat):
            # field names can vary
            fmts = getattr(ext, "ecpl", None)
            if fmts is None:
                fmts = getattr(ext, "point_formats", [])
            return list(fmts) if fmts else []
    return []


def build_ja3(ch):
    # JA3 uses client hello version
    version = int(getattr(ch, "version", 0))

    ciphers = [c for c in (getattr(ch, "ciphers", []) or []) if not is_grease(c)]

    exts = []
    for ext in ch.ext or []:
        et = get_ext_type(ext)
        if et is None:
            continue
        if not is_grease(et):
            exts.append(et)

    groups = get_supported_groups(ch)
    ec_formats = get_ec_point_formats(ch)

    ja3_str = "{},{},{},{},{}".format(
        version,
        "-".join(str(c) for c in ciphers),
        "-".join(str(e) for e in exts),
        "-".join(str(g) for g in groups),
        "-".join(str(f) for f in ec_formats),
    )

    ja3_hash = hashlib.md5(ja3_str.encode("utf-8")).hexdigest()
    return ja3_str, ja3_hash


def detect_esni_ech(ch):
    for ext in ch.ext or []:
        et = get_ext_type(ext)
        if et in (ESNI_EXT, ECH_EXT):
            return True
    return False


def parse_args():
    parser = argparse.ArgumentParser(description="TLS ClientHello forensic parser")
    parser.add_argument("--pcap", required=True, help="Path to PCAP file")
    parser.add_argument("--source", required=False, help="Filter by source IP")
    parser.add_argument("--dest", required=False, help="Filter by destination IP")
    parser.add_argument("--limit", type=int, default=0, help="Optional limit of records")
    parser.add_argument(
        "--output",
        choices=["tabulate", "pandas", "plain"],
        default="tabulate",
        help="Table formatter (default: tabulate).",
    )
    return parser.parse_args()


def ts_to_str(ts):
    # Use ISO8601 UTC for consistent forensics
    # scapy can return EDecimal for pcapng timestamps
    try:
        ts_val = float(ts)
    except Exception:
        ts_val = float(ts.as_float()) if hasattr(ts, "as_float") else float(ts)
    return datetime.fromtimestamp(ts_val, timezone.utc).isoformat().replace("+00:00", "Z")


def main():
    args = parse_args()

    rows = []
    count = 0

    try:
        pcap = PcapNgReader(args.pcap)
    except Exception:
        try:
            pcap = PcapReader(args.pcap)
        except Exception as e:
            print(f"Error opening PCAP/PCAPNG: {e}", file=sys.stderr)
            return 2

    with pcap:
        for pkt in pcap:
            if TCP not in pkt:
                continue

            src, dst = get_ip(pkt)
            if not src or not dst:
                continue

            if args.source and src != args.source:
                continue
            if args.dest and dst != args.dest:
                continue

            if TLS not in pkt:
                continue

            tls = pkt[TLS]
            # TLS records can contain multiple messages
            for msg in getattr(tls, "msg", []) or []:
                if not isinstance(msg, TLSClientHello):
                    continue

                ch = msg

                sni = extract_sni(ch)
                ja3_str, ja3_hash = build_ja3(ch)
                encrypted_sni = detect_esni_ech(ch)

                rows.append({
                    "timestamp": ts_to_str(pkt.time),
                    "src_ip": src,
                    "dst_ip": dst,
                    "dst_port": int(pkt[TCP].dport),
                    "sni": sni or "",
                    "ja3": ja3_hash,
                    "ja3_string": ja3_str,
                    "esni_ech": "ENCRYPTED_SNI_DETECTED" if encrypted_sni else "",
                })

                count += 1
                if args.limit and count >= args.limit:
                    break

            if args.limit and count >= args.limit:
                break

    if not rows:
        print("No ClientHello records found.")
        return 0

    # Output table
    if args.output == "pandas":
        try:
            import pandas as pd
            df = pd.DataFrame(rows)
            print(df.to_string(index=False))
        except Exception:
            print("Failed to use pandas output. Falling back to tabulate.", file=sys.stderr)
            args.output = "tabulate"

    if args.output == "tabulate":
        try:
            from tabulate import tabulate
            print(tabulate(rows, headers="keys", tablefmt="github"))
            return 0
        except Exception:
            print("Failed to use tabulate output. Falling back to plain output.", file=sys.stderr)

    # Minimal fallback
    for r in rows:
        print(r)

    return 0


if __name__ == "__main__":
    sys.exit(main())

