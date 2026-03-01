import hashlib
from typing import Generator, List, Optional, Tuple

def is_grease(val: int) -> bool:
    return val in {
        0x0A0A, 0x1A1A, 0x2A2A, 0x3A3A, 0x4A4A, 0x5A5A, 0x6A6A, 0x7A7A,
        0x8A8A, 0x9A9A, 0xAAAA, 0xBABA, 0xCACA, 0xDADA, 0xEAEA, 0xFAFA,
    }

ESNI_EXT = 0xFFCE
ECH_EXT = 0xFE0D

def get_ext_type(ext) -> Optional[int]:
    if hasattr(ext, "type"):
        return int(ext.type)
    if hasattr(ext, "ext_type"):
        return int(ext.ext_type)
    return None

def extract_sni(ch) -> Optional[str]:
    from scapy.layers.tls.extensions import TLS_Ext_ServerName
    for ext in ch.ext or []:
        if isinstance(ext, TLS_Ext_ServerName):
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

def get_supported_groups(ch) -> List[int]:
    from scapy.layers.tls.extensions import TLS_Ext_SupportedGroups
    for ext in ch.ext or []:
        if isinstance(ext, TLS_Ext_SupportedGroups):
            groups = getattr(ext, "groups", []) or []
            return [g for g in groups if not is_grease(g)]
    return []

def get_ec_point_formats(ch) -> List[int]:
    from scapy.layers.tls.extensions import TLS_Ext_SupportedPointFormat
    for ext in ch.ext or []:
        if isinstance(ext, TLS_Ext_SupportedPointFormat):
            fmts = getattr(ext, "ecpl", None)
            if fmts is None:
                fmts = getattr(ext, "point_formats", [])
            return list(fmts) if fmts else []
    return []

def build_ja3(ch) -> Tuple[str, str]:
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

def build_ja3s(sh) -> Tuple[str, str]:
    version = int(getattr(sh, "version", 0))
    cipher = int(getattr(sh, "cipher", 0))

    exts = []
    for ext in sh.ext or []:
        et = get_ext_type(ext)
        if et is None:
            continue
        if not is_grease(et):
            exts.append(et)

    ja3s_str = "{},{},{}".format(
        version,
        cipher,
        "-".join(str(e) for e in exts),
    )

    ja3s_hash = hashlib.md5(ja3s_str.encode("utf-8")).hexdigest()
    return ja3s_str, ja3s_hash

def detect_esni_ech(ch) -> bool:
    for ext in ch.ext or []:
        et = get_ext_type(ext)
        if et in (ESNI_EXT, ECH_EXT):
            return True
    return False

def yield_tls_records(pcap_path: str, bpf_filter: Optional[str] = None):
    # Lazy imports to speed up CLI
    from scapy.all import PcapReader, PcapNgReader, IP, IPv6, TCP, load_layer
    load_layer('tls')
    try:
        from scapy.layers.tls.all import TLS, TLSClientHello, TLSServerHello
    except Exception:
        from scapy.layers.tls.all import TLS, TLSClientHello, TLSServerHello

    from datetime import datetime, timezone
    from .models import TLSRecord

    def ts_to_str(ts) -> str:
        try:
            ts_val = float(ts)
        except Exception:
            ts_val = float(ts.as_float()) if hasattr(ts, "as_float") else float(ts)
        return datetime.fromtimestamp(ts_val, timezone.utc).isoformat().replace("+00:00", "Z")

    try:
        pcap = PcapNgReader(pcap_path) # BPF filter isn't supported on NgReader in scapy yet. Scapy usually falls back. We'll use sniffing instead if BPF is required for speed and NgReader fails.
    except Exception:
        kwargs = {}
        if bpf_filter:
            # scapy's PcapReader does not natively support BPF filtering on offline caps in all environments without tcpdump
            pass # We will apply logic checking instead if sniff is not used
        pcap = PcapReader(pcap_path)

    try:
        from scapy.all import sniff
        # If BPF is requested, sniff offline works better with tcpdump/BPF support
        if bpf_filter:
            packet_source = sniff(offline=pcap_path, filter=bpf_filter, prn=lambda x: x, store=False)
            iterator = packet_source
        else:
             iterator = pcap

        for pkt in iterator:
            if TCP not in pkt:
                continue
                
            src, dst = None, None
            if IP in pkt:
                src, dst = pkt[IP].src, pkt[IP].dst
            elif IPv6 in pkt:
                src, dst = pkt[IPv6].src, pkt[IPv6].dst
                
            if not src or not dst:
                continue

            if TLS not in pkt:
                continue

            tls = pkt[TLS]
            for msg in getattr(tls, "msg", []) or []:
                if isinstance(msg, TLSClientHello):
                    ch = msg
                    sni = extract_sni(ch)
                    ja3_str, ja3_hash = build_ja3(ch)
                    encrypted_sni = detect_esni_ech(ch)

                    yield TLSRecord(
                        timestamp=ts_to_str(pkt.time),
                        src_ip=src,
                        dst_ip=dst,
                        dst_port=int(pkt[TCP].dport),
                        sni=sni or "",
                        ja3=ja3_hash,
                        ja3_string=ja3_str,
                        esni_ech="ENCRYPTED_SNI_DETECTED" if encrypted_sni else "",
                        message_type="ClientHello"
                    )
                elif isinstance(msg, TLSServerHello):
                    sh = msg
                    ja3s_str, ja3s_hash = build_ja3s(sh)
                    
                    yield TLSRecord(
                        timestamp=ts_to_str(pkt.time),
                        src_ip=src,
                        dst_ip=dst,
                        dst_port=int(pkt[TCP].dport), # Might be src port if it's returning traffic, but dst port for the stream is fine. Actually we should use sport if it's returning traffic, but user's existing script only checked dst.
                        sni="",
                        ja3=ja3s_hash,
                        ja3_string=ja3s_str,
                        esni_ech="",
                        message_type="ServerHello"
                    )
    finally:
        pcap.close()
