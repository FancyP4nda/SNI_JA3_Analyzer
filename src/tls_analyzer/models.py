from dataclasses import dataclass
from typing import Optional

@dataclass
class TLSRecord:
    timestamp: str
    src_ip: str
    dst_ip: str
    dst_port: int
    sni: str
    ja3: str
    ja3_string: str
    esni_ech: str
    message_type: str = "ClientHello"
