import pytest
from tls_analyzer.parser import is_grease, extract_sni, build_ja3

class DummyExt:
    def __init__(self, ext_type, **kwargs):
        self.ext_type = ext_type
        for k, v in kwargs.items():
            setattr(self, k, v)

class DummySNI:
    def __init__(self, servername):
         self.servername = servername

class DummyClientHello:
    def __init__(self, version, ciphers, exts=None):
        self.version = version
        self.ciphers = ciphers
        self.ext = exts or []

def test_is_grease():
    assert is_grease(0x0A0A) is True
    assert is_grease(0x1A1A) is True
    assert is_grease(0xFFFF) is False
    assert is_grease(0x0000) is False

def test_extract_sni_valid():
    from scapy.layers.tls.extensions import TLS_Ext_ServerName
    sn = DummySNI(b"example.com")
    ext = TLS_Ext_ServerName()
    ext.servernames = [sn]
    
    ch = DummyClientHello(version=0x0303, ciphers=[], exts=[ext])
    assert extract_sni(ch) == "example.com"

def test_extract_sni_missing():
    ch = DummyClientHello(version=0x0303, ciphers=[], exts=[])
    assert extract_sni(ch) is None

def test_build_ja3_basic():
    # Version 771 (0x0303), Ciphers (4865, 4866), no exts
    ch = DummyClientHello(version=771, ciphers=[4865, 4866], exts=[])
    ja3_str, ja3_hash = build_ja3(ch)
    
    assert ja3_str == "771,4865-4866,,,"
    # Expected MD5 of "771,4865-4866,,,"
    import hashlib
    expected_hash = hashlib.md5(b"771,4865-4866,,,").hexdigest()
    assert ja3_hash == expected_hash

def test_build_ja3_with_grease():
    # GREASE values should be stripped
    ch = DummyClientHello(version=771, ciphers=[0x0A0A, 4865, 4866], exts=[])
    ja3_str, ja3_hash = build_ja3(ch)
    
    # 0x0A0A (2570) should be missing
    assert ja3_str == "771,4865-4866,,,"
    
def test_build_ja3_with_extensions():
    # Exts: 10, 11 (Supported Groups, EC Point Formats)
    ext1 = DummyExt(ext_type=10)
    ext2 = DummyExt(ext_type=11)
    
    ch = DummyClientHello(version=771, ciphers=[4865], exts=[ext1, ext2])
    ja3_str, ja3_hash = build_ja3(ch)
    
    # Notice: the dummy exts don't have .groups or .ecpl, so they return empty lists for those specific parts, 
    # but the extension IDs should still be recorded.
    assert ja3_str == "771,4865,10-11,,"
