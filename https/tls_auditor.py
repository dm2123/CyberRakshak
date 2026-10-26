"""CyberRakshak HTTPS/TLS auditor - the deepest free TLS check.

Checks (all defensive, own systems only):
  1. TLS versions offered (1.0 - 1.3) - old ones flagged
  2. Cipher suite enumeration - weak ciphers flagged
  3. Certificate: expiry, chain trust, hostname match, self-signed,
     weak signature (SHA1/MD5), RSA key size < 2048
  4. HSTS: present? max-age? includeSubDomains? preload?
  5. Security headers: CSP, X-Frame-Options, X-Content-Type-Options,
     Referrer-Policy
  6. TLS compression (CRIME)
  7. Heartbeat extension -> Heartbleed guidance (NO active exploit probe;
     sending malformed heartbeats reads server memory, so we only
     advise manual verification with nmap/testssl.sh on own systems)
  8. OCSP stapling (via raw ClientHello status_request)
  9. SNI handling (required? ignored?)
 10. Session resumption + session tickets

v0.3 Phase 1 additions (check IDs per V03_DEEP_AUDITOR_SPEC.md):
 11. Secure renegotiation (TLS-015): only OBSERVES the RFC 5746
     renegotiation_info extension in the ServerHello - a renegotiation
     is never attempted.
 12. Forward secrecy (TLS-017) + static-RSA key-exchange rule
     (TLS-019) over the enumerated cipher list.
 13. Certificate deep-dive: validity > 825 days (TLS-028), expiry
     within 7 days escalated to HIGH (TLS-029), missing serverAuth
     EKU (TLS-030), CA:TRUE on a CA-issued leaf (TLS-031), multi-level
     wildcard / SAN sprawl (TLS-032).
 14. ALPN negotiation note (TLS-023), session resumption detail -
     mechanism + negotiated version (TLS-024), no TLS 1.3 (TLS-033).

v0.3 Phase 2 additions (raw-TLS parsing; observation only):
 15. Downgrade protection TLS_FALLBACK_SCSV (TLS-016): one fallback
     ClientHello; a completed handshake (instead of the RFC 7507
     inappropriate_fallback alert) is flagged. Never forces a downgrade.
 16. SSLv2 / DROWN probe (TLS-018): one SSLv2-format CLIENT-HELLO; only
     an SSLv2 SERVER-HELLO reply is flagged. No oracle queries.
 17. Logjam DH size (TLS-020): DHE-only ClientHello; reads the DH prime
     the server voluntarily sends in ServerKeyExchange. The discrete
     log is never computed.
 18. 64-bit block ciphers Blowfish/IDEA (TLS-021, SWEET32 class) via
     cipher candidates + rules, and CBC suites combined with TLS 1.0/1.1
     (TLS-022, Lucky13 class) as a cross-check over enumerated data.
 19. Certificate chain via the raw Certificate message (getpeercert()
     only returns the leaf): chain order (TLS-025) and weak signature /
     weak key on intermediates or the root (TLS-026).
 20. OCSP Must-Staple cross-check (TLS-027): leaf promises status_request
     via the TLS Feature extension but the server does not staple.

Every finding carries severity + fix recommendation.
100% original code.
"""

import datetime
import re
import socket
import ssl
import struct

# --------------------------------------------------------------------------
# Cipher candidates for enumeration (OpenSSL names). Weak ones flagged.
# --------------------------------------------------------------------------
CIPHER_CANDIDATES = [
    # --- known weak (expected to be rejected by sane servers) ---
    "RC4-SHA", "RC4-MD5",
    "DES-CBC-SHA",
    "DES-CBC3-SHA",                    # 3DES - Sweet32
    "IDEA-CBC-SHA",                    # IDEA - 64-bit block (Sweet32 class)
    "BF-CBC",                          # Blowfish - 64-bit block (not in TLS RFCs;
                                       # probed per spec TLS-021, normally rejected)
    "ECDHE-RSA-DES-CBC3-SHA",
    "EXP-RC4-MD5", "EXP-DES-CBC-SHA",  # EXPORT grade
    "ADH-AES256-SHA", "ADH-AES128-SHA",  # anonymous DH
    "AECDH-AES256-SHA",
    "NULL-SHA", "NULL-MD5",
    "PSK-AES256-CBC-SHA", "PSK-AES128-CBC-SHA",
    # --- acceptable / strong ---
    "ECDHE-RSA-AES256-GCM-SHA384",
    "ECDHE-RSA-AES128-GCM-SHA256",
    "ECDHE-RSA-CHACHA20-POLY1305",
    "ECDHE-RSA-AES256-SHA384",
    "ECDHE-RSA-AES128-SHA256",
    "ECDHE-RSA-AES256-SHA",
    "ECDHE-RSA-AES128-SHA",
    "AES256-GCM-SHA384",
    "AES128-GCM-SHA256",
    "AES256-SHA256",
    "AES128-SHA256",
    "AES256-SHA",
    "AES128-SHA",
]

# (substring marker, severity, explanation)
WEAK_CIPHER_RULES = [
    ("RC4", "HIGH", "RC4 is broken (bias attacks). Disable all RC4 ciphers."),
    ("DES-CBC", "HIGH", "Single DES has 56-bit keys - brute-forceable. Disable."),
    ("DES-CBC3", "MEDIUM", "3DES uses 64-bit blocks - Sweet32 attack. Disable; use AES."),
    ("EXP", "HIGH", "EXPORT-grade ciphers are deliberately weak (FREAK/Logjam). Disable."),
    ("ADH", "HIGH", "Anonymous DH has no authentication - MITM possible. Disable."),
    ("AECDH", "HIGH", "Anonymous ECDH has no authentication - MITM possible. Disable."),
    ("NULL", "HIGH", "NULL cipher = NO encryption. Never allow."),
    ("MD5", "MEDIUM", "MD5-based suites are weak. Prefer SHA-256+."),
    ("PSK", "LOW", "Pre-shared-key suites need out-of-band key management; "
                   "ensure PSK identity is strong if used."),
    # TLS-021 (SWEET32 class, CVE-2016-2183): 64-bit block ciphers fall to
    # birthday attacks after ~32 GB of traffic under one key. The optional
    # 4th tuple element is the v0.3 check ID for these newer rules.
    ("BF", "MEDIUM", "Blowfish uses 64-bit blocks - Sweet32 birthday attacks "
                     "apply after ~32 GB under one key (CVE-2016-2183). "
                     "Disable; use AES-GCM / ChaCha20-Poly1305.", "TLS-021"),
    ("IDEA", "MEDIUM", "IDEA uses 64-bit blocks - Sweet32 birthday attacks "
                       "apply after ~32 GB under one key (CVE-2016-2183). "
                       "Disable; use AES-GCM / ChaCha20-Poly1305.", "TLS-021"),
]

# Signature algorithm OIDs -> (name, weak?)
SIG_ALG_OIDS = {
    "1.2.840.113549.1.1.2": ("md2WithRSAEncryption", True),
    "1.2.840.113549.1.1.4": ("md5WithRSAEncryption", True),
    "1.2.840.113549.1.1.5": ("sha1WithRSAEncryption", True),
    "1.2.840.10045.4.1": ("ecdsa-with-SHA1", True),
    "1.2.840.113549.1.1.11": ("sha256WithRSAEncryption", False),
    "1.2.840.113549.1.1.12": ("sha384WithRSAEncryption", False),
    "1.2.840.113549.1.1.13": ("sha512WithRSAEncryption", False),
    "1.2.840.10045.4.3.2": ("ecdsa-with-SHA256", False),
    "1.2.840.10045.4.3.3": ("ecdsa-with-SHA384", False),
    "1.2.840.10045.4.3.4": ("ecdsa-with-SHA512", False),
}

EC_CURVE_SIZES = {  # OID -> bits
    "1.2.840.10045.3.1.7": 256,   # secp256r1
    "1.3.132.0.34": 384,          # secp384r1
    "1.3.132.0.35": 521,          # secp521r1
    "1.3.132.0.10": 256,          # secp256k1
}


# --------------------------------------------------------------------------
# Minimal DER/ASN.1 parser (reads cert fields without any external library)
# --------------------------------------------------------------------------
class _DERReader:
    def __init__(self, data):
        self.d = data
        self.p = 0

    def _read(self, n):
        if self.p + n > len(self.d):
            raise ValueError("DER truncated")
        out = self.d[self.p:self.p + n]
        self.p += n
        return out

    def read_tlv(self):
        """Return (tag, value_bytes, constructed)."""
        tag = self._read(1)[0]
        lb = self._read(1)[0]
        if lb & 0x80:
            n = lb & 0x7F
            if n == 0 or n > 4:
                raise ValueError("bad DER length")
            length = int.from_bytes(self._read(n), "big")
        else:
            length = lb
        val = self._read(length)
        return tag, val, bool(tag & 0x20)

    def read_oid(self, val):
        first = val[0]
        nums = [first // 40, first % 40]
        i = 1
        while i < len(val):
            n = 0
            while True:
                b = val[i]
                i += 1
                n = (n << 7) | (b & 0x7F)
                if not (b & 0x80):
                    break
            nums.append(n)
        return ".".join(str(x) for x in nums)

    @property
    def remaining(self):
        return len(self.d) - self.p


def _parse_time(val, tag):
    """UTCTime / GeneralizedTime -> datetime (UTC)."""
    s = val.decode("ascii")
    if tag == 0x17:  # UTCTime YYMMDDHHMMSSZ
        yy = int(s[0:2])
        year = 2000 + yy if yy < 50 else 1900 + yy
        return datetime.datetime(year, int(s[2:4]), int(s[4:6]),
                                 int(s[6:8]), int(s[8:10]), int(s[10:12]))
    # GeneralizedTime YYYYMMDDHHMMSSZ
    return datetime.datetime(int(s[0:4]), int(s[4:6]), int(s[6:8]),
                             int(s[8:10]), int(s[10:12]), int(s[12:14]))


def _decode_name_string(tag, val):
    try:
        if tag == 0x1E:  # BMPString
            return val.decode("utf-16-be")
        if tag == 0x1C:  # UniversalString
            return val.decode("utf-32-be")
        return val.decode("utf-8", errors="replace")
    except Exception:
        return ""


def _parse_name(name_bytes):
    """Parse X.501 Name -> dict of OID -> value (we mainly need CN 2.5.4.3)."""
    attrs = {}
    try:
        r = _DERReader(name_bytes)
        while r.remaining > 0:
            stag, s_val, _ = r.read_tlv()       # SET (RDN)
            if stag != 0x31:
                continue
            sr = _DERReader(s_val)
            while sr.remaining > 0:
                atag, a_val, _ = sr.read_tlv()  # SEQ (ATV)
                ar = _DERReader(a_val)
                otag, o_val, _ = ar.read_tlv()  # OID
                vtag, v_val, _ = ar.read_tlv()  # value
                attrs[ar.read_oid(o_val)] = _decode_name_string(vtag, v_val)
    except Exception:
        pass
    return attrs


def _parse_san(ext_val):
    """Parse SubjectAltName extension value -> (dns_names, ip_addrs)."""
    dns, ips = [], []
    try:
        # ext_val is OCTET STRING wrapping the SEQUENCE
        r = _DERReader(ext_val)
        tag, inner, _ = r.read_tlv()
        if tag == 0x04:  # OCTET STRING wrapper
            seq_data = inner
        else:
            seq_data = ext_val
        sr = _DERReader(seq_data)
        stag, s_val, _ = sr.read_tlv()  # SEQUENCE
        gr = _DERReader(s_val)
        while gr.remaining > 0:
            gtag = gr._read(1)[0]
            lb = gr._read(1)[0]
            glen = lb if not (lb & 0x80) else int.from_bytes(gr._read(lb & 0x7F), "big")
            gval = gr._read(glen)
            if gtag == 0x82:  # dNSName
                dns.append(gval.decode("ascii", errors="replace"))
            elif gtag == 0x87 and len(gval) == 4:  # iPAddress v4
                ips.append(".".join(str(b) for b in gval))
    except Exception:
        pass
    return dns, ips


def _unwrap_ext_value(ext_val):
    """Extension values may wrap the real value in an OCTET STRING."""
    try:
        r = _DERReader(ext_val)
        tag, inner, _ = r.read_tlv()
        if tag == 0x04:  # OCTET STRING wrapper
            return inner
    except Exception:
        pass
    return ext_val


def _parse_oid_sequence(ext_val):
    """Parse a SEQUENCE OF OID extension value -> list of OID strings."""
    oids = []
    try:
        data = _unwrap_ext_value(ext_val)
        r = _DERReader(data)
        tag, seq, _ = r.read_tlv()
        if tag != 0x30:  # SEQUENCE
            return oids
        sr = _DERReader(seq)
        while sr.remaining > 0:
            otag, oval, _ = sr.read_tlv()
            if otag == 0x06:  # OID
                oids.append(sr.read_oid(oval))
    except Exception:
        pass
    return oids


def _parse_basic_constraints(ext_val):
    """Parse a basicConstraints value -> cA boolean (None if unparsable)."""
    try:
        data = _unwrap_ext_value(ext_val)
        r = _DERReader(data)
        tag, seq, _ = r.read_tlv()
        if tag != 0x30:  # SEQUENCE
            return None
        if not seq:
            return False  # empty SEQUENCE -> cA defaults to FALSE
        sr = _DERReader(seq)
        btag, bval, _ = sr.read_tlv()
        if btag == 0x01:  # BOOLEAN cA comes first when present
            return bval != b"\x00"
        return False  # first element is pathLenConstraint -> cA FALSE
    except Exception:
        return None


def parse_cert_der(der):
    """Extract security-relevant fields from a DER certificate.

    Returns dict with keys: sig_oid, key_type, key_bits, subject_cn,
    issuer_cn, subject_raw, issuer_raw, not_before, not_after,
    san_dns, san_ip, extensions, eku_oids, basic_constraints_ca.
    Missing values are None / [] / {}.
    """
    out = {"sig_oid": None, "key_type": None, "key_bits": None,
           "subject_cn": None, "issuer_cn": None,
           "subject_raw": None, "issuer_raw": None,
           "not_before": None, "not_after": None,
           "san_dns": [], "san_ip": [],
           "extensions": {}, "eku_oids": None, "basic_constraints_ca": None}
    try:
        r = _DERReader(der)
        tag, cert_seq, _ = r.read_tlv()          # Certificate SEQUENCE
        cr = _DERReader(cert_seq)
        tag, tbs, _ = cr.read_tlv()              # tbsCertificate
        tr = _DERReader(tbs)
        # optional [0] version
        tag, val, _ = tr.read_tlv()
        if tag == 0xA0:
            tag, val, _ = tr.read_tlv()          # serialNumber INTEGER
        # signature AlgorithmIdentifier
        tag, sig_seq, _ = tr.read_tlv()
        sr = _DERReader(sig_seq)
        stag, sval, _ = sr.read_tlv()
        out["sig_oid"] = sr.read_oid(sval)
        # issuer
        tag, issuer_raw, _ = tr.read_tlv()
        out["issuer_raw"] = issuer_raw
        out["issuer_cn"] = _parse_name(issuer_raw).get("2.5.4.3")
        # validity
        tag, validity, _ = tr.read_tlv()
        vr = _DERReader(validity)
        vtag, vval, _ = vr.read_tlv()
        out["not_before"] = _parse_time(vval, vtag)
        vtag, vval, _ = vr.read_tlv()
        out["not_after"] = _parse_time(vval, vtag)
        # subject
        tag, subject_raw, _ = tr.read_tlv()
        out["subject_raw"] = subject_raw
        out["subject_cn"] = _parse_name(subject_raw).get("2.5.4.3")
        # subjectPublicKeyInfo
        tag, spki, _ = tr.read_tlv()
        pr = _DERReader(spki)
        ptag, alg_seq, _ = pr.read_tlv()
        ar = _DERReader(alg_seq)
        atag, aval, _ = ar.read_tlv()
        key_oid = ar.read_oid(aval)
        ptag, bitstr, _ = pr.read_tlv()
        key_bytes = bitstr[1:]
        if key_oid == "1.2.840.113549.1.1.1":    # rsaEncryption
            out["key_type"] = "RSA"
            kr = _DERReader(key_bytes)
            ktag, kseq, _ = kr.read_tlv()
            kr2 = _DERReader(kseq)
            mtag, modulus, _ = kr2.read_tlv()
            out["key_bits"] = int.from_bytes(modulus, "big").bit_length()
        elif key_oid == "1.2.840.10045.2.1":     # ecPublicKey
            out["key_type"] = "EC"
            try:
                ptag2, pval2, _ = ar.read_tlv()
                if ptag2 == 0x06:
                    out["key_bits"] = EC_CURVE_SIZES.get(ar.read_oid(pval2))
            except Exception:
                pass
        # extensions [3] - look for SAN
        while tr.remaining > 0:
            tag, val, _ = tr.read_tlv()
            if tag == 0xA3:  # [3] extensions
                er = _DERReader(val)
                etag, esequence, _ = er.read_tlv()
                xr = _DERReader(esequence)
                while xr.remaining > 0:
                    xtag, xval, _ = xr.read_tlv()   # Extension SEQUENCE
                    xrr = _DERReader(xval)
                    otag, oval, _ = xrr.read_tlv()  # extnID OID
                    oid = xrr.read_oid(oval)
                    # optional critical BOOLEAN, then extnValue OCTET STRING
                    critical = False
                    ctag, cval, _ = xrr.read_tlv()
                    if ctag == 0x01:                 # critical flag present
                        critical = cval != b"\x00"
                        ctag, cval, _ = xrr.read_tlv()
                    if ctag == 0x04:
                        # v0.3: capture EVERY extension (OID -> critical/value)
                        out["extensions"][oid] = {"critical": critical,
                                                  "value": cval}
                        if oid == "2.5.29.17":       # SubjectAltName
                            dns, ips = _parse_san(cval)
                            out["san_dns"].extend(dns)
                            out["san_ip"].extend(ips)
                        elif oid == "2.5.29.37":     # Extended Key Usage
                            out["eku_oids"] = _parse_oid_sequence(cval)
                        elif oid == "2.5.29.19":     # Basic Constraints
                            out["basic_constraints_ca"] = \
                                _parse_basic_constraints(cval)
    except Exception:
        pass
    return out


def hostname_matches(cert_info, hostname):
    """RFC-6125-style check: SAN dNSName/iPAddress first, else CN fallback."""
    host = hostname.lower().rstrip(".")
    sans = [d.lower().rstrip(".") for d in cert_info.get("san_dns", [])]
    if host.replace(".", "").isdigit() or ":" in host:
        return host in cert_info.get("san_ip", [])
    names = sans or ([cert_info["subject_cn"].lower()] if cert_info.get("subject_cn") else [])

    def _match(pattern, name):
        if pattern.startswith("*."):
            # wildcard: single left-most label only
            return name.count(".") == pattern.count(".") and \
                name.endswith(pattern[1:])
        return pattern == name

    return any(_match(p, host) for p in names)


# --------------------------------------------------------------------------
# Minimal raw TLS ClientHello (for OCSP stapling / SNI / renegotiation probes)
# --------------------------------------------------------------------------
def build_client_hello(hostname=None, with_status_request=False,
                       with_empty_reneg_info=False, fallback_scsv=False,
                       ciphers=None):
    rnd = b"\x00" * 28 + b"\x01\x02\x03\x04"  # fixed random is fine for probing
    session_id = b""
    # a few common suites + SCSV
    if ciphers is not None:
        suites = list(ciphers)
    else:
        suites = [0xC02F, 0xC02B, 0x009C, 0x009D, 0x002F, 0x0035, 0x000A, 0x00FF]
    client_version = b"\x03\x03"  # TLS 1.2 record-style version in the body
    if fallback_scsv:
        # TLS-016 (RFC 7507): signal "this client is falling back" by
        # appending TLS_FALLBACK_SCSV (0x5600) and offering only TLS 1.1.
        # A protected server aborts with inappropriate_fallback (86);
        # completing the handshake means downgrade protection is missing.
        suites = suites + [0x5600]
        client_version = b"\x03\x02"  # TLS 1.1
    suites_b = b"".join(struct.pack("!H", s) for s in suites)
    comp = b"\x01\x00"  # null compression only

    exts = b""
    if hostname:
        hn = hostname.encode()
        exts += struct.pack("!HH", 0x0000, len(hn) + 5)
        exts += struct.pack("!H", len(hn) + 3) + b"\x00" + struct.pack("!H", len(hn)) + hn
    # signature_algorithms (0x000D): without it, OpenSSL 3 servers treat the
    # client as supporting only legacy MD5/SHA-1 signature pairs and abort
    # with handshake_failure at security level >= 1, so no ServerHello would
    # ever be observed. Values: rsa_pkcs1_sha256/384/512, ecdsa_sha256/384,
    # rsa_pss_rsae_sha256.
    sigalgs = b"".join(struct.pack("!H", s) for s in
                       (0x0401, 0x0501, 0x0601, 0x0403, 0x0503, 0x0804))
    exts += struct.pack("!HH", 0x000D, len(sigalgs) + 2)
    exts += struct.pack("!H", len(sigalgs)) + sigalgs
    if with_status_request:
        # status_request (OCSP): cert_status_type=1, empty responder/extensions
        body = b"\x01" + struct.pack("!H", 0) + struct.pack("!H", 0)
        exts += struct.pack("!HH", 0x0005, len(body)) + body
    if with_empty_reneg_info:
        exts += struct.pack("!HH", 0xFF01, 1) + b"\x00"

    hello = (client_version + rnd + struct.pack("B", len(session_id)) + session_id +
             struct.pack("!H", len(suites_b)) + suites_b + comp +
             struct.pack("!H", len(exts)) + exts)
    hs = b"\x01" + len(hello).to_bytes(3, "big") + hello
    return b"\x16\x03\x01" + struct.pack("!H", len(hs)) + hs


def parse_server_hello_extensions(data):
    """Parse raw TLS records, return set of extension types from ServerHello."""
    exts = set()
    try:
        p = 0
        while p + 5 <= len(data):
            rtype, ver, rlen = data[p], data[p + 1:p + 3], struct.unpack("!H", data[p + 3:p + 5])[0]
            body = data[p + 5:p + 5 + rlen]
            p += 5 + rlen
            if rtype != 22 or len(body) < 4:
                continue
            htype = body[0]
            hlen = int.from_bytes(body[1:4], "big")
            hb = body[4:4 + hlen]
            if htype != 2 or len(hb) < 38:  # not ServerHello
                continue
            q = 2 + 32  # version + random
            sid_len = hb[q]
            q += 1 + sid_len + 2 + 1  # session id, cipher, compression
            if q + 2 > len(hb):
                continue
            elen = struct.unpack("!H", hb[q:q + 2])[0]
            q += 2
            end = q + elen
            while q + 4 <= end and q + 4 <= len(hb):
                etype, elen2 = struct.unpack("!HH", hb[q:q + 4])
                exts.add(etype)
                q += 4 + elen2
            break  # only first ServerHello
    except Exception:
        pass
    return exts


def parse_handshake_messages(data):
    """Reassemble handshake messages from a raw TLS record stream.

    Returns a list of (handshake_type, body_bytes). Non-handshake records
    (alerts, CCS, application data) are skipped; handshake bytes spread
    over several records are concatenated before splitting, as on the
    wire. Used by the Phase 2 chain (0x0B) and ServerKeyExchange (0x0C)
    captures.
    """
    msgs = []
    try:
        stream = bytearray()
        p = 0
        while p + 5 <= len(data):
            rtype = data[p]
            rlen = struct.unpack("!H", data[p + 3:p + 5])[0]
            body = data[p + 5:p + 5 + rlen]
            if len(body) < rlen:
                break
            if rtype == 22:  # handshake
                stream += body
            p += 5 + rlen
        q = 0
        while q + 4 <= len(stream):
            htype = stream[q]
            hlen = int.from_bytes(stream[q + 1:q + 4], "big")
            hb = bytes(stream[q + 4:q + 4 + hlen])
            if len(hb) < hlen:
                break
            msgs.append((htype, hb))
            q += 4 + hlen
    except Exception:
        pass
    return msgs


def parse_certificate_message(body):
    """Certificate handshake body (TLS <= 1.2) -> ordered list of DER certs."""
    ders = []
    try:
        if len(body) < 3:
            return ders
        total = int.from_bytes(body[0:3], "big")
        q = 3
        end = min(len(body), 3 + total)
        while q + 3 <= end:
            clen = int.from_bytes(body[q:q + 3], "big")
            q += 3
            if q + clen > end:
                break
            ders.append(body[q:q + clen])
            q += clen
    except Exception:
        pass
    return ders


def parse_server_key_exchange_dh_bits(body):
    """ServerKeyExchange body for DHE -> bit length of the DH prime dh_p.

    Wire layout: dh_p (2-byte length + bytes), dh_g, dh_Ys, then the
    signature. We read only dh_p - the parameter the server voluntarily
    sends. Returns None when the body is not a DHE params block.
    """
    try:
        if len(body) < 2:
            return None
        plen = struct.unpack("!H", body[0:2])[0]
        p_bytes = body[2:2 + plen]
        if len(p_bytes) < plen or plen == 0:
            return None
        return int.from_bytes(p_bytes, "big").bit_length()
    except Exception:
        return None


def fallback_scsv_verdict(data):
    """TLS-016 verdict from a raw fallback-probe response.

    "protected"    - fatal alert inappropriate_fallback (86), per RFC 7507
    "vulnerable"   - server completed the handshake (ServerHello received)
    "inconclusive" - anything else (other alert, reset, silence): the
                     server may simply not support the offered version,
                     which proves nothing about SCSV handling.
    """
    try:
        if not data or len(data) < 7:
            return "inconclusive"
        rtype = data[0]
        if rtype == 21:  # alert record: level(1) + description(1)
            return "protected" if data[6] == 86 else "inconclusive"
        if rtype == 22:  # handshake record
            for htype, _hb in parse_handshake_messages(data):
                if htype == 2:  # ServerHello
                    return "vulnerable"
            return "inconclusive"
    except Exception:
        pass
    return "inconclusive"


def build_sslv2_client_hello():
    """Minimal SSLv2 CLIENT-HELLO (TLS-018 / DROWN observation probe).

    Pure protocol observation: one normal SSLv2 handshake attempt, the
    same any legacy client would make. No oracle queries, no decryption.
    """
    # classic SSLv2 cipher specs (3 bytes each): RC4/MD5, RC2/MD5,
    # IDEA/MD5, DES/MD5, 3DES/MD5
    specs = bytes([0x01, 0x00, 0x80, 0x03, 0x00, 0x80, 0x04, 0x00, 0x80,
                   0x06, 0x00, 0x40, 0x07, 0x00, 0xC0])
    challenge = b"\x00" * 16 + b"\x01\x02\x03\x04" * 4  # 32 bytes
    body = (b"\x01" + struct.pack("!H", 0x0002) +
            struct.pack("!H", len(specs)) + struct.pack("!H", 0) +
            struct.pack("!H", len(challenge)) + specs + challenge)
    # 2-byte header with the high bit set (SSLv2 record framing)
    return struct.pack("!H", len(body) | 0x8000) + body


def sslv2_verdict(data):
    """True only when the reply is an SSLv2 SERVER-HELLO (msg-type 0x04).

    A TLS record (0x16...), an SSLv2 error message (0x0F), an alert, a
    reset or silence all mean SSLv2 was not spoken.
    """
    try:
        if not data or len(data) < 3:
            return False
        if data[0] & 0x80:  # 2-byte SSLv2 header
            return data[2] == 0x04
        if data[0] == 0x80 and len(data) > 3:  # 3-byte header variant
            return data[3] == 0x04
    except Exception:
        pass
    return False


def _parse_tls_feature(ext_val):
    """TLS Feature extension value (RFC 7633) -> list of feature codes.

    The value is a SEQUENCE OF INTEGER; status_request is code 5.
    """
    codes = []
    try:
        data = _unwrap_ext_value(ext_val)
        r = _DERReader(data)
        tag, seq, _ = r.read_tlv()
        if tag != 0x30:  # SEQUENCE
            return codes
        sr = _DERReader(seq)
        while sr.remaining > 0:
            itag, ival, _ = sr.read_tlv()
            if itag == 0x02 and ival:  # INTEGER
                codes.append(int.from_bytes(ival, "big"))
    except Exception:
        pass
    return codes


# --------------------------------------------------------------------------
# The auditor
# --------------------------------------------------------------------------
class HTTPSAuditor:
    def __init__(self, target, port=443, timeout=5):
        self.target = target
        self.port = port
        self.timeout = timeout
        self.findings = []
        self.info = {}

    # -- helpers ---------------------------------------------------------
    def _add(self, severity, issue, detail, check=None, cve=None):
        # "check" is the optional v0.3 stable check ID (spec section 2);
        # "cve" likewise, only for verified CVE IDs (spec section 5.5).
        # The v0.2 keys (severity/issue/detail) are unchanged.
        finding = {"severity": severity, "issue": issue, "detail": detail}
        if check:
            finding["check"] = check
        if cve:
            finding["cve"] = cve
        self.findings.append(finding)

    def _raw_connect(self):
        return socket.create_connection((self.target, self.port), timeout=self.timeout)

    def _recv_handshake(self, sock, max_bytes=65536):
        """Read raw records until ServerHelloDone / EOF / timeout.

        A single recv() often returns only the first flight record, so
        Phase 2's Certificate / ServerKeyExchange captures need a loop.
        Bounded by max_bytes and the socket timeout; fail-soft.
        """
        data = b""
        try:
            while len(data) < max_bytes:
                chunk = sock.recv(16384)
                if not chunk:
                    break
                data += chunk
                types = [t for t, _ in parse_handshake_messages(data)]
                if 14 in types:  # ServerHelloDone - flight complete
                    break
        except Exception:
            pass
        return data

    def _std_ctx(self, verify=True):
        ctx = ssl.create_default_context()
        if not verify:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        return ctx

    # -- main ------------------------------------------------------------
    def audit(self):
        self.findings = []
        self.info = {}
        self._check_tls_versions()
        self._enumerate_ciphers()
        self._check_forward_secrecy()
        self._check_rsa_kx()
        self._check_certificate()
        self._check_compression()
        self._check_headers()
        self._check_ocsp_stapling()
        self._check_must_staple()
        self._check_renegotiation()
        self._check_sni()
        self._check_session()
        self._check_alpn()
        self._check_fallback_scsv()
        self._check_sslv2()
        self._check_logjam()
        self._check_chain_order()
        self._check_chain_strength()
        self._check_cbc_legacy_tls()
        self._check_heartbeat_guidance()
        return self.findings

    # 1. TLS versions -----------------------------------------------------
    def _try_version(self, minimum, maximum):
        try:
            ctx = self._std_ctx(verify=False)
            ctx.minimum_version = minimum
            ctx.maximum_version = maximum
            sock = self._raw_connect()
            ssock = ctx.wrap_socket(sock, server_hostname=self.target)
            ver = ssock.version()
            ssock.close()
            return ver
        except Exception:
            return None

    def _check_tls_versions(self):
        results = {}
        pairs = [
            ("TLS 1.0", ssl.TLSVersion.TLSv1, ssl.TLSVersion.TLSv1),
            ("TLS 1.1", ssl.TLSVersion.TLSv1_1, ssl.TLSVersion.TLSv1_1),
            ("TLS 1.2", ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_2),
            ("TLS 1.3", ssl.TLSVersion.TLSv1_3, ssl.TLSVersion.TLSv1_3),
        ]
        for name, lo, hi in pairs:
            try:
                results[name] = self._try_version(lo, hi)
            except Exception:
                results[name] = None
        offered = [n for n, v in results.items() if v]
        self.info["tls_versions_offered"] = offered

        for old in ("TLS 1.0", "TLS 1.1"):
            if results.get(old):
                self._add("HIGH", f"Weak protocol accepted: {old}",
                          f"{old} has known vulnerabilities (BEAST, POODLE variants). "
                          "Disable it server-side; require TLS 1.2+.")
        if offered and not results.get("TLS 1.2") and not results.get("TLS 1.3"):
            self._add("HIGH", "Only legacy TLS offered (no 1.2/1.3)",
                      "Modern clients may refuse to connect. Enable TLS 1.2 and 1.3.")
        if not offered:
            self.info["tls_versions_offered"] = ["unknown (handshake failed)"]

        # TLS-033: no TLS 1.3 support (INFO - TLS 1.2 done well is acceptable)
        if offered and "TLS 1.3" not in offered:
            self._add("INFO", "No TLS 1.3 support",
                      "Server offers at most TLS 1.2. TLS 1.2 with a strong "
                      "configuration is acceptable, but TLS 1.3 adds AEAD-only "
                      "cipher suites, removes static RSA key exchange and "
                      "encrypts more of the handshake. Enable TLS 1.3.",
                      check="TLS-033")

    # 2. Cipher enumeration ------------------------------------------------
    def _check_one_cipher(self, cipher_name):
        try:
            ctx = self._std_ctx(verify=False)
            ctx.set_ciphers(cipher_name)
            # keep TLS <= 1.2 for the cipher-suite probe
            try:
                ctx.maximum_version = ssl.TLSVersion.TLSv1_2
            except Exception:
                pass
            sock = self._raw_connect()
            ssock = ctx.wrap_socket(sock, server_hostname=self.target)
            negotiated = ssock.cipher()
            ssock.close()
            return negotiated  # (name, version, bits) or None
        except Exception:
            return None

    def _enumerate_ciphers(self):
        accepted = []
        for cand in CIPHER_CANDIDATES:
            neg = self._check_one_cipher(cand)
            if neg and neg[0] not in [a[0] for a in accepted]:
                accepted.append(neg)
        self.info["ciphers_accepted"] = [a[0] for a in accepted]
        for name, _ver, bits in accepted:
            for rule in WEAK_CIPHER_RULES:
                marker, sev, expl = rule[0], rule[1], rule[2]
                rule_check = rule[3] if len(rule) > 3 else None
                if marker.lower() in name.lower().replace("-", "") or \
                   marker.lower() in name.lower():
                    # avoid double-flagging DES inside DES-CBC3 already handled above
                    self._add(sev, f"Weak cipher accepted: {name}",
                              expl + f" (negotiated {bits} bits). "
                              "Restrict server cipher list to AES-GCM / ChaCha20-Poly1305.",
                              check=rule_check)
                    break
        # modern baseline: is any AEAD suite accepted?
        strong = [a for a in accepted
                  if "GCM" in a[0] or "POLY1305" in a[0] or "CCM" in a[0]]
        if accepted and not strong:
            self._add("MEDIUM", "No AEAD cipher suite accepted",
                      "No AES-GCM/ChaCha20-Poly1305 suite was accepted. "
                      "Enable at least one AEAD suite.")

    # 2b. Forward secrecy (TLS-017) ------------------------------------------
    def _check_forward_secrecy(self):
        accepted = self.info.get("ciphers_accepted") or []
        if not accepted:
            return
        fs = [n for n in accepted
              if "ECDHE" in n or "DHE" in n or "TLS_AES" in n or "TLS_CHACHA" in n]
        if not fs and "TLS 1.3" in (self.info.get("tls_versions_offered") or []):
            fs = ["(TLS 1.3 suites are implicitly forward-secret)"]
        self.info["forward_secrecy"] = bool(fs)
        if not fs:
            self._add("HIGH", "No forward secrecy on any accepted cipher",
                      "Every accepted suite uses static key transport, so if "
                      "the server's private key ever leaks, all previously "
                      "recorded traffic can be decrypted. It also removes the "
                      "main mitigation for Bleichenbacher/ROBOT-class attacks "
                      "against RSA key exchange. Enable ECDHE (or DHE) suites "
                      "and prefer them over static ones.", check="TLS-017")

    # 2c. Static-RSA key exchange rule (TLS-019) ------------------------------
    # Markers for key exchanges that are NOT static RSA key transport.
    _NON_RSA_KX = ("ECDHE", "DHE", "ECDH", "ADH", "AECDH", "PSK", "SRP",
                   "KRB5", "GOST", "TLS_AES", "TLS_CHACHA")

    def _check_rsa_kx(self):
        accepted = self.info.get("ciphers_accepted") or []
        rsa_kx = [n for n in accepted
                  if not any(m in n.upper() for m in self._NON_RSA_KX)]
        self.info["rsa_kx_suites"] = rsa_kx
        for name in rsa_kx:
            self._add("MEDIUM",
                      f"RSA key exchange accepted (no forward secrecy): {name}",
                      "Static RSA key transport lets anyone who later obtains "
                      "the server's private key decrypt recorded sessions, and "
                      "RSA PKCS#1 v1.5 key exchange is the ROBOT/Bleichenbacher "
                      "attack surface. Prefer ECDHE suites and disable "
                      "static-RSA suites where clients allow.", check="TLS-019")

    # 3. Certificate -------------------------------------------------------
    def _obs_ctx(self):
        """Observation context: permissive on purpose.

        A scanner must be able to OBSERVE weak configurations (weak certs,
        old protocols) in order to report them, so verification is off and
        the security level is lowered for this handshake only. Nothing here
        weakens the actual security assessment.
        """
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        try:
            ctx.set_ciphers("DEFAULT@SECLEVEL=0")
        except Exception:
            pass
        return ctx

    def _check_certificate(self):
        # permissive handshake -> always retrieve the cert bytes, even weak ones
        try:
            ctx = self._obs_ctx()
            sock = self._raw_connect()
            ssock = ctx.wrap_socket(sock, server_hostname=self.target)
            der = ssock.getpeercert(binary_form=True)
            ssock.close()
        except Exception as e:
            self._add("INFO", "Could not retrieve certificate", str(e))
            return

        parsed = parse_cert_der(der) if der else {}
        subject = parsed.get("subject_cn") or ""
        issuer = parsed.get("issuer_cn") or ""
        self.info["cert_subject"] = subject
        self.info["cert_issuer"] = issuer
        self.info["cert_san_dns"] = parsed.get("san_dns", [])

        # expiry (from DER - reliable even when cert dict is empty)
        not_after = parsed.get("not_after")
        if not_after:
            days = (not_after - datetime.datetime.utcnow()).days
            self.info["cert_expires_in_days"] = days
            if days < 0:
                self._add("HIGH", "Certificate EXPIRED",
                          f"Expired {-days} days ago. Renew immediately.")
            elif days <= 7:
                # TLS-029: escalation of the 30-day warning - imminent outage
                self._add("HIGH",
                          f"Certificate expires within 7 days ({days} days left)",
                          "Expiry this close is an imminent outage: browsers "
                          "will block the site the moment it lapses. Renew "
                          "NOW and automate renewal (e.g. certbot) so this "
                          "cannot sneak up again.", check="TLS-029")
            elif days < 30:
                self._add("MEDIUM", f"Certificate expires in {days} days",
                          "Renew soon to avoid outages and browser warnings.")

        # TLS-028: total validity window too long (> 825 days)
        not_before = parsed.get("not_before")
        if not_before and not_after:
            validity_days = (not_after - not_before).days
            self.info["cert_validity_days"] = validity_days
            if validity_days > 825:
                self._add("LOW",
                          f"Certificate validity too long ({validity_days} days)",
                          "The CA/Browser Forum baseline has capped public "
                          "certificate lifetimes at 825 days since Sept 2020. "
                          "Long-lived certificates widen the key-compromise "
                          "window and are hard to revoke reliably. Reissue "
                          "with a shorter lifetime and automate renewal.",
                          check="TLS-028")

        # self-signed (compare raw Name bytes - most reliable)
        s_raw, i_raw = parsed.get("subject_raw"), parsed.get("issuer_raw")
        if s_raw and i_raw and s_raw == i_raw:
            self._add("MEDIUM", "Self-signed certificate",
                      "No public CA vouches for this certificate. Browsers will warn; "
                      "use a proper CA certificate in production.")

        # weak signature algorithm
        sig_oid = parsed.get("sig_oid")
        if sig_oid:
            name, weak = SIG_ALG_OIDS.get(sig_oid, (sig_oid, False))
            self.info["cert_sig_alg"] = name
            if weak:
                self._add("HIGH", f"Weak certificate signature: {name}",
                          "SHA-1/MD5 signatures are forgeable (SHAttered, chosen-prefix "
                          "attacks). Reissue with SHA-256 or better.")
        # key size
        bits = parsed.get("key_bits")
        ktype = parsed.get("key_type")
        if bits:
            self.info["cert_key"] = f"{ktype}-{bits}"
            if ktype == "RSA" and bits < 2048:
                self._add("HIGH", f"Weak RSA key: {bits} bits",
                          "Keys under 2048 bits are brute-forceable. Use 2048+ (3072+ "
                          "recommended).")
            if ktype == "EC" and bits and bits < 256:
                self._add("HIGH", f"Weak EC key: {bits} bits",
                          "Use P-256 or stronger curves.")

        # TLS-027 setup: TLS Feature extension (RFC 7633) - does the leaf
        # promise OCSP stapling (status_request, code 5)? The cross-check
        # against what the server actually staples runs in
        # _check_must_staple() after the stapling probe.
        exts = parsed.get("extensions") or {}
        if "1.3.6.1.5.5.7.1.24" in exts:
            features = _parse_tls_feature(exts["1.3.6.1.5.5.7.1.24"]["value"])
            self.info["cert_tls_features"] = features
            self.info["ocsp_must_staple_promised"] = 5 in features

        # TLS-030: Extended Key Usage present but serverAuth missing
        eku = parsed.get("eku_oids")
        if eku is not None:
            self.info["cert_eku"] = eku
            if "1.3.6.1.5.5.7.3.1" not in eku and "2.5.29.37.0" not in eku:
                self._add("MEDIUM", "Certificate EKU lacks serverAuth",
                          "The Extended Key Usage extension is present but "
                          "does not include serverAuth (1.3.6.1.5.5.7.3.1), "
                          "so this certificate was not issued for server "
                          "authentication - a mis-issuance indicator. "
                          "Reissue with the serverAuth EKU.", check="TLS-030")

        # TLS-031: basicConstraints CA:TRUE on a CA-issued leaf.
        # (A self-signed cert is its own CA by definition, so CA:TRUE is
        # expected there and is NOT flagged.)
        if parsed.get("basic_constraints_ca") and \
                not (s_raw and i_raw and s_raw == i_raw):
            self._add("HIGH", "Leaf certificate has CA:TRUE (basicConstraints)",
                      "This end-entity certificate asserts cA=TRUE, i.e. it "
                      "claims to be a certificate authority. In the hands of "
                      "an attacker it could sign arbitrary certificates that "
                      "clients trust. Treat as mis-issuance: revoke and "
                      "reissue with basicConstraints CA:FALSE.", check="TLS-031")

        # TLS-032: overly broad certificate scope
        for name in parsed.get("san_dns", []):
            if name.startswith("*.") and name[2:].startswith("*."):
                self._add("LOW", f"Multi-level wildcard in SAN: {name}",
                          "Wildcards may only cover a single left-most label "
                          "(RFC 6125); a multi-level wildcard is invalid yet "
                          "some clients accept it, silently widening the "
                          "certificate's scope. Reissue with one wildcard "
                          "level per name.", check="TLS-032")
                break
        san_count = len(parsed.get("san_dns", [])) + len(parsed.get("san_ip", []))
        if san_count > 50:
            self._add("INFO", f"Certificate covers {san_count} SAN names",
                      "A certificate valid for this many names has a wide "
                      "blast radius: if its key leaks, every listed service "
                      "is impersonable. Prefer separate certificates per "
                      "service.", check="TLS-032")

        # chain trust (verified handshake, default security level)
        try:
            ctx = self._std_ctx(verify=True)
            sock = self._raw_connect()
            ssock = ctx.wrap_socket(sock, server_hostname=self.target)
            ssock.close()
            self.info["chain_trusted"] = True
        except ssl.SSLCertVerificationError as e:
            self.info["chain_trusted"] = False
            msg = str(e)
            if "unable to get local issuer certificate" in msg or \
               "self-signed" in msg.lower() or "self signed" in msg.lower():
                self._add("MEDIUM", "Incomplete/untrusted certificate chain",
                          "Clients cannot build a trust chain (missing intermediate or "
                          "self-signed). Install the full chain including intermediates.")
            else:
                self._add("HIGH", "Certificate verification failed", msg)
        except Exception:
            pass

        # hostname match (SAN first, CN fallback - RFC 6125 style)
        if hostname_matches(parsed, self.target):
            self.info["hostname_match"] = True
        else:
            self.info["hostname_match"] = False
            # IP target with matching CN is legacy-but-common: softer rating
            cn = (parsed.get("subject_cn") or "").lower().rstrip(".")
            legacy_ip_cn = cn and cn == self.target.lower().rstrip(".") and \
                not parsed.get("san_dns") and not parsed.get("san_ip")
            if legacy_ip_cn:
                self._add("MEDIUM", "Certificate uses CN (not SAN) for IP",
                          f"CN={parsed.get('subject_cn')} matches, but modern browsers "
                          "ignore CN and require a SubjectAltName entry. Add SAN "
                          "iPAddress/DNS entries when reissuing.")
            else:
                self._add("HIGH", "Certificate hostname mismatch",
                          f"Certificate is not valid for '{self.target}'. Clients will show "
                          "a name-mismatch warning (easy phishing vector). "
                          f"SANs seen: {parsed.get('san_dns') or ['(none)']}.")

    @staticmethod
    def _cert_days_left(cert_dict):
        """Days until expiry from a cert dict (legacy helper). None on error."""
        try:
            not_after = datetime.datetime.strptime(cert_dict["notAfter"],
                                                   "%b %d %H:%M:%S %Y %Z")
            return (not_after - datetime.datetime.utcnow()).days
        except Exception:
            return None

    # 4. TLS compression (CRIME) -------------------------------------------
    def _check_compression(self):
        try:
            ctx = self._std_ctx(verify=False)
            sock = self._raw_connect()
            ssock = ctx.wrap_socket(sock, server_hostname=self.target)
            comp = ssock.compression()
            ssock.close()
            self.info["tls_compression"] = comp
            if comp:
                self._add("HIGH", f"TLS compression enabled ({comp})",
                          "Compression leaks plaintext via CRIME attack. Disable TLS "
                          "compression (it is rarely needed).")
        except Exception:
            pass

    # 5. HTTP security headers ----------------------------------------------
    def _fetch_headers(self):
        """HEAD request over TLS; return (status_line, {header: value})."""
        try:
            ctx = self._std_ctx(verify=False)
            sock = self._raw_connect()
            ssock = ctx.wrap_socket(sock, server_hostname=self.target)
            ssock.sendall(f"HEAD / HTTP/1.1\r\nHost: {self.target}\r\n"
                          f"Connection: close\r\n\r\n".encode())
            data = b""
            while True:
                chunk = ssock.recv(8192)
                if not chunk:
                    break
                data += chunk
                if b"\r\n\r\n" in data or len(data) > 16384:
                    break
            ssock.close()
        except Exception:
            return None, {}
        try:
            head = data.split(b"\r\n\r\n", 1)[0].decode("utf-8", errors="ignore")
        except Exception:
            return None, {}
        lines = head.split("\r\n")
        status = lines[0] if lines else ""
        headers = {}
        for ln in lines[1:]:
            if ":" in ln:
                k, v = ln.split(":", 1)
                headers[k.strip().lower()] = v.strip()
        return status, headers

    def _check_headers(self):
        status, h = self._fetch_headers()
        if not h and status is None:
            return
        self.info["http_status"] = status

        # HSTS - parsed properly
        hsts = h.get("strict-transport-security")
        if not hsts:
            self._add("MEDIUM", "HSTS header missing",
                      "Without Strict-Transport-Security, users are vulnerable to "
                      "SSL-stripping downgrade attacks. Add: "
                      "Strict-Transport-Security: max-age=31536000; includeSubDomains")
        else:
            m = re.search(r"max-age\s*=\s*(\d+)", hsts, re.I)
            max_age = int(m.group(1)) if m else 0
            subs = "includesubdomains" in hsts.lower()
            preload = "preload" in hsts.lower()
            self.info["hsts"] = {"max_age": max_age, "includeSubDomains": subs,
                                 "preload": preload}
            if max_age < 31536000:
                self._add("MEDIUM", f"HSTS max-age too short ({max_age}s)",
                          "Use max-age=31536000 (1 year) or more so browsers remember "
                          "long enough.")
            if not subs:
                self._add("LOW", "HSTS without includeSubDomains",
                          "Subdomains stay unprotected. Add includeSubDomains once all "
                          "subdomains are HTTPS-ready.")
            if not preload:
                self.info["hsts_preload"] = "not submitted (optional)"

        # CSP
        csp = h.get("content-security-policy")
        if not csp:
            self._add("MEDIUM", "Content-Security-Policy missing",
                      "CSP blocks XSS and injection attacks. Add a CSP header; start "
                      "with default-src 'self'.")
        elif "unsafe-inline" in csp:
            self._add("LOW", "CSP allows 'unsafe-inline'",
                      "unsafe-inline weakens XSS protection. Move code to external "
                      "files with nonces/hashes.")

        # X-Frame-Options
        if "x-frame-options" not in h:
            self._add("MEDIUM", "X-Frame-Options missing",
                      "Page can be framed -> clickjacking risk. Add "
                      "X-Frame-Options: DENY (or SAMEORIGIN).")

        # X-Content-Type-Options
        xcto = h.get("x-content-type-options", "").lower()
        if xcto != "nosniff":
            self._add("LOW", "X-Content-Type-Options missing/incorrect",
                      "Without 'nosniff', browsers may MIME-sniff responses into "
                      "executable content. Add X-Content-Type-Options: nosniff.")

        # Referrer-Policy
        if "referrer-policy" not in h:
            self._add("INFO", "Referrer-Policy missing",
                      "Consider Referrer-Policy: strict-origin-when-cross-origin to "
                      "limit URL leakage.")

    # 6. OCSP stapling (raw ClientHello with status_request) -----------------
    def _check_ocsp_stapling(self):
        try:
            sock = self._raw_connect()
            sock.sendall(build_client_hello(hostname=self.target,
                                            with_status_request=True))
            data = sock.recv(8192)
            sock.close()
        except Exception:
            return
        exts = parse_server_hello_extensions(data)
        if 0x05 in exts:
            self.info["ocsp_stapling"] = "offered"
        else:
            self.info["ocsp_stapling"] = "not offered"
            self._add("LOW", "OCSP stapling not offered",
                      "Without stapling, clients make extra OCSP connections (slower "
                      "and leaks browsing to the CA). Enable ssl_stapling (nginx) / "
                      "SSLUseStapling (Apache).")

    # 6b. Secure renegotiation (TLS-015) - OBSERVE ONLY -------------------------
    def _check_renegotiation(self):
        # We only look at whether the ServerHello echoes the RFC 5746
        # renegotiation_info extension (0xFF01). A renegotiation is NEVER
        # attempted - that would be an active attack step.
        try:
            sock = self._raw_connect()
            sock.sendall(build_client_hello(hostname=self.target,
                                            with_empty_reneg_info=True))
            data = sock.recv(8192)
            sock.close()
        except Exception:
            return
        if not data or data[0] != 0x16:
            return  # no handshake record (refused/alert) - nothing to observe
        exts = parse_server_hello_extensions(data)
        # 0x002B = supported_versions in the ServerHello means TLS 1.3 was
        # negotiated, where renegotiation does not exist at all.
        if 0xFF01 in exts or 0x002B in exts:
            self.info["secure_renegotiation"] = True
            return
        self.info["secure_renegotiation"] = False
        self._add("HIGH", "Insecure renegotiation: no renegotiation_info extension",
                  "The server did not echo the renegotiation_info extension "
                  "(RFC 5746), so a client cannot cryptographically bind a "
                  "renegotiated session to the original one - the classic "
                  "renegotiation plaintext-injection attack applies. Upgrade "
                  "the TLS library / disable insecure renegotiation. "
                  "(CyberRakshak only observes the extension; it never "
                  "attempts a renegotiation.)", check="TLS-015")

    # 6c. OCSP Must-Staple cross-check (TLS-027) --------------------------------
    def _check_must_staple(self):
        # The leaf's TLS Feature extension (captured in _check_certificate)
        # promises status_request, i.e. the certificate REQUIRES clients to
        # receive a stapled OCSP response. If the server does not staple,
        # strict clients hard-fail - worse than not promising at all.
        if not self.info.get("ocsp_must_staple_promised"):
            return
        if self.info.get("ocsp_stapling") == "offered":
            self.info["ocsp_must_staple"] = True  # promised and delivered
            return
        self.info["ocsp_must_staple"] = False
        self._add("HIGH", "OCSP Must-Staple promised but stapling not offered",
                  "The certificate carries the TLS Feature extension "
                  "(RFC 7633) requiring a stapled OCSP response "
                  "(status_request), but this server did not offer OCSP "
                  "stapling in the handshake. Browsers honoring Must-Staple "
                  "will hard-fail the connection. Either enable stapling "
                  "(nginx: ssl_stapling on + ssl_stapling_verify on; Apache: "
                  "SSLUseStapling) or reissue the certificate without the "
                  "Must-Staple feature.", check="TLS-027")

    # 6d. Downgrade protection - TLS_FALLBACK_SCSV (TLS-016) ---------------------
    def _check_fallback_scsv(self):
        # One normal fallback handshake attempt (RFC 7507). We never force
        # or complete a downgrade attack - we only observe whether the
        # server aborts, as a conforming server must.
        try:
            sock = self._raw_connect()
            sock.sendall(build_client_hello(hostname=self.target,
                                            fallback_scsv=True))
            data = sock.recv(8192)
            sock.close()
        except Exception:
            return
        verdict = fallback_scsv_verdict(data)
        if verdict == "protected":
            self.info["fallback_scsv"] = True
            return
        if verdict == "vulnerable":
            self.info["fallback_scsv"] = False
            self._add("MEDIUM", "No downgrade protection (TLS_FALLBACK_SCSV ignored)",
                      "The server completed a fallback handshake (ClientHello "
                      "marked with TLS_FALLBACK_SCSV, RFC 7507) instead of "
                      "aborting with an inappropriate_fallback alert, so "
                      "nothing stops a network attacker from forcing clients "
                      "down to the weakest protocol both sides still allow. "
                      "Upgrade the TLS library / enable FALLBACK_SCSV "
                      "support server-side.", check="TLS-016")
            return
        self.info["fallback_scsv"] = "inconclusive"

    # 6e. SSLv2 / DROWN probe (TLS-018) - OBSERVE ONLY ----------------------------
    def _check_sslv2(self):
        # A single SSLv2-format CLIENT-HELLO - the same first message any
        # legacy client sends. Only an SSLv2 SERVER-HELLO reply proves the
        # protocol is enabled. No Bleichenbacher oracle queries, no
        # decryption attempt (spec section 6).
        try:
            sock = self._raw_connect()
            sock.sendall(build_sslv2_client_hello())
            data = sock.recv(4096)
            sock.close()
        except Exception:
            data = b""
        vulnerable = sslv2_verdict(data)
        self.info["sslv2"] = vulnerable
        if vulnerable:
            self._add("CRITICAL", "SSLv2 enabled (DROWN, CVE-2016-0800)",
                      "This server still speaks SSLv2. With DROWN, an attacker "
                      "can use the SSLv2 service as an oracle to decrypt "
                      "modern TLS sessions that share the same RSA key. "
                      "Disable SSLv2 (and SSLv3) completely, and make sure "
                      "this RSA key/certificate is not shared with any other "
                      "service that still allows SSLv2 or weak export "
                      "ciphers.", check="TLS-018", cve="CVE-2016-0800")

    # 6f. Logjam - DH parameter size from ServerKeyExchange (TLS-020) -------------
    # DHE suites offered to the raw probe (TLS 1.2 and classic).
    _DHE_PROBE_SUITES = (0x009E, 0x009F, 0x006B, 0x0067, 0x0039, 0x0033, 0x00FF)

    def _check_logjam(self):
        # Offer ONLY DHE suites so the server must answer with a
        # ServerKeyExchange carrying its DH parameters if it supports DHE
        # at all. We read the prime size the server voluntarily sends;
        # computing the discrete log would be active cryptanalysis and is
        # never attempted (spec section 6).
        try:
            sock = self._raw_connect()
            sock.sendall(build_client_hello(
                hostname=self.target, ciphers=list(self._DHE_PROBE_SUITES)))
            data = self._recv_handshake(sock)
            sock.close()
        except Exception:
            return
        bits = None
        for htype, hb in parse_handshake_messages(data):
            if htype == 0x0C:  # ServerKeyExchange
                bits = parse_server_key_exchange_dh_bits(hb)
                break
        self.info["dh_param_bits"] = bits
        if bits and bits < 2048:
            self._add("HIGH",
                      f"Weak DH parameters: {bits}-bit prime (Logjam)",
                      "The server's DHE ServerKeyExchange uses a DH prime of "
                      f"{bits} bits. Logjam (CVE-2015-4000) showed that "
                      "export-era and sub-2048-bit DH groups can be broken "
                      "or downgraded to, letting an attacker compute the "
                      "session keys. Use 2048-bit or larger DH parameters "
                      "(or prefer ECDHE and disable DHE).",
                      check="TLS-020", cve="CVE-2015-4000")

    # 6g. Certificate chain from the raw Certificate message (TLS-025/026) --------
    def _capture_chain(self):
        """Ordered parsed certs exactly as the server presents them.

        ssl's getpeercert() returns only the leaf, so the chain must come
        from the raw handshake's Certificate message. The probe hello
        negotiates at most TLS 1.2, where the chain travels in cleartext.
        Cached; fail-soft to [] (e.g. TLS 1.3-only servers).
        """
        cached = getattr(self, "_chain_cache", None)
        if cached is not None:
            return cached
        chain = []
        try:
            sock = self._raw_connect()
            sock.sendall(build_client_hello(hostname=self.target))
            data = self._recv_handshake(sock)
            sock.close()
            for htype, hb in parse_handshake_messages(data):
                if htype == 0x0B:  # Certificate
                    chain = [parse_cert_der(d)
                             for d in parse_certificate_message(hb)]
                    break
        except Exception:
            chain = []
        self._chain_cache = chain
        return chain

    def _check_chain_order(self):
        chain = self._capture_chain()
        if chain:
            self.info["chain_length"] = len(chain)
        if len(chain) < 2:
            return
        for i in range(len(chain) - 1):
            issuer = chain[i].get("issuer_raw")
            subject = chain[i + 1].get("subject_raw")
            if issuer and subject and issuer != subject:
                self.info["chain_order_ok"] = False
                self._add("MEDIUM",
                          "Certificate chain presented out of order",
                          f"Certificate #{i + 1} in the presented chain was "
                          f"issued by '{chain[i].get('issuer_cn') or '?'}', but "
                          f"the next certificate presented is "
                          f"'{chain[i + 1].get('subject_cn') or '?'}'. TLS "
                          "requires each certificate to be signed by the one "
                          "that follows it; strict clients reject a misordered "
                          "chain. Reorder the server's chain file: leaf first, "
                          "then its issuer, and so on up to (optionally) the "
                          "root.", check="TLS-025")
                return
        self.info["chain_order_ok"] = True

    def _check_chain_strength(self):
        chain = self._capture_chain()
        if len(chain) < 2:
            return
        last = len(chain) - 1
        for idx in range(1, len(chain)):
            cert = chain[idx]
            # A self-signed final certificate is a root: weak material
            # there is legacy-tolerated (LOW note), per spec TLS-026.
            is_root = idx == last and \
                cert.get("issuer_raw") and \
                cert.get("issuer_raw") == cert.get("subject_raw")
            role = "root" if is_root else "intermediate"
            sev = "LOW" if is_root else "HIGH"
            cn = cert.get("subject_cn") or f"certificate #{idx + 1}"
            sig_oid = cert.get("sig_oid")
            if sig_oid:
                name, weak = SIG_ALG_OIDS.get(sig_oid, (sig_oid, False))
                if weak:
                    self._add(sev,
                              f"Weak signature on {role} certificate ({cn}): {name}",
                              "A SHA-1/MD5 signature anywhere in the chain "
                              "lets an attacker forge that link and impersonate "
                              "every site below it (chosen-prefix collisions "
                              "are practical for MD5/SHA-1). Reissue the chain "
                              "with SHA-256 or better signatures.",
                              check="TLS-026")
            bits, ktype = cert.get("key_bits"), cert.get("key_type")
            if bits:
                if ktype == "RSA" and bits < 2048:
                    self._add(sev,
                              f"Weak RSA key on {role} certificate ({cn}): {bits} bits",
                              "Keys under 2048 bits in the chain weaken every "
                              "certificate issued under them. Reissue with "
                              "2048-bit or larger keys.", check="TLS-026")
                elif ktype == "EC" and bits < 256:
                    self._add(sev,
                              f"Weak EC key on {role} certificate ({cn}): {bits} bits",
                              "Use P-256 or stronger curves throughout the "
                              "chain.", check="TLS-026")

    # 6h. CBC suites combined with legacy TLS (TLS-022) ----------------------------
    _AEAD_MARKERS = ("GCM", "POLY1305", "CCM", "TLS_AES", "TLS_CHACHA")

    def _check_cbc_legacy_tls(self):
        accepted = self.info.get("ciphers_accepted") or []
        offered = self.info.get("tls_versions_offered") or []
        cbc = [n for n in accepted
               if not any(m in n.upper() for m in self._AEAD_MARKERS)]
        legacy = [v for v in ("TLS 1.0", "TLS 1.1") if v in offered]
        self.info["cbc_with_legacy_tls"] = bool(cbc and legacy)
        if cbc and legacy:
            self._add("MEDIUM",
                      "CBC cipher suites accepted together with " +
                      " and ".join(legacy) + " (Lucky13 class)",
                      "Non-AEAD (CBC) suites such as " + ", ".join(cbc[:3]) +
                      " are accepted while legacy TLS is offered. Padding-"
                      "oracle timing attacks of the Lucky13 class "
                      "(CVE-2013-0169) target exactly this combination. "
                      "Disable TLS 1.0/1.1, or restrict the server to "
                      "AEAD suites (AES-GCM / ChaCha20-Poly1305).",
                      check="TLS-022", cve="CVE-2013-0169")

    # 8b. ALPN negotiation (TLS-023) ----------------------------------------------
    def _check_alpn(self):
        try:
            ctx = self._obs_ctx()
            ctx.set_alpn_protocols(["h2", "http/1.1"])
            sock = self._raw_connect()
            ssock = ctx.wrap_socket(sock, server_hostname=self.target)
            proto = ssock.selected_alpn_protocol()
            ssock.close()
        except Exception:
            return
        self.info["alpn"] = proto
        if proto:
            detail = (f"The server negotiated application protocol '{proto}' "
                      "via ALPN. Informational - recorded for the report.")
            if proto == "h2":
                detail += (" HTTP/2 has its own hardening history (rapid-reset "
                           "and related DoS classes) - keep the HTTP/2 "
                           "implementation patched.")
            self._add("INFO", f"ALPN negotiated: {proto}", detail,
                      check="TLS-023")

    # 7. SNI handling ---------------------------------------------------------
    def _check_sni(self):
        # handshake WITHOUT SNI
        try:
            ctx = self._std_ctx(verify=False)
            sock = self._raw_connect()
            ssock = ctx.wrap_socket(sock)  # no server_hostname -> no SNI
            cert = ssock.getpeercert()
            ssock.close()
            no_sni_ok = True
        except Exception:
            no_sni_ok, cert = False, None
        # handshake WITH SNI
        try:
            ctx = self._std_ctx(verify=False)
            sock = self._raw_connect()
            ssock = ctx.wrap_socket(sock, server_hostname=self.target)
            cert_sni = ssock.getpeercert()
            ssock.close()
            sni_ok = True
        except Exception:
            sni_ok, cert_sni = False, None

        self.info["sni_required"] = (not no_sni_ok) and sni_ok
        if self.info["sni_required"]:
            self._add("INFO", "Server requires SNI",
                      "Clients without SNI support (very old) cannot connect. "
                      "Usually fine.")
        # wrong-SNI test via raw hello
        try:
            sock = self._raw_connect()
            sock.sendall(build_client_hello(hostname="wrong.invalid"))
            data = sock.recv(4096)
            sock.close()
            got_hello = len(data) > 0 and data[0] == 0x16
        except Exception:
            got_hello = False
        if got_hello:
            self.info["sni_wrong_hostname"] = "server still completed handshake"
            self._add("INFO", "Server ignores wrong SNI hostname",
                      "Server completed a handshake for an unknown hostname. Ensure "
                      "the default vhost does not leak internal content.")

    # 8. Session resumption / tickets -------------------------------------------
    def _check_session(self):
        try:
            ctx = self._std_ctx(verify=False)
            s1 = self._raw_connect()
            ss1 = ctx.wrap_socket(s1, server_hostname=self.target)
            sess = ss1.session
            has_ticket = bool(getattr(sess, "has_ticket", False))
            ver = ss1.version()
            ss1.close()
            s2 = self._raw_connect()
            ss2 = ctx.wrap_socket(s2, server_hostname=self.target)
            reused = bool(getattr(ss2, "session_reused", False))
            ss2.close()
        except Exception:
            return
        self.info["session_ticket"] = has_ticket
        self.info["session_resumed"] = reused
        # TLS-024: resumption detail - negotiated version + mechanism.
        # TLS 1.3 has no classic session IDs/tickets: resumption is PSK-based.
        self.info["session_version"] = ver
        if ver == "TLSv1.3":
            mechanism = "PSK (TLS 1.3)"
        elif reused:
            mechanism = "session ID / ticket resumption"
        elif has_ticket:
            mechanism = "session tickets offered (not resumed in this probe)"
        else:
            mechanism = "none observed"
        self.info["session_mechanism"] = mechanism
        if has_ticket:
            self._add("INFO", "TLS session tickets enabled",
                      "Tickets are normal, but rotate ticket keys regularly; stale "
                      "keys let old sessions decrypt (and Ticketbleed CVE-2016-9244 "
                      "affected old F5 devices - keep firmware updated). "
                      f"Observed here: {ver} with {mechanism}.")
        if reused:
            self.info["session_resumption"] = "works"

    # 9. Heartbeat / Heartbleed - guidance only ----------------------------------
    def _check_heartbeat_guidance(self):
        # Deliberately NO active Heartbleed probe: detecting it requires sending
        # a malformed heartbeat request and reading leaked server memory, which
        # is exploit code. We stay on the safe side and tell the user how to
        # verify manually on their OWN systems.
        self._add(
            "INFO",
            "Heartbleed (CVE-2014-0160) not actively probed",
            "A real Heartbleed test sends a malformed heartbeat and reads leaked "
            "memory - CyberRakshak will not do that automatically. Verify manually "
            "on YOUR OWN systems with: nmap --script ssl-heartbleed -p 443 <host> "
            "or: testssl.sh --heartbleed <host>. Patch: OpenSSL 1.0.1g+.",
        )
