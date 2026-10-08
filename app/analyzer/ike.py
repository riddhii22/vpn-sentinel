"""IKE (ISAKMP) dissection from observable headers and cleartext SA payloads."""

from __future__ import annotations

from collections import Counter

from scapy.layers.isakmp import ISAKMP, ISAKMP_payload_Transform

from app.analyzer.capture import packet_endpoint
from app.analyzer.models import NOT_DETECTED, detected, not_detected

# RFC 2409 / IKEv1 Phase 1 transform attribute values (not IKEv2 Transform IDs).
IKEV1_ENC = {
    1: "DES",
    5: "3DES",
    7: "AES-CBC",
    8: "AES-CTR",
    20: "AES-GCM",
}
IKEV1_HASH = {
    1: "MD5",
    2: "SHA",
    4: "SHA2-256",
    5: "SHA2-384",
    6: "SHA2-512",
}
IKEV1_AUTH = {
    1: "PSK",
    2: "DSS-SIG",
    3: "RSA-SIG",
    4: "RSA-ENC",
    5: "Revised RSA-ENC",
}

# RFC 7296 IKEv2 transform type 1 (ENCR) IDs.
IKEV2_ENCR = {
    1: "DES",
    2: "IDEA",
    3: "3DES",
    12: "AES-CBC",
    13: "AES-CTR",
    18: "AES-CCM-8",
    19: "AES-GCM-8",
    20: "AES-GCM-16",
}

IKEV2_PRF = {1: "HMAC-MD5", 2: "HMAC-SHA1", 5: "HMAC-SHA2-256", 6: "HMAC-SHA2-384", 7: "HMAC-SHA2-512"}
IKEV2_INTEG = {
    1: "HMAC-MD5-96",
    2: "HMAC-SHA1-96",
    12: "HMAC-SHA2-256-128",
    13: "HMAC-SHA2-384-192",
    14: "HMAC-SHA2-512-256",
}

# Common DH / GroupDesc numbers (IKEv1 Group Description / IKEv2 KE group).
DH_GROUPS = {
    1: "MODP-768 (weak)",
    2: "MODP-1024 (weak)",
    5: "MODP-1536 (legacy)",
    14: "MODP-2048",
    15: "MODP-3072",
    16: "MODP-4096",
    19: "ECP-256",
    20: "ECP-384",
    21: "ECP-521",
}

DH_NAME_TO_ID = {
    "768MODPgr": 1,
    "1024MODPgr": 2,
    "1536MODPgr": 5,
    "2048MODPgr": 14,
    "3072MODPgr": 15,
    "4096MODPgr": 16,
    "256EC2Ngr": 19,
    "384EC2Ngr": 20,
}


def _dh_id(value) -> int | None:
    if value is None:
        return None
    if isinstance(value, int):
        return value
    text = str(value).strip()
    if text.isdigit():
        return int(text)
    if text in DH_NAME_TO_ID:
        return DH_NAME_TO_ID[text]
    # GroupDesc 20 already int from sample; names from Scapy maps
    for gid, name in DH_GROUPS.items():
        if text.lower() in name.lower() or text == str(gid):
            return gid
    return None

WEAK_DH = {1, 2, 5}
WEAK_ENC = {"DES", "3DES", "DES-CBC", "3DES-CBC"}
WEAK_HASH = {"MD5", "SHA", "SHA1", "SHA-1", "TIGER", "HMAC-MD5-96", "HMAC-SHA1-96"}

IKEV1_EXCH = {
    2: "Identity Protection (Main Mode)",
    4: "Aggressive Mode",
    5: "Informational",
    6: "Transaction",
    32: "Quick Mode",
}

IKEV2_EXCH = {
    34: "IKE_SA_INIT",
    35: "IKE_AUTH",
    36: "CREATE_CHILD_SA",
    37: "INFORMATIONAL",
}


def _major_version(version_field) -> int | None:
    """Scapy stores the ISAKMP version byte (e.g. 0x10=v1, 0x20=v2)."""
    if version_field is None:
        return None
    try:
        value = int(version_field)
    except (TypeError, ValueError):
        return None
    if value in (1, 2):
        return value
    major = value >> 4
    if major in (1, 2):
        return major
    return None


def ike_datagram(packet) -> bytes | None:
    """ISAKMP bytes from UDP/500 or NAT-T UDP/4500 (RFC 3948 non-ESP marker)."""
    if packet.haslayer("UDP"):
        sport = int(packet["UDP"].sport)
        dport = int(packet["UDP"].dport)
        payload = bytes(packet["UDP"].payload) if packet["UDP"].payload else b""
        if sport == 500 or dport == 500:
            return payload or None
        if (sport == 4500 or dport == 4500) and len(payload) >= 32 and payload[:4] == b"\x00" * 4:
            return payload[4:]
        return None
    if packet.haslayer(ISAKMP):
        raw = bytes(packet[ISAKMP])
        return raw or None
    return None


def _cookie_hex(value) -> str | None:
    if value in (None, b"", b"\x00" * 8):
        return None
    if isinstance(value, bytes):
        return value.hex()
    return str(value)


# RFC 2409 §3.3: IKEv1 data attributes. AF=1 (high bit) means TV (2-byte value).
# Type 1 = Encryption Algorithm → short form on the wire is 0x80 0x01 <id>.
_IKEV1_ATTR_ENCRYPTION = 1
_IKEV1_ATTR_HASH = 2
_IKEV1_ATTR_AUTH = 3
_IKEV1_ATTR_GROUP = 4
_IKEV1_ATTR_KEYLEN = 14


def _walk_ikev1_tv_attributes(blob: bytes, start: int = 0) -> list[dict]:
    """Walk consecutive IKEv1 transform attributes (RFC 2409 short/long form)."""
    rows: list[dict] = []
    current: dict = {}
    pos = start
    while pos + 4 <= len(blob):
        af_and_type = blob[pos]
        atype = blob[pos + 1]
        if not (af_and_type & 0x80):
            break
        aval = int.from_bytes(blob[pos + 2 : pos + 4], "big")
        pos += 4
        if atype == _IKEV1_ATTR_ENCRYPTION and current.get("encryption_id") is not None:
            rows.append(current)
            current = {}
        if atype == _IKEV1_ATTR_ENCRYPTION:
            current["encryption_id"] = aval
            current["encryption"] = IKEV1_ENC.get(aval, f"ENC-{aval}")
        elif atype == _IKEV1_ATTR_HASH:
            current["hash_id"] = aval
            current["hash"] = IKEV1_HASH.get(aval, f"HASH-{aval}")
        elif atype == _IKEV1_ATTR_AUTH:
            current["auth_id"] = aval
            current["auth_method"] = IKEV1_AUTH.get(aval, f"AUTH-{aval}")
        elif atype == _IKEV1_ATTR_GROUP:
            current["dh_group"] = aval
        elif atype == _IKEV1_ATTR_KEYLEN:
            current["key_length"] = aval
        elif atype == 12:
            current["lifetime"] = aval
    if current:
        rows.append(current)
    return [r for r in rows if r]


def parse_ikev1_sa(raw_bytes: bytes) -> dict:
    """Parse an IKEv1 ISAKMP datagram's Phase 1 SA (RFC 2409 attribute list).

    Do not use this on IKEv2. IKEv1 Encryption Algorithm is short-form
    0x80 0x01 at transform attributes, then a 2-byte IKEv1 algorithm ID
    (7 = AES-CBC). That encoding is not how IKEv2 names ciphers.
    """
    empty = {
        "ike_version": 1,
        "encryption": None,
        "encryption_id": None,
        "key_length": None,
        "dh_group": None,
        "auth_method": None,
        "auth_id": None,
        "hash": None,
        "transforms": [],
        "note": "No IKEv1 transform attributes found",
    }
    if not raw_bytes or len(raw_bytes) < 28:
        return empty
    marker = raw_bytes.find(b"\x80\x01")
    if marker < 0:
        return empty
    start = marker
    while start >= 4 and raw_bytes[start - 4] & 0x80:
        start -= 4
    transforms = _walk_ikev1_tv_attributes(raw_bytes, start)
    if not transforms:
        return empty
    first = transforms[0]
    return {
        "ike_version": 1,
        "encryption": first.get("encryption"),
        "encryption_id": first.get("encryption_id"),
        "key_length": first.get("key_length"),
        "dh_group": first.get("dh_group"),
        "auth_method": first.get("auth_method"),
        "auth_id": first.get("auth_id"),
        "hash": first.get("hash"),
        "transforms": transforms,
        "note": "IKEv1 RFC 2409 short-form attributes (0x80 | type)",
    }


def parse_ikev2_sa(raw_bytes: bytes) -> dict:
    """Parse IKEv2 SA proposals (RFC 7296 §3.3 Transform Substructure).

    Confirmed on samples/IKEv2.pcap packet 1 (IKE_SA_INIT) in Wireshark:
    ENCR_AES_CBC (12) key 256, PRF_HMAC_SHA2_512 (7), AUTH_HMAC_SHA2_512_256 (14),
    DH group 20.

    Each transform (offsets from that transform's first byte):
      0     Last Substruc (0=last, 3=more)
      1     Reserved
      2–3   Transform Length
      4     Transform Type (1=ENCR, 2=PRF, 3=INTEG, 4=DH)
      5     Reserved
      6–7   Transform ID
      8…    Attributes (e.g. 0x80 0x0E = Key Length, type 14 — not 0x80 0x01)

    IKEv2 IKE SA does not carry IKEv1 'Authentication Method' (PSK/RSA).
    That appears later in IKE_AUTH, often encrypted.
    """
    empty = {
        "ike_version": 2,
        "encryption": None,
        "encryption_id": None,
        "key_length": None,
        "dh_group": None,
        "auth_method": None,
        "prf": None,
        "integrity": None,
        "proposals": [],
        "note": "No IKEv2 SA transforms found",
    }
    proposals = _parse_ikev2_sa_raw(raw_bytes)
    if not proposals:
        return empty
    enc = prf = integ = None
    enc_id = keylen = dh = None
    for prop in proposals:
        for t in prop.get("transforms") or []:
            ttype, tid, name = t.get("type"), t.get("id"), t.get("name")
            if ttype == 1 and enc is None:
                enc, enc_id, keylen = name, tid, t.get("key_length")
            elif ttype == 2 and prf is None:
                prf = name
            elif ttype == 3 and integ is None:
                integ = name
            elif ttype == 4 and dh is None:
                dh = tid
    return {
        "ike_version": 2,
        "encryption": _normalize_enc(enc, keylen) or enc,
        "encryption_id": enc_id,
        "key_length": keylen,
        "dh_group": dh,
        "auth_method": None,
        "prf": prf,
        "integrity": integ,
        "proposals": proposals,
        "note": (
            "Auth method is not an IKE_SA_INIT transform; PRF/INTEG are listed instead. "
            "RFC 7296 §3.3"
        ),
    }


def _parse_ikev1_transforms(packet) -> list[dict]:
    found = []
    trans = packet
    seen = 0
    while trans is not None and seen < 16:
        if trans.haslayer(ISAKMP_payload_Transform):
            layer = trans[ISAKMP_payload_Transform]
            row = {"source": "ikev1_transform"}
            for item in getattr(layer, "transforms", []) or []:
                if isinstance(item, tuple) and len(item) == 2:
                    key, val = item
                    row[str(key)] = val
            found.append(row)
            trans = layer.payload
        else:
            trans = getattr(trans, "payload", None)
        seen += 1
        if trans is None or trans.name in ("NoPayload", "Raw"):
            break
    return found


def _parse_ikev2_sa_raw(raw: bytes) -> list[dict]:
    """Parse IKEv2 generic payloads looking for SA proposal bodies (RFC 7296)."""
    if len(raw) < 32:
        return []
    proposals = []
    offset = 28
    while offset + 4 <= len(raw):
        nxt = raw[offset]
        length = int.from_bytes(raw[offset + 2 : offset + 4], "big")
        if length < 4 or offset + length > len(raw):
            break
        body = raw[offset + 4 : offset + length]
        if len(body) >= 8:
            proposals.extend(_ikev2_proposal(body))
        offset += length
        if nxt == 0:
            break
    return proposals


def _ikev2_proposal(body: bytes) -> list[dict]:
    # proposal header: last(1) reserved(1) len(2) already stripped? body is SA contents
    # SA payload data = concatenated proposals. Each: 0,0,len(2), prop#, proto, spi_size, ntrans, SPI, transforms
    proposals = []
    pos = 0
    while pos + 8 <= len(body):
        plen = int.from_bytes(body[pos + 2 : pos + 4], "big") if pos + 4 <= len(body) else 0
        # When body starts at proposal: bytes 0-3 are last, res, length
        if plen == 0 or pos + plen > len(body):
            # try interpret from start as proposal without extra SA header
            if pos == 0 and len(body) >= 8:
                plen = len(body)
            else:
                break
        prop_num = body[pos + 4]
        proto = body[pos + 5]
        spi_size = body[pos + 6]
        ntrans = body[pos + 7]
        tpos = pos + 8 + spi_size
        transforms = []
        for _ in range(ntrans):
            if tpos + 8 > len(body):
                break
            tlen = int.from_bytes(body[tpos + 2 : tpos + 4], "big")
            ttype = body[tpos + 4]
            tid = int.from_bytes(body[tpos + 6 : tpos + 8], "big")
            attrs = body[tpos + 8 : tpos + tlen] if tlen >= 8 else b""
            keylen = None
            a = 0
            while a + 4 <= len(attrs):
                # TV format: 0x8000 | type, 16-bit value
                if attrs[a] & 0x80:
                    atype = attrs[a + 1]
                    aval = int.from_bytes(attrs[a + 2 : a + 4], "big")
                    if atype == 14:
                        keylen = aval
                    a += 4
                else:
                    break
            name = None
            if ttype == 1:
                name = IKEV2_ENCR.get(tid, f"ENCR-{tid}")
            elif ttype == 2:
                name = IKEV2_PRF.get(tid, f"PRF-{tid}")
            elif ttype == 3:
                name = IKEV2_INTEG.get(tid, f"INTEG-{tid}")
            elif ttype == 4:
                name = DH_GROUPS.get(tid, f"DH-{tid}")
            transforms.append(
                {
                    "type": ttype,
                    "id": tid,
                    "name": name,
                    "key_length": keylen,
                    "proposal": prop_num,
                    "proto": proto,
                }
            )
            if tlen < 8:
                break
            tpos += tlen
        proposals.append({"proposal": prop_num, "transforms": transforms})
        if plen < 8:
            break
        pos += plen
        if pos >= len(body):
            break
    return proposals


def _normalize_enc(name, key_length) -> str | None:
    if name is None:
        return None
    text = str(name)
    if key_length in (128, 256) and "AES" in text.upper():
        if "GCM" in text.upper():
            return f"AES-GCM-{key_length}"
        if "CBC" in text.upper() or text.upper() == "AES-CBC":
            return f"AES-CBC-{key_length}"
        return f"{text}-{key_length}"
    return text


def analyze_ike(packets) -> dict:
    messages = []
    versions: Counter[int] = Counter()
    exchanges: Counter[str] = Counter()
    enc_seen: Counter[str] = Counter()
    auth_seen: Counter[str] = Counter()
    hash_seen: Counter[str] = Counter()
    dh_seen: Counter[int] = Counter()
    lifetimes: list[int] = []
    evidence_v1 = []
    evidence_v2 = []
    encrypted_ike = 0
    clear_sa = 0

    for index, packet in enumerate(packets, start=1):
        raw_ike = ike_datagram(packet)
        if not raw_ike or len(raw_ike) < 28:
            continue
        ike = packet[ISAKMP] if packet.haslayer(ISAKMP) else None
        major = _major_version(getattr(ike, "version", None) if ike is not None else None)
        if major is None and len(raw_ike) > 17:
            major = raw_ike[17] >> 4
        exch = getattr(ike, "exch_type", None) if ike is not None else raw_ike[18]
        flags_field = getattr(ike, "flags", None) if ike is not None else raw_ike[19]
        flags = str(flags_field or "")
        encrypted = "encryption" in flags.lower() or "encrypt" in flags.lower()
        if not encrypted and ike is None and major == 1:
            encrypted = bool(raw_ike[19] & 0x01)
        if encrypted:
            encrypted_ike += 1

        exch_name = None
        if major == 1:
            exch_name = IKEV1_EXCH.get(int(exch), f"type-{exch}") if exch is not None else NOT_DETECTED
        elif major == 2:
            exch_name = IKEV2_EXCH.get(int(exch), f"type-{exch}") if exch is not None else NOT_DETECTED
        if exch_name:
            exchanges[exch_name] += 1
        if major in (1, 2):
            versions[major] += 1

        init_c = _cookie_hex(getattr(ike, "init_cookie", None) if ike is not None else raw_ike[0:8])
        resp_c = _cookie_hex(getattr(ike, "resp_cookie", None) if ike is not None else raw_ike[8:16])
        msgid = getattr(ike, "id", None) if ike is not None else int.from_bytes(raw_ike[20:24], "big")

        note = f"IKEv{major}" if major else "IKE"
        item = packet_endpoint(packet, index, "ISAKMP/IKE", note)
        if major == 1:
            evidence_v1.append(item.to_dict())
        elif major == 2:
            evidence_v2.append(item.to_dict())

        messages.append(
            {
                "packet_number": index,
                "ike_version": major,
                "exchange": exch_name or NOT_DETECTED,
                "message_id": msgid if msgid is not None else NOT_DETECTED,
                "initiator_cookie": init_c or NOT_DETECTED,
                "responder_cookie": resp_c or NOT_DETECTED,
                "encrypted_payload": encrypted,
                "timestamp": item.timestamp,
                "source": item.source,
                "destination": item.destination,
            }
        )

        if encrypted:
            continue

        if ike is not None:
            raw_ike = bytes(ike)
        # major = ISAKMP version nibble (0x10 → 1, 0x20 → 2). Separate parsers.
        if major == 1:
            parsed_v1 = parse_ikev1_sa(raw_ike)
            rows = list(parsed_v1.get("transforms") or [])
            if not rows and parsed_v1.get("encryption"):
                rows = [parsed_v1]
            for row in rows:
                clear_sa += 1
                enc = row.get("encryption")
                keylen = row.get("key_length")
                if enc:
                    enc_seen[_normalize_enc(enc, keylen) or str(enc)] += 1
                if row.get("auth_method"):
                    auth_seen[str(row["auth_method"])] += 1
                if row.get("hash"):
                    hash_seen[str(row["hash"])] += 1
                gid = _dh_id(row.get("dh_group"))
                if gid is not None:
                    dh_seen[gid] += 1
                life = row.get("lifetime")
                if isinstance(life, int):
                    lifetimes.append(life)

        if major == 2:
            parsed_v2 = parse_ikev2_sa(raw_ike)
            for prop in parsed_v2.get("proposals") or []:
                for t in prop.get("transforms") or []:
                    clear_sa += 1
                    ttype = t.get("type")
                    name = t.get("name")
                    if ttype == 1 and name:
                        enc_seen[_normalize_enc(name, t.get("key_length")) or name] += 1
                    elif ttype == 3 and name:
                        hash_seen[str(name)] += 1
                    elif ttype == 2 and name:
                        auth_seen[f"PRF {name}"] += 1
                    elif ttype == 4 and t.get("id") is not None:
                        dh_seen[int(t["id"])] += 1

    def pick(counter: Counter):
        if not counter:
            return not_detected("No cleartext SA transform observed")
        value, _ = counter.most_common(1)[0]
        return detected(value, {"all_observed": list(counter.keys())})

    dh_param = not_detected("No Group Description / DH transform in cleartext")
    if dh_seen:
        gid, _ = dh_seen.most_common(1)[0]
        dh_param = detected(
            gid,
            {"name": DH_GROUPS.get(gid, f"group {gid}"), "weak": gid in WEAK_DH},
        )

    life_param = not_detected("Lifetime not present in cleartext SA")
    if lifetimes:
        life_param = detected(lifetimes[0], {"unit": "seconds", "all_observed": lifetimes})

    # PFS / encapsulation mode live in Quick Mode / Child SA, often encrypted.
    pfs = not_detected(
        "PFS is negotiated on Child SA / Quick Mode; those payloads were absent or encrypted"
    )
    mode = not_detected("Tunnel vs transport is in IPsec (ESP) proposals, not in the IKE SA header")

    version_label = None
    if 1 in versions and 2 in versions:
        version_label = "IKEv1 and IKEv2"
    elif 1 in versions:
        version_label = "IKEv1"
    elif 2 in versions:
        version_label = "IKEv2"

    return {
        "present": bool(messages),
        "version": detected(version_label) if version_label else not_detected("No ISAKMP/IKE packets"),
        "ikev1_packet_count": versions.get(1, 0),
        "ikev2_packet_count": versions.get(2, 0),
        "exchange_types": dict(exchanges),
        "encrypted_ike_packets": encrypted_ike,
        "cleartext_sa_payloads_parsed": clear_sa,
        "messages": messages[:40],
        "parameters": {
            "encryption": pick(enc_seen),
            "authentication": pick(auth_seen),
            "integrity": pick(hash_seen),
            "dh_group": dh_param,
            "lifetime_seconds": life_param,
            "pfs": pfs,
            "mode": mode,
            "replay_protection": not_detected(
                "Replay window / ESN was not confirmed from this capture"
            ),
        },
        "evidence": {"ikev1": evidence_v1[:50], "ikev2": evidence_v2[:50]},
        "weak_encryption_observed": [e for e in enc_seen if e in WEAK_ENC or e.startswith("DES")],
        "weak_dh_observed": [g for g in dh_seen if g in WEAK_DH],
        "weak_integrity_observed": [
            h
            for h in hash_seen
            if str(h).upper() in WEAK_HASH or str(h).upper().startswith("HMAC-MD5") or str(h).upper().startswith("HMAC-SHA1") or str(h) == "SHA"
        ],
        "aes_cbc_observed": [e for e in enc_seen if "AES-CBC" in str(e).upper()],
        "aes_gcm_observed": [e for e in enc_seen if "AES-GCM" in str(e).upper()],
        "aes_128_observed": [e for e in enc_seen if "AES" in str(e).upper() and "128" in str(e)],
        "aes_256_observed": [e for e in enc_seen if "AES" in str(e).upper() and "256" in str(e)],
    }
