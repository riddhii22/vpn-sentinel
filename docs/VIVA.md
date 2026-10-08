# Viva — say this without notes

**What it is:** Upload a PCAP. We parse IKE/IPsec **headers**, apply YAML rules, show findings and a 0–100 score. We never decrypt ESP.

**IKEv1 vs IKEv2:** Two parsers. Version is the ISAKMP nibble (`0x10` vs `0x20`), not the filename. IKEv1 uses RFC 2409 TV attributes. IKEv2 uses RFC 7296 transform types.

**Why two parsers?** The bytes mean different things. Hunting `0x80 0x01` on both versions is wrong.

**Score:** `min(100, sum of finding points)`. IKEv1 is a **critical** finding worth **30**, so the band is **moderate**. That is intentional. Not CVSS. Not “AI score.”

**AI:** IsolationForest on ESP **size and timing**. Finding **ESP-ANOM** has score **0** and origin **ml_anomaly**. It is not YouTube, not a weak cipher, not IKE parsing.

**Did you decrypt?** No.

**What you did in Wireshark:** Confirmed C10 Main Mode AES-128/SHA/DH2 and C8 IKE_SA_INIT 3DES/SHA1. Dashboard contrast: C10 → IKE-001; C8 → ENC-001.

**What this is not:** Full SIH PS (~45% of that map). No traffic-type accuracy. No IPv6. C5/C6 are not true transport.
