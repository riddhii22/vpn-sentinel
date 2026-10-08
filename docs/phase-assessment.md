# Core IPsec security assessment (this phase)

This is **not** a rewrite of T-API-01, Phase 2 parsing, or the Phase 3 additive risk formula.

## IMPLEMENTED now (assessment completeness)

- Findings include `rule_id`, `detected_value`, `explanation`
- ENC-002: AES-CBC observed → **info, score 0** (acceptable; AEAD preferred)
- ENC-003: AES-GCM if observed → info, score 0
- HASH-001: SHA-1/MD5 when observed → medium, +10 (lab fixture; not in shipped samples)
- API aliases `pcap`, `overview`, `protocols` for a later React UI

## Risk formula (unchanged)

`min(100, sum(finding.score))` from YAML. PPT subtractive formula still **not** used (`docs/conflicts-ppt-requirements-repo.md` S3).

## NOT DETECTABLE on shipped samples

PFS, tunnel/transport, AES-GCM, UDP/4500, AH, DES
