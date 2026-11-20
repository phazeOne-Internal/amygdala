# Global IoT cybersecurity regulation — what firmware review can evidence

The product is sold globally, so tag findings with the regulations they affect (`references` field) and call out market-access blockers. This is engineering guidance, not legal advice: say so in the report, and recommend that the compliance owner confirm the applicability and current dates. These rules change. The status below is as known at the time this skill was written; if the user has newer information, use theirs.

## The regimes that matter most

| Regime | Scope | Status (verify) | Firmware-relevant core requirements |
|---|---|---|---|
| **EU Cyber Resilience Act (CRA)**, Regulation (EU) 2024/2847 | Products with digital elements placed on the EU market | In force Dec 2024; vulnerability and incident reporting obligations apply from 11 Sep 2026; main obligations from 11 Dec 2027 | Secure by default config; no known exploitable vulnerabilities at release; protection from unauthorised access; confidentiality and integrity of data (encryption); data minimisation; security updates (automatic where possible, separable from feature updates) for the support period; attack surface minimisation; logging of security-relevant events; SBOM; vulnerability handling process |
| **EU Radio Equipment Directive Delegated Act (EU) 2022/30**, harmonised standards **EN 18031-1/-2/-3** | Internet-connected radio equipment (Wi-Fi, BLE, cellular) on the EU market | Mandatory since 1 Aug 2025 (to be superseded by CRA) | Network protection (‑1), personal data protection (‑2), fraud/financial (‑3). Authentication mechanisms, no default passwords, secure update, secure storage and communication of credentials, access control, resilience to DoS |
| **UK PSTI Act 2022** + Product Security regulations 2023 | Consumer connectable products sold in the UK | In force since 29 Apr 2024 | (1) No universal default passwords — passwords unique per device or user-defined; (2) published vulnerability disclosure policy / point of contact; (3) published minimum security update support period |
| **ETSI EN 303 645** | Consumer IoT baseline standard (referenced by PSTI, Singapore, Australia, many schemes) | Current v3.x | 13 provisions: 5.1 no universal default passwords; 5.2 vulnerability reporting; 5.3 keep software updated (secure, authenticated updates); 5.4 securely store sensitive security parameters (no hardcoded critical secrets); 5.5 communicate securely; 5.6 minimise exposed attack surfaces (disable debug interfaces, unused services); 5.7 ensure software integrity (secure boot); 5.8 personal data protection; 5.9 resilience to outages; 5.10 telemetry; 5.11 easy deletion of user data; 5.12 easy installation; 5.13 validate input data |
| **US FCC Cyber Trust Mark** (voluntary labelling, based on **NIST IR 8425**) and **NIST IR 8259A/B** | Consumer IoT in the US | Voluntary programme; status of the programme should be checked | Device identification, product configuration, data protection, interface access control, software update, cybersecurity state awareness (logging) |
| **US state laws** — California SB-327, Oregon HB 2395 | Connected devices sold in those states | In force since 2020 | "Reasonable security features"; preshared passwords must be unique per device, or the user must set a new one on first use |
| **Australia Cyber Security Act 2024** — smart device security standard | Consumer smart devices supplied in Australia | Applies from 4 Mar 2026 | Mirrors PSTI: no universal default passwords, vulnerability disclosure, stated support period |
| **Singapore Cybersecurity Labelling Scheme (CLS)** | Consumer IoT; mandatory for Wi-Fi routers and smart home hubs, voluntary otherwise | In force | Levels 1–4 built on ETSI EN 303 645, plus penetration testing at higher levels |
| **Japan JC-STAR** | IoT products labelling scheme | Started 2025 | ★1 baseline aligned with ETSI EN 303 645 / NIST IR 8425 |
| **Industrial / B2B**: IEC 62443-4-1 / 4-2 | Industrial components | Standard | Secure development lifecycle (4-1), component security levels (4-2) — relevant if the product goes into industrial settings |
| **Privacy**: GDPR (EU/UK), CCPA/CPRA (California), PIPL (China), LGPD (Brazil) etc. | Any personal data | In force | Data minimisation, encryption, deletion on request / factory reset, transparency |

Sector rules may also apply (medical: FDA premarket cybersecurity guidance, EU MDR; automotive: UN R155/R156; payments: PCI). Mention them only if the product evidently falls in that sector.

## Mapping findings to regulation

Use these when filling the `references` field. Rate as the checklist says; the regulatory tag increases the priority when the issue is a **market-access blocker** (marked ★ below), because it can stop sales in a jurisdiction regardless of technical exploitability.

| Firmware evidence | Regulations affected |
|---|---|
| ★ Universal default password / fixed PIN / fixed BLE passkey / shared credential across units | UK PSTI §1, EN 303 645 5.1, EN 18031-1, CRA Annex I, CA SB-327, Australia standard |
| ★ No secure update mechanism, or updates not authenticated | EN 303 645 5.3, CRA Annex I, EN 18031-1, NIST IR 8425 |
| ★ Hardcoded critical secrets (private keys, shared keys) | EN 303 645 5.4, EN 18031-1/-2, CRA Annex I |
| ★ Unencrypted communication of credentials / personal data | EN 303 645 5.5, EN 18031-1/-2, CRA Annex I, GDPR Art. 32 |
| Known exploitable vulnerabilities in dependencies at release | CRA Annex I (no known exploitable vulnerabilities), EN 303 645 5.3 |
| No secure boot / integrity check | EN 303 645 5.7, CRA Annex I |
| Debug interfaces / unused services exposed | EN 303 645 5.6, CRA Annex I (attack surface), EN 18031-1 |
| Input not validated (parsers, protocol handlers) | EN 303 645 5.13, CRA Annex I |
| No resilience to network/power outage | EN 303 645 5.9, EN 18031-1 (DoS resilience) |
| No security logging / telemetry | EN 303 645 5.10, CRA Annex I, NIST IR 8425 (state awareness) |
| Factory reset doesn't delete user data | EN 303 645 5.11, CRA Annex I, GDPR |
| Excessive personal data collected | EN 303 645 5.8, EN 18031-2, CRA Annex I, GDPR |
| No SBOM producible | CRA Annex I Part II |

## Process items that code can't prove

These are required by several regimes but live outside the firmware. Raise one consolidated finding (category `regulatory`, `confidence: needs-verification`, Amber) listing those you found no evidence for, and the evidence that would close each:

- Vulnerability disclosure policy and contact point (PSTI, CRA, EN 303 645 5.2, Australia).
- Published security support period (PSTI, CRA, Australia).
- SBOM generation in the build/release process (CRA).
- Vulnerability handling and reporting process — CRA requires actively exploited vulnerabilities and severe incidents to be reported to ENISA/CSIRTs within 24h (early warning) from 11 Sep 2026.
- Production provisioning: unique credentials per unit, debug lock / lifecycle transition at manufacturing.
- Technical documentation / conformity assessment (CRA, RED).

If the repo contains evidence for any of them (e.g. a `SECURITY.md`, an SBOM step in CI, a provisioning script), say so in the strengths.
