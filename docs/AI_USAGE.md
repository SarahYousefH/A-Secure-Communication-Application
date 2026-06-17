# AI Usage Statement

**Course:** ENCS4320 – Applied Cryptography, Birzeit University, Term 1252

---

## Tools Used

Claude (Anthropic) was used during this project.

---

## What AI Helped With

| Task | AI Role |
|------|---------|
| Project structure and file layout | AI proposed directory structure, team agreed on it |
| Function stub interfaces | AI drafted signatures/docstrings; team reviewed and agreed before any implementation |
| `utilities/channel_setup.py` | AI wrote TCP socket boilerplate |
| `server.py` and `client.py` | AI wrote thin orchestrator structure and argparse setup |
| `tests/run_tests.py` | AI wrote test runner scaffold |
| Test vector JSON format | AI designed the JSON schema; values were sourced from RFCs by the team |
| `docs/` diagrams and this file | AI wrote; team reviewed |
| Debugging and concept clarification | AI answered questions during implementation |

---

## What the Team Wrote Without AI

| File | Owner |
|------|-------|
| `primitives/sha256.py` | Student 1 — implemented from FIPS 180-4 |
| `primitives/hmac_impl.py` | Student 1 — implemented from RFC 2104 |
| `primitives/hkdf.py` | Student 1 — implemented from RFC 5869 |
| `primitives/x25519.py` | Student 1 — implemented from RFC 7748 |
| `protocol/handshake.py` | Student 1 — implemented from protocol spec |
| `primitives/chacha20.py` | Student 2 — implemented from RFC 8439 |
| `primitives/poly1305.py` | Student 2 — implemented from RFC 8439 |
| `primitives/aead.py` | Student 2 — implemented from RFC 8439 §2.8 |
| `protocol/channel.py` (incl. replay detection via `last_seen_seq_number`) | Student 2 — implemented from protocol spec |
| All `tests/*/test_*.py` | Respective student per primitive |
| Design report | Team — written without AI |

---
