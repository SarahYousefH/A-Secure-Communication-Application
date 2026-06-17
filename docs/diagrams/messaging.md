# Phase B — Secure Messaging

Authenticated encryption loop. Runs after handshake completes.

## Sending a Message

```
SENDER SIDE
───────────

1. Build plaintext header (not encrypted, but authenticated):
   header = {
       version:         "v1",
       message_type:    "chat",
       sender_id:       "client" | "server",
       sequence_number: N   ← strictly increasing
   }

2. Compute nonce:
   nonce = nonce_material XOR sequence_number
   (unique per message, never reused)

3. Encrypt and authenticate:
   ciphertext, tag = ChaCha20_Poly1305_encrypt(
       key             = key_send,
       nonce           = nonce,
       plaintext       = message,
       associated_data = header
   )

4. Send: [ header (plaintext) ][ ciphertext ][ tag ]
```

## Receiving a Message

```
RECEIVER SIDE
─────────────

1. Read and parse header

2. Replay check:
   sequence_number > last_seen?
   → NO  : reject — replayed message ✗
   → YES : continue ✓

3. Decrypt and verify:
   plaintext = ChaCha20_Poly1305_decrypt(
       key             = key_recv,
       nonce           = nonce,
       ciphertext      = ciphertext,
       tag             = tag,
       associated_data = header
   )

4. Tag valid?
   → NO  : reject — tampered message ✗
   → YES : display plaintext ✓

5. Update last_seen = sequence_number
```

## Full Conversation Flow

```
CLIENT                                        SERVER
──────                                        ──────

encrypt("hello!", seq=1)   ─────────────────► decrypt + verify seq=1
                                               display "hello!"

                           ◄─────────────────  encrypt("hi there!", seq=1)
decrypt + verify seq=1
display "hi there!"

encrypt("how are you?", seq=2) ─────────────► decrypt + verify seq=2

[attacker replays seq=1]   ─────────────────► seq=1 ≤ last_seen=2 → REJECTED ✗
```

## Security Properties

| Threat | Defense |
|--------|---------|
| Eavesdropping | ChaCha20 encryption |
| Tampering with message body | Poly1305 tag over ciphertext |
| Tampering with header | Header is AEAD associated data |
| Replay attack | Strictly increasing sequence numbers |
| Nonce reuse | Nonce derived from sequence number |
