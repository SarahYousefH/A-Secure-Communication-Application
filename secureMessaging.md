# Student B Implementation Notes

## Required Theory

### ChaCha20 (Stream Cipher)
#### Purpose
To provide high-speed symmetric encryption for the secure communication application.

#### Core Concepts
* **State Layout:** Operates on a state consisting of 16 32-bit words arranged as a $4 \times 4$ matrix.
* **Parameters:** Uses a 256-bit key, 96-bit nonce, and 32-bit block counter.
* **Output:** Produces 64-byte blocks of pseudorandom keystream.

#### Algorithm
The cipher repeatedly applies the Quarter Round function using:
1. Addition modulo $2^{32}$
2. XOR operations
3. Constant-distance bit rotations

A fixed permutation is applied for 20 rounds (alternating between column rounds and diagonal rounds), and the resulting state is added to the original state to produce a keystream block.

#### RFC Reference
* RFC 8439 Section 2
* RFC 8439 Section 2.3

#### Common Implementation Mistakes
* **Endianness:** Incorrect little-endian byte ordering during initialization and serialization.
* **Counter Tracking:** Failure to increment the block counter between sequential blocks.
* **Constants:** Incorrect rotation constants (must strictly be 16, 12, 8, 7).

---

### Poly1305 (Authenticator)
#### Purpose
A one-time Message Authentication Code (MAC) used to ensure message integrity and authenticity.

#### Core Concepts
* **Mathematical Base:** Polynomial evaluation modulo the prime $2^{130} - 5$.
* **Key Setup:** Uses a 32-byte one-time key divided into two 16-byte parts:
  * `r` (used as the polynomial evaluation point)
  * `s` (used as a clearing/masking value)

#### Algorithm
1. Divide the input message into 16-byte blocks.
2. Clear/clamp specific bits of `r` to ensure security properties.
3. Treat each block as a coefficient in a polynomial.
4. Evaluate the polynomial modulo $2^{130} - 5$.
5. Add `s` to the final accumulator result to produce the authentication tag.

#### Security Considerations
The key pair `(r, s)` **must never be reused** across different messages. Reusing `r` across multiple messages allows an attacker to recover the authentication keys.

#### RFC Reference
* RFC 8439 Section 3

---

### ChaCha20-Poly1305 AEAD
#### Purpose
Provides authenticated encryption with associated data (AEAD), ensuring simultaneous confidentiality, integrity, and authenticity.

#### Algorithm
1. **Key Generation:** Generate a one-time Poly1305 key using ChaCha20 on an all-zero block (with counter set to 0).
2. **Encryption:** Encrypt the plaintext using ChaCha20 starting at block counter 1.
3. **MAC Construction:** Construct uniform MAC input format:
   ```text
   AAD | Padding | Ciphertext | Padding | AAD Length | Ciphertext Length
