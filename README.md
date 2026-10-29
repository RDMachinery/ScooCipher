# TraceCipher

A 256 bit key, authenticated stream cipher built around a simple visual transform: the **two-row trace**.

> **Not for real secrets.** The keystream generator is a new, unanalysed ARX design. It passes basic statistical checks, but that says nothing about resistance to serious cryptanalysis. For real use, choose ChaCha20-Poly1305 or AES-GCM.

---

## 1. The two-row trace

The transform was devised independently by the author while experimenting with data compression.

Write a row of random bits, and beneath it the same row inverted. For each data bit, step to the next column and land on whichever row holds that bit. The path traced across the two rows is the output, reading the top row as 0 and the bottom row as 1.

```
Random row:   1 0 1 1 0 0 1 0
Inverted:     0 1 0 0 1 1 0 1
Data:         0 1 1 0 1 0 0 1

Path:         _ _ / - \ _ _ / - \ _ _      (- top row, _ bottom row)
Output:       1 1 0 1 1 0 1 1
```

The path is on the top row exactly when the data bit equals the random bit, so

```
output_i = data_i ⊕ row_i
```

The trace is therefore a visual realisation of XOR. Applied with a keystream as the random row, it is the combining step of an additive (binary) stream cipher, and it is its own inverse: tracing the ciphertext across the same rows returns the plaintext.

The security of the scheme rests entirely on how the random rows are produced. TraceCipher produces them with a keyed pseudorandom function described below.

## 2. Construction overview

| Component | Choice |
|---|---|
| Key | 256 bits |
| Nonce | 64 bits, random per message |
| Block counter | 64 bits |
| Keystream generator | 512-bit ARX permutation, 20 rounds, feed-forward (ChaCha-style) |
| Combining step | Two-row trace (equivalent to XOR) |
| Authentication | HMAC-SHA256, encrypt-then-MAC, one-time MAC key from keystream block 0 |
| Message format | `nonce (8 bytes) ‖ ciphertext ‖ tag (32 bytes)` |

## 3. Keystream generator

### 3.1 State

The state is sixteen 32-bit words, arranged as a 4×4 matrix. Bytes are read into words little-endian.

```
 c0  c1  c2  c3          constants
 k0  k1  k2  k3          key, words 0–3
 k4  k5  k6  k7          key, words 4–7
 t0  t1  n0  n1          counter (low, high), nonce (2 words)
```

The constants are the ASCII string `two rows, trace!`:

```
c0 = 0x206f7774   c1 = 0x73776f72   c2 = 0x7274202c   c3 = 0x21656361
```

### 3.2 Mixing function

All arithmetic is on 32-bit words: ⊞ is addition mod 2³², ⊕ is XOR, and ⋘ is left rotation.

```
G(a, b, c, d):
    a ← a ⊞ b;   d ← (d ⊕ a) ⋘ 13
    c ← c ⊞ d;   b ← (b ⊕ c) ⋘ 7
    a ← a ⊞ b;   d ← (d ⊕ a) ⋘ 17
    c ← c ⊞ d;   b ← (b ⊕ c) ⋘ 11
```

The structure follows ChaCha's quarter-round; the rotation amounts differ (ChaCha uses 16, 12, 8, 7). These amounts were chosen without analysis.

### 3.3 Rounds

Ten double rounds (20 rounds) are applied to a copy x of the initial state s. Words are numbered 0–15 in reading order. Before double round r (r = 0 … 9):

```
x0 ← x0 ⊕ (0x9E3779B9 · (r + 1) mod 2³²)

Column round:    G(0,4,8,12)   G(1,5,9,13)   G(2,6,10,14)  G(3,7,11,15)
Diagonal round:  G(0,5,10,15)  G(1,6,11,12)  G(2,7,8,13)   G(3,4,9,14)
```

The round constant is not present in ChaCha; it was added to break the similarity between rounds.

### 3.4 Output

```
block = x ⊞ s     (word-wise, serialised little-endian → 64 bytes)
```

The feed-forward addition prevents the block function from being inverted to recover the key.

## 4. Encryption

1. Choose a random 64-bit nonce N.
2. MAC key: K_mac = first 32 bytes of block(K, N, counter = 0).
3. Keystream: block(K, N, 1) ‖ block(K, N, 2) ‖ …, truncated to the message length.
4. Ciphertext: trace each plaintext bit across the keystream row (C = P ⊕ keystream).
5. Tag: T = HMAC-SHA256(K_mac, N ‖ C).
6. Output N ‖ C ‖ T.

Decryption recomputes T over N ‖ C and compares it in constant time. If the tags differ, the message is rejected and nothing is decrypted. Otherwise the ciphertext is traced across the same keystream.

Reserving block 0 for the MAC key mirrors ChaCha20-Poly1305. Because the nonce has fixed length, N ‖ C is parsed unambiguously. There is no support for associated data.

## 5. Security notes and limitations

**What is claimed:** nothing beyond the generic argument. *If* the block function behaves as a PRF, the construction is a standard nonce-based stream cipher with encrypt-then-MAC, and inherits the corresponding security.

**What is not established:**

- **The block function is unanalysed.** No differential, linear, rotational or other cryptanalysis has been done on the modified rotation amounts or round constant. The reduced-round security margin is unknown.
- **Nonce collisions.** Nonces are 64 random bits, so a collision becomes likely after about 2³² messages under one key. A collision reuses the keystream and exposes P₁ ⊕ P₂. Rotate keys well before that point.
- **Side channels.** The reference implementation traces bit by bit with a data-dependent branch. Its timing may leak information about plaintext ⊕ keystream. It makes no constant-time claims.
- **Key handling.** Keys are stored as hexadecimal text files. There is no password-based key derivation.
- **Message length** is not hidden.

## 6. Empirical checks

The program's built-in demonstration runs these checks. They detect gross design errors but are not evidence of cryptographic strength.

| Check | Result |
|---|---|
| Trace equals XOR for all 65,536 byte pairs | 0 mismatches |
| Encrypt/decrypt round trip (text and file) | Correct |
| Same plaintext, two encryptions | Different ciphertexts |
| One ciphertext bit flipped | Rejected |
| Wrong key | Rejected |
| Key avalanche: 1 key bit flipped, 512-bit block, 2,000 trials | 49.97% bits changed (min 220, max 294) |
| Nonce avalanche: 1 nonce bit flipped, 2,000 trials | 50.02% bits changed (min 215, max 297) |
| Bit balance over 10,240,000 keystream bits | 50.0015% ones |

## 7. Running it

TraceCipher is a single Java file and needs Java 17 or later.

```
java TraceCipher.java demo                              # run the checks above
java TraceCipher.java keygen  secret.key                # make a random 256-bit key
java TraceCipher.java encrypt secret.key in.txt out.bin
java TraceCipher.java decrypt secret.key out.bin back.txt
```

## Author

Mario Gianota
