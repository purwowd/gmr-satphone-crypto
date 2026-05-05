# Example (Synthetic) Satphone Payloads

This folder contains **synthetic example data** to demonstrate the crypto PoC:

- **Not** RF intercept output / real communications
- All ciphertext is produced by encrypting local plaintext using `gmr1_cipher.py` / `gmr2_cipher.py`
- Goal: show the “decoder artifacts” format and how to “decode” (XOR keystream) using the bridge script

## Contents

| File | Purpose |
|------|---------|
| `generate_examples.py` | Regenerates all example files (plaintext, ciphertext, artifact JSON) |
| `gmr1_artifacts.json` | Example artifact for `scheme=gmr1` |
| `gmr2_artifacts.json` | Example artifact for `scheme=gmr2` |
| `gmr1_plaintext.txt` | Plaintext (pre-encryption) for the GMR-1 example |
| `gmr2_plaintext.txt` | Plaintext (pre-encryption) for the GMR-2 example |

## Run the decode demo

From the PoC root:

```bash
cd pocs/gmr_satphone_crypto

# Decode synthetic “ciphertext” (GMR-1)
python3 integrations/apply_from_decoder_artifacts.py example/gmr1_artifacts.json

# Decode synthetic “ciphertext” (GMR-2)
python3 integrations/apply_from_decoder_artifacts.py example/gmr2_artifacts.json
```

### Why is this “more realistic”?

- The **GMR-1** example uses a **208-bit cipher field** (`channel=tch3_speech`), so the demo operates at the **bit** level (closer to L1).
- Artifacts include `channel`, `nbits`, and `ciphertext_bits` in addition to hex `ciphertext`.
- Ciphertext is produced by XORing the PoC keystream with a deterministic plaintext bit pattern (reproducible).

### Independent cross-check (C keystream generator)

To strengthen PoC integrity, a **standalone C** implementation is included to generate a GMR-1 keystream (no Osmocom dependency):

```bash
cd pocs/gmr_satphone_crypto/integrations
cc -O2 -Wall -Wextra -o osmo_gmr_keystream osmo_gmr1_a5_standalone.c
./osmo_gmr_keystream --kc 0123456789abcdef --fn 0x1a2b3 --nbits 208 | head
```

Compare with Python:

```bash
cd pocs/gmr_satphone_crypto
python3 -c "import gmr1_cipher as g1; print(''.join(map(str,g1.keystream_bits(bytes.fromhex('0123456789abcdef'),0x1a2b3,208))))" | head
```

Output will include:

- `keystream_head_hex` (sanity check)
- `plaintext_hex`
- `plaintext_utf8` if valid UTF-8

## Regenerate examples

```bash
cd pocs/gmr_satphone_crypto/example
python3 generate_examples.py
```

