# Beep demo (synthetic AFSK) — "hello, 1,2,3"

This demo generates a WAV file containing “beep” audio (AFSK 1200/2200 Hz in a Bell-202 style),
then demodulates and decodes it back into plaintext.

This is **not** GMR/Inmarsat PHY. It is a safe, end-to-end example to understand the concept:
“beep → bitstream → message”.

## Run

```bash
cd pocs/gmr_satphone_crypto/example/beep_afsk

# Create a WAV containing the message
python3 make_beep_wav.py --message "hello, 1,2,3" --out hello.wav

# Demod + decode from the WAV
python3 demod_decode_wav.py --in hello.wav
```

The output prints the recovered payload and CRC status.

