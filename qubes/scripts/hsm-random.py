#!/usr/bin/env python3
"""hsm-random.py — read random bytes from an attached SmartCard-HSM (Nitrokey HSM 2 or Pico HSM).

  hsm-random.py --out hsm.bin            # 32 bytes from the first HSM that answers
  hsm-random.py --out hsm.bin --bytes 32 --reader Pico

Talks to the chip directly over PC/SC: SELECT the SmartCard-HSM application, then ISO 7816
GET CHALLENGE (00 84 00 00 20), which returns bytes from the token's hardware random number
generator. No PIN is involved. It deliberately does NOT go through OpenSC/pkcs11-tool: on the
bench (2026-09-25) `pkcs11-tool -L` stalled on a Pico HSM until the device stopped answering
USB at all, while the same two commands sent directly returned fresh bytes from both the Pico
and a Nitrokey HSM 2 every time.

Before writing, it checks what it can about the bytes without trusting them: the status word,
the length, not all-zero, and two reads that differ (a stuck generator or a replayed answer
fails that). It proves nothing about quality; that is why its output is only ever one input to
entropy-mix.py, next to dice and /dev/urandom.
"""
import argparse
import os
import sys

SELECT_SC_HSM = [0x00, 0xA4, 0x04, 0x00, 0x0B,
                 0xE8, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x81, 0xC3, 0x1F, 0x02, 0x01]
HSM_NAMES = ("nitrokey hsm", "smartcard-hsm", "pico")


def get_challenge(conn, n):
    data, sw1, sw2 = conn.transmit([0x00, 0x84, 0x00, 0x00, n])
    if (sw1, sw2) != (0x90, 0x00) or len(data) != n:
        raise RuntimeError("GET CHALLENGE answered %d bytes, SW %02X%02X" % (len(data), sw1, sw2))
    return bytes(data)


def read_random(conn, n):
    """n random bytes from an already-connected SmartCard-HSM, with the sanity checks."""
    _, sw1, sw2 = conn.transmit(SELECT_SC_HSM)
    # 9000, or 61xx ("xx more bytes of FCI available"), which the Pico answers
    if not (sw1 == 0x90 and sw2 == 0x00) and sw1 != 0x61:
        raise RuntimeError("SELECT SmartCard-HSM refused: SW %02X%02X" % (sw1, sw2))
    first, second = get_challenge(conn, n), get_challenge(conn, n)
    if first == bytes(n) or second == bytes(n):
        raise RuntimeError("the generator returned all zeros")
    if first == second:
        raise RuntimeError("two reads returned the same bytes: a stuck generator or a replay")
    return first


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", required=True)
    ap.add_argument("--bytes", type=int, default=32)
    ap.add_argument("--reader", help="substring of the reader name (default: first HSM that answers)")
    a = ap.parse_args()
    if not 16 <= a.bytes <= 255:
        sys.exit("hsm-random: --bytes must be 16..255")
    try:
        from smartcard.System import readers
    except ImportError as exc:
        sys.exit("hsm-random: pyscard not available (%s)" % exc)
    candidates = [r for r in readers()
                  if any(k in str(r).lower() for k in HSM_NAMES)
                  and (a.reader is None or a.reader.lower() in str(r).lower())]
    if not candidates:
        sys.exit("hsm-random: no Nitrokey HSM / Pico HSM reader found")
    errors = []
    for r in candidates:
        try:
            conn = r.createConnection()
            conn.connect()
            data = read_random(conn, a.bytes)
            conn.disconnect()
        except Exception as exc:          # try the next HSM; report every failure if none works
            errors.append("%s: %s" % (str(r)[:48], exc))
            continue
        fd = os.open(a.out, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
        print("hsm-random: %d bytes from %s" % (len(data), str(r).strip()))
        return
    sys.exit("hsm-random: no HSM returned random bytes:\n  " + "\n  ".join(errors))


if __name__ == "__main__":
    main()
