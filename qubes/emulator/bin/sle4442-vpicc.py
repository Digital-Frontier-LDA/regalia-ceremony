#!/usr/bin/env python3
"""sle4442-vpicc.py — a faithful SLE-4442 memory-card emulator exposed over PC/SC.

It speaks the vpcd <-> vpicc wire protocol (vsmartcard) so the emulated card shows
up through pcscd as a real reader+card. Any PC/SC application that drives an SLE-4442
the standard way — the PC/SC "memory card" pseudo-APDU set (CLA=0xFF) used by ACS /
SCM / Identiv readers — talks to this emulator byte-for-byte as it would the chip.

What is modelled (per the Infineon/Siemens SLE 4442 datasheet):
  * 256-byte main memory.
  * 32-bit protection memory (PROM): one write-once lock bit per byte of main[0..31];
    once a byte is locked it can never be rewritten.
  * 4-byte security memory: byte0 = error counter (0x07 = 3 attempts left; a wrong PSC
    clears one bit; 0x00 = card permanently locked), bytes1..3 = the 3-byte PSC
    (write-only — reads back as 0xFF). A correct PSC restores the counter to 0x07.
  * Writes (UPDATE main memory, WRITE protection, CHANGE PSC) require a prior successful
    PSC verification in the same session, exactly like the chip's "processing" gate.

vpcd protocol (see vsmartcard docs): 2-byte big-endian length prefix, then payload.
Control payloads from vpcd: 0x00 power-off, 0x01 power-on, 0x02 reset, 0x04 get-ATR.
Everything else is a C-APDU; we reply with a length-prefixed R-APDU. Get-ATR replies
with a length-prefixed ATR.

Usage (inside the emulator container; vpcd listens, we connect):
    sle4442-vpicc.py --port 35963 [--state /run/sle4442.state] [--psc FFFFFF]

This is a TEST/REHEARSAL emulator. It never holds a real key unless you put one there
on purpose for a drill; treat its state file as throwaway.
"""
import argparse
import os
import signal
import socket
import struct
import sys
import time

# ATR a typical PC/SC reader synthesises for an SLE4442 (memory card). The exact bytes
# vary by reader; this is the widely-seen SLE4442 ATR. PC/SC apps key off card *type*
# via the FF A4 SELECT pseudo-APDU, not the ATR, so any plausible ATR is fine.
ATR = bytes.fromhex("3B0492231091")

CARD_TYPE_SLE4442 = 0x06  # PC/SC "select card type" value for SLE4442

SW_OK = b"\x90\x00"
SW_NO_AUTH = b"\x69\x82"          # security status not satisfied
SW_WRONG_LEN = b"\x67\x00"
SW_WRONG_P1P2 = b"\x6b\x00"
SW_LOCKED = b"\x69\x83"           # authentication method blocked
SW_INS_UNSUPPORTED = b"\x6d\x00"
SW_CLA_UNSUPPORTED = b"\x6e\x00"


class SLE4442:
    """Pure software model of the SLE4442 chip state + PC/SC pseudo-APDU handling."""

    MAIN_SIZE = 256
    PROTECTED_BYTES = 32  # main[0..31] are lockable via the 32-bit protection memory

    def __init__(self, psc=b"\xff\xff\xff", state_path=None):
        self.state_path = state_path
        self.main = bytearray(self.MAIN_SIZE)
        # Factory data lives in the first bytes on a real card; seed a recognisable
        # pattern so a fresh emulated card isn't all-zero (and reads are observable).
        self.main[0:6] = bytes.fromhex("A2131091FFFF")
        self.protection = bytearray(b"\xff\xff\xff\xff")  # 1 bit/byte, 1 = unlocked
        self.error_counter = 0x07                          # 3 attempts left
        self.psc = bytes(psc)
        self.authenticated = False
        self._load()

    # ---- persistence (so a multi-step ceremony drill survives card re-power) -------
    def _load(self):
        if not self.state_path or not os.path.exists(self.state_path):
            return
        try:
            with open(self.state_path, "rb") as fh:
                blob = fh.read()
            # layout: main(256) protection(4) errctr(1) psc(3)
            if len(blob) >= 264:
                self.main = bytearray(blob[0:256])
                self.protection = bytearray(blob[256:260])
                self.error_counter = blob[260]
                self.psc = bytes(blob[261:264])
        except Exception:
            pass

    def _save(self):
        if not self.state_path:
            return
        try:
            blob = bytes(self.main) + bytes(self.protection) + bytes([self.error_counter]) + bytes(self.psc)
            # The state file holds the card's memory (a stored share) and the PSC — write it
            # 0600 so it is never world/group-readable on disk.
            tmp = self.state_path + ".tmp"
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            try:
                # O_CREAT's mode is IGNORED if the .tmp already exists (leftover/planted),
                # so fchmod to 0600 BEFORE writing the card memory + PSC, not after.
                os.fchmod(fd, 0o600)
                os.write(fd, blob)
            finally:
                os.close(fd)
            os.replace(tmp, self.state_path)
        except Exception:
            pass

    # ---- chip events ---------------------------------------------------------------
    def power_on_reset(self):
        # A card reset clears the volatile "authenticated" gate (PSC must be re-presented).
        self.authenticated = False

    def _byte_locked(self, addr):
        if addr >= self.PROTECTED_BYTES:
            return False
        return ((self.protection[addr // 8] >> (addr % 8)) & 1) == 0

    # ---- PC/SC pseudo-APDU dispatch (CLA = 0xFF) -----------------------------------
    def apdu(self, apdu: bytes) -> bytes:
        if len(apdu) < 4:
            return SW_WRONG_LEN
        cla, ins, p1, p2 = apdu[0], apdu[1], apdu[2], apdu[3]
        if cla != 0xFF:
            return SW_CLA_UNSUPPORTED
        # ISO 7816 short-APDU framing: byte 4 (if present) is P3 — Lc for command-data
        # cases (write/verify) or Le for response-data cases (read). The data field, when
        # present, follows P3.
        p3 = apdu[4] if len(apdu) >= 5 else None
        # Command DATA is exactly Lc (=P3) bytes for case-3 commands — honour it rather than
        # trusting everything after byte 5, so a malformed APDU can't write trailing bytes.
        if p3 is not None:
            data = apdu[5:5 + p3]
            short = len(apdu[5:]) < p3       # fewer data bytes than Lc declared
        else:
            data = b""
            short = False

        # SELECT CARD TYPE — FF A4 00 00 01 <type>
        if ins == 0xA4:
            if p3 == 0x01 and len(data) >= 1:
                return SW_OK if data[0] == CARD_TYPE_SLE4442 else SW_WRONG_P1P2
            return SW_WRONG_LEN

        # READ MAIN MEMORY — FF B0 00 <addr> <le>
        if ins == 0xB0:
            addr = p2
            le = p3 if p3 else 0
            if le == 0:
                le = self.MAIN_SIZE - addr
            if addr + le > self.MAIN_SIZE:
                return SW_WRONG_P1P2
            return bytes(self.main[addr:addr + le]) + SW_OK

        # READ PROTECTION MEMORY — FF B2 00 00 04
        if ins == 0xB2:
            return bytes(self.protection) + SW_OK

        # READ SECURITY MEMORY — FF B1 00 00 04 (error counter + PSC; PSC reads as FF)
        if ins == 0xB1:
            return bytes([self.error_counter, 0xFF, 0xFF, 0xFF]) + SW_OK

        # PRESENT/VERIFY PSC — FF 20 00 00 03 <psc>
        if ins == 0x20:
            body = data
            if p3 != 3 or len(body) != 3:
                return SW_WRONG_LEN
            if self.error_counter == 0x00:
                return SW_LOCKED
            if bytes(body) == self.psc:
                self.error_counter = 0x07
                self.authenticated = True
                self._save()
                return SW_OK
            # wrong PSC: clear one error-counter bit (decrement remaining attempts).
            # SLE4442 clears from the high bit down, so the counter steps
            # 0x07 -> 0x03 -> 0x01 -> 0x00 (matches PC/SC reader datasheets).
            self.authenticated = False
            for bit in (2, 1, 0):
                if (self.error_counter >> bit) & 1:
                    self.error_counter &= ~(1 << bit)
                    break
            self._save()
            remaining = bin(self.error_counter & 0x07).count("1")
            return bytes([0x63, 0xC0 | remaining])  # 63 Cx = wrong, x attempts left

        # UPDATE MAIN MEMORY — FF D0 00 <addr> <lc> <data>  (needs auth)
        if ins == 0xD0:
            if not self.authenticated:
                return SW_NO_AUTH
            if short:
                return SW_WRONG_LEN
            addr = p2
            if addr + len(data) > self.MAIN_SIZE:
                return SW_WRONG_P1P2
            # ATOMIC: reject the whole write if ANY target byte is permanently locked, so a
            # locked byte mid-range cannot leave a partial modification behind.
            if any(self._byte_locked(addr + i) for i in range(len(data))):
                return SW_NO_AUTH
            for i, byte in enumerate(data):
                self.main[addr + i] = byte
            self._save()
            return SW_OK

        # WRITE PROTECTION MEMORY — FF D1 00 <addr> <lc> <data> (lock bytes; needs auth)
        if ins == 0xD1:
            if not self.authenticated:
                return SW_NO_AUTH
            addr = p2
            for i in range(len(data)):
                target = addr + i
                if target < self.PROTECTED_BYTES:
                    # locking is write-once: only clears bits, never restores them
                    self.protection[target // 8] &= ~(1 << (target % 8))
            self._save()
            return SW_OK

        # CHANGE PSC — FF D2 00 00 03 <new psc> (needs auth)
        if ins == 0xD2:
            if not self.authenticated:
                return SW_NO_AUTH
            if p3 != 3 or len(data) != 3:
                return SW_WRONG_LEN
            self.psc = bytes(data)
            self._save()
            return SW_OK

        return SW_INS_UNSUPPORTED


# --------------------------------------------------------------------------------------
# vpcd wire protocol
# --------------------------------------------------------------------------------------
def _recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return None
        buf += chunk
    return buf


def _recv_msg(sock):
    hdr = _recv_exact(sock, 2)
    if hdr is None:
        return None
    (length,) = struct.unpack(">H", hdr)
    if length == 0:
        return b""
    return _recv_exact(sock, length)


def _send_msg(sock, payload):
    sock.sendall(struct.pack(">H", len(payload)) + payload)


def serve(card, host, port, listen, log):
    while True:
        try:
            if listen:
                srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                srv.bind((host, port))
                srv.listen(1)
                log(f"listening for vpcd on {host}:{port}")
                conn, _ = srv.accept()
                srv.close()
            else:
                conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                conn.connect((host, port))
                log(f"connected to vpcd at {host}:{port}")
        except OSError as exc:
            log(f"connect/listen failed ({exc}); retrying in 1s")
            time.sleep(1)
            continue

        try:
            _session(card, conn, log)
        except (ConnectionError, OSError) as exc:
            log(f"session ended ({exc})")
        finally:
            try:
                conn.close()
            except OSError:
                pass
        if not listen:
            time.sleep(1)  # vpcd dropped us; reconnect


# INS whose command DATA field carries a secret (must never be logged in clear):
#   0x20 VERIFY PSC, 0xD0 UPDATE/WRITE (the stored share), 0xD2 CHANGE PSC.
_SECRET_CMD_INS = {0x20, 0xD0, 0xD2}


def _redact(n):
    return f"<redacted:{n}B>"


def log_line(apdu, resp):
    """Return a log-safe one-line description of an APDU exchange. The card holds and moves
    SECRETS (the PSC, and whatever share/seed bytes you store in memory), so this NEVER puts
    a command's secret data field or a memory-read's response body into the log — only the
    non-secret header (CLA/INS/P1/P2/Lc) and status word. This is the in-logs guarantee."""
    if len(apdu) < 4:
        return f"APDU <malformed:{len(apdu)}B> -> {resp[-2:].hex() if len(resp) >= 2 else resp.hex()}"
    cla, ins = apdu[0], apdu[1]
    # --- command side ---
    if cla == 0xFF and ins in _SECRET_CMD_INS:
        header = apdu[:5].hex()            # CLA INS P1 P2 Lc — addresses/lengths, no secret
        cstr = f"{header} {_redact(max(0, len(apdu) - 5))}"
    else:
        cstr = apdu.hex()                  # SELECT / read-counter / read-protection: no secret
    # --- response side: a main-memory READ (0xB0) returns stored secret bytes ---
    if cla == 0xFF and ins == 0xB0 and len(resp) > 2:
        rstr = f"{_redact(len(resp) - 2)} {resp[-2:].hex()}"
    else:
        rstr = resp.hex()
    return f"APDU {cstr} -> {rstr}"


def _session(card, conn, log):
    while True:
        msg = _recv_msg(conn)
        if msg is None:
            return
        if len(msg) == 1:
            ctrl = msg[0]
            if ctrl == 0x00:
                log("power off")
            elif ctrl == 0x01:
                log("power on")
                card.power_on_reset()
            elif ctrl == 0x02:
                log("reset")
                card.power_on_reset()
            elif ctrl == 0x04:
                _send_msg(conn, ATR)
            else:
                # single-byte APDU is technically possible; fall through to handler
                resp = card.apdu(msg)
                _send_msg(conn, resp)
            continue
        resp = card.apdu(msg)
        log(log_line(msg, resp))           # redacted: never logs PSC / stored / read secrets
        _send_msg(conn, resp)


def main(argv=None):
    ap = argparse.ArgumentParser(description="SLE4442 PC/SC memory-card emulator (vpicc)")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=35963)
    ap.add_argument("--listen", action="store_true",
                    help="listen for vpcd instead of connecting to it")
    ap.add_argument("--psc", default=None,
                    help="initial 3-byte PSC in hex. PREFER the SLE4442_EMU_PSC env var so a "
                         "real PSC never appears on argv / in ps / in shell history. (default FFFFFF)")
    ap.add_argument("--state", default=None, help="persist card state to this file")
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args(argv)

    # Env wins over argv so a real PSC is not exposed in the process listing.
    psc_hex = os.environ.get("SLE4442_EMU_PSC", args.psc or "FFFFFF")
    psc = bytes.fromhex(psc_hex)
    if len(psc) != 3:
        ap.error("PSC must be exactly 3 bytes (6 hex chars)")

    def log(msg):
        if not args.quiet:
            sys.stderr.write(f"[sle4442] {msg}\n")
            sys.stderr.flush()

    card = SLE4442(psc=psc, state_path=args.state)
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
    serve(card, args.host, args.port, args.listen, log)


if __name__ == "__main__":
    main()
