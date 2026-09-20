#!/usr/bin/env python3
"""hsm-forensic-capture.py — capture the firmware's framed trace off the Debug Probe's UART.

    hsm-forensic-capture.py <seconds> <outfile> [device] [baud]

WHY THIS EXISTS INSTEAD OF `stty` + `cat`.

`stty` does not reliably apply CDC line coding to the Raspberry Pi Debug Probe's UART bridge on
macOS. The port opens, `cat` returns bytes, and everything looks healthy — but the probe's UART runs
at whatever rate it was last left at, not the one requested, so the bytes are a mis-clocked read of
a real signal.

MEASURED 2026-08-09, same firmware, same wiring, same keygen:

    stty + cat       ~2800 bytes,  0-7 syncs,   0 records   at EVERY baud 19200..230400
    pyserial         35074 bytes,  935 syncs,   947 records, 0 rejected, lost_total 0

The tell was that the byte count did not change with baud. A stream whose framing the host controls
cannot deliver the same volume at 19200 and 230400; that only happens when the host's setting is
not reaching the device at all. That single misreading produced a day of wrong conclusions — a
"probe degrades from DUT power cuts" finding with a measured table behind it, a floating-pin
theory, and two hardware purchase recommendations, all retracted.

pyserial issues an explicit CDC SET_LINE_CODING and asserts DTR/RTS, which is what actually
configures the bridge.

Exits non-zero if nothing was captured, so a caller cannot mistake an empty file for a quiet bus.
"""
import signal, sys, time

try:
    import serial
except ImportError:
    sys.stderr.write(
        "pyserial is required (the ceremony venv has it):\n"
        "  ~/.local/share/akash-hsm-venv/bin/pip install pyserial\n"
        "Do NOT fall back to stty+cat — it silently mis-clocks this bridge.\n")
    sys.exit(2)


def find_device():
    import glob
    c = sorted(glob.glob("/dev/cu.usbmodem*"))
    return c[0] if c else None


def main():
    secs = float(sys.argv[1]) if len(sys.argv) > 1 else 20.0
    out = sys.argv[2] if len(sys.argv) > 2 else "trace.bin"
    dev = sys.argv[3] if len(sys.argv) > 3 else find_device()
    baud = int(sys.argv[4]) if len(sys.argv) > 4 else 115200
    if not dev:
        sys.stderr.write("no /dev/cu.usbmodem* found — is the Debug Probe attached?\n")
        return 2

    s = serial.Serial(dev, baud, timeout=0.2, rtscts=False, dsrdtr=False)
    s.dtr = True
    s.rts = True
    s.reset_input_buffer()
    end = time.time() + secs
    buf = bytearray()

    # SIGTERM MUST NOT DISCARD THE TRACE. The caller stops this process once the cut has happened,
    # and Python does NOT run `finally` on a default SIGTERM — the process dies where it stands.
    # Two full experiment runs lost their entire trace that way: the file simply never appeared, and
    # the run still printed a confident INCOMPLETE. Turn the signal into a loop exit so the bytes
    # captured before the cut — which are the evidence — get written.
    stop = {"now": False}
    def _stop(signum, frame):
        stop["now"] = True
    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGINT, _stop)
    # THE DEVICE DISAPPEARING IS THE EXPECTED ENDING, NOT AN ERROR.
    #
    # This captures across a deliberate power cut: the DUT vanishes mid-read and pyserial raises.
    # An earlier version wrote the file only after the loop, so the exception propagated and the
    # entire trace — every byte captured BEFORE the cut, which is the whole evidence — was lost.
    # The bytes up to the cut are the point; the cut is just where they stop.
    # STREAM TO DISK, DO NOT BUFFER TO THE END. A caller needs to inspect the trace WHILE it is
    # being captured — the experiment peeks at it to verify the channel is delivering before it
    # spends a destructive run. Buffering until close made that peek read an empty file and the
    # run refused itself. Streaming also means an unexpected death keeps everything up to it.
    total = 0
    fh = open(out, "wb", buffering=0)
    try:
        while time.time() < end and not stop["now"]:
            try:
                d = s.read(8192)
            except (serial.SerialException, OSError) as e:
                sys.stderr.write(f"device went away ({e.__class__.__name__}) — keeping {total} bytes\n")
                break
            if d:
                fh.write(d)
                total += len(d)
                buf += d
    finally:
        try:
            fh.flush(); fh.close()
        except Exception:
            pass
        try:
            s.close()
        except Exception:
            pass
    syncs = bytes(buf).count(b"\xa5")
    sys.stderr.write(f"captured {len(buf)} bytes, {syncs} sync bytes -> {out}\n")
    return 0 if buf else 1


if __name__ == "__main__":
    sys.exit(main())
