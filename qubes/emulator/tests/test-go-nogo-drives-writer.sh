#!/usr/bin/env bash
# test-go-nogo-drives-writer.sh — the `--need drives` gate must not GO on a pair of optical
# units that cannot BURN. A read-only DVD-ROM drive has a /dev/srN node just like a writer, so
# counting device nodes alone lets TWO DVD-ROM readers pass the gate — yet the M-DISC burn
# (growisofs -Z /dev/sr0) then fails mid-ceremony, when the operator has already been told the
# archive path is ready. The gate must probe write capability (the kernel's read-only
# /proc/sys/dev/cdrom/info table) and STOP when no attached drive advertises a DVD writer
# profile.
#
# Runs natively, no daemons: the optical device glob and the capability table are pointed at
# fixtures via GONOGO_OPTICAL_GLOB / GONOGO_CDROM_INFO (both default to the real values in
# production). We assert on the drives section only; preflight noise on a non-vault host is
# irrelevant to this check.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
GN="${CEREMONY_SCRIPTS:-$HERE/../../scripts}/go-nogo.sh"

pass=0; fail=0
P(){ printf '  \033[32mPASS\033[0m %s\n' "$1"; pass=$((pass+1)); }
F(){ printf '  \033[31mFAIL\033[0m %s\n' "$1"; fail=$((fail+1)); }
hdr(){ printf '\n\033[1m### %s\033[0m\n' "$1"; }

FAKE="$(mktemp -d)"
cleanup(){ rm -rf "$FAKE"; }
trap cleanup EXIT

# Two emulated optical device nodes (a reader and a writer both present a /dev/srN node).
mkdir -p "$FAKE/dev"
: > "$FAKE/dev/sr0"; : > "$FAKE/dev/sr1"
export GONOGO_OPTICAL_GLOB="$FAKE/dev/sr*"

# Kernel capability-table fixtures. A DVD writer advertises 'Can write DVD-R: 1'; a DVD-ROM
# reader advertises 'Can write DVD-R: 0'. Columns are one-per-attached-drive, tab-separated.
cat > "$FAKE/cdinfo-two-readers" <<'EOS'
CD-ROM information, Id: cdrom.c 3.20 2003/12/17

drive name:		sr1	sr0
Can write CD-R:		0	0
Can write DVD-R:	0	0
Can write DVD-RAM:	0	0
Can read DVD:		1	1
EOS
# A GENUINELY burnable pair: the ceremony hardcodes `growisofs -Z /dev/sr0`, so sr0 (the burn
# target) must itself be the writer. The kernel lists drives most-recently-added first, named by
# the 'drive name:' header row; here that maps sr0's column to the '1' in 'Can write DVD-R:'.
cat > "$FAKE/cdinfo-one-writer" <<'EOS'
CD-ROM information, Id: cdrom.c 3.20 2003/12/17

drive name:		sr1	sr0
Can write CD-R:		0	1
Can write DVD-R:	0	1
Can write DVD-RAM:	0	0
Can read DVD:		1	1
EOS

# DEFECT REPRO: sr0 is a read-only DVD-ROM reader, sr1 is the DVD/M-DISC writer. The kernel
# lists drives reversed vs /dev/srN, so the writer's '1' sits in sr1's column. A gate that only
# counts total '1's sees writers=1 and issues GO — but the ceremony burns to /dev/sr0 (the
# READER), so `growisofs -Z /dev/sr0` fails mid-ceremony. The gate must map the '1' back to the
# burn node and STOP.
cat > "$FAKE/cdinfo-writer-is-sr1" <<'EOS'
CD-ROM information, Id: cdrom.c 3.20 2003/12/17

drive name:		sr1	sr0
Can write CD-R:		1	0
Can write DVD-R:	1	0
Can write DVD-RAM:	0	0
Can read DVD:		1	1
EOS

run(){ GONOGO_CDROM_INFO="$1" "$GN" --need drives 2>&1 || true; }

hdr "two DVD-ROM readers (2 nodes, 0 writers) -> drives gate must STOP (not GO)"
out="$(run "$FAKE/cdinfo-two-readers")"
if grep -qiE 'NONE can WRITE|cannot (burn|write)' <<< "$out"; then
  P "STOPs when no attached drive can write (read-only DVD-ROM pair caught)"
else
  F "false GO: two read-only drives passed the drives gate with no write-capability check"
  echo "$out" | grep -iE 'optical|drive|sr' | sed 's/^/      /'
fi
# The STOP must actually poison the verdict, not just print a line.
if grep -qi 'NO-GO' <<< "$out"; then
  P "overall verdict is NO-GO for the read-only pair"
else
  F "read-only pair did not drive the overall verdict to NO-GO"
fi

hdr "one writer + one reader (2 nodes, >=1 writer) -> drives gate says GO"
out="$(run "$FAKE/cdinfo-one-writer")"
if grep -qiE 'DVD writer profile|can write DVD' <<< "$out"; then
  P "accepts a pair that includes at least one DVD writer"
else
  F "false NO-GO: a valid writer+reader pair was rejected by the drives gate"
  echo "$out" | grep -iE 'optical|drive|sr' | sed 's/^/      /'
fi
if grep -qiE 'NONE can WRITE' <<< "$out"; then
  F "writer+reader pair wrongly flagged as having no writer"
else
  P "no false 'NONE can WRITE' STOP when a writer is present"
fi

hdr "writer is sr1, sr0 is the READER (kernel reverses drive order) -> gate must STOP"
# The ceremony burns to /dev/sr0; a writer on sr1 does NOT make sr0 burnable. Counting total
# writers (>=1) wrongly issues GO here and the burn fails mid-ceremony.
out="$(run "$FAKE/cdinfo-writer-is-sr1")"
if grep -qiE 'read-only|NONE can WRITE|will fail' <<< "$out"; then
  P "STOPs when the burn drive (sr0) is the read-only unit even though a writer exists elsewhere"
else
  F "false GO: writer sat on sr1 while sr0 (the burn target) is read-only, gate still said GO"
  echo "$out" | grep -iE 'optical|drive|sr|writer|burn' | sed 's/^/      /'
fi
if grep -qi 'NO-GO' <<< "$out"; then
  P "overall verdict is NO-GO when the burn drive cannot write"
else
  F "burn-drive-is-reader case did not drive the overall verdict to NO-GO"
fi
# Must NOT be a blanket 'NONE can WRITE' claim — a writer IS attached, just on the wrong node.
# (Advisory only: the specific message is asserted above; this documents the intended wording.)

hdr "capability table unreadable (emulator/unknown host) -> WARN, do not false-STOP"
out="$(GONOGO_CDROM_INFO="$FAKE/does-not-exist" "$GN" --need drives 2>&1 || true)"
if grep -qiE 'could not read optical write-capability' <<< "$out"; then
  P "degrades to an advisory WARN when the capability table is absent"
else
  F "expected an advisory WARN when the capability table cannot be read"
  echo "$out" | grep -iE 'optical|drive|sr' | sed 's/^/      /'
fi
if grep -qiE 'NONE can WRITE' <<< "$out"; then
  F "false STOP when the capability table is merely unreadable (would break the CI emulator)"
else
  P "does not hard-STOP on an unreadable capability table"
fi

hdr "RESULT"
printf '  %d passed, %d failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ] && exit 0 || exit 1
