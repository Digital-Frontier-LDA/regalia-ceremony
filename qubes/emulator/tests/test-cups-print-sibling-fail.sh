#!/usr/bin/env bash
# test-cups-print-sibling-fail.sh — print_share() must WAIT for the printer to drain before it
# PURGES the CUPS spool EVEN WHEN one of the two `lp` jobs fails. Guards the failure-branch bug.
#
# THE DEFECT this guards against: print_share() spools TWO jobs — the plaintext share-words page
# (txt) first, then the QR PNG. The drain-wait poll loop lived ONLY inside the success branch of
#   if run "lp … txt" && run "lp … png"; then <wait-for-drain> else <warn> fi
#   cancel -x -a "$PRINTER"
# If qrencode fails (binary missing, or a 33-word SLIP-39 QR exceeds QR capacity) the PNG is never
# created, so the FIRST `lp` still spools the plaintext words page (an idle USB laser leaves it
# PENDING) but the SECOND `lp` fails on the missing PNG — taking the `else` branch, which SKIPS the
# wait loop. Control then falls straight to the UNCONDITIONAL `cancel -x -a`, deleting the still-
# pending plaintext page before a single sheet emerges. The wizard reports the share as
# skipped/failed while its paper backup was silently dropped, and $WORK is shredded on exit — a
# set-once, real-money loss of a Shamir share. The fix: drain the queue (poll lpstat -o until empty)
# BEFORE purging on BOTH branches, so a page that DID spool always prints before the spool is wiped.
#
# Runs natively, no daemons/deps. Same asynchronous CUPS model as test-cups-print-before-purge.sh,
# except `lp` returns NON-ZERO when its target file is missing (as real lp does) so we can model the
# QR page failing while the plaintext page spooled fine.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
SCRIPTS="${CEREMONY_SCRIPTS:-$HERE/../../scripts}"
CER="$SCRIPTS/ceremony.sh"

pass=0; fail=0
P(){ printf '  \033[32mPASS\033[0m %s\n' "$1"; pass=$((pass+1)); }
F(){ printf '  \033[31mFAIL\033[0m %s\n' "$1"; fail=$((fail+1)); }
hdr(){ printf '\n\033[1m### %s\033[0m\n' "$1"; }

W="$(mktemp -d)"; trap 'rm -rf "$W"' EXIT
FAKE="$W/bin"; mkdir -p "$FAKE"
SPOOL="$W/spool"; mkdir -p "$SPOOL/queue"

# fake qrencode : FAIL — do NOT create the PNG (models missing binary / QR-capacity overflow).
cat > "$FAKE/qrencode" <<'QR'
#!/usr/bin/env bash
exit 1
QR

# fake lp -d <printer> <file> : enqueue a PENDING job and return, BUT fail (non-zero, nothing
# spooled) if the target file does not exist — exactly what real lp does for a missing QR PNG.
cat > "$FAKE/lp" <<LP
#!/usr/bin/env bash
file=""; for a in "\$@"; do case "\$a" in -*) : ;; *) file="\$a";; esac; done
[ -f "\$file" ] || { echo "lp: unable to access \$file" >&2; exit 1; }
n=0; [ -f "$SPOOL/.jobctr" ] && n="\$(cat "$SPOOL/.jobctr")"; n=\$((n+1)); printf '%s' "\$n" > "$SPOOL/.jobctr"
cp "\$file" "$SPOOL/d0000\$n-001"        # rendered document data in the spool
printf '2' > "$SPOOL/queue/\$n"           # remaining steps until the page prints
exit 0
LP

# fake lpstat : -o <printer> lists outstanding jobs, then advances the queue one step.
cat > "$FAKE/lpstat" <<LPS
#!/usr/bin/env bash
mode=""; for a in "\$@"; do case "\$a" in -o) mode=o;; -*) : ;; esac; done
[ "\$mode" = o ] || exit 0
for j in "$SPOOL"/queue/*; do [ -e "\$j" ] || continue; printf 'printer-%s operator 1024 job\n' "\$(basename "\$j")"; done
for j in "$SPOOL"/queue/*; do
  [ -e "\$j" ] || continue
  r="\$(cat "\$j")"; r=\$((r-1))
  if [ "\$r" -le 0 ]; then
    id="\$(basename "\$j")"; cat "$SPOOL/d0000\$id-001" >> "$SPOOL/printed.log"; rm -f "\$j"
  else
    printf '%s' "\$r" > "\$j"
  fi
done
exit 0
LPS

# fake cancel [-x] -a <printer> : purge pending jobs WITHOUT printing; -x also deletes data files.
cat > "$FAKE/cancel" <<CANCEL
#!/usr/bin/env bash
purge=0; for a in "\$@"; do [ "\$a" = "-x" ] && purge=1; done
rm -f "$SPOOL"/queue/*                       # pending jobs are lost (never printed)
[ "\$purge" = 1 ] && rm -f "$SPOOL"/d*-* 2>/dev/null
exit 0
CANCEL
chmod +x "$FAKE/qrencode" "$FAKE/lp" "$FAKE/lpstat" "$FAKE/cancel"
export PATH="$FAKE:$PATH"

MARK="TOPSECRET-share-$$-abandon all hope"

# ---- drive the REAL print_share() with a FAILING QR page --------------------------------------
hdr "print_share() must PRINT the plaintext page before purging, even when the QR page fails"
: > "$SPOOL/.jobctr"; rm -f "$SPOOL"/queue/* "$SPOOL"/d*-* "$SPOOL/printed.log" 2>/dev/null
(
  export PATH SPOOL MARK CER
  export CEREMONY_PRINT_POLL=0   # don't actually sleep; the model advances on each lpstat call
  bash -c '
    set -uo pipefail
    source "$CER" >/dev/null 2>&1          # load functions only (main is BASH_SOURCE-guarded)
    ask() { return 0; }                     # auto-confirm every run "run it?" prompt
    WORK="$(mktemp -d)"; PRINTER="brotherlaser"
    printf "%s\n" "$MARK" > "$WORK/share1"
    print_share "SLIP-0039 share 1 of 6 (need 4)" "$WORK/share1" >/dev/null 2>&1
    rm -rf "$WORK"
  ' >/dev/null 2>&1
) || true

pages="$(grep -cF "$MARK" "$SPOOL/printed.log" 2>/dev/null || printf 0)"
if [ "$pages" -ge 1 ]; then
  P "the plaintext share page printed before print_share() purged the spool ($pages page(s) emerged)"
else
  F "NO page emerged: the QR job failed and print_share() purged the CUPS spool while the plaintext"
  F "share page was still PENDING — the paper backup was silently dropped (a set-once Shamir share)"
fi

# and the plaintext must NOT linger in the spool afterward (purge still happens, just AFTER draining)
if grep -rqF "$MARK" "$SPOOL/queue" "$SPOOL"/d*-* 2>/dev/null; then
  F "plaintext share still present in the CUPS spool after print_share() — purge did not run"
else
  P "spool holds no plaintext share data after printing (purge ran AFTER the page drained)"
fi

hdr "RESULT"
printf '  %d passed, %d failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ] && exit 0 || exit 1
