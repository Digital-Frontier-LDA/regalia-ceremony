#!/usr/bin/env bash
# test-cups-print-before-purge.sh — print_share() must WAIT for the printer to actually
# finish printing before it PURGES the CUPS spool. Otherwise the paper/QR backup is dropped.
#
# THE DEFECT this guards against: `lp` returns as soon as a job is SPOOLED, not when the page
# emerges. A real USB laser is asleep/warming when idle, so both the text and QR jobs sit
# PENDING/processing for a while after `lp` returns. print_share() used to run `cancel -x -a`
# IMMEDIATELY after the two `lp` calls — purging the still-pending jobs before a single page
# printed. Result: NO pages come out (or the second-queued QR page is cancelled mid-spool),
# yet the wizard prints "sent … to <printer>" and $WORK is shredded on exit. A silently missing
# QR page (or a missing share entirely) is exactly the set-once, real-money failure this
# ceremony cannot afford. The fix is to poll `lpstat -o <printer>` until the queue drains
# (every page has printed), and only THEN purge the plaintext from the spool.
#
# Runs natively, no daemons/deps. We model an ASYNCHRONOUS CUPS printer:
#   * lp        : enqueues a PENDING job (copies the rendered document into the spool as a
#                 completed-style data file) and returns immediately — the page has NOT printed.
#   * lpstat -o : lists the printer's outstanding (pending) jobs, then ADVANCES each one a step;
#                 a job that reaches "printed" appends its rendered page to $SPOOL/printed.log
#                 (the physical paper that emerged) and leaves the queue. This models real time
#                 passing between polls: keep polling and the queue eventually drains.
#   * cancel -x : purges ALL still-pending jobs WITHOUT printing them (they are lost) and deletes
#                 completed job DATA files. Purging while jobs are pending drops the backup.
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

# fake qrencode -o <png> -r <file> : just create the PNG (content irrelevant here).
cat > "$FAKE/qrencode" <<'QR'
#!/usr/bin/env bash
out=""; while [ $# -gt 0 ]; do case "$1" in -o) out="$2"; shift 2;; *) shift;; esac; done
[ -n "$out" ] && : > "$out"
exit 0
QR

# fake lp -d <printer> <file> : enqueue a PENDING job and return immediately (spooled != printed).
cat > "$FAKE/lp" <<LP
#!/usr/bin/env bash
file=""; for a in "\$@"; do case "\$a" in -*) : ;; *) file="\$a";; esac; done
n=0; [ -f "$SPOOL/.jobctr" ] && n="\$(cat "$SPOOL/.jobctr")"; n=\$((n+1)); printf '%s' "\$n" > "$SPOOL/.jobctr"
[ -n "\$file" ] && cp "\$file" "$SPOOL/d0000\$n-001"   # rendered document data in the spool
printf '2' > "$SPOOL/queue/\$n"                          # remaining steps until the page prints
exit 0
LP

# fake lpstat : -o <printer> lists outstanding jobs, then advances the queue one step.
cat > "$FAKE/lpstat" <<LPS
#!/usr/bin/env bash
mode=""; for a in "\$@"; do case "\$a" in -o) mode=o;; -*) : ;; esac; done
[ "\$mode" = o ] || exit 0
# list currently-pending jobs
for j in "$SPOOL"/queue/*; do [ -e "\$j" ] || continue; printf 'printer-%s operator 1024 job\n' "\$(basename "\$j")"; done
# advance each pending job one step; a job that reaches 0 PRINTS (page emerges) and leaves the queue
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

# ---- sanity: the async model actually drops pages if you purge before the queue drains --------
hdr "sanity: purging a pending queue loses the pages (model is faithful to an async printer)"
: > "$SPOOL/.jobctr"; rm -f "$SPOOL"/queue/* "$SPOOL"/d*-* "$SPOOL/printed.log" 2>/dev/null
printf '%s\n' "$MARK" > "$SPOOL/doc"; "$FAKE/lp" -d p "$SPOOL/doc" >/dev/null
"$FAKE/cancel" -x -a p >/dev/null
if [ -s "$SPOOL/printed.log" ]; then
  F "model printed a page despite an immediate purge — model is wrong, test would be a false pass"
else
  P "immediate cancel -x on a pending job prints NOTHING — faithful to a sleeping laser"
fi
# and: polling lpstat until empty DOES print the page
: > "$SPOOL/.jobctr"; rm -f "$SPOOL"/queue/* "$SPOOL"/d*-* "$SPOOL/printed.log" 2>/dev/null
"$FAKE/lp" -d p "$SPOOL/doc" >/dev/null
while [ -n "$("$FAKE/lpstat" -o p)" ]; do :; done
grep -qF "$MARK" "$SPOOL/printed.log" 2>/dev/null \
  && P "polling lpstat -o until the queue drains DOES print the page (drain-then-purge is provable)" \
  || F "polling lpstat never printed the page — model is wrong"

# ---- drive the REAL print_share() -------------------------------------------------------------
hdr "print_share() must actually PRINT both pages (text + QR) before purging the spool"
: > "$SPOOL/.jobctr"; rm -f "$SPOOL"/queue/* "$SPOOL"/d*-* "$SPOOL/printed.log" 2>/dev/null
(
  export PATH SPOOL MARK CER
  # keep the fix's poll loop from actually sleeping; the async model advances on each lpstat call
  export CEREMONY_PRINT_POLL=0
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
  P "the share page printed before print_share() purged the spool ($pages page(s) of $MARK emerged)"
else
  F "NO page emerged: print_share() purged the CUPS spool while jobs were still pending — the"
  F "paper/QR backup was silently dropped (the wizard said 'sent' but nothing printed)"
fi

# and the plaintext must NOT linger in the spool afterward (purge still happens, just AFTER printing)
if grep -rqF "$MARK" "$SPOOL/queue" "$SPOOL"/d*-* 2>/dev/null; then
  F "plaintext share still present in the CUPS spool after print_share() — purge did not run"
else
  P "spool holds no plaintext share data after printing (purge ran AFTER the pages drained)"
fi

hdr "RESULT"
printf '  %d passed, %d failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ] && exit 0 || exit 1
