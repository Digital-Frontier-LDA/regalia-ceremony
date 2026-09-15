#!/usr/bin/env bash
# test-cups-spool-purge.sh — print_share() must actually PURGE the rendered plaintext share
# document from the CUPS spool after printing, not merely cancel active jobs.
#
# THE DEFECT this guards against: `cancel -a "$PRINTER"` (without -x) removes only QUEUED
# (active) jobs. Once `lp` has finished rendering, the job is COMPLETE and CUPS keeps its
# document data file (/var/spool/cups/d<jobid>-NNN) under the default PreserveJobFiles
# (~1 day) policy. So on any vault qube whose /var/spool/cups is NOT a DispVM tmpfs, the
# plaintext Shamir/SLIP-39 share words + QR remain readable on disk after the ceremony —
# while the operator believes the spool was cleared. The fix is a purge that deletes job
# DATA files (`cancel -x -a`), which this test drives end-to-end through the real
# print_share() against a faithful CUPS-spool model.
#
# Runs natively, no daemons/deps: we fake `lp` (renders the document into a spool file and
# marks the job COMPLETE, exactly as CUPS does), `cancel` (models -x = purge data files vs.
# no -x = keep completed jobs), and `qrencode`, then assert no plaintext lingers in the spool.
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
SPOOL="$W/spool"; mkdir -p "$SPOOL"          # stand-in for /var/spool/cups (persistent volume)

# ---- faithful CUPS-spool model -------------------------------------------------------
# fake `qrencode -o <png> -r <file> ...` : just create the PNG (content irrelevant here).
cat > "$FAKE/qrencode" <<'QR'
#!/usr/bin/env bash
out=""; while [ $# -gt 0 ]; do case "$1" in -o) out="$2"; shift 2;; *) shift;; esac; done
[ -n "$out" ] && : > "$out"
exit 0
QR

# fake `lp -d <printer> <file>` : CUPS copies the RENDERED document into the spool as a job
# data file (d<jobid>-001) and the job COMPLETES. The data file then persists per
# PreserveJobFiles — this is the on-disk plaintext the purge is supposed to remove.
cat > "$FAKE/lp" <<LP
#!/usr/bin/env bash
file=""; for a in "\$@"; do case "\$a" in -*) : ;; *) file="\$a";; esac; done
n=0; [ -f "$SPOOL/.jobctr" ] && n="\$(cat "$SPOOL/.jobctr")"; n=\$((n+1)); printf '%s' "\$n" > "$SPOOL/.jobctr"
# render (copy) the document data into the spool, exactly like a completed CUPS job
[ -n "\$file" ] && cp "\$file" "$SPOOL/d0000\$n-001"
exit 0
LP

# fake `cancel [-x] -a <printer>` : model CUPS semantics.
#   -a          : cancel ACTIVE (queued) jobs only. Completed jobs' data files are KEPT.
#   -x (purge)  : ALSO delete the job DATA files (d<jobid>-NNN) — the real purge.
# Our lp jobs complete synchronously, so there are never active jobs to cancel: only -x
# actually removes the on-disk plaintext.
cat > "$FAKE/cancel" <<CANCEL
#!/usr/bin/env bash
purge=0; for a in "\$@"; do [ "\$a" = "-x" ] && purge=1; done
if [ "\$purge" = 1 ]; then rm -f "$SPOOL"/d*-* 2>/dev/null; fi
exit 0
CANCEL
chmod +x "$FAKE/qrencode" "$FAKE/lp" "$FAKE/cancel"
export PATH="$FAKE:$PATH"

MARK="TOPSECRET-share-$$-abandon all hope"

# ---- drive the REAL print_share() ----------------------------------------------------
hdr "print_share() must leave NO plaintext share in the CUPS spool after printing"
run_out="$(
  export PATH SPOOL MARK CER
  bash -c '
    set -uo pipefail
    source "$CER" >/dev/null 2>&1          # load functions only (main is BASH_SOURCE-guarded)
    ask() { return 0; }                     # auto-confirm every run "run it?" prompt
    WORK="$(mktemp -d)"; PRINTER="brotherlaser"
    printf "%s\n" "$MARK" > "$WORK/share1"
    print_share "SLIP-0039 share 1 of 6 (need 4)" "$WORK/share1" >/dev/null 2>&1
    rm -rf "$WORK"
  ' 2>&1
)" || true

leaked="$(grep -rlF "$MARK" "$SPOOL" 2>/dev/null || true)"
if [ -n "$leaked" ]; then
  F "the plaintext share remains in the CUPS spool after print_share() 'purged' it — $(printf '%s' "$leaked" | tr '\n' ' ')"
  F "cancel -a does not delete COMPLETED job data files; use 'cancel -x -a' (purge)"
else
  P "no plaintext share data file left in the CUPS spool (purge deleted completed job data)"
fi

# sanity: the model is real — an lp job WITHOUT the purge would have left the file behind.
hdr "sanity: the spool model actually retains completed job data (so the check above is meaningful)"
: > "$SPOOL/.jobctr"
"$FAKE/lp" -d brotherlaser <(printf '%s\n' "$MARK") >/dev/null 2>&1
printf '%s\n' "$MARK" > "$SPOOL/render.tmp"; "$FAKE/lp" -d brotherlaser "$SPOOL/render.tmp" >/dev/null 2>&1
"$FAKE/cancel" -a brotherlaser >/dev/null 2>&1     # non-purge cancel: must NOT remove data
if grep -rqF "$MARK" "$SPOOL"; then
  P "cancel -a (no -x) leaves completed job data in the spool — model is faithful to CUPS"
else
  F "spool model removed data on a plain 'cancel -a' — model is wrong, test would be a false pass"
fi
rm -f "$SPOOL"/d*-* "$SPOOL/render.tmp" 2>/dev/null

hdr "RESULT"
printf '  %d passed, %d failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ] && exit 0 || exit 1
