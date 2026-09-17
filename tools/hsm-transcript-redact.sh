#!/usr/bin/env bash
# hsm-transcript-redact.sh — remove the credentials THIS RUN holds from a stream, at write time.
#
#   cmd 2>&1 | tools/hsm-transcript-redact.sh                 # filter: redacted stdin -> stdout
#   cmd 2>&1 | tools/hsm-transcript-redact.sh -o FILE         # + also write the redacted stream
#                                                             #   to FILE (a tee that redacts)
#
# WHY THIS EXISTS (#185). The staging battery tees everything every tool writes into a transcript
# that ships as a 90-day artifact, and its per-step logs land in the same uploaded directory.
# GitHub masks `secrets.*` in the JOB LOG; nothing masks them in the tee'd transcript or the
# artifact, so the day a tool starts echoing what it was handed (a new OpenSC release printing its
# argv on failure, a `set -x` left in a child, a traceback that includes locals), the credential
# is preserved in plaintext for 90 days with no diff marking the run where it started. No tool
# echoes today — measured 2026-09-05 against pkcs11-tool, sc-hsm-tool and opensc-explorer — which
# is why this filter must be proven by a test that SYNTHESIZES the echo, not by observing one.
#
# SECRETS ARRIVE BY ENVIRONMENT, NEVER BY ARGV AND NEVER BY FILE. `awk -v secret=$PIN` would put
# the PIN in the process listing for the whole run, and a file would put it on the runner's disk —
# each is a smaller cousin of the leak this exists to stop. The environment is the channel the
# battery already uses, and /proc/<pid>/environ is readable only by the same user.
#
#   HSM_USER_PIN          the effective user PIN           -> [redacted:user-pin]
#   HSM_SO_PIN            the SO-PIN, when the run has one -> [redacted:so-pin]
#   HSM_CI_REDACT_EXTRA   colon-separated anything else    -> [redacted:extra]
#                                                        (DKEK share material, future shapes)
#
# THE BOUNDARY, STATED. Values shorter than 4 characters are skipped (a 1-char "secret" would
# shred the transcript's English while protecting nothing — real PINs are 6+). Matching is
# line-bounded: a value wrapped across two lines by a tool's output is NOT caught. Both are
# documented limits, not accidents. Identity material (ATR, C.DevAut, serials) passes through
# untouched — those are the artifact's CONTENT, not credentials.
#
# THIS FILTER MUST NEVER DROP BYTES. A redactor that eats output under some condition would
# corrupt the transcript — the one artifact a red run is read by. Unknown input is passed through;
# only the exact byte strings above are replaced.
set -u

out=""
if [ "${1:-}" = "-o" ]; then
  [ $# -ge 2 ] || { printf 'hsm-transcript-redact.sh: -o needs a file argument\n' >&2; exit 2; }
  out="$2"
fi

# LC_ALL=C: byte semantics. Tool output carries ANSI escapes and occasional binary debris, and a
# UTF-8 locale would make awk reinterpret invalid sequences instead of passing them through.
# Replacement is index()/substr() — plain byte search — so a PIN containing a regex metacharacter
# ('.', '*', '[') is still replaced literally rather than parsed as a pattern.
LC_ALL=C exec awk -v out="$out" '
function redact(line, s, mark,    res, pos, off) {
  res = ""; off = 1
  while ((pos = index(substr(line, off), s)) > 0) {
    res = res substr(line, off, pos - 1) mark
    off = off + pos - 1 + length(s)
  }
  return res substr(line, off)
}
BEGIN {
  n = 0
  if (length(ENVIRON["HSM_USER_PIN"]) >= 4) { S[++n] = ENVIRON["HSM_USER_PIN"]; M[n] = "[redacted:user-pin]" }
  if (length(ENVIRON["HSM_SO_PIN"])   >= 4) { S[++n] = ENVIRON["HSM_SO_PIN"];   M[n] = "[redacted:so-pin]" }
  m = split(ENVIRON["HSM_CI_REDACT_EXTRA"], X, ":")
  for (i = 1; i <= m; i++)
    if (length(X[i]) >= 4) { S[++n] = X[i]; M[n] = "[redacted:extra]" }
  # LONGEST FIRST. If one secret is a substring of another — an extra token that embeds the PIN —
  # redacting the shorter one first replaces only its span and leaves the remainder of the longer
  # value in the clear: pin=1234, extra=1234567890 -> "[redacted:user-pin]567890" (found on #211).
  for (i = 2; i <= n; i++) {
    v = S[i]; vm = M[i]
    for (j = i - 1; j >= 1 && length(S[j]) < length(v); j--) { S[j+1] = S[j]; M[j+1] = M[j] }
    S[j+1] = v; M[j+1] = vm
  }
}
{
  line = $0
  for (i = 1; i <= n; i++) line = redact(line, S[i], M[i])
  print line
  if (out != "") {
    print line > out
    fflush(out)   # a SIGTERM must not cost the tail of the transcript; the battery is killed
  }               # mid-run as a matter of routine (cancelled soaks)
  fflush()        # keep the console stream live while a multi-hour soak runs
}'
