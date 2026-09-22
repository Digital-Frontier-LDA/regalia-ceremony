#!/usr/bin/env bash
# test-pcscd-diagnosis.sh — "No smart card readers found" must not read as a card fault.
#
# THE FAILURE THIS ADDRESSES. Debian runs pcscd with `--foreground --auto-exit`, so it leaves about
# a minute after the last client disconnects; pcscd.socket is what starts it again on the next
# request. With that socket inactive every tool here reports "No smart card readers found" with the
# cards plainly on the USB bus. Measured 2026-09-22: pcscd had to be started by hand three times in
# one session before the cause was noticed, and each time the first suspicion was the hardware.
#
# hsm_ensure_readers reports rather than repairs: a drill that silently fixes the host hides the
# condition from its own transcript, and restarting pcscd under another operator's session on a
# shared bench is not a drill's decision.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/../../.." && pwd)"
RESOLVER="$REPO/tools/hsm-reader-select.sh"
pass=0; fail=0
P(){ printf '  \033[32mPASS\033[0m %s\n' "$1"; pass=$((pass+1)); }
F(){ printf '  \033[31mFAIL\033[0m %s\n' "$1"; fail=$((fail+1)); }
hdr(){ printf '\n\033[1m### %s\033[0m\n' "$1"; }
[ -r "$RESOLVER" ] || { echo "no resolver at $RESOLVER" >&2; exit 1; }

T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
BIN="$T/bin"; mkdir -p "$BIN"

# A host with no readers, and two cards on the USB bus.
cat > "$BIN/opensc-tool" <<'STUB'
#!/usr/bin/env bash
case "$*" in
  *-l*) printf '# Detected readers (pcsc)\nNr.  Card  Features  Name\n';;
esac
exit 0
STUB
cat > "$BIN/lsusb" <<'STUB'
#!/usr/bin/env bash
printf 'Bus 001 Device 010: ID 20a0:4230 Clay Logic Nitrokey HSM\n'
printf 'Bus 001 Device 012: ID 2e8a:10fd Pol Henarejos Pico Key\n'
STUB
chmod +x "$BIN/opensc-tool" "$BIN/lsusb"

run_ensure(){ PATH="$BIN:$PATH" bash -c '. "$1"; hsm_ensure_readers' _ "$RESOLVER" 2>&1; }

hdr "no readers: it fails, and blames the daemon rather than the card"
out="$(run_ensure)"; rc=$?
[ "$rc" -ne 0 ] && P "it returns non-zero when nothing is visible" || F "it returned 0 with no readers"
grep -q 'NO PC/SC READERS ARE VISIBLE' <<<"$out" && P "…saying so plainly" || F "no clear statement: $out"
grep -q 'this is the daemon, not the hardware' <<<"$out" \
  && P "…and, seeing the cards on the USB bus, rules the hardware out" \
  || F "it does not distinguish a daemon problem from a card problem"
grep -q 'Nitrokey HSM' <<<"$out" && P "…naming what it can see on the bus" || F "it does not show the bus"
grep -q 'systemctl enable --now pcscd.socket' <<<"$out" \
  && P "…and gives the command that fixes it" || F "no fix is offered"
grep -q 'auto-exit' <<<"$out" && P "…and the reason it happens at all" || F "the cause is not explained"

hdr "it REPORTS, it does not repair"
# A drill that silently restarts the daemon hides the condition from its own transcript.
grep -qE 'hsm_ensure_readers\(\)' -A40 "$RESOLVER" >/dev/null 2>&1
body="$(sed -n '/^hsm_ensure_readers() {/,/^}$/p' "$RESOLVER")"
grep -qE 'systemctl (start|restart|enable)[^-]' <<<"$(grep -v '^ *printf' <<<"$body")" \
  && F "it runs systemctl itself; a drill must not repair the host it is measuring" \
  || P "it runs no systemctl of its own — the commands appear only in the message"
grep -q 'pkill\|killall' <<<"$body" && F "it kills processes" || P "…and kills nothing"

hdr "readers present: it succeeds quietly"
cat > "$BIN/opensc-tool" <<'STUB'
#!/usr/bin/env bash
case "$*" in
  *-l*) printf '# Detected readers (pcsc)\nNr.  Card  Features  Name\n0    Yes             Nitrokey Nitrokey HSM (X) 00 00\n';;
esac
exit 0
STUB
chmod +x "$BIN/opensc-tool"
out="$(run_ensure)"; rc=$?
[ "$rc" -eq 0 ] && P "it returns 0 when a reader is visible" || F "it failed with a reader present: $out"
[ -z "$out" ] && P "…and says nothing, so it can be called before every drill" \
  || F "it printed on the happy path: $out"

hdr "the bootstrap enables the socket, not just a restart"
BOOT="$REPO/qubes/scripts/dev-image-bootstrap.sh"
grep -q 'systemctl enable --now pcscd.socket' "$BOOT" \
  && P "dev-image-bootstrap.sh enables pcscd.socket" \
  || F "the bootstrap only restarts the service, which buys one auto-exit interval"

printf '\n\033[1m### RESULT\033[0m\n  %d passed, %d failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
