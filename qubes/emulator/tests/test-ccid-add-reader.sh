#!/usr/bin/env bash
# test-ccid-add-reader.sh — ccid-add-reader.py, which the vault-tools recipe uses to make libccid
# accept the Pico HSM (2e8a:10fd; Debian 13's libccid 1.6.2 does not list it). Runs on a small
# fixture shaped like /etc/libccid_Info.plist and, when this machine has libccid, on a copy of the
# real one.
export PCSCLITE_CSOCK_NAME="${PCSCLITE_CSOCK_NAME:-/nonexistent/regalia-no-pcscd.comm}"   # no real card, even run by hand (#104)
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
S="${CEREMONY_SCRIPTS:-$HERE/../../scripts}/ccid-add-reader.py"
pass=0; fail=0
P(){ printf '  \033[32mPASS\033[0m %s\n' "$1"; pass=$((pass+1)); }
F(){ printf '  \033[31mFAIL\033[0m %s\n' "$1"; fail=$((fail+1)); }
hdr(){ printf '\n\033[1m### %s\033[0m\n' "$1"; }
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
cat > "$T/f.plist" <<'X'
<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0">
<dict>
	<key>ifdVendorID</key>
	<array>
		<string>0x20A0</string>
		<string>0x1050</string>
	</array>
	<key>ifdProductID</key>
	<array>
		<string>0x4230</string>
		<string>0x0407</string>
	</array>
	<key>ifdFriendlyName</key>
	<array>
		<string>Nitrokey Nitrokey HSM</string>
		<string>Yubico YubiKey OTP+FIDO+CCID</string>
	</array>
</dict>
</plist>
X
chmod 0644 "$T/f.plist"
pico(){ python3 "$S" --plist "$1" --vid 0x2E8A --pid 0x10FD "${@:2}"; }
lens(){ python3 -c "import plistlib,sys; d=plistlib.load(open(sys.argv[1],'rb')); print(*[len(d[k]) for k in ('ifdVendorID','ifdProductID','ifdFriendlyName')]); print(d['ifdVendorID'][-1], d['ifdProductID'][-1], d['ifdFriendlyName'][-1])" "$1"; }

hdr "not listed, then added in lockstep; the file stays a valid plist with its mode"
pico "$T/f.plist" --check && F "reported listed before adding" || P "--check: not listed"
pico "$T/f.plist" --name "Pol Henarejos Pico Key" >/dev/null && P "added" || F "add failed"
[ "$(lens "$T/f.plist")" = $'3 3 3\n0x2E8A 0x10FD Pol Henarejos Pico Key' ] && P "3/3/3 entries, the new one last in each" || F "arrays wrong: $(lens "$T/f.plist")"
[ "$(stat -c %a "$T/f.plist")" = 644 ] && P "mode kept" || F "mode changed"
pico "$T/f.plist" --check && P "--check: listed" || F "--check after add"
python3 "$S" --plist "$T/f.plist" --vid 0x20a0 --pid 0x4230 --check && P "--check ignores hex case (0x20a0 = 0x20A0)" || F "case-sensitive check"

hdr "a second run changes nothing"
cp "$T/f.plist" "$T/before"; o="$(pico "$T/f.plist" --name "Pol Henarejos Pico Key")"; grep -q "already listed" <<< "$o" && cmp -s "$T/before" "$T/f.plist" && P "idempotent" || F "second run changed the file"

hdr "arrays of different lengths: refused, file untouched"
sed 's#<string>0x0407</string>##' "$T/f.plist" > "$T/bad.plist"; cp "$T/bad.plist" "$T/bad.orig"
o="$(python3 "$S" --plist "$T/bad.plist" --vid 0x1234 --pid 0x5678 --name X 2>&1)"
grep -q "differ in length" <<< "$o" && cmp -s "$T/bad.orig" "$T/bad.plist" && P "refused" || F "edited an inconsistent plist"

hdr "bad input refused"
o="$(python3 "$S" --plist "$T/f.plist" --vid 2E8A --pid 0x10FD --name X 2>&1)"
grep -q "look like 0x2E8A" <<< "$o" && P "malformed ID" || F "malformed ID accepted"
o="$(python3 "$S" --plist "$T/f.plist" --vid 0x1111 --pid 0x2222 --name 'a</string><string>b' 2>&1)"
grep -q "plain text" <<< "$o" && P "markup in the name" || F "markup accepted"

hdr "on this machine's real libccid list (if installed)"
if [ -r /etc/libccid_Info.plist ]; then
  cp /etc/libccid_Info.plist "$T/real.plist"
  python3 "$S" --plist "$T/real.plist" --vid 0x20A0 --pid 0x4230 --check && P "the real list has the Nitrokey HSM" || F "Nitrokey HSM missing from the real list"
  pico "$T/real.plist" --name "Pol Henarejos Pico Key" >/dev/null && pico "$T/real.plist" --check && P "Pico added to a copy of the real list" || F "could not add to the real list"
  l="$(lens "$T/real.plist" | head -1)"; set -- $l; [ "$1" = "$2" ] && [ "$2" = "$3" ] && P "real list still parallel ($1 readers)" || F "real list arrays diverged: $l"
else
  echo "  (no /etc/libccid_Info.plist here; the fixture cases above still ran)"
fi

hdr "RESULT"
printf '  %d passed, %d failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
