#!/usr/bin/env bash
# test-dev-image-bootstrap.sh — the two decisions in dev-image-bootstrap.sh that are not apt calls.
# NO ROOT, NO NETWORK: each is exercised as the script itself runs it, against fixtures.
#
#   1. Registering the Pico with libccid. Its three arrays are INDEX-ALIGNED, and libccid binds a
#      reader only when the vendor and product entries line up. Searching for the vendor id alone
#      called a plist "already registered" when 0x2E8A was listed against a different product — and
#      the image then declares itself ready while the card stays invisible to pcscd.
#
#   2. Where the requirements file comes from. `--require-hashes` pins the PACKAGES it names; it
#      says nothing about the file. Fetched from a branch, whoever can move that branch chooses
#      what pip installs AS ROOT on the image.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
SCRIPT="$HERE/../../scripts/dev-image-bootstrap.sh"

pass=0; fail=0
P(){ printf '  \033[32mPASS\033[0m %s\n' "$1"; pass=$((pass+1)); }
F(){ printf '  \033[31mFAIL\033[0m %s\n' "$1"; fail=$((fail+1)); }
hdr(){ printf '\n\033[1m### %s\033[0m\n' "$1"; }

[ -r "$SCRIPT" ] || { echo "no dev-image-bootstrap.sh at $SCRIPT" >&2; exit 1; }
WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT

# The registration step, lifted verbatim from the script so this tests the shipped code and not a
# copy of it. If the heredoc markers ever change, the extraction fails loudly below.
python3 - "$SCRIPT" "$WORK/register.py" <<'EXTRACT'
import sys
src = open(sys.argv[1]).read()
marker = "python3 - \"$plist\" <<'PICO'\n"
if marker not in src:
    sys.exit("could not find the libccid registration heredoc in the bootstrap script")
body = src.split(marker, 1)[1].split("\nPICO\n", 1)[0]
open(sys.argv[2], "w").write(body)
EXTRACT
[ -s "$WORK/register.py" ] || { echo "extraction produced nothing" >&2; exit 1; }

plist() {   # $1=path, then VID:PID pairs
    local out="$1"; shift
    local vids="" pids="" names="" i=0
    for pair in "$@"; do
        vids="$vids\n\t<string>${pair%%:*}</string>"
        pids="$pids\n\t<string>${pair##*:}</string>"
        i=$((i+1)); names="$names\n\t<string>device $i</string>"
    done
    printf '<plist><dict>\n<key>ifdVendorID</key><array>%b\n</array>\n<key>ifdProductID</key><array>%b\n</array>\n<key>ifdFriendlyName</key><array>%b\n</array>\n</dict></plist>\n' \
        "$vids" "$pids" "$names" > "$out"
}

pairs_of() {   # print "VID PID" lines from a plist
    python3 - "$1" <<'PY'
import re, sys
s = open(sys.argv[1]).read()
def arr(key):
    m = re.search(r'<key>' + key + r'</key>\s*<array>(.*?)</array>', s, re.S)
    return re.findall(r'<string>([^<]*)</string>', m.group(1)) if m else []
for v, p in zip(arr('ifdVendorID'), arr('ifdProductID')):
    print(v, p)
PY
}

hdr "libccid registration binds the Pico by VID *and* PID"

plist "$WORK/empty.plist" "0x20A0:0x4230"
python3 "$WORK/register.py" "$WORK/empty.plist" >/dev/null 2>&1
pairs_of "$WORK/empty.plist" | grep -qi '^0x2E8A 0x10FD$' \
  && P "a plist without the Pico gains the aligned 0x2E8A:0x10FD entry" \
  || F "the Pico was not registered at all"

# THE REGRESSION. 0x2E8A listed against another product satisfied a vendor-only search.
plist "$WORK/othervid.plist" "0x2E8A:0x000A" "0x20A0:0x4230"
python3 "$WORK/register.py" "$WORK/othervid.plist" >/dev/null 2>&1
if pairs_of "$WORK/othervid.plist" | grep -qi '^0x2E8A 0x10FD$'; then
  P "0x2E8A present for a DIFFERENT product does not count as registered"
else
  F "the Pico stayed unregistered because its vendor id appeared against another product"
  pairs_of "$WORK/othervid.plist" | sed 's/^/      /'
fi

plist "$WORK/already.plist" "0x2E8A:0x10FD"
before="$(cat "$WORK/already.plist")"
out="$(python3 "$WORK/register.py" "$WORK/already.plist" 2>&1)"
if [ "$before" = "$(cat "$WORK/already.plist")" ] && grep -qi 'already present' <<< "$out"; then
  P "an already-registered plist is left untouched (idempotent)"
else
  F "re-running the registration modified a plist that was already correct"
fi

# Misaligned arrays are someone else's edit; appending to them makes it worse.
printf '<plist><dict>\n<key>ifdVendorID</key><array>\n\t<string>0x20A0</string>\n</array>\n<key>ifdProductID</key><array>\n</array>\n<key>ifdFriendlyName</key><array>\n\t<string>x</string>\n</array>\n</dict></plist>\n' > "$WORK/skew.plist"
before="$(cat "$WORK/skew.plist")"
python3 "$WORK/register.py" "$WORK/skew.plist" >/dev/null 2>&1
[ "$before" = "$(cat "$WORK/skew.plist")" ] \
  && P "arrays that are already misaligned are refused, not appended to" \
  || F "wrote into a plist whose arrays do not line up"

hdr "the remote requirements file must be pinned to CONTENT"
# The same `case` the script uses to decide whether REQ_REF is content-addressed.
ref_is_pinned() {
  local REQ_REF="$1" pinned_by_ref=0
  case "$REQ_REF" in
    *[!0-9a-fA-F]*) ;;
    ????????????????????????????????????????) pinned_by_ref=1 ;;
  esac
  [ "$pinned_by_ref" = 1 ]
}
grep -q 'REFUSING to install from https://raw.githubusercontent.com' "$SCRIPT" \
  && P "the script refuses a moving ref rather than fetching it" \
  || F "no refusal for an unpinned requirements fetch"
grep -q 'REQ_SHA256' "$SCRIPT" \
  && P "…and offers REQ_SHA256 as the other way to pin it" \
  || F "no digest option for the remote fetch"

ref_is_pinned "$(printf '%040d' 0 | tr '0' 'a')" && P "a 40-hex commit sha counts as pinned" \
                                                 || F "a full commit sha was rejected"
for bad in main v1.2.3 "$(printf '%039d' 0)" "$(printf '%041d' 0)" "feature/abc"; do
  ref_is_pinned "$bad" && F "'$bad' was accepted as content-addressed" \
                       || P "'$bad' is not accepted as content-addressed"
done

hdr "RESULT"
printf '  %d passed, %d failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ] || exit 1
