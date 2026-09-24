#!/usr/bin/env bash
# tools/nitrokey-acceptance.sh must REJECT each measured symptom of the 2025 batch defect (regalia#482)
# and accept a healthy unit. The defective unit is not on any bench, so the three symptoms are
# replayed here from what DENK0400664 did: a serial that flips to 01A001000000000 on re-enumeration,
# a 3-byte ATR, and APDUs that die after 242 exchanges.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
TOOL="$HERE/../../../tools/nitrokey-acceptance.sh"
pass=0; fail=0
P(){ printf '  PASS %s\n' "$1"; pass=$((pass+1)); }
F(){ printf '  FAIL %s\n' "$1"; fail=$((fail+1)); }

run_case(){ # run_case <serials, space-separated, one per enumeration> <atr> <apdus that answer>
  local root; root="$(mktemp -d)"
  mkdir -p "$root/sys/1-1" "$root/bin"
  printf '20a0\n' > "$root/sys/1-1/idVendor"; printf '4230\n' > "$root/sys/1-1/idProduct"
  printf '0101\n' > "$root/sys/1-1/bcdDevice"; printf '1\n' > "$root/sys/1-1/authorized"
  printf '%s\n' $1 > "$root/serials"; printf 'DENK04041440000\n' > "$root/sys/1-1/serial"
  printf '%s\n' "$2" > "$root/atr"; printf '%s\n' "$3" > "$root/budget"
  # sudo: run the command; re-authorising the device moves to the next serial in the list.
  cat > "$root/bin/sudo" <<S
#!/usr/bin/env bash
[ "\$1" = -n ] && shift && [ "\$1" = true ] && exit 0
[ "\$1" = tee ] || exec "\$@"
v="\$(cat)"; printf '%s\n' "\$v" > "\$2"
if [ "\$v" = 1 ] && [ -s "$root/serials" ]; then head -1 "$root/serials" > "$root/sys/1-1/serial"; sed -i 1d "$root/serials"; fi
S
  cat > "$root/bin/opensc-tool" <<S
#!/usr/bin/env bash
case "\$*" in
  --info) echo "OpenSC 0.26.1 [stub]";;
  -l) echo "2    Yes             Nitrokey Nitrokey HSM (\$(tr -d ' ' < "$root/sys/1-1/serial")         ) 00 00";;
  *" -a") cat "$root/atr";;
  *) budget=\$(cat "$root/budget")
     for a in "\$@"; do
       case "\$a" in
         "00 84 00 00 08") if [ "\$budget" -gt 0 ]; then echo "Received (SW1=0x90, SW2=0x00):"; budget=\$((budget-1));
                           else echo "Transmit failed: Card not present / T=1 state machine is DEAD"; echo 0 > "$root/budget"; exit 1; fi;;
         00\ A4*) echo "Received (SW1=0x90, SW2=0x00):";;
       esac
     done; echo "\$budget" > "$root/budget";;
esac
S
  cat > "$root/bin/sleep" <<'S'
#!/usr/bin/env bash
exit 0
S
  chmod +x "$root/bin/"*
  out="$(PATH="$root/bin:$PATH" NITROKEY_USB_DEVICES="$root/sys" bash "$TOOL" --enumerations 4 --apdus 600 2>&1)"; rc=$?
  rm -rf "$root"
}
GOOD=3b:de:96:ff:81:91:fe:1f:c3:80:31:81:54:48:53:4d:31:73:80:21:40:81:07:92
S4="DENK04041440000 DENK04041440000 DENK04041440000 DENK04041440000"

run_case "$S4" "$GOOD" 100000
[ "$rc" = 0 ] && grep -q "ACCEPTED" <<< "$out" && P "a healthy unit is accepted" || F "healthy unit not accepted (rc=$rc): $out"

run_case "DENK04006640000 01A001000000000 DENK04006640000 DENK04006640000" "$GOOD" 100000
[ "$rc" = 1 ] && grep -q "MALFORMED serial" <<< "$out" && P "the serial flipping to 01A001000000000 is rejected" || F "flipping serial accepted: $out"

run_case "$S4" "ce:00:00" 100000
[ "$rc" = 1 ] && grep -q "truncated or foreign ATR" <<< "$out" && P "a 3-byte ATR is rejected" || F "3-byte ATR accepted: $out"

run_case "$S4" "$GOOD" 242
[ "$rc" = 1 ] && grep -q "exchange 243 failed after 242 good ones" <<< "$out" && P "APDUs dying after 242 exchanges are rejected, at exchange 243" || F "APDU death not caught: $out"

run_case "DENK04041440000 DENK04041450000 DENK04041440000 DENK04041440000" "$GOOD" 100000
[ "$rc" = 1 ] && grep -q "changed from" <<< "$out" && P "a serial that changes between enumerations is rejected" || F "changing serial accepted: $out"

printf '  %d passed, %d failed\n' "$pass" "$fail"
[ "$fail" = 0 ]
