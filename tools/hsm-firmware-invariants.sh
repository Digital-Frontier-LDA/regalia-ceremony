#!/usr/bin/env bash
# hsm-firmware-invariants.sh — assert the hard-won firmware fixes are still present in the SDK
# source. NO HARDWARE REQUIRED.
#
#   tools/hsm-firmware-invariants.sh [path-to-pico-keys-sdk]
#
# WHY THIS EXISTS. Four firmware defects were root-caused on this bench, each costing hours and
# several wrong hypotheses. Every one is a small edit in someone else's tree, and every one would
# disappear silently in a submodule bump, a rebase onto upstream, or a merge that takes "theirs".
# Nothing would fail loudly — the device would simply start wedging again, and the next person
# would re-derive the same findings from scratch.
#
# These are SOURCE-LEVEL assertions, which is a weaker thing than a behavioural test and is chosen
# deliberately: the behaviours involved (a watchdog reset loop, a HardFault on a corrupt flash
# structure) need a physical card in a provoked failure state to observe, so a test that runs
# everywhere is worth more here than one that runs only on the bench.
set -u

SDK="${1:-/Users/jonathanborduas/code/pico-hsm/pico-keys-sdk}"
HERE="$(cd "$(dirname "$0")" && pwd)"
# The lexer lives in qubes/emulator/tests/ here; ../ceremony/qubes/… is the retired monorepo
# layout, where this file came from. Both are tried so either checkout shape works — without this
# the invariant checker exits 2 ("cannot evaluate") on every file it is pointed at.
LEXER=""
for _fi_c in "$HERE/../qubes/emulator/tests/source_lexing.py" \
             "$HERE/../ceremony/qubes/emulator/tests/source_lexing.py"; do
    [ -r "$_fi_c" ] && { LEXER="$_fi_c"; break; }
done
LEXER="${LEXER:-$HERE/../qubes/emulator/tests/source_lexing.py}"
pass=0; fail=0
P(){ printf '  \033[32mPASS\033[0m %s\n' "$1"; pass=$((pass+1)); }
F(){ printf '  \033[31mFAIL\033[0m %s\n' "$1"; fail=$((fail+1)); }

[ -d "$SDK/src" ] || { echo "no SDK source at $SDK"; exit 2; }
echo "checking firmware invariants in $SDK"
echo

file_code="$(python3 "$LEXER" c "$SDK/src/fs/file.c")" || exit 2
main_code="$(python3 "$LEXER" c "$SDK/src/main.c")" || exit 2
rescue_code="$(python3 "$LEXER" c "$SDK/src/rescue.c")" || exit 2
flash_code="$(python3 "$LEXER" c "$SDK/src/fs/flash.c")" || exit 2

# 1. The scan must validate a chain link before dereferencing it.
#    Without this a corrupt link is read directly: MEASURED BFAR=0x40130000, precise bus fault
#    escalated to HardFault, core parked in the bootrom at pc=0x3ec, recoverable only by BOOTSEL.
scan_loop="$(awk '/for \(uintptr_t base = flash_read_uintptr\(endp\)/,/^    }/' <<<"$file_code")"
if grep -q 'flash_range_in_fs' <<<"$scan_loop"; then
    P "fs scan validates chain links against the pools before dereferencing them"
else
    F "fs scan does NOT validate chain links — a corrupt link will HardFault the device (BFAR-class fault)"
fi

# 2. The stale watchdog must be disarmed BEFORE main(), in preinit.
#    A disarm inside main() was measured NOT to work: the reset loop never reaches main().
if grep -q 'PICO_RUNTIME_INIT_FUNC_HW' <<<"$main_code" \
   && grep -q 'WATCHDOG_CTRL_ENABLE_BITS' <<<"$main_code"; then
    P "stale watchdog is disarmed in preinit (before main), breaking the reset loop"
else
    F "no preinit watchdog disarm — a slow boot after watchdog_reboot() will loop forever"
fi

# 3. POWMAN_WDSEL must NOT be armed globally at boot.
#    Arming it globally converts every unrelated watchdog_reboot() in the tree into a switched-core
#    power cycle, and a deep reset does not reliably return the USB peripheral.
if grep -qE '^\s*powman_set_bits' <<<"$main_code"; then
    F "main.c arms POWMAN_WDSEL globally — every reset in the tree becomes a deep power cycle"
else
    P "POWMAN_WDSEL is not armed globally at boot"
fi

# 4. rescue.c must not reboot via a raw short-window watchdog.
if grep -qE '^\s*watchdog_reboot\(' <<<"$rescue_code"; then
    F "rescue.c calls watchdog_reboot() directly — leaves the watchdog armed across the reset"
else
    P "rescue.c reboots through the vetted reset path, not a raw watchdog_reboot()"
fi

# 5. The FILE_DATA_FUNC guard must accept-and-discard rather than error.
#    Returning an error maps to SW=6581, which makes the Smart Card Shell abort initialisation
#    where OpenSC merely ignores it.
if grep -q 'FILE_DATA_FUNC' <<<"$flash_code"; then
    P "FILE_DATA_FUNC guard is present in the flash write path"
else
    F "FILE_DATA_FUNC guard missing — a function pointer can be written as a flash address"
fi

# 6. The SUPERPROJECT MUST PIN THE SDK COMMIT THAT WAS CHECKED ABOVE.
#    Checks 1-5 read the SDK WORKING TREE. That is what gets flashed by hand on this bench, but it
#    is NOT what `git clone --recursive` builds — that builds the commit the superproject pins.
#    MEASURED 2026-08-08: pico-hsm pinned c7060b9, five fixes behind its own SDK checkout, so this
#    script reported 5/5 green while a clean clone produced firmware with none of them. Every
#    reliability number on record had been measured against a tree the repo did not describe.
#
#    So the source assertions above are only worth as much as this check: they prove the fixes
#    exist SOMEWHERE, and this proves that somewhere is what anyone else would actually build.
SUPER="$(cd "$SDK/.." 2>/dev/null && pwd)"
if [ -d "$SUPER/.git" ] && command -v git >/dev/null 2>&1; then
    sdk_head="$(git -C "$SDK" rev-parse HEAD 2>/dev/null)"
    sdk_name="$(basename "$SDK")"
    pinned="$(git -C "$SUPER" ls-tree HEAD "$sdk_name" 2>/dev/null | awk '{print $3}')"
    if [ -z "$pinned" ]; then
        P "superproject does not track the SDK as a submodule — nothing to drift (skipped)"
    elif [ "$pinned" = "$sdk_head" ]; then
        P "superproject pins the exact SDK commit checked above (${sdk_head:0:7}) — a clean clone builds these fixes"
    else
        behind="$(git -C "$SDK" log --oneline "$pinned..$sdk_head" 2>/dev/null | wc -l | tr -d ' ')"
        F "superproject pins ${pinned:0:7} but the checked tree is ${sdk_head:0:7} (${behind} commits of fixes would be MISSING from a clean clone)"
    fi
else
    P "no superproject git repo above the SDK — pin check not applicable (skipped)"
fi

echo
printf '  %d passed, %d failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ] || {
    echo
    echo "  A failure here means a firmware fix has been LOST, not that a test is stale."
    echo "  See hardware/pico-hsm/UPSTREAM-WDSEL-SCOPE.md for what each one prevents."
    exit 1
}
