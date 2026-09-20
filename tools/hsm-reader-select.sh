#!/usr/bin/env bash
# hsm-reader-select.sh — resolve a Pico HSM to a PC/SC reader index and a PKCS#11 slot index
# BY ITS TOKEN SERIAL, never by enumeration order.
#
# Source this; it defines functions, it does not run anything.
#
#   . tools/hsm-reader-select.sh
#   READER="$(hsm_reader_for ESP2202E14A)"      # -> sc-hsm-tool -r / opensc-tool -r
#   SLOTIX="$(hsm_slot_index_for ESP2202E14A)"  # -> pkcs11-tool --slot-index
#
# WHY THIS EXISTS. From 2026-09-02 the bench has two RP2350B boards, so there are two identically
# named "Pol Henarejos Pico Key CCID Interface" readers. Index 0 is whichever enumerated first,
# which changes across replug, reboot and firmware reset. Every destructive tool here
# (`--initialize`, PIN-spending scenarios) defaulted to reader 0, so an ordering flip would have
# pointed a wipe at the wrong card. Serial is the only stable handle the host can see.
#
# It also refuses to answer when the serial matches more than one reader, rather than picking one.

HSM_P11_MODULE="${HSM_PKCS11_MODULE:-/opt/homebrew/lib/opensc-pkcs11.so}"

_hsm_run() { perl -e 'alarm shift; exec @ARGV' "$@"; }

# All PC/SC reader indices, one per line.
hsm_reader_indices() {
    opensc-tool --list-readers 2>/dev/null | awk '$1 ~ /^[0-9]+$/ {print $1}'
}

# AN EARLY awk `exit` MAKES THE PIPELINE'S EXIT STATUS A RACE. Every reader here pipes a card tool
# into awk, and awk used to `exit` on the first match. That closes the pipe while the tool is still
# writing, the tool takes SIGPIPE, and under `set -o pipefail` — which hsm-staging-ci.sh and
# hsm-fleet-drill.sh both set — the function returns 141 EXACTLY WHEN IT SUCCEEDS. Whether it bites
# depends only on how fast the producer is: MEASURED 2026-09-11, hsm_serial_at_reader returned 141
# with the serial on line 3 of pkcs15-tool's 30 lines of card I/O, while hsm_reader_name returned 0
# because opensc-tool writes its four short lines in one burst before awk can exit. A caller that
# tested the status read "could not identify this reader" from a reader it had just identified.
# So: match first-wins with a `seen` flag and CONSUME THE WHOLE STREAM. Never `exit` early here.

# Full PC/SC reader NAME for index $1. Smart Card Shell selects by name, not index.
hsm_reader_name() {
    # Cut at the column where the header's "Name" starts, rather than by field number. The
    # Features column is EMPTY for these readers, so "blank $1..$3" ate the first word of the
    # name and yielded "Henarejos Pico Key CCID Interface" — a reader name that matches nothing.
    opensc-tool --list-readers 2>/dev/null \
      | awk -v want="$1" '
          /^Nr\./ { col = index($0, "Name"); next }
          col && $1 == want && !seen { print substr($0, col); seen = 1 }'
}

# Token serial visible at PC/SC reader $1, or empty. Bounded; a blank/mute card yields "".
hsm_serial_at_reader() {
    _hsm_run 25 pkcs15-tool -r "$1" --dump 2>/dev/null \
        | awk -F': *' '/^[[:space:]]*Serial number/ && !seen {print $2; seen = 1}'
}

# PC/SC reader index holding the card with serial $1. Fails (rc 1) if not found or ambiguous.
hsm_reader_for() {
    # Counted explicitly rather than via `set -- $hits`: unquoted parameters do NOT word-split
    # in zsh, so that idiom silently yields one argument containing every hit — a count of 1 no
    # matter how many readers matched, which is precisely the ambiguity this is meant to catch.
    local want="$1" idx s hit="" n=0
    [ -n "$want" ] || { echo "hsm_reader_for: no serial given" >&2; return 1; }
    for idx in $(hsm_reader_indices); do
        s="$(hsm_serial_at_reader "$idx")"
        if [ "$s" = "$want" ]; then hit="$idx"; n=$((n+1)); fi
    done
    if [ "$n" -eq 1 ]; then printf '%s\n' "$hit"; return 0; fi
    if [ "$n" -eq 0 ]; then
        echo "hsm_reader_for: no reader holds a card with serial '$want'" >&2; return 1
    fi
    echo "hsm_reader_for: serial '$want' matches $n readers — refusing to guess" >&2; return 1
}

# PKCS#11 slot INDEX (position in --list-token-slots) for serial $1. Resolved by reading the
# slot list rather than assuming slot-index == reader index; OpenSC usually keeps them in step,
# but "usually" is not a thing to point a wipe at.
hsm_slot_index_for() {
    local want="$1"
    [ -n "$want" ] || { echo "hsm_slot_index_for: no serial given" >&2; return 1; }
    _hsm_run 60 pkcs11-tool --module "$HSM_P11_MODULE" --list-token-slots 2>/dev/null \
      | awk -v want="$want" '
          /^Slot [0-9]+/ { ix++ }
          /serial num/   { gsub(/.*:[ \t]*/, ""); gsub(/[ \t]+$/, "");
                           if ($0 == want && !found) { print ix - 1; found=1 } }
          END { if (!found) exit 1 }'
}

# The PKCS#11 slot listing, as "<decimal slot id> <serial>" lines.
#
# Parsed in shell rather than awk: macOS ships BSD awk, which has no strtonum(), so the hex slot
# id in "Slot 1 (0x4)" cannot be converted there. Measured 2026-09-02 — the gawk version failed
# with "calling undefined function strtonum" and returned nothing at all, which every caller
# would have read as "no such slot".
hsm_slot_table() {
    local line id cur=""
    _hsm_run 60 pkcs11-tool --module "$HSM_P11_MODULE" --list-token-slots 2>/dev/null |
    while IFS= read -r line; do
        case "$line" in
            "Slot "*"("0x*")"*)
                id="${line#*\(}"; id="${id%%\)*}"
                cur="$(printf '%d' "$id" 2>/dev/null)" || cur=""
                ;;
            *"serial num"*:*)
                [ -n "$cur" ] || continue
                line="${line#*: }"
                # strip surrounding whitespace
                line="$(printf '%s' "$line" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')"
                printf '%s %s\n' "$cur" "$line"
                cur=""
                ;;
        esac
    done
}

# PKCS#11 slot ID (the number in "Slot 1 (0x4)") holding serial $1. The ID identifies the slot;
# its position in the list does not. With two cards the ids here were 0x0 and 0x4, so treating an
# ordinal as an id addresses the wrong device.
hsm_slot_id_for() {
    local want="$1" id ser n=0 hit=""
    [ -n "$want" ] || { echo "hsm_slot_id_for: no serial given" >&2; return 1; }
    while read -r id ser; do
        [ "$ser" = "$want" ] && { hit="$id"; n=$((n+1)); }
    done <<EOF
$(hsm_slot_table)
EOF
    [ "$n" -eq 1 ] || { echo "hsm_slot_id_for: '$want' matched $n slots — refusing" >&2; return 1; }
    printf '%s\n' "$hit"
}

# Serial reported by the slot whose ID is $1. Needed because `pkcs11-tool --list-slots` prints
# EVERY slot no matter what --slot / --slot-index say, so "take the first serial" reads whichever
# card is listed first — which is exactly how the battery pinned the wrong device.
hsm_serial_at_slot_id() {
    local want="$1" id ser
    while read -r id ser; do
        [ "$id" = "$want" ] && { printf '%s\n' "$ser"; return 0; }
    done <<EOF
$(hsm_slot_table)
EOF
    return 1
}

# ---- platform detection: is this token an RP2350 board we can recover over SWD? -------------
#
# SWD recovery is only meaningful on the Pico. The production token is a Nitrokey HSM 2
# (USB 20a0:4230) with no debug port at all, so firing a POWMAN cycle or a rescue-DP reset at it
# is not a recovery, it is noise — and a battery that "recovers" a token it cannot reach would be
# reporting a capability it does not have.
#
# The Pico HSM enumerates as 2e8a:10fd. 0x2e8a is the Raspberry Pi vendor id, which is the actual
# claim being made here: this is RP-series silicon with a debug port.
#
# IT ALSO WORKS ON A WEDGED CARD. The wedge is "enumerated but mute" — USB descriptors are still
# there when the applet has stopped answering, so this reads correctly at exactly the moment the
# card cannot be asked anything over PC/SC.
HSM_PICO_VID="${HSM_PICO_VID:-2e8a}"
HSM_PICO_PID="${HSM_PICO_PID:-10fd}"

# USB serials of every attached Pico HSM. The USB serial IS the OTP board id — verified on this
# bench: USB C858BA452202E14A reads back as OTP 0x40130000 = C858BA452202E14A.
hsm_pico_boards() {
    local vid=$((16#$HSM_PICO_VID)) pid=$((16#$HSM_PICO_PID))
    ioreg -p IOUSB -l -w 0 2>/dev/null | awk -v vid="$vid" -v pid="$pid" '
        /"idVendor"/   { for(i=1;i<=NF;i++) if($i=="=") v=$(i+1) }
        /"idProduct"/  { for(i=1;i<=NF;i++) if($i=="=") d=$(i+1) }
        /"USB Serial Number"/ {
            s=$0; sub(/.*= "/,"",s); sub(/".*/,"",s)
            if (v==vid && d==pid && s ~ /^[0-9A-Fa-f]{16}$/) print toupper(s)
        }' | sort -u
}

# The FULL board id pinned for token $1 by HSM_BOARD_MAP, or empty. The map is space-separated
# "token:fullboardid" pairs, the same shape as HSM_CI_PROBE_MAP's "probe:board".
hsm_board_map_lookup() {
    local want="$1" pair
    # SPLIT EXPLICITLY, never by word-splitting. `for pair in ${HSM_BOARD_MAP}` works in bash and
    # does NOT split in zsh — and this file is meant to be SOURCED, so the shell is the caller's
    # choice, not ours. Measured 2026-09-03: under zsh the whole map arrived as one word, the
    # pattern matched the entire string, and the lookup returned
    # "C858BA452202E14A ESP41D722E2:8625B32841D722E2" as a board id. It fails closed (no attached
    # board equals that), but it silently disables recovery, which is its own kind of wrong.
    while IFS= read -r pair; do
        [ -n "$pair" ] || continue
        case "$pair" in
            "$want":*) printf '%s\n' "$(printf '%s' "${pair#*:}" | tr 'a-z' 'A-Z')"; return 0 ;;
        esac
    done <<EOF
$(printf '%s' "${HSM_BOARD_MAP:-}" | tr ' \t' '\n\n')
EOF
    return 1
}

# The full board (OTP) id for token serial $1, or empty. REQUIRES an explicit HSM_BOARD_MAP entry.
#
# WHY THERE IS NO SUFFIX FALLBACK. The token serial carries only the LAST FOUR BYTES of the board id
# ("ESP" + 8 hex chars; OpenSC strips the 5-digit CVC sequence), so the serial alone can never be
# more than a suffix — and a suffix is not an identity. An earlier version matched that suffix and
# accepted the answer when exactly one attached board matched. That uniqueness check tests the WRONG
# PREDICATE, and it was measured failing on 2026-09-03:
#
#   the wanted board is OFF THE BUS (which is *why* recovery is running), an unrelated board sharing
#   its last four bytes is attached  ->  exactly one match, n=1, and the WRONG board is returned rc=0.
#
# Uniqueness among ATTACHED boards is not identity when the right board is the one that is missing.
# The result is not a false positive — it is worse. This function chooses the board that
# hsm-swd-powman-recover.sh halts, power-cycles, rescue-resets and may re-flash, so a wrong answer
# resets a HEALTHY device and reports success. The OTP interlock in that script does not catch it:
# it compares the attached board against the id it was GIVEN, so a wrong resolution is
# self-consistent and passes. It catches a mis-wired probe, not a mis-resolved token.
#
# So identity must be SUPPLIED, never inferred. HSM_BOARD_MAP is space-separated "token:fullboardid"
# pairs (same shape as HSM_CI_PROBE_MAP's "probe:board"). Unmapped means "no SWD recovery path for
# this token" — a fail-closed refusal, not a guess.
hsm_board_for_token() {
    local token="$1" mapped=""
    [ -n "$token" ] || return 1

    # A MAPPED ID IS THE IDENTITY, AND USB PRESENCE IS NOT PART OF IT.
    #
    # An earlier version also required the mapped board to be enumerated on USB. That looked like a
    # useful sanity check and was in fact a serious bug: the wedge state that MOST needs SWD recovery
    # is the card vanishing from the USB bus, so the resolver refused exactly when recovery was the
    # remedy, and the ladder was never even attempted. Measured 2026-09-03 — two consecutive nightly
    # runs ended with five red steps and no recovery attempt, because the board was "not on the bus".
    #
    # The probe reaches the chip over SWD when USB is long gone, and hsm-swd-powman-recover.sh
    # independently verifies the OTP chip id before it touches anything. So presence is a fact to
    # REPORT (hsm_board_attached), never a precondition for resolving identity.
    mapped="$(hsm_board_map_lookup "$token" 2>/dev/null)" || mapped=""
    [ -n "$mapped" ] || return 1
    printf '%s\n' "$mapped"
    return 0
}

# Is board id $1 currently enumerated on USB? A fact worth reporting, never a gate on recovery.
hsm_board_attached() {
    local want b
    want="$(printf '%s' "${1:-}" | tr 'a-z' 'A-Z')"
    [ -n "$want" ] || return 1
    while IFS= read -r b; do
        [ "$b" = "$want" ] && return 0
    done <<EOF
$(hsm_pico_boards | sort -u)
EOF
    return 1
}

# Prove WHICH PHYSICAL DEVICE is in front of us when the card is BLANK. Echoes the board id on
# success. A blank Pico HSM has no EF 2F02 and no token serial, so the only identity it still exposes
# is its USB serial — which IS the RP2350 OTP board id (verified on hardware). This exists because
# hsm-init-hardened.js cannot do it for itself: scsh reads smartcards, not USB descriptors, so the
# wrapper establishes identity and attests it with HSM_BOARD_VERIFIED=1.
#
# It REFUSES when more than one Pico is attached. With two devices on the bus there is no way here to
# tie a PC/SC reader to a particular USB device, so "which one am I about to wipe?" has no answer —
# and INITIALIZE DEVICE is not a question to settle by elimination plus a guess.
hsm_verify_blank_board() {
    local want b n=0 only=""
    want="$(printf '%s' "${1:-}" | tr 'a-z' 'A-Z')"
    [ -n "$want" ] || { printf 'no board id given to verify against\n' >&2; return 1; }
    while IFS= read -r b; do
        [ -n "$b" ] || continue
        only="$b"; n=$((n+1))
    done <<EOF
$(hsm_pico_boards | sort -u)
EOF
    if [ "$n" -eq 0 ]; then
        printf 'no Pico HSM is on the USB bus — there is nothing to verify\n' >&2; return 1
    fi
    if [ "$n" -gt 1 ]; then
        printf '%s Pico boards are attached — a blank card cannot be tied to a PC/SC reader, so this refuses rather than pick one by elimination\n' "$n" >&2
        return 1
    fi
    if [ "$only" != "$want" ]; then
        printf 'the only attached board is %s, not %s — REFUSING\n' "$only" "$want" >&2; return 1
    fi
    printf '%s\n' "$only"
    return 0
}

# True when token $1 is an RP2350 Pico HSM — i.e. SWD recovery is even possible for it.
hsm_token_is_pico() { hsm_board_for_token "$1" >/dev/null 2>&1; }

# Can Smart Card Shell address reader $1 UNAMBIGUOUSLY by name? scsh's `new Card(name)` matches by
# name PREFIX and takes the first hit, so a reader whose full name is a strict PREFIX of another
# reader's name cannot be addressed at all — asking for it returns the other card. Measured
# 2026-09-03: "...Pico Key CCID Interface" is a strict prefix of "...Pico Key CCID Interface 01",
# and asking for the first card's exact full name returned the SECOND card's certificate.
#
# The rule is ASYMMETRIC: the longer name is always safe, the prefix name never is. Which card holds
# which is not stable — they swap across replugs — so this must be asked per run, not assumed.
hsm_reader_scsh_addressable() {
    local idx="$1" me other j
    me="$(hsm_reader_name "$idx" 2>/dev/null)" || return 1
    [ -n "$me" ] || return 1
    for j in $(hsm_reader_indices); do
        [ "$j" = "$idx" ] && continue
        other="$(hsm_reader_name "$j" 2>/dev/null)" || continue
        # If MY name is a strict prefix of another reader's name, scsh may hand me that one instead.
        case "$other" in
            "$me") return 1 ;;      # identical names: unaddressable either way
            "$me"*) return 1 ;;
        esac
    done
    return 0
}

# REFUSE, WITH THE REASON, when scsh cannot address reader $1 (the card we mean is $2). Every scsh
# entry point here runs something destructive, and each one had grown its own partial version of this
# check or none at all: hsm-staging-restore.sh passed a reader NAME and trusted it,
# hsm-staging-e2e.sh passed a name plus HSM_EXPECT_SERIAL and relied on the JS guard to refuse, and
# hsm-fleet-drill.sh had the only full message. Relying on the JS guard works but reports the wrong
# thing — a "WRONG CARD" refusal from inside the initializer reads as a defect in the guard rather
# than as a bench that cannot be addressed. Refusing here, before the wipe, says which it is.
#
# There is no software workaround to reach for. Holding the other board in reset does not remove its
# reader: a held RP2350 stays ENUMERATED, measured 2026-09-03, so PC/SC still lists two readers and
# the prefix match still wins. The remedies are physical.
hsm_require_scsh_addressable() {
    local idx="$1" want="${2:-the intended card}" nm
    command -v hsm_reader_scsh_addressable >/dev/null 2>&1 || return 0
    hsm_reader_scsh_addressable "$idx" && return 0
    nm="$(hsm_reader_name "$idx" 2>/dev/null)"
    echo "REFUSING: reader $idx is named \"$nm\", a strict PREFIX of another attached reader's name. Smart Card Shell matches reader names by PREFIX and takes the first hit, so asking for this reader returns the OTHER card, and this step writes to the card it reaches. Replug so $want takes the longer \"... Interface 01\" name, or detach the other board." >&2
    return 1
}

# ---- the role registry: DEFAULT-DENY for every destructive step --------------------------------
#
# "Which card is a scratch device" used to live only in per-invocation env pins (HSM_CI_SERIAL,
# HSM_RESTORE_SERIAL, ...), so a destructive step was exactly as safe as the expected serial the
# operator supplied that day — and the flash tools that ask for no serial at all were exactly as
# safe as whatever the default probe found. The registry inverts the burden: destructibility is a
# property of the SERIAL, recorded in the committed staging registry (tools/hsm-staging-registry.json), and everything
# else — unlisted, unknown, `prod`, or a registry that cannot be read — is PROTECTED. Future
# hardware (the prod Nitrokeys) is covered the moment it enumerates, because unlisted IS the
# protected state.
#
# This supersedes hsm_assert_not (refuse if reader $1 holds serial $2), which had the right
# fail-closed instinct, was unit-tested, and was never wired to a single caller. Its duty —
# "cannot read" must mean "not safe" — carries into hsm_role_of below.

# Where the registry lives: tools/hsm-staging-registry.json, a sibling of this file -- the SAME file
# hsm-staging-registry.sh loads for the board and probe maps. One file, one answer: this gate began
# with its own tools/hsm-staging-registry.json, and two files that must agree about which card may be wiped,
# with nothing making them agree, is the failure this gate exists to prevent. Resolved per call, not
# at source time, so HSM_STAGING_REGISTRY_FILE (the loader's own override) is honoured however the
# resolver was sourced, and nothing is assumed about the caller's working directory.
_hsm_roles_path() {
    if [ -n "${HSM_STAGING_REGISTRY_FILE:-}" ]; then printf '%s\n' "$HSM_STAGING_REGISTRY_FILE"; return 0; fi
    local d=""
    d="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" 2>/dev/null && pwd)" || return 1
    printf '%s\n' "$d/hsm-staging-registry.json"
}

# The role of token serial $1: "staging", "prod", or "protected" -- the answer for everything
# else, including the empty serial, an unlisted serial, an unknown role word, a serial listed twice,
# and a registry that is missing, unreadable, not valid JSON, or of another schema. Prints exactly
# one word and always returns 0: this is a SAFETY READOUT, not a lookup that can fail into a
# caller's default, because "protected" IS the failure mode. A registry that cannot be read warns
# on stderr so a broken deployment is diagnosable, and still answers protected.
#
# The committed registry is staging-only (its loader refuses any other role), so a production card is
# protected by being ABSENT. "prod" is still read distinctly so a fixture or a future split registry
# cannot turn it into permission.
hsm_role_of() {
    local want="${1:-}" f="" role=""
    f="$(_hsm_roles_path 2>/dev/null)" || f=""
    if [ -z "$want" ]; then printf 'protected\n'; return 0; fi
    if [ -z "$f" ] || [ ! -f "$f" ] || [ ! -r "$f" ]; then
        printf 'hsm_role_of: no readable staging registry at %s — every card is PROTECTED until one exists\n' \
            "${f:-<path unresolved>}" >&2
        printf 'protected\n'; return 0
    fi
    if ! command -v python3 >/dev/null 2>&1; then
        printf 'hsm_role_of: python3 is required to read %s — every card is PROTECTED\n' "$f" >&2
        printf 'protected\n'; return 0
    fi
    role="$(python3 -c '
import json, sys
# NO `assert` HERE: python3 -O (or PYTHONOPTIMIZE in the environment) strips assert statements, and
# these are the checks that keep an unrecognised registry from naming a card wipeable.
try:
    data = json.load(open(sys.argv[1], encoding="utf-8"))
    if not (isinstance(data, dict) and data.get("schema") == "regalia.staging-hardware/v1"):
        raise ValueError("not a regalia.staging-hardware/v1 registry")
    devices = data.get("devices")
    if not isinstance(devices, list):
        raise ValueError("devices is not a list")
    matches = [d for d in devices if isinstance(d, dict) and d.get("token_serial") == sys.argv[2]]
    # Listed twice is ambiguous, and ambiguity never arms a wipe.
    role = matches[0].get("role") if len(matches) == 1 else None
    print(role if role in ("staging", "prod") else "protected")
except Exception:
    print("unreadable")
' "$f" "$want" 2>/dev/null)" || role="unreadable"
    case "$role" in
        staging|prod|protected) printf '%s\n' "$role" ;;
        *)
            printf 'hsm_role_of: %s is not a readable staging registry — every card is PROTECTED\n' "$f" >&2
            printf 'protected\n' ;;
    esac
    return 0
}

# REFUSE, WITH THE REASON AND THE REMEDY, unless token serial $1 is registered `staging`. This is
# the DEFAULT-DENY gate every destructive entry point calls after resolving its target by serial:
# --initialize, DKEK import, key deletion, re-provisioning. A refusal nobody can act on is how
# safety checks end up commented out, so it names the serial, the registry it consulted, and the
# one legitimate way to widen it.
hsm_assert_staging() {
    local want="${1:-}" role f
    f="$(_hsm_roles_path 2>/dev/null)" || f="<registry path unresolved>"
    [ -n "$want" ] || {
        echo "REFUSING: no token serial to check against the role registry. A destructive step" >&2
        echo "may not run against an unnamed card — resolve the target by serial first." >&2
        return 1
    }
    role="$(hsm_role_of "$want" 2>/dev/null)"
    if [ "$role" != staging ]; then
        echo "REFUSING: token $want is not registered as staging in $f (role: ${role:-unknown})." >&2
        echo "  Default-deny: ONLY serials listed 'staging' in the committed registry may be wiped," >&2
        echo "  re-personalised or reflashed. Unlisted, prod, and unreadable-registry are all protected." >&2
        echo "  If this card really is a scratch device, add '$want=staging' to the registry in a" >&2
        echo "  pull request. Do not work around the refusal locally." >&2
        return 1
    fi
    return 0
}

# The token serial pinned to board id $1 by HSM_BOARD_MAP, or empty with a refusal on stderr.
#
# WHY IT IS SHARED. Tools that flash a board over SWD also have to TALK to its card over PC/SC —
# to count objects, take an inventory, or ask whether it answers at all. Those calls had no slot or
# reader selector, so on the two-board bench they addressed whichever token enumerated first. The
# board was pinned by OTP id and the measurement was taken from the other card: an experiment whose
# subject and whose evidence are two different devices. Every such tool now resolves the token from
# the board it just verified, through the same map hsm_assert_staging_board reverse-maps.
hsm_token_for_board() {
    local board pair matches n
    board="$(printf '%s' "${1:-}" | tr 'a-f' 'A-F')"
    [ -n "$board" ] || { echo "hsm_token_for_board: no board id given" >&2; return 1; }
    matches=""
    while IFS= read -r pair; do
        [ -n "$pair" ] || continue
        [ "$(printf '%s' "${pair#*:}" | tr 'a-f' 'A-F')" = "$board" ] || continue
        matches="$matches${pair%%:*} "
    done <<EOF
$(printf '%s' "${HSM_BOARD_MAP:-}" | tr ' \t' '\n\n')
EOF
    # EXACTLY ONE, NEVER THE FIRST. HSM_BOARD_MAP is an environment variable that the standalone
    # destructive tools accept directly — they do not load the committed registry — so a duplicate
    # entry for one board is a way to pass the board gate and then have the reader or slot resolved
    # from a DIFFERENT token. An ambiguous map is a mistake worth stopping on, not one to resolve
    # by ordering.
    n="$(printf '%s' "$matches" | wc -w | tr -d ' ')"
    if [ "$n" = "1" ]; then
        printf '%s\n' "${matches% }"
        return 0
    fi
    if [ "$n" = "0" ]; then
        echo "hsm_token_for_board: board $board has no HSM_BOARD_MAP entry, so its card cannot be" >&2
        echo "named — refusing to address whichever token enumerates first." >&2
    else
        echo "hsm_token_for_board: board $board is mapped to $n tokens ($matches) — refusing to" >&2
        echo "pick one. Fix HSM_BOARD_MAP: a board has exactly one card." >&2
    fi
    return 1
}

# The role gate for tools that address a BOARD over SWD rather than a token over PC/SC. Flash
# erases and filesystem rewrites go down the debug port, where no token serial exists — the
# stable identity there is the RP2350 OTP board id. Reverse-map the board through the same
# REQUIRED HSM_BOARD_MAP that hsm_board_for_token uses, then apply the same registry rule. A
# board with no map entry has no token to ask about, which is a refusal, never a guess.
hsm_assert_staging_board() {
    local board pair
    board="$(printf '%s' "${1:-}" | tr 'a-f' 'A-F')"
    [ -n "$board" ] || {
        echo "REFUSING: no board id to check against the role registry — a destructive step may" >&2
        echo "not run against an unnamed board. Pass the OTP board id (HSM_BOARD_MAP has the pairing)." >&2
        return 1
    }
    # Split explicitly (see hsm_board_map_lookup): this file is sourced, so the shell is the
    # caller's choice and word-splitting is not portable.
    while IFS= read -r pair; do
        [ -n "$pair" ] || continue
        [ "$(printf '%s' "${pair#*:}" | tr 'a-f' 'A-F')" = "$board" ] || continue
        hsm_assert_staging "${pair%%:*}"
        return $?
    done <<EOF
$(printf '%s' "${HSM_BOARD_MAP:-}" | tr ' \t' '\n\n')
EOF
    echo "REFUSING: board $board has no HSM_BOARD_MAP entry, so it cannot be tied to a registered" >&2
    echo "token serial — refusing rather than guess which card this is. Add 'token:$board' to" >&2
    echo "HSM_BOARD_MAP (and list that token as staging in the role registry) if this is a scratch board." >&2
    return 1
}

# Prove the board at the other end of debug probe $1 is board id $2, by reading the RP2350 OTP
# chip id over SWD (0x40130000, 64-bit) BEFORE anything destructive goes down the wire. This is
# the interlock hsm-quiesce.sh pioneered, shared so every flash tool gets it in one line instead
# of growing its own partial copy. FAILS CLOSED: an unreadable OTP is an unidentified board, and
# an unidentified board is not a flashable one. Echoes the verified board id on success.
hsm_verify_board_over_probe() {
    local probe="${1:-}" want="$2" ocd="${3:-${OCD_BIN:-$HOME/tools/xpack-openocd-0.12.0-7/bin/openocd}}"
    local otp lo hi got
    want="$(printf '%s' "$want" | tr 'a-f' 'A-F')"
    [ -n "$probe" ] && [ -n "$want" ] || {
        echo "REFUSING: hsm_verify_board_over_probe needs a probe serial and the expected board id" >&2
        return 1
    }
    [ -x "$ocd" ] || {
        echo "REFUSING: openocd not found at $ocd (set OCD_BIN) — cannot verify which board the" >&2
        echo "probe reaches, so nothing may be sent down it." >&2
        return 1
    }
    # Capture, then match — never `producer | grep -q` under pipefail (grep -q closes the pipe on
    # the first match and the producer dies 141, reporting failure exactly on success).
    otp="$(perl -e 'alarm 60; exec @ARGV' -- "$ocd" -f interface/cmsis-dap.cfg \
        -c "adapter serial $probe" -c "adapter speed 5000" -f target/rp2350.cfg \
        -c "gdb port disabled" -c "tcl port disabled" -c "telnet port disabled" \
        -c init -c "mdw 0x40130000 2" -c exit 2>&1)" || otp=""
    lo="$(grep -oE '0x40130000: [0-9a-f]{8} [0-9a-f]{8}' <<< "$otp" | awk '{print $2}')"
    hi="$(grep -oE '0x40130000: [0-9a-f]{8} [0-9a-f]{8}' <<< "$otp" | awk '{print $3}')"
    [ -n "$lo" ] && [ -n "$hi" ] || {
        echo "REFUSING: could not read the OTP board id over probe $probe — an unreadable board is" >&2
        echo "an unidentified board, and unidentified boards are not flashable." >&2
        return 1
    }
    got="$(printf '%s%s' "$hi" "$lo" | tr 'a-f' 'A-F')"
    [ "$got" = "$want" ] || {
        echo "REFUSING: probe $probe reaches board $got, expected $want" >&2
        return 1
    }
    printf '%s\n' "$got"
    return 0
}
