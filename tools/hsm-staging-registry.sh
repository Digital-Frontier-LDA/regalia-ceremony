#!/usr/bin/env bash
# Load the committed staging inventory into the map variables consumed by recovery tooling.
# The parser is intentionally strict and fail-closed: malformed or incomplete records never
# produce a partial map that could aim a destructive operation at an unintended board.

# Canonical form of a whitespace-separated pair list: one pair per line, sorted, duplicates removed.
# The input is split with tr rather than by unquoted expansion so a value containing a glob character
# is compared as text and never expanded against the working directory.
_hsm_registry_pairs() {
    printf '%s' "$1" | tr -s ' \t\n' '\n' | sed '/^$/d' | LC_ALL=C sort -u
}

hsm_staging_registry_load() {
    local registry="${HSM_STAGING_REGISTRY_FILE:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/hsm-staging-registry.json}"
    local maps probes devauts raw
    [ -r "$registry" ] || { echo "registry unavailable: $registry" >&2; return 1; }
    raw="$(python3 - "$registry" <<'PY'
import json, re, sys

# NO `assert` IN THIS VALIDATOR. `python3 -O`, or a PYTHONOPTIMIZE set anywhere in the environment,
# REMOVES assert statements outright — so every check below would vanish and a malformed registry
# would load clean. This registry is what decides which cards may be wiped; it must validate the
# same way no matter how the interpreter was invoked.
def need(cond, msg):
    if not cond:
        raise ValueError(msg)

try:
    data = json.load(open(sys.argv[1], encoding='utf-8'))
    need(isinstance(data, dict), 'top level is not an object')
    devices = data.get('devices')
    need(data.get('schema') == 'regalia.staging-hardware/v1',
         f"schema is {data.get('schema')!r}, expected 'regalia.staging-hardware/v1'")
    need(data.get('environment') == 'staging', f"environment is {data.get('environment')!r}, expected 'staging'")
    need(isinstance(devices, list) and devices, 'devices is empty or not a list')
    # TWO KINDS, IDENTIFIED BY WHAT EACH CARD CAN ACTUALLY PROVE.
    #
    # A Pico HSM is an RP2350 board: it has an OTP chip id readable over SWD and a debug probe, and
    # those are what the flash tools address it by. A Nitrokey HSM 2 has neither — its hardware
    # identity is C.DevAut in EF 2F02, verifiable to the CardContact root. Requiring board_id and
    # debug_probe of EVERY device is why the authorised Nitrokey units could not be listed at all,
    # and an unlistable card is one every drill refuses (regalia#481).
    #
    # The fields are required per kind and REFUSED where they do not belong: a board_id on a
    # Nitrokey entry is a copy-paste from the Pico rows, and accepting it would let the flash tools
    # aim SWD at a card that has no debug port.
    seen = set()
    for d in devices:
        need(isinstance(d, dict), 'a device entry is not an object')
        t = d.get('token_serial')
        need(d.get('role') == 'staging', f"device {t!r} has role {d.get('role')!r}, expected 'staging'")
        kind = d.get('kind')
        need(kind in ('pico-hsm2', 'nitrokey-hsm2', 'yubikey-piv'),
             f"device {t!r} has kind {kind!r}, expected 'pico-hsm2', 'nitrokey-hsm2' or 'yubikey-piv'")
        if kind == 'yubikey-piv':
            # A YubiKey is not a SmartCard-HSM: it has no DKEK, no C.DevAut and no board to flash.
            # Its identity is the PIV serial, and what governs a destructive step is the SLOT and
            # the fingerprint of the public key in it — `ykman piv reset` is the wipe here, and it
            # takes the whole PIV application, not one object. The slot is recorded so a tool can
            # say which slot it is authorised to touch.
            slot = d.get('piv_slot')
            fp = d.get('piv_9a_sha256')
            need(isinstance(t, str) and re.fullmatch(r'[0-9]{6,10}', t),
                 f'token_serial {t!r} is malformed for a YubiKey (expected the decimal PIV serial)')
            need(isinstance(slot, str) and re.fullmatch(r'9[ade]', slot, re.I),
                 f'piv_slot {slot!r} is malformed (expected a PIV slot such as 9a)')
            need(isinstance(fp, str) and re.fullmatch(r'[0-9a-f]{64}', fp),
                 f'piv_9a_sha256 {fp!r} is not a lowercase sha256 of the slot public key (DER)')
            need('board_id' not in d and 'debug_probe' not in d and 'devaut_chr' not in d,
                 f'{t} is a YubiKey and has no board id, debug probe or C.DevAut; remove those fields')
            need(not ({t, fp} & seen), f'{t} reuses an identifier already claimed by another device')
            seen.update((t, fp))
            print(f'yubikey\t{t}\t{slot}\t{fp}')
        elif kind == 'pico-hsm2':
            b = d.get('board_id')
            p = (d.get('debug_probe') or {}).get('serial')
            need(isinstance(t, str) and re.fullmatch(r'ESP[0-9A-F]{8}', t), f'token_serial {t!r} is malformed')
            need(isinstance(b, str) and re.fullmatch(r'[0-9A-F]{16}', b), f'board_id {b!r} is malformed')
            need(isinstance(p, str) and re.fullmatch(r'[0-9A-F]{16}', p), f'debug_probe.serial {p!r} is malformed')
            need(not ({t, b, p} & seen), f'{t} reuses an identifier already claimed by another device')
            seen.update((t, b, p))
            print(f'pico\t{t}\t{b}\t{p}')
        else:
            chr_, sha = d.get('devaut_chr'), d.get('devaut_sha256')
            need(isinstance(t, str) and re.fullmatch(r'DENK[0-9]{7}', t), f'token_serial {t!r} is malformed for a Nitrokey HSM 2')
            need(isinstance(chr_, str) and re.fullmatch(r'[A-Z0-9]{8,16}', chr_),
                 f'devaut_chr {chr_!r} is malformed (the certificate holder reference from EF 2F02)')
            need(isinstance(sha, str) and re.fullmatch(r'[0-9a-f]{64}', sha),
                 f'devaut_sha256 {sha!r} is not a lowercase sha256 of C.DevAut')
            need('board_id' not in d and 'debug_probe' not in d,
                 f'{t} is a Nitrokey HSM 2 and has no board id or debug probe; remove those fields')
            need(not ({t, sha} & seen), f'{t} reuses an identifier already claimed by another device')
            seen.update((t, sha))
            print(f'nitrokey\t{t}\t{chr_}\t{sha}')
except Exception as exc:
    print(f'registry invalid: {exc}', file=sys.stderr)
    raise SystemExit(1)
PY
    )" || return 1
    # The board and probe maps stay PICO-ONLY: they exist for tools that drive a board over SWD,
    # and a Nitrokey has no board to name. Its pin goes into HSM_DEVAUT_MAP, which is what a
    # destructive step checks the card against before it wipes anything.
    maps=""; probes=""; devauts=""; yubikeys=""
    local kind a b c
    while IFS=$'\t' read -r kind a b c; do
        [ -n "$kind" ] || continue
        case "$kind" in
            pico)     maps="${maps:+$maps }$a:$b"; probes="${probes:+$probes }$c:$b" ;;
            nitrokey) devauts="${devauts:+$devauts }$a:$c" ;;
            # serial:slot:pubkey-sha — what a destructive PIV step checks before `ykman piv reset`.
            yubikey)  yubikeys="${yubikeys:+$yubikeys }$a:$b:$c" ;;
        esac
    done <<< "$raw"
    [ -n "$maps$devauts$yubikeys" ] || { echo "registry contains no devices: $registry" >&2; return 1; }
    # An override is compared as a SET of pairs, not as a string. Both maps are lists of independent
    # token:board / probe:board pairs whose order carries no meaning, and an exact string comparison
    # refused the CI repo variables for listing the same correct pairs in a different order than the
    # registry file — which turned every scheduled battery red with "disagrees with registry" while
    # nothing about the hardware disagreed. What must still refuse is any difference in the pairs
    # themselves: a probe or token paired with the other board, a device missing, or one extra.
    if [ -n "${HSM_BOARD_MAP:-}" ] && [ "$(_hsm_registry_pairs "$HSM_BOARD_MAP")" != "$(_hsm_registry_pairs "$maps")" ]; then
        echo "HSM_BOARD_MAP disagrees with registry; refusing override" >&2; return 1
    fi
    if [ -n "${HSM_CI_PROBE_MAP:-}" ] && [ "$(_hsm_registry_pairs "$HSM_CI_PROBE_MAP")" != "$(_hsm_registry_pairs "$probes")" ]; then
        echo "HSM_CI_PROBE_MAP disagrees with registry; refusing override" >&2; return 1
    fi
    if [ -n "${HSM_DEVAUT_MAP:-}" ] && [ "$(_hsm_registry_pairs "$HSM_DEVAUT_MAP")" != "$(_hsm_registry_pairs "$devauts")" ]; then
        echo "HSM_DEVAUT_MAP disagrees with registry; refusing override" >&2; return 1
    fi
    export HSM_BOARD_MAP="$maps" HSM_CI_PROBE_MAP="$probes" HSM_DEVAUT_MAP="$devauts" HSM_YUBIKEY_MAP="$yubikeys"
}
