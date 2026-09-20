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
    local maps probes raw token board probe
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
    seen = set()
    for d in devices:
        need(isinstance(d, dict), 'a device entry is not an object')
        need(d.get('role') == 'staging', f"device {d.get('token_serial')!r} has role {d.get('role')!r}, expected 'staging'")
        need(d.get('kind') == 'pico-hsm2', f"device {d.get('token_serial')!r} has kind {d.get('kind')!r}, expected 'pico-hsm2'")
        t, b = d.get('token_serial'), d.get('board_id')
        p = (d.get('debug_probe') or {}).get('serial')
        need(isinstance(t, str) and re.fullmatch(r'ESP[0-9A-F]{8}', t), f'token_serial {t!r} is malformed')
        need(isinstance(b, str) and re.fullmatch(r'[0-9A-F]{16}', b), f'board_id {b!r} is malformed')
        need(isinstance(p, str) and re.fullmatch(r'[0-9A-F]{16}', p), f'debug_probe.serial {p!r} is malformed')
        need(not ({t, b, p} & seen), f'{t} reuses an identifier already claimed by another device')
        seen.update((t, b, p))
        print(f'{t}\t{b}\t{p}')
except Exception as exc:
    print(f'registry invalid: {exc}', file=sys.stderr)
    raise SystemExit(1)
PY
    )" || return 1
    maps=""; probes=""
    while IFS=$'\t' read -r token board probe; do
        [ -n "$token" ] || continue
        maps="${maps:+$maps }$token:$board"
        probes="${probes:+$probes }$probe:$board"
    done <<< "$raw"
    [ -n "$maps" ] || { echo "registry contains no devices: $registry" >&2; return 1; }
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
    export HSM_BOARD_MAP="$maps" HSM_CI_PROBE_MAP="$probes"
}
