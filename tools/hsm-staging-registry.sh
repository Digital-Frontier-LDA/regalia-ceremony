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
try:
    data = json.load(open(sys.argv[1], encoding='utf-8'))
    devices = data['devices']
    assert data['schema'] == 'regalia.staging-hardware/v1'
    assert data['environment'] == 'staging' and devices
    seen = set()
    for d in devices:
        assert d['role'] == 'staging' and d['kind'] == 'pico-hsm2'
        t, b = d['token_serial'], d['board_id']
        p = d['debug_probe']['serial']
        assert re.fullmatch(r'ESP[0-9A-F]{8}', t)
        assert re.fullmatch(r'[0-9A-F]{16}', b) and re.fullmatch(r'[0-9A-F]{16}', p)
        assert not ({t, b, p} & seen)
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
