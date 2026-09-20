#!/usr/bin/env bash
# hsm-ceremony-scripts.sh — resolve the ceremony helper scripts, wherever this checkout keeps them.
#
# WHY IT EXISTS. These tools were written in the monorepo, where the ceremony lived under
# ceremony/qubes/scripts/. In the published repository it is qubes/scripts/, and the defaults kept
# the old prefix — so `hsm-cycle-test.sh --full`, `hsm-staging-restore.sh`, `hsm-staging-pin.sh` and
# most of `hsm-scenarios.sh` pointed at files that do not exist here. Each would have failed at the
# moment it reached for a helper, on a bench, mid-run, having already touched a card.
#
# Sourcing this defines HSM_CEREMONY_SCRIPTS (the directory) and hsm_ceremony_script (one file),
# preferring this repository's layout and falling back to the monorepo one so a checkout of either
# shape works. Nothing is executed and nothing is required to exist: a caller that needs a helper
# says so itself, with its own message.
[ -n "${HSM_CEREMONY_SCRIPTS:-}" ] || {
    _hcs_repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
    for _hcs_c in "$_hcs_repo/qubes/scripts" "$_hcs_repo/ceremony/qubes/scripts"; do
        [ -d "$_hcs_c" ] && { HSM_CEREMONY_SCRIPTS="$_hcs_c"; break; }
    done
    HSM_CEREMONY_SCRIPTS="${HSM_CEREMONY_SCRIPTS:-$_hcs_repo/qubes/scripts}"
    unset _hcs_repo _hcs_c
}

# Path to ONE ceremony script by name, preferring a copy that exists.
hsm_ceremony_script() {
    local n="${1:-}" c
    [ -n "$n" ] || { echo "hsm_ceremony_script: no script name given" >&2; return 1; }
    for c in "$HSM_CEREMONY_SCRIPTS/$n" "$(dirname "$HSM_CEREMONY_SCRIPTS")/../ceremony/qubes/scripts/$n"; do
        [ -r "$c" ] && { printf '%s' "$c"; return 0; }
    done
    printf '%s' "$HSM_CEREMONY_SCRIPTS/$n"
}
