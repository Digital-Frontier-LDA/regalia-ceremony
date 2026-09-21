#!/usr/bin/env bash
# ceremony-python.sh — find the interpreter that has the ceremony's hash-pinned dependencies.
# Source it; it defines two functions and changes nothing by itself.
#
# WHY THIS EXISTS. The pinned dependencies (pycvc, mnemonic, shamir_mnemonic, pycryptodome) go into
# a venv, never the system interpreter — and the repo had FOUR different opinions about where that
# venv is:
#
#     qubes/scripts/dev-image-bootstrap.sh   creates  /opt/dev-bin/regalia-venv      <- the installer
#     qubes/emulator/run-tests.sh            looked in ~/.local/share/akash-hsm-venv
#     hardware/pico-hsm/STAGING-GATE-GREEN.md  documents ~/.local/share/regalia-ceremony-venv
#     the qualification box                  actually had ~/.venvs/regalia-qual
#
# Nothing looked where the installer writes. On a freshly bootstrapped dev image the emulator tier
# therefore fell through to the system python3 and six suites failed with ModuleNotFoundError and
# "EVM derivation needs keccak256" — six unrelated-looking failures whose single cause was an
# interpreter nobody had pointed at the dependencies. Measured on this box 2026-09-21: 6 suites
# failed; with the venv on PATH, 3 of them passed unchanged and the rest were daemon issues.
#
# A search alone is not enough: a path can EXIST and its interpreter still be missing a module, so
# candidates are accepted only after they import what the caller asked for.

# ceremony_python_find [module]... -> prints the bin dir of the first interpreter that imports them
ceremony_python_find() {
  local mods=("$@") c py
  # $HOME is /root under sudo, which is not where a developer's venv lives — the invoking user's
  # home is searched too, or `sudo run-tests.sh` can never find it.
  local homes=("$HOME")
  if [ -n "${SUDO_USER:-}" ]; then
    local sudo_home
    sudo_home="$(getent passwd "$SUDO_USER" 2>/dev/null | cut -d: -f6)"
    [ -n "$sudo_home" ] && [ "$sudo_home" != "$HOME" ] && homes+=("$sudo_home")
  fi
  local cands=()
  [ -n "${CEREMONY_VENV:-}" ] && cands+=("$CEREMONY_VENV")
  cands+=(/opt/dev-bin/regalia-venv)                       # what dev-image-bootstrap.sh creates
  local h
  for h in "${homes[@]}"; do
    cands+=("$h/.local/share/akash-hsm-venv" "$h/.local/share/regalia-ceremony-venv" "$h/.venvs/regalia-qual")
  done
  for c in "${cands[@]}"; do
    py="$c/bin/python3"
    [ -x "$py" ] || continue
    if [ "${#mods[@]}" -eq 0 ] || "$py" -c "import $(IFS=,; echo "${mods[*]}")" >/dev/null 2>&1; then
      printf '%s\n' "$c/bin"; return 0
    fi
  done
  # The system interpreter counts as a candidate when it genuinely has them (CI installs them there).
  py="$(command -v python3 2>/dev/null)" || return 1
  if [ "${#mods[@]}" -eq 0 ] || "$py" -c "import $(IFS=,; echo "${mods[*]}")" >/dev/null 2>&1; then
    printf '%s\n' "$(dirname "$py")"; return 0
  fi
  return 1
}

# ceremony_python_prefer [module]... — prepend that bin dir to PATH if one was found. Never fails:
# for callers that have their own dependency errors and only want the venv preferred when present.
ceremony_python_prefer() {
  local bin; bin="$(ceremony_python_find "$@")" || return 0
  case ":$PATH:" in *":$bin:"*) :;; *) PATH="$bin:$PATH";; esac
  export PATH
}

# ceremony_python_require <module>... — prefer it, or REFUSE. For test tiers and gates, where an
# interpreter that cannot import the pinned deps produces failures that describe the environment
# instead of the code: a run that cannot evaluate must say so, not report results.
ceremony_python_require() {
  local bin
  if bin="$(ceremony_python_find "$@")"; then
    case ":$PATH:" in *":$bin:"*) :;; *) PATH="$bin:$PATH";; esac
    export PATH
    return 0
  fi
  cat >&2 <<MSG
REFUSING: no interpreter here can import the ceremony's pinned dependencies ($*).

  Looked in \$CEREMONY_VENV, /opt/dev-bin/regalia-venv, and ~/.local/share/akash-hsm-venv,
  ~/.local/share/regalia-ceremony-venv, ~/.venvs/regalia-qual (for both \$HOME and \$SUDO_USER),
  and at the system python3.

  Build the venv the way the dev image does:

      python3 -m venv /opt/dev-bin/regalia-venv
      /opt/dev-bin/regalia-venv/bin/pip install --require-hashes -r qubes/requirements.txt

  or point CEREMONY_VENV at one you already have. Running the suites against an interpreter
  without these modules produces failures about the environment, not about the code — which is
  why this refuses instead of continuing.
MSG
  return 1
}
