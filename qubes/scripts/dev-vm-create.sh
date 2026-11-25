#!/usr/bin/env bash
# dev-vm-create.sh — create (or resize) the Qubes DEV StandaloneVM from dom0.
#
# Run in dom0. It performs the "## Build the dev VM" sequence from qubes/DEV-IMAGE.md, with the size,
# RAM and CPU count as knobs instead of numbers edited by hand:
#   bash dev-vm-create.sh                                  # defaults, sized to this machine
#   VCPUS=8 MAXMEM=57344 ROOT_SIZE=80g bash dev-vm-create.sh
#   DRY_RUN=1 bash dev-vm-create.sh                        # print the commands, change nothing
#
# Knobs (environment, all optional):
#   VM=dev-regalia  TEMPLATE=debian-12  LABEL=blue  ROOT_SIZE=60g  PRIVATE_SIZE=40g  MEMORY=4096
#   VCPUS   default: host CPUs - 2 (at least 2)
#   MAXMEM  default: host RAM in MiB - 6144 (at least 4096), ~6 GiB left for dom0 and the sys-* qubes
#   DRY_RUN=1  print every command instead of running it
#
# Idempotent: an existing VM is not recreated. Its prefs are (re)applied and its volumes grown;
# a volume already at or above the requested size is left alone (qvm-volume only grows).
#
# SEPARATION. This provisions ONLY the dev StandaloneVM, which has network (sys-firewall) and will
# run editors and AI CLIs. It must never touch the vault-tools ceremony template: not create it, not
# clone it, not base a VM on it, and never give it a netvm. The guards below refuse those cases, and
# refuse to modify an existing qube that is not a StandaloneVM (a TemplateVM built per the
# DEV-IMAGE.md alternative is re-isolated with `netvm none`; this script would undo that).
set -euo pipefail

VM="${VM:-dev-regalia}"
TEMPLATE="${TEMPLATE:-debian-12}"
LABEL="${LABEL:-blue}"
ROOT_SIZE="${ROOT_SIZE:-60g}"
PRIVATE_SIZE="${PRIVATE_SIZE:-40g}"
MEMORY="${MEMORY:-4096}"
VCPUS="${VCPUS:-}"
MAXMEM="${MAXMEM:-}"
DRY_RUN="${DRY_RUN:-0}"
CEREMONY_TEMPLATE=vault-tools

die(){ echo "dev-vm-create: $*" >&2; exit 1; }
note(){ echo "dev-vm-create: $*"; }
run(){
  printf '+'; printf ' %q' "$@"; printf '\n'
  [ "$DRY_RUN" = 1 ] || "$@"
}

# The ceremony image is off limits, whatever the spelling.
lc(){ printf '%s' "$1" | tr '[:upper:]' '[:lower:]'; }
[ "$(lc "$VM")" != "$CEREMONY_TEMPLATE" ] \
  || die "refusing: VM='$VM' is the ceremony template. This script only provisions the dev VM."
[ "$(lc "$TEMPLATE")" != "$CEREMONY_TEMPLATE" ] \
  || die "refusing: TEMPLATE='$TEMPLATE' is the ceremony template; the dev VM must not be built from it."

have_qvm=0
command -v qvm-prefs >/dev/null 2>&1 && have_qvm=1
if [ "$have_qvm" = 0 ]; then
  [ "$DRY_RUN" = 1 ] || die "not in dom0 (qvm-prefs not found). Use DRY_RUN=1 to preview."
  note "qvm-* not found: dry run without dom0, assuming '$VM' does not exist yet."
fi

# Host size. dom0's own nproc and /proc/meminfo describe dom0, not the machine; `xl info` describes
# the machine. Fall back to the local view only when xl is unavailable, and say so.
host_cpus="" host_mib="" src="xl info"
xlinfo="$(xl info 2>/dev/null || sudo -n xl info 2>/dev/null || true)"
if [ -n "$xlinfo" ]; then
  host_cpus="$(awk -F: '$1 ~ /^nr_cpus/ {gsub(/ /,"",$2); print $2}' <<<"$xlinfo")"
  host_mib="$(awk -F: '$1 ~ /^total_memory/ {gsub(/ /,"",$2); print $2}' <<<"$xlinfo")"
fi
if [ -z "$host_cpus" ] || [ -z "$host_mib" ]; then
  src="nproc + /proc/meminfo (xl unavailable; in dom0 this may undercount RAM)"
  host_cpus="$(nproc)"
  host_mib="$(awk '/^MemTotal:/ {print int($2/1024)}' /proc/meminfo)"
fi

if [ -z "$VCPUS" ]; then
  VCPUS=$(( host_cpus - 2 )); [ "$VCPUS" -ge 2 ] || VCPUS=2
  vcpus_how="auto: $host_cpus CPUs - 2, min 2"
else vcpus_how="set"; fi
if [ -z "$MAXMEM" ]; then
  MAXMEM=$(( host_mib - 6144 )); [ "$MAXMEM" -ge 4096 ] || MAXMEM=4096
  maxmem_how="auto: $host_mib MiB - 6144, min 4096"
else maxmem_how="set"; fi

for v in VCPUS MAXMEM MEMORY; do
  case "${!v}" in ''|*[!0-9]*) die "$v='${!v}' must be a positive integer";; esac
  [ "${!v}" -gt 0 ] || die "$v must be greater than 0"
done
[ "$MEMORY" -le "$MAXMEM" ] || die "MEMORY=$MEMORY exceeds MAXMEM=$MAXMEM"

# A size such as 60g, 60G, 60GiB (1024-based) or 60GB (1000-based), or plain bytes, to bytes.
to_bytes(){
  local s n u m
  s="$(lc "$1")"
  [[ "$s" =~ ^([0-9]+)([kmgt]?)(i?b?)$ ]] || die "size '$1' not understood (use e.g. 60g)"
  n="${BASH_REMATCH[1]}" u="${BASH_REMATCH[2]}" m=1024
  [ "${BASH_REMATCH[3]}" = b ] && m=1000
  case "$u" in k) n=$(( n*m ));; m) n=$(( n*m*m ));; g) n=$(( n*m*m*m ));; t) n=$(( n*m*m*m*m ));; esac
  echo "$n"
}
root_bytes="$(to_bytes "$ROOT_SIZE")"
private_bytes="$(to_bytes "$PRIVATE_SIZE")"

echo "== dev VM '$VM' (host size from $src) =="
echo "  template=$TEMPLATE label=$LABEL netvm=sys-firewall"
echo "  vcpus=$VCPUS ($vcpus_how)  maxmem=$MAXMEM MiB ($maxmem_how)  memory=$MEMORY MiB"
echo "  root=$ROOT_SIZE  private=$PRIVATE_SIZE"
[ "$DRY_RUN" = 1 ] && echo "  DRY RUN: printing commands only"

exists=0
if [ "$have_qvm" = 1 ] && qvm-check --quiet "$VM" 2>/dev/null; then exists=1; fi

if [ "$exists" = 1 ]; then
  klass="$(qvm-prefs "$VM" klass)"
  [ "$klass" = StandaloneVM ] \
    || die "refusing: '$VM' exists as a $klass, not a StandaloneVM. This script would give it a netvm."
  if qvm-check --quiet --running "$VM" 2>/dev/null; then
    [ "$DRY_RUN" = 1 ] || die "'$VM' is running; shut it down first: qvm-shutdown --wait $VM"
    note "'$VM' is running; a real run would refuse until it is shut down."
  fi
  note "'$VM' exists: not recreating it; applying prefs and growing volumes."
else
  run qvm-create --class StandaloneVM --template "$TEMPLATE" --label "$LABEL" "$VM"
fi

run qvm-prefs "$VM" netvm sys-firewall      # dev needs network; vault-tools must NOT have one
run qvm-prefs "$VM" vcpus "$VCPUS"
run qvm-prefs "$VM" maxmem "$MAXMEM"
run qvm-prefs "$VM" memory "$MEMORY"

grow(){
  local vol="$1" want="$2" want_bytes="$3" cur=""
  if [ "$have_qvm" = 1 ] && { [ "$exists" = 1 ] || [ "$DRY_RUN" != 1 ]; }; then
    cur="$(qvm-volume info "$VM:$vol" size)"
  fi
  if [ -n "$cur" ] && [ "$cur" -ge "$want_bytes" ]; then
    note "skip: $VM:$vol is already $cur bytes (>= $want); qvm-volume resize only grows."
    return
  fi
  run qvm-volume resize "$VM:$vol" "$want"
}
grow root "$ROOT_SIZE" "$root_bytes"       # room for Go + VS Code + node
grow private "$PRIVATE_SIZE" "$private_bytes"

echo "== done. Next: qvm-run -a $VM xterm, then the in-VM steps in qubes/DEV-IMAGE.md =="
