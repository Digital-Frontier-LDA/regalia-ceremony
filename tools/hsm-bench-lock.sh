#!/usr/bin/env bash
# Shared advisory lock for every script that can touch the staging HSM bench.
# mkdir is atomic on macOS and Linux. A stale lock is reclaimed only when its holder is PROVABLY
# gone -- same host, recorded pid not running -- and the reclaim is announced, never silent.
#
# Ownership (#444). The lock belongs to the process that created it, identified by a token written
# into the holder record and exported alongside HSM_BENCH_LOCK_HELD. Children inherit the export, so
# a nested script's acquire is re-entrant, but its release is a no-op. Before this, release trusted
# the exported flag alone: hsm-staging-ci.sh runs hsm-recovery-drill.sh and hsm-fleet-drill.sh as
# children, their EXIT traps call release, and the first child to exit deleted the PARENT's lock,
# leaving the rest of the nightly battery running unlocked. That was measured, not inferred.

_hsm_bench_lock_field_in() { # $1 = record file, $2 = field name
  [ -r "$1" ] || return 1
  # First match wins, and what makes that safe is ORDER: label is the only free-text field and it is
  # written last, so a label containing "token=..." comes after the real token and never shadows it
  # (the label test pins this; writing label first fails it). Matching whole fields rather than
  # substrings is belt-and-braces: no parsed value contains "=", so for records this lock writes the
  # two cannot differ, and a mutation between them survives by construction. awk reads the file
  # itself, so exiting on the first match cannot SIGPIPE a producer.
  awk -v key="$2=" '{ for (i = 1; i <= NF; i++) if (index($i, key) == 1) { print substr($i, length(key) + 1); exit } }' "$1"
}

_hsm_bench_lock_field() { # $1 = field name; reads the holder record of $HSM_BENCH_LOCK_DIR
  _hsm_bench_lock_field_in "$HSM_BENCH_LOCK_DIR/holder" "$1"
}

hsm_bench_lock_release() {
  [ "${HSM_BENCH_LOCK_HELD:-0}" = 1 ] || return 0
  # Only the creating process releases, and only while the record on disk is still ours. A nested
  # child inherits HELD=1 but not ownership; a holder whose lock was reclaimed as stale finds a
  # different token on disk and must not delete the new holder's lock.
  if [ "${HSM_BENCH_LOCK_OWNER_PID:-}" != "$$" ]; then
    return 0
  fi
  if [ "$(_hsm_bench_lock_field token 2>/dev/null)" = "${HSM_BENCH_LOCK_TOKEN:-}" ] && [ -n "${HSM_BENCH_LOCK_TOKEN:-}" ]; then
    rm -f -- "$HSM_BENCH_LOCK_DIR/holder"
    rmdir -- "$HSM_BENCH_LOCK_DIR" 2>/dev/null || true
  else
    printf 'bench lock %s is no longer ours (holder: %s); not releasing it\n' \
      "$HSM_BENCH_LOCK_DIR" "$(cat -- "$HSM_BENCH_LOCK_DIR/holder" 2>/dev/null || echo none)" >&2
  fi
  HSM_BENCH_LOCK_HELD=0
}

# A holder is provably gone only when it recorded this host and a pid that no longer exists.
# `ps -p` answers for processes of any user, where `kill -0` fails with EPERM for a live process
# owned by someone else and would read it as dead. A record from another host, or one with no pid,
# is never reclaimed: that cannot be proven from here.
# _hsm_bench_lock_record_is_gone applies the holder liveness rule to an arbitrary record file: the
# recorded pid is a number, was written on this host (or before #444, no host), and is not running.
# Used for the holder and for the reclaim-claim's owner, so a waiter that died mid-reclaim cannot
# wedge the bench any more than a dead holder can.
_hsm_bench_lock_record_is_gone() { # $1 = record file
  local pid host
  pid="$(_hsm_bench_lock_field_in "$1" pid 2>/dev/null)"
  host="$(_hsm_bench_lock_field_in "$1" host 2>/dev/null)"
  case "$pid" in ''|*[!0-9]*) return 1 ;; esac
  [ -z "$host" ] || [ "$host" = "$(hostname 2>/dev/null)" ] || return 1
  ! ps -p "$pid" >/dev/null 2>&1
}

_hsm_bench_lock_holder_is_gone() {
  local pid host
  pid="$(_hsm_bench_lock_field pid 2>/dev/null)"
  host="$(_hsm_bench_lock_field host 2>/dev/null)"
  case "$pid" in ''|*[!0-9]*) return 1 ;; esac
  # Records written before #444 carry no host. They can only have been written on this machine's
  # TMPDIR, which is where the lock lives, so a missing host is treated as this host.
  [ -z "$host" ] || [ "$host" = "$(hostname 2>/dev/null)" ] || return 1
  ! ps -p "$pid" >/dev/null 2>&1
}

# _hsm_bench_lock_try_reclaim reclaims a lock whose holder is PROVABLY gone, without ever moving a
# live lock. $1 is the holder text, only for the announcement.
#
# WHY A CLAIM MUTEX. The previous reclaim judged the holder dead and then `mv`-ed the lock directory
# in two unbound steps. Between them a second waiter could reclaim the same dead holder and a NEW
# LIVE holder could rebuild the directory, so the first waiter's mv moved the live holder's lock to
# a grave and rm -rf'd it -- two runs on one card. Measured on the pre-fix code: 12 live-lock steals
# in 10 rounds of 8 concurrent waiters.
#
# The fix serializes reclaimers: only the waiter holding "$HSM_BENCH_LOCK_DIR.claim" may move the
# lock. While the claim is held the dead lock directory is stable -- a new holder can appear only by
# mkdir of the main directory, which fails while the dead directory still exists -- so the reclaimer
# re-reads the record, confirms the SAME token is still there and still dead, and only then moves it.
# The claim is a sibling rather than inside the lock (which the mv would carry away) and carries its
# own pid record, so a waiter that dies mid-reclaim is cleared by the same dead-pid rule and cannot
# wedge the bench.
_hsm_bench_lock_try_reclaim() {
  local holder="$1" claim="$HSM_BENCH_LOCK_DIR.claim" dead_token now_token grave
  dead_token="$(_hsm_bench_lock_field token 2>/dev/null)"
  if ! mkdir -- "$claim" 2>/dev/null; then
    # Someone is already reclaiming. Only clear the claim if its own owner is dead, so a crash mid
    # reclaim self-heals while a live reclaimer is left alone.
    if _hsm_bench_lock_record_is_gone "$claim/owner"; then
      rm -rf -- "$claim" 2>/dev/null || true
    fi
    return 1
  fi
  printf 'pid=%s host=%s\n' "$$" "$(hostname 2>/dev/null)" > "$claim/owner" 2>/dev/null || true
  # Re-judge UNDER the claim. If the token changed, a different holder took the lock since we judged
  # it (it may be alive); if it is no longer gone, the holder came back. Either way it is not ours.
  now_token="$(_hsm_bench_lock_field token 2>/dev/null)"
  if { [ -n "$dead_token" ] && [ "$now_token" != "$dead_token" ]; } || ! _hsm_bench_lock_holder_is_gone; then
    rm -rf -- "$claim" 2>/dev/null || true
    return 1
  fi
  grave="$HSM_BENCH_LOCK_DIR.stale.$$"
  if mv -- "$HSM_BENCH_LOCK_DIR" "$grave" 2>/dev/null; then
    printf 'bench lock %s: reclaimed from a holder that is no longer running (%s)\n' "$HSM_BENCH_LOCK_DIR" "$holder" >&2
    rm -rf -- "$grave"
  fi
  rm -rf -- "$claim" 2>/dev/null || true
  return 0
}

hsm_bench_lock_acquire() {
  HSM_BENCH_LOCK_DIR="${HSM_BENCH_LOCK_DIR:-${HSM_BENCH_LOCK_PATH:-${TMPDIR:-/tmp}/regalia-hsm-bench.lock}}"
  # Re-entrant for a nested script, but only when the record on disk carries the token we inherited.
  # A forged or leftover HSM_BENCH_LOCK_HELD=1 with no matching record is ignored.
  if [ "${HSM_BENCH_LOCK_HELD:-0}" = 1 ] && [ -d "$HSM_BENCH_LOCK_DIR" ] && [ -n "${HSM_BENCH_LOCK_TOKEN:-}" ] \
     && [ "$(_hsm_bench_lock_field token 2>/dev/null)" = "$HSM_BENCH_LOCK_TOKEN" ]; then
    return 0
  fi
  HSM_BENCH_LOCK_HELD=0
  local mode="${1:-failfast}" label="${HSM_BENCH_LOCK_LABEL:-${0##*/}}" holder token started waited=0
  local timeout="${HSM_BENCH_LOCK_WAIT_TIMEOUT:-14400}" interval="${HSM_BENCH_LOCK_WAIT_SECONDS:-1}"
  while :; do
    if mkdir -- "$HSM_BENCH_LOCK_DIR" 2>/dev/null; then
      token="$$-$(date -u +%s)-${RANDOM:-0}${RANDOM:-0}"
      started="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
      # label stays LAST: it is free text and may contain spaces; every parsed field precedes it.
      if ! printf 'pid=%s host=%s token=%s started=%s label=%s\n' "$$" "$(hostname 2>/dev/null)" "$token" "$started" "$label" > "$HSM_BENCH_LOCK_DIR/holder"; then
        rmdir -- "$HSM_BENCH_LOCK_DIR" 2>/dev/null || true
        return 1
      fi
      HSM_BENCH_LOCK_HELD=1 HSM_BENCH_LOCK_TOKEN="$token" HSM_BENCH_LOCK_OWNER_PID="$$"
      export HSM_BENCH_LOCK_DIR HSM_BENCH_LOCK_HELD HSM_BENCH_LOCK_TOKEN HSM_BENCH_LOCK_OWNER_PID
      # A signal must END the script, not just drop its lock. The previous `trap release INT TERM`
      # ran the release and then resumed the script, so a SIGTERM'd destructive run carried on
      # unlocked and exited 0 (measured). Callers that install their own traps later still override.
      trap hsm_bench_lock_release EXIT
      trap 'hsm_bench_lock_release; exit 130' INT
      trap 'hsm_bench_lock_release; exit 143' TERM
      return 0
    fi
    holder="unknown holder"
    [ -r "$HSM_BENCH_LOCK_DIR/holder" ] && holder="$(cat -- "$HSM_BENCH_LOCK_DIR/holder")"
    if _hsm_bench_lock_holder_is_gone; then
      # Reclaimed: go straight back to mkdir. Not reclaimed (another waiter holds the claim, or the
      # holder changed under us): fall through to the bounded wait rather than busy-spinning on the
      # claim -- the reclaim branch must not `continue` unconditionally, or a legitimately-held claim
      # spins a waiter with no sleep and no timeout.
      if _hsm_bench_lock_try_reclaim "$holder"; then
        continue
      fi
    fi
    if [ "$mode" = wait ]; then
      if [ "$waited" -ge "$timeout" ]; then
        printf 'bench lock unavailable: %s (%s) -- timed out after %ss waiting\n' "$HSM_BENCH_LOCK_DIR" "$holder" "$waited" >&2
        return 75
      fi
      sleep "$interval"
      waited=$((waited + interval))
      continue
    fi
    printf 'bench lock unavailable: %s (%s)\n' "$HSM_BENCH_LOCK_DIR" "$holder" >&2
    return 75
  done
}
