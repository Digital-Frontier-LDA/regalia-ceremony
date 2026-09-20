#!/usr/bin/env bash
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../../.." && pwd)"
LOCK="$REPO/tools/hsm-bench-lock.sh"
[ -f "$LOCK" ] || { printf 'missing %s\n' "$LOCK" >&2; exit 1; }
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
# shellcheck source=/dev/null
. "$LOCK"
HSM_BENCH_LOCK_PATH="$work/bench.lock" HSM_BENCH_LOCK_LABEL="owner-run"
export HSM_BENCH_LOCK_PATH HSM_BENCH_LOCK_LABEL
hsm_bench_lock_acquire failfast || exit $?
trap 'hsm_bench_lock_release; rm -rf "$work"' EXIT
out="$(env -u HSM_BENCH_LOCK_HELD HSM_BENCH_LOCK_PATH="$work/bench.lock" HSM_BENCH_LOCK_LABEL="loser-run" bash -c '. "$1"; hsm_bench_lock_acquire failfast' bash "$LOCK" 2>&1)"
rc=$?
[ "$rc" -eq 75 ] || { printf 'contention returned %s, want 75: %s\n' "$rc" "$out" >&2; exit 1; }
case "$out" in *"bench lock unavailable"*"label=owner-run"*) ;; *) printf 'contention did not name holder: %s\n' "$out" >&2; exit 1 ;; esac
hsm_bench_lock_release
HSM_BENCH_LOCK_LABEL="new-owner" hsm_bench_lock_acquire failfast || exit 1
hsm_bench_lock_release
HSM_BENCH_LOCK_HELD=1 HSM_BENCH_LOCK_PATH="$work/forged" hsm_bench_lock_acquire failfast || exit 1
hsm_bench_lock_release
for script in "$REPO/qubes/scripts/hsm-staging-ci.sh" "$REPO/qubes/scripts/hsm-staging-e2e.sh" "$REPO/qubes/scripts/hsm-recovery-drill.sh" "$REPO/qubes/scripts/hsm-fleet-drill.sh" "$REPO/tools/hsm-scenarios.sh" "$REPO/tools/hsm-cycle-test.sh" "$REPO/tools/hsm-staging-restore.sh"; do
  grep -q 'hsm_bench_lock_acquire' "$script" || { printf '%s does not acquire lock\n' "$script" >&2; exit 1; }
done

fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }
# The cases above leave the lock variables exported in this shell. A child inherits
# HSM_BENCH_LOCK_DIR, which takes precedence over HSM_BENCH_LOCK_PATH, so without this every case below
# would silently aim at the suite's own lock instead of its own path.
hsm_bench_lock_release
unset HSM_BENCH_LOCK_DIR HSM_BENCH_LOCK_HELD HSM_BENCH_LOCK_TOKEN HSM_BENCH_LOCK_OWNER_PID
here="$(hostname)"

# #444 — A NESTED CHILD'S RELEASE MUST NOT DELETE ITS PARENT'S LOCK. hsm-staging-ci.sh runs the
# recovery and fleet drills as children; both release from their EXIT traps. Measured on the old lock:
# the first child to exit removed the parent's lock and the nightly ran on unlocked.
nested="$(HSM_BENCH_LOCK_PATH="$work/nested.lock" bash -c '
  . "$1"; HSM_BENCH_LOCK_LABEL=parent hsm_bench_lock_acquire failfast || exit 9
  bash -c ". \"$1\"; hsm_bench_lock_acquire failfast || exit 8; hsm_bench_lock_release" || exit $?
  [ -d "$HSM_BENCH_LOCK_DIR" ] && echo PRESENT || echo GONE' bash "$LOCK" 2>&1)"
[ "$nested" = PRESENT ] || fail "a nested child's release removed the parent's lock: $nested"

# #444 — A SIGNAL ENDS THE SCRIPT. The old INT/TERM trap released the lock and resumed, so a
# SIGTERM'd run kept working unlocked and exited 0.
HSM_BENCH_LOCK_PATH="$work/term.lock" bash -c '. "$1"; hsm_bench_lock_acquire failfast || exit 9; sleep 5; echo CONTINUED' bash "$LOCK" > "$work/term.out" 2>&1 &
tpid=$!; sleep 1; kill -TERM "$tpid"; wait "$tpid"; trc=$?
grep -q CONTINUED "$work/term.out" && fail "the script continued after SIGTERM"
[ "$trc" -eq 143 ] || fail "SIGTERM exit was $trc, want 143"
[ ! -d "$work/term.lock" ] || fail "SIGTERM left the lock behind"

# #444 — A PROVABLY DEAD HOLDER IS RECLAIMED, AND SAYS SO. Measured: a dead hsm-fleet-drill.sh held the
# real lock ~22h; failfast refused every run and wait slept forever. 999999 exceeds any pid_max here.
mkdir "$work/dead.lock"; printf 'pid=999999 host=%s token=gone started=2026-09-13T08:31:14Z label=crashed drill\n' "$here" > "$work/dead.lock/holder"
out="$(env -u HSM_BENCH_LOCK_HELD HSM_BENCH_LOCK_PATH="$work/dead.lock" HSM_BENCH_LOCK_LABEL=after-crash bash -c '. "$1"; hsm_bench_lock_acquire failfast && cat "$HSM_BENCH_LOCK_DIR/holder"' bash "$LOCK" 2>&1)" || fail "a dead holder was not reclaimed: $out"
case "$out" in *"reclaimed from a holder that is no longer running"*"label=crashed drill"*"label=after-crash"*) ;; *) fail "reclaim not announced or not taken: $out" ;; esac

# The record format written before #444 has no host field; it is still reclaimable when its pid is dead.
mkdir "$work/legacy.lock"; printf 'pid=999999 label=hsm-fleet-drill.sh started=2026-09-13T08:31:14Z\n' > "$work/legacy.lock/holder"
env -u HSM_BENCH_LOCK_HELD HSM_BENCH_LOCK_PATH="$work/legacy.lock" bash -c '. "$1"; hsm_bench_lock_acquire failfast' bash "$LOCK" >/dev/null 2>&1 || fail "a pre-#444 dead record was not reclaimed"

# A LIVE holder is never reclaimed, whatever its age.
sleep 30 & live=$!
mkdir "$work/live.lock"; printf 'pid=%s host=%s token=live started=2020-01-01T00:00:00Z label=long run\n' "$live" "$here" > "$work/live.lock/holder"
env -u HSM_BENCH_LOCK_HELD HSM_BENCH_LOCK_PATH="$work/live.lock" bash -c '. "$1"; hsm_bench_lock_acquire failfast' bash "$LOCK" >/dev/null 2>&1; lrc=$?
[ "$lrc" -eq 75 ] || fail "a live holder's lock was taken (rc $lrc)"
[ -f "$work/live.lock/holder" ] && grep -q 'label=long run' "$work/live.lock/holder" || fail "the live holder's record was disturbed"

# A holder recorded on ANOTHER host is never reclaimed from here, even with a pid that is dead here.
mkdir "$work/remote.lock"; printf 'pid=999999 host=some-other-host token=r started=2026-09-13T08:31:14Z label=elsewhere\n' > "$work/remote.lock/holder"
env -u HSM_BENCH_LOCK_HELD HSM_BENCH_LOCK_PATH="$work/remote.lock" bash -c '. "$1"; hsm_bench_lock_acquire failfast' bash "$LOCK" >/dev/null 2>&1; rrc=$?
[ "$rrc" -eq 75 ] || fail "another host's holder was reclaimed (rc $rrc)"

# #444 — WAIT IS BOUNDED. Against a live holder, wait refuses after its timeout instead of sleeping forever.
out="$(env -u HSM_BENCH_LOCK_HELD HSM_BENCH_LOCK_PATH="$work/live.lock" HSM_BENCH_LOCK_WAIT_TIMEOUT=2 bash -c '. "$1"; hsm_bench_lock_acquire wait' bash "$LOCK" 2>&1)"; wrc=$?
[ "$wrc" -eq 75 ] || fail "bounded wait returned $wrc, want 75"
case "$out" in *"timed out after 2s"*) ;; *) fail "bounded wait did not say it timed out: $out" ;; esac
case "$out" in *"label=long run"*) ;; *) fail "timeout did not name the holder: $out" ;; esac
kill "$live" 2>/dev/null; wait "$live" 2>/dev/null

# #444 — RELEASE ONLY WHAT IS STILL OURS. If our lock was reclaimed and re-taken, the record carries
# another token; our release must leave the new holder's lock in place.
out="$(HSM_BENCH_LOCK_PATH="$work/stolen.lock" bash -c '
  . "$1"; hsm_bench_lock_acquire failfast || exit 9
  printf "pid=1 host=x token=someone-else started=t label=new holder\n" > "$HSM_BENCH_LOCK_DIR/holder"
  hsm_bench_lock_release
  [ -d "$HSM_BENCH_LOCK_DIR" ] && echo KEPT || echo DELETED' bash "$LOCK" 2>&1)"
case "$out" in *"no longer ours"*KEPT) ;; *) fail "release deleted a lock it no longer owned: $out" ;; esac

# A label is free text. One containing "token=" must not be read as the token.
out="$(HSM_BENCH_LOCK_PATH="$work/label.lock" HSM_BENCH_LOCK_LABEL="evil token=forged" bash -c '
  . "$1"; hsm_bench_lock_acquire failfast || exit 9; hsm_bench_lock_release
  [ -d "$HSM_BENCH_LOCK_DIR" ] && echo KEPT || echo RELEASED' bash "$LOCK" 2>&1)"
[ "$out" = RELEASED ] || fail "a label containing token= shadowed the real token: $out"

# #463 — RECLAIM IS RACE-FREE. The old reclaim judged a holder dead and then mv-ed the lock in two
# unbound steps; between them a second waiter could reclaim and a new LIVE holder rebuild the dir, so
# the first waiter's mv moved the live holder's lock to a grave and deleted it — two runs on one
# card. Measured on the pre-fix code: 12 live-lock steals in 10 rounds of 8 waiters.

# (a) DETERMINISTIC: while a reclaim claim is held by a LIVE owner, no other waiter may move the
# lock. This is the serialization the fix rests on. Falsifier: the pre-fix mv-first reclaim ignores
# the claim and moves the dead lock anyway.
det="$work/claim.lock"
mkdir "$det"; printf 'pid=999999 host=%s token=dead started=t label=dead holder\n' "$here" > "$det/holder"
mkdir "$det.claim"; printf 'pid=%s host=%s\n' "$$" "$here" > "$det.claim/owner"   # a LIVE reclaimer holds the claim
out="$(env -u HSM_BENCH_LOCK_HELD HSM_BENCH_LOCK_PATH="$det" HSM_BENCH_LOCK_WAIT_TIMEOUT=2 bash -c '. "$1"; hsm_bench_lock_acquire wait' bash "$LOCK" 2>&1)"; drc=$?
[ "$drc" -eq 75 ] || fail "a waiter reclaimed a lock while a live reclaimer held the claim (rc $drc): $out"
[ -d "$det" ] && [ "$(_hsm_bench_lock_field_in "$det/holder" token)" = dead ] || fail "the dead lock was moved despite a held claim"
for g in "$det".stale.*; do [ -e "$g" ] && fail "a grave appeared while the claim was held: $g"; done
rm -rf "$det" "$det.claim" "$det".stale.* 2>/dev/null

# (b) DETERMINISTIC: a claim whose OWN owner is dead is cleared, so a waiter that died mid-reclaim
# cannot wedge the bench. Here the claim owner is a dead pid, so the dead holder is reclaimed.
det2="$work/claim-stale.lock"
mkdir "$det2"; printf 'pid=999999 host=%s token=dead started=t label=dead holder\n' "$here" > "$det2/holder"
mkdir "$det2.claim"; printf 'pid=999999 host=%s\n' "$here" > "$det2.claim/owner"   # a DEAD reclaimer
out="$(env -u HSM_BENCH_LOCK_HELD HSM_BENCH_LOCK_PATH="$det2" HSM_BENCH_LOCK_WAIT_TIMEOUT=5 HSM_BENCH_LOCK_LABEL=after-stale-claim bash -c '. "$1"; hsm_bench_lock_acquire wait && cat "$HSM_BENCH_LOCK_DIR/holder"' bash "$LOCK" 2>&1)" || fail "a dead reclaimer's claim was not cleared: $out"
case "$out" in *"label=after-stale-claim"*) ;; *) fail "the lock was not reclaimed after a dead claim was cleared: $out" ;; esac
rm -rf "$det2" "$det2.claim" "$det2".stale.* 2>/dev/null

# (c) DETERMINISTIC: the reclaimer RE-JUDGES the holder under the claim and must never move a lock
# whose holder is alive. In the race, a live holder can take the lock between one waiter's dead-
# judgement and its reclaim; the under-claim re-check is what stops that waiter moving the live lock.
# Called directly on a live holder (this shell's own pid), the reclaimer must decline and leave it.
# Falsifier: dropping the "|| ! _hsm_bench_lock_holder_is_gone" re-check moves this live lock.
rej="$work/rejudge.lock"; mkdir "$rej"
printf 'pid=%s host=%s token=live-token started=t label=live holder\n' "$$" "$here" > "$rej/holder"
HSM_BENCH_LOCK_DIR="$rej" _hsm_bench_lock_try_reclaim "live holder" && fail "the reclaimer moved a LIVE holder's lock"
[ -d "$rej" ] && [ "$(_hsm_bench_lock_field_in "$rej/holder" token)" = live-token ] || fail "the reclaimer disturbed a live holder's record"
for g in "$rej".stale.*; do [ -e "$g" ] && fail "the reclaimer graved a live holder: $g"; done
unset HSM_BENCH_LOCK_DIR
rm -rf "$rej" "$rej.claim" "$rej".stale.* 2>/dev/null

printf 'bench-lock tests passed\n'
