#!/usr/bin/env python3
"""hsm-time-bound.py — fail the scheduled HSM battery when it has not been green for too long.

WHY THIS EXISTS.

`Staging HSM battery` in .github/workflows/hsm-staging.yml has been red on every PR and every push
to main since 2026-08-26 because the physical Pico bench is unplugged. A check that is always red is
not a check — it is a habit of dismissal — and the next time it goes red *for a real reason* the
response will be the same shrug. #76 fixed one half by reporting grey (skipped) on the gate tier
when the card is unreachable; this script closes the other half, which is bounding how long the
bench may be absent before absence is treated as a failure rather than as a permanent excuse.

There is no recorded "last-successful-evaluation" timestamp; one is not added. Adding a cache
entry or an artifact creates a *second* source of truth for "when did this last pass", and the two
can disagree (a run that passes and fails to upload; a cache evicted; an artifact expiring on a
different schedule than the runs it describes). GitHub's run history is the only source, and it
fails in the right direction: if retention has aged out every successful run, the query returns
nothing, and "no successful evaluation within retention" is unambiguously past any reasonable
bound — the absence of data is itself the alarm.

TWO FILTERS PEER CAUGHT IN REVIEW.

The filter is on the *battery job's* conclusion, not the workflow's. The workflow can be green
while the battery skipped (the gate tier's grey row), and a workflow green because the battery
skipped is not a successful evaluation. Likewise, a battery job with conclusion=`skipped` is not
success — that is the whole point of #100's grey row, and a check that ignored it would recreate
the dismissal habit the bound is meant to fix.

WHERE THE CONSTANT LIVES.

The bound is a policy choice, not a measurement. The number 14 is meaningless without knowing
which failure mode is being traded against: too short and a routine bench outage (a week away, a
broken cable) reads as "nobody was in the room"; too long and NOT EVALUATED stops being tracked
debt and becomes the background. 14 days sits between them, and the comment next to the constant
holds the trade-off so a future reader cannot tune the number without reading it.

The constant is module-level and named; the Prometheus rule observes the outcome, the check
decides the bound. Changing the number changes a policy decision, not a measurement, and that is
the place a reader who is going to argue with the bound has to find.
"""
import argparse
import datetime as dt
import json
import os
import subprocess
import sys
from typing import Any

# THE 14-DAY BOUND, AND THE TRADE-OFF IT REPRESENTS.
#
# - Shorter (e.g. 7 days): an ordinary bench outage (a week away, a broken cable, a re-flash) turns
#   the row red with no real defect. That trains the same dismissal the bound exists to prevent;
#   the only difference is that the dismissal arrives faster.
# - Longer (e.g. 30 days): NOT EVALUATED stops being tracked debt and becomes the background; the
#   next time the gate is needed, the team has to reconstruct how long it has been grey.
# - 14 days: long enough to survive a routine bench absence, short enough that "we have not run
#   the battery on the staging card in a fortnight" is the kind of sentence a reviewer is glad to
#   have written down.
MAX_HARDWARE_EVALUATION_GAP_DAYS = 14


# THE WORKFLOW FILE THIS SCRIPT QUERIES IS NAMED HERE, IN ONE PLACE.
#
# `gh api /repos/.../actions/runs?workflow_id=...` is the only place the script's history
# filter assumes a specific workflow name, and changing this string is a deliberate reviewable
# change — a typo would silently query nothing and report "no history" on every run. Pinned by
# `test_endpoint_for_runs_uses_the_hsm_staging_workflow_name`.
HSM_STAGING_WORKFLOW_NAME = "hsm-staging.yml"


def endpoint_for_runs(owner_repo: str) -> str:
    """Build the `gh api` endpoint that lists completed successful workflow runs for this workflow.

    Pure: takes the owner/repo slug (the same shape `GITHUB_REPOSITORY` carries in Actions),
    returns the endpoint string. Extracted so the I/O layer is the only place that depends on
    `subprocess.run` and `gh api` parsing semantics — defects in how the endpoint is built
    (missing substitution, wrong owner_repo, missed query string) are testable here without
    the network.

    `status=completed&conclusion=success` narrows the run list to green runs of any kind; the
    battery-job-level filter is still applied by `_find_last_successful_battery`, which is
    where the peer-caught "skipped battery is not success" rule lives.
    """
    return (
        f"/repos/{owner_repo}/actions/runs"
        f"?workflow_id={HSM_STAGING_WORKFLOW_NAME}&status=completed&conclusion=success"
    )


def endpoint_for_jobs(owner_repo: str, run_id: int) -> str:
    """Build the `gh api` endpoint that lists jobs for one workflow run. Pure; same rationale as
    `endpoint_for_runs`."""
    return f"/repos/{owner_repo}/actions/runs/{run_id}/jobs"


def parse_pages(raw: str, key: str) -> list[dict[str, Any]]:
    """Parse the JSON `gh api --slurp --paginate` returns, merging per-page lists.

    `gh api --paginate` without `--slurp` emits one JSON document per page back-to-back, and
    `json.loads("{...}{...}")` raises `JSONDecodeError`. `--slurp` wraps the output in a JSON
    array so `json.loads` succeeds. Each page is a dict whose list of items is keyed by
    `workflow_runs` (runs endpoint) or `jobs` (jobs endpoint). The caller declares which
    key it expects via `key=`, and a missing key is a `KeyError` rather than an empty list.

    Round 5 caught a defect where this function only knew about `workflow_runs`. When the
    jobs endpoint was called, `page.get("workflow_runs", [])` returned `[]` for every page,
    and the time-bound job raised on `isinstance(jobs, dict)` because the function only ever
    returned a list. The wrong-key lookup turned into a successful empty answer — the same
    shape of defect that produced the original `--paginate`-without-`--slurp` bug: an
    absence that reads as a successful empty answer. Falsified by reverting the
    key-parameter and confirming the wrong-key case raises instead.
    """
    pages = json.loads(raw)
    if not isinstance(pages, list):
        # A single page (no pagination triggered) is one dict; wrap it so the merger is
        # uniform. With --paginate this branch should not run, but --slurp on a single page
        # does wrap the dict in a list, so the wrap is defensive against future gh behaviour.
        pages = [pages]
    merged: list[dict[str, Any]] = []
    for page in pages:
        if not isinstance(page, dict):
            # A page is always a dict from gh (the endpoint shape is JSON object with a
            # keyed list inside). Anything else is malformed output and refusing to silently
            # fabricate is the right failure mode.
            raise ValueError(
                f"gh api page is {type(page).__name__}, expected dict: {page!r}"
            )
        if key not in page:
            # Wrong key: the caller named the runs endpoint but got a jobs page (or vice
            # versa). Raising here makes the typo loud rather than silently reporting
            # "no history" on every scheduled run.
            raise KeyError(
                f"gh api page is missing the {key!r} key; the wrong endpoint or pagination "
                f"shape is producing an unexpected page. Got keys: {sorted(page.keys())}"
            )
        page_list = page[key]
        if not isinstance(page_list, list):
            raise ValueError(
                f"gh api page[{key!r}] is {type(page_list).__name__}, expected list: "
                f"{page_list!r}"
            )
        merged.extend(page_list)
    return merged


def _parse_iso(value: str) -> dt.datetime:
    """Parse a GitHub API timestamp. GitHub returns 'YYYY-MM-DDTHH:MM:SSZ' in UTC."""
    return dt.datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=dt.timezone.utc)


def check(
    now: dt.datetime,
    runs: list[dict[str, Any]],
    jobs_by_run: dict[int, list[dict[str, Any]]],
    current_battery_conclusion: str | None,
    current_reason: str,
    max_days: int = MAX_HARDWARE_EVALUATION_GAP_DAYS,
) -> dict[str, Any]:
    """Decide whether the scheduled battery is within its time bound.

    The data sources are split so the rule is testable without `gh api` or the network. The
    script's main() does the I/O; this function is the rule, and the tests pin the rule.

    `current_battery_conclusion` is the conclusion of THIS run's `battery` job, or None if it did
    not run (e.g. the preflight went grey). A success here means this run is the freshest data
    point and no historical check is needed.

    `current_reason` is `preflight.outputs.reason` from this run, or an empty string. It is
    carried into the failure so the operator reading the red row knows whether the answer is
    "card unplugged" or "PC/SC layer down" without opening the run.

    Returns a dict with `verdict` (one of "pass", "stale", "no-history") and `message` (the
    human-readable explanation that goes in the step summary). On `stale` and `no-history` the
    script exits non-zero.
    """
    # THE FRESHEST DATA POINT IS THIS RUN. If the battery just succeeded, the bound is satisfied
    # trivially; history is irrelevant. The interesting case is failure or absence.
    if current_battery_conclusion == "success":
        return {
            "verdict": "pass",
            "message": f"the scheduled battery succeeded in this run; no history check needed "
            f"(bound is {max_days} days)",
        }

    # NO CANDIDATES AT ALL. Retention has aged out every successful run, or the workflow has never
    # produced a successful battery. Per peer: "If retention has aged out every successful run, the
    # query returns nothing, and 'no successful evaluation within retention' is unambiguously past
    # a 14-day bound — so the absence of data is itself the alarm rather than a gap you have to
    # special-case." We carry the current preflight reason in either case — both signal a bench
    # that is absent right now.
    candidate = _find_last_successful_battery(runs, jobs_by_run)
    if candidate is None:
        reason = current_reason or "no preflight reason recorded"
        return {
            "verdict": "no-history",
            "message": f"no successful battery run in GitHub retention "
            f"(>{max_days} days; bound is {max_days}). "
            f"Current preflight says: {reason}.",
        }

    last_at, last_run_id, last_conclusion = candidate
    age = now - last_at
    if age > dt.timedelta(days=max_days):
        days = age.days
        reason = current_reason or "no preflight reason recorded"
        return {
            "verdict": "stale",
            "message": f"the last successful battery run was {days} days ago "
            f"(run {last_run_id}, concluded {last_conclusion}); bound is {max_days} days. "
            f"Current preflight says: {reason}.",
        }

    return {
        "verdict": "pass",
        "message": f"the last successful battery ran {age.days} days ago (run {last_run_id}); "
        f"within the {max_days}-day bound",
    }


def _find_last_successful_battery(
    runs: list[dict[str, Any]],
    jobs_by_run: dict[int, list[dict[str, Any]]],
) -> tuple[dt.datetime, int, str] | None:
    """Return (created_at, run_id, battery_conclusion) of the newest run whose battery job
    succeeded, or None if no such run exists.

    Two filters that the review caught:
    - the run must be `completed` with workflow-level `conclusion=success` (a still-running or
      failed run is not a candidate);
    - the run's `battery` job must have `conclusion=success` (not `skipped`, which is the whole
      point of #100's grey row).

    Both filters matter. A workflow green because the battery skipped is not a successful
    evaluation. A battery job with `skipped` is not a success — it is a grey row that counts
    toward the bound, not against it.
    """
    for run in runs:
        run_id = run["id"]
        if run.get("status") != "completed" or run.get("conclusion") != "success":
            continue
        jobs = jobs_by_run.get(run_id, [])
        battery = next((job for job in jobs if job.get("name") == "battery"), None)
        if battery is None or battery.get("conclusion") != "success":
            continue
        return _parse_iso(run["created_at"]), run_id, battery["conclusion"]
    return None


def _gh_api(endpoint: str, key: str) -> list[dict[str, Any]]:
    """Run `gh api --paginate --slurp` and return the merged list of dicts via `parse_pages`.

    Network is only here, in the I/O layer. `endpoint` is expected to be built by one of the
    pure helpers above, which substitute the owner/repo from `GITHUB_REPOSITORY`; passing a
    literal `/repos/${REPO}/...` (a templated string gh cannot resolve) returns 404, and that
    is what we got caught on — the substitution happens in pure helpers now, not in an f-string
    the workflow reader can mistake for shell interpolation.

    `key` is the merge key for the response (`workflow_runs` for the runs endpoint,
    `jobs` for the jobs endpoint). Passed through to `parse_pages`. The previous version did
    not accept a key, which meant the runs-shaped extractor was used for both endpoints; that
    is the round-5 defect this parameter exists to prevent.
    """
    result = subprocess.run(
        ["gh", "api", endpoint, "--paginate", "--slurp"],
        check=True,
        capture_output=True,
        text=True,
    )
    return parse_pages(result.stdout, key=key)


def _run_jobs(run_id: int, owner_repo: str) -> list[dict[str, Any]]:
    """Fetch the jobs of one run, returning just the fields the check needs."""
    jobs = _gh_api(endpoint_for_jobs(owner_repo, run_id), key="jobs")
    return [
        {"name": job.get("name"), "conclusion": job.get("conclusion")}
        for job in jobs
    ]


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Time-bound check for the HSM staging battery on the scheduled run path."
    )
    parser.add_argument(
        "--max-days",
        type=int,
        default=MAX_HARDWARE_EVALUATION_GAP_DAYS,
        help=f"max days since the last successful battery (default: {MAX_HARDWARE_EVALUATION_GAP_DAYS})",
    )
    parser.add_argument(
        "--current-battery-conclusion",
        default=os.environ.get("CURRENT_BATTERY_CONCLUSION", ""),
        help="conclusion of THIS run's battery job (success/failure/skipped/empty)",
    )
    parser.add_argument(
        "--current-reason",
        default=os.environ.get("CURRENT_REASON", ""),
        help="preflight.outputs.reason from this run, for the failure message",
    )
    args = parser.parse_args()

    # The owner/repo slug is the value of `GITHUB_REPOSITORY`, set by the Actions runner for
    # every job. Without it, the endpoint helpers would substitute an empty string and `gh`
    # would 404. Surfacing this as a hard requirement (rather than a default to ${REPO}) is
    # what the test in tests/test_hsm_time_bound.py pins.
    owner_repo = os.environ.get("GITHUB_REPOSITORY")
    if not owner_repo:
        print("error: GITHUB_REPOSITORY is not set; cannot resolve the actions API", file=sys.stderr)
        return 2

    # NO NETWORK WHEN THE ANSWER IS ALREADY KNOWN. If this run's battery succeeded, the bound is
    # satisfied by this run and `check()` ignores history entirely — but main() still walked the
    # whole Actions API first: one call for the runs and one MORE PER RUN. Beyond the waste, every
    # one of those calls is a way for a green bench to report red, because `gh` failures raise
    # (check=True) and a rate-limited or flaky API would fail a check whose answer was "fresh".
    if args.current_battery_conclusion == "success":
        result = check(
            now=dt.datetime.now(dt.timezone.utc),
            runs=[],
            jobs_by_run={},
            current_battery_conclusion="success",
            current_reason=args.current_reason,
            max_days=args.max_days,
        )
        print(json.dumps(result, indent=2, default=str))
        return 0

    runs = _gh_api(endpoint_for_runs(owner_repo), key="workflow_runs")

    # For each candidate run, fetch its jobs. This is the per-run API call; the workflow-level
    # filter above narrows the set, and the battery filter below narrows further. We could batch
    # with a single call to /actions/runs/{id}/jobs?per_page=100, but at the volume of scheduled
    # runs (one per day) the per-run cost is trivial.
    jobs_by_run: dict[int, list[dict[str, Any]]] = {
        run["id"]: _run_jobs(run["id"], owner_repo) for run in runs
    }

    result = check(
        now=dt.datetime.now(dt.timezone.utc),
        runs=runs,
        jobs_by_run=jobs_by_run,
        current_battery_conclusion=args.current_battery_conclusion or None,
        current_reason=args.current_reason,
        max_days=args.max_days,
    )

    # The verdict is rendered into the step summary in a stable shape so the workflow YAML can
    # surface it without parsing prose. A failing verdict exits non-zero; a passing one exits zero.
    print(json.dumps(result, indent=2, default=str))
    if result["verdict"] in ("stale", "no-history"):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
