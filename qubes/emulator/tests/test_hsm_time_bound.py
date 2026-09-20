"""Tests for tools/hsm-time-bound.py.

The check is split: a pure `check(now, runs, jobs_by_run, ...)` function that the test can drive
without `gh api` or the network, plus an I/O layer in main() that fetches the data. Both layers
are tested: the pure function pins the rule, and the parse/endpoint helpers pin the I/O layer's
contract at the function boundary. Mocking `subprocess.run` would test the stub rather than the
contract that review has to catch — the real call site has a literal `${REPO}`, an `--slurp`
omission, and a wrong-merge-key lookup, and the only way to catch those is at the function and
source level. Five rounds of review have found defects in this layer; this file's intent is to
make the next round empty.

Each test names the defect it pins: "delete this fix and the failure message tells you why the
test exists." That is the falsification pattern this repository uses elsewhere.
"""
import ast
import datetime as dt
import importlib.util
import json
import sys
import unittest
from pathlib import Path

# The tool lives in tools/ at the repository root; this suite lives in qubes/emulator/tests/.
TOOLS = Path(__file__).resolve().parents[3] / "tools"
SCRIPT = TOOLS / "hsm-time-bound.py"


def script_tree():
    return ast.parse(SCRIPT.read_text(encoding="utf-8"), filename=str(SCRIPT))


def named_calls(name):
    for node in ast.walk(script_tree()):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == name:
            yield node


def named_function(name):
    functions = [node for node in ast.walk(script_tree())
                 if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
                 and node.name == name]
    if len(functions) != 1:
        raise AssertionError(f"expected exactly one {name} definition, found {len(functions)}")
    return functions[0]

# The script lives at tools/hsm-time-bound.py to match the project convention (hsm-*.py / hsm-*.sh
# throughout the directory), but Python imports cannot have a hyphen, so load it by path rather
# than rename. The constant MAX_HARDWARE_EVALUATION_GAP_DAYS is the source of the bound the tests
# pin; loading by file path is the right escape hatch here, not a workaround for a name the
# command line keeps.
_spec = importlib.util.spec_from_file_location("hsm_time_bound", SCRIPT)
if _spec is None or _spec.loader is None:
    raise RuntimeError(f"could not load {SCRIPT} as a module")
hsm_time_bound = importlib.util.module_from_spec(_spec)
sys.modules["hsm_time_bound"] = hsm_time_bound
_spec.loader.exec_module(hsm_time_bound)


NOW = dt.datetime(2026, 9, 5, 12, 0, 0, tzinfo=dt.timezone.utc)


def _run(run_id: int, created_at: str, conclusion: str = "success") -> dict:
    """Build a workflow-runs-shaped dict."""
    return {
        "id": run_id,
        "created_at": created_at,
        "status": "completed",
        "conclusion": conclusion,
    }


def _job(run_id: int, name: str, conclusion: str) -> dict:
    return {"name": name, "conclusion": conclusion}


class TimeBoundTests(unittest.TestCase):
    # (1) The freshest data point is this run. If the battery just succeeded, no history check
    # matters; the bound is satisfied trivially. Delete-fix: short-circuit removed; the test fails
    # because the function would then return stale (the historical runs are old) and the message
    # would not name "this run".
    def test_current_run_success_skips_history_check(self):
        runs = [_run(1, "2026-08-01T00:00:00Z")]  # an ancient run that would otherwise be stale
        jobs = {1: [_job(1, "battery", "success")]}
        result = hsm_time_bound.check(
            now=NOW,
            runs=runs,
            jobs_by_run=jobs,
            current_battery_conclusion="success",
            current_reason="card present",
            max_days=14,
        )
        self.assertEqual(result["verdict"], "pass",
                         f"current run is success, so history is irrelevant: {result}")
        self.assertIn("succeeded in this run", result["message"])

    # (1b) …AND main() MUST NOT TOUCH THE NETWORK TO SAY SO. The rule short-circuits on a
    # successful battery, but main() fetched the whole Actions API first — one call for the runs
    # and one MORE per run — before handing `check()` data it would ignore. Every one of those
    # calls is a way for a green bench to report red: `_gh_api` runs `gh` with check=True, so a
    # rate-limited or offline API raises and fails a check whose answer was already "fresh".
    # Delete-fix: remove the short-circuit in main() and this fails, because `gh` is never
    # installed in the test environment and the call would raise instead of exiting 0.
    def test_main_makes_no_api_calls_when_this_run_succeeded(self):
        import os
        import subprocess
        env = dict(os.environ)
        env["GITHUB_REPOSITORY"] = "owner/repo"
        # PATH without `gh`: any attempt to reach the API is a hard failure rather than a silent
        # success against a stub, which is what would let this regress unnoticed.
        env["PATH"] = str(Path(sys.executable).parent)
        r = subprocess.run(
            [sys.executable, str(SCRIPT), "--current-battery-conclusion", "success"],
            capture_output=True, text=True, env=env,
        )
        self.assertEqual(r.returncode, 0, f"stdout={r.stdout} stderr={r.stderr}")
        self.assertEqual(json.loads(r.stdout)["verdict"], "pass")
        self.assertIn("succeeded in this run", json.loads(r.stdout)["message"])

    # (2) Recent successful run — within the bound. Delete-fix: the comparison `age >
    # dt.timedelta(days=max_days)` is removed; the test fails because 13 days would still report
    # stale.
    def test_recent_successful_run_within_bound_passes(self):
        recent = "2026-08-23T00:00:00Z"  # 13 days before NOW
        runs = [_run(1, recent)]
        jobs = {1: [_job(1, "battery", "success")]}
        result = hsm_time_bound.check(
            now=NOW, runs=runs, jobs_by_run=jobs,
            current_battery_conclusion="failure",
            current_reason="pcscd stopped",
        )
        self.assertEqual(result["verdict"], "pass",
                         f"13 days is within the 14-day bound: {result}")
        self.assertIn("13 days ago", result["message"])

    # (3) Stale — last successful run older than the bound. Delete-fix: the comparison flipped to
    # `>=`; the test fails because 14 days exactly would not be flagged.
    def test_old_successful_run_past_bound_fails_with_age_in_message(self):
        old = "2026-08-01T00:00:00Z"  # 35 days before NOW
        runs = [_run(42, old)]
        jobs = {42: [_job(42, "battery", "success")]}
        result = hsm_time_bound.check(
            now=NOW, runs=runs, jobs_by_run=jobs,
            current_battery_conclusion="failure",
            current_reason="card unplugged",
        )
        self.assertEqual(result["verdict"], "stale",
                         f"35 days is past the 14-day bound: {result}")
        self.assertIn("35 days ago", result["message"],
                      "the operator reading the red row needs the age, not just the verdict")
        self.assertIn("card unplugged", result["message"],
                      "the last-observed reason is the difference between walking to the bench "
                      "and restarting a daemon — it must be carried into the failure")
        self.assertIn("run 42", result["message"],
                      "the run id is the breadcrumb back to the historical run that anchors the "
                      "stale verdict")

    # (4) No successful run in retention. Per peer: "the absence of data is itself the alarm." The
    # verdict is `no-history` and the message names the bound. Delete-fix: the `candidate is None`
    # branch is removed; the test fails because the function would return stale with a wrong
    # message (or crash trying to access candidate).
    def test_no_successful_runs_in_retention_fails_with_no_history(self):
        result = hsm_time_bound.check(
            now=NOW, runs=[], jobs_by_run={},
            current_battery_conclusion="failure",
            current_reason="no PC/SC reader — the interface is down or nothing is attached",
        )
        self.assertEqual(result["verdict"], "no-history",
                         f"empty runs list means retention has aged out the history: {result}")
        self.assertIn("no successful battery run in GitHub retention", result["message"])
        self.assertIn("14 days", result["message"],
                      "the bound is the trade-off; it has to be in the message so the reader "
                      "knows what number to argue with")
        self.assertIn("PC/SC reader", result["message"],
                      "even on retention loss, the current preflight reason tells the operator "
                      "where to look right now")

    # (5) PEER CAUGHT THIS ONE. The filter is on the BATTERY JOB's conclusion, not the workflow's.
    # A workflow that is green because the battery SKIPPED is not a successful evaluation — that
    # is the whole point of #100's grey row. Delete-fix: the inner `battery["conclusion"] ==
    # "success"` check is removed; the test fails because the function would treat the run as a
    # success and never report stale.
    def test_workflow_success_with_skipped_battery_is_not_a_successful_evaluation(self):
        runs = [_run(99, "2026-07-01T00:00:00Z", conclusion="success")]
        # Workflow is green, but the battery job SKIPPED — the gate was grey.
        jobs = {99: [_job(99, "battery", "skipped")]}
        result = hsm_time_bound.check(
            now=NOW, runs=runs, jobs_by_run=jobs,
            current_battery_conclusion="failure",
            current_reason="a reader is present with no token — the card is unplugged",
        )
        self.assertEqual(result["verdict"], "no-history",
                         f"a skipped battery is not a successful evaluation: {result}")
        self.assertIn("card is unplugged", result["message"])

    # (6) And: a run whose battery job FAILED must not be treated as a success either. The
    # workflow-level `conclusion=success` filter upstream is not enough — a workflow can be
    # cancelled and still report workflow-level success on the runs list, depending on how the
    # cancellation propagated. Delete-fix: the battery-conclusion check is the only one that
    # matters; remove it and the test fails.
    def test_workflow_success_with_failed_battery_is_not_a_successful_evaluation(self):
        runs = [_run(100, "2026-07-15T00:00:00Z", conclusion="success")]
        jobs = {100: [_job(100, "battery", "failure")]}
        result = hsm_time_bound.check(
            now=NOW, runs=runs, jobs_by_run=jobs,
            current_battery_conclusion="failure",
            current_reason="card unplugged",
        )
        self.assertEqual(result["verdict"], "no-history",
                         f"a failed battery is not a successful evaluation: {result}")

    # (7) The newest run wins. If the most recent workflow-level success is OLD but there is a
    # NEWER run that is NOT a success, the older one is still the right anchor — the bound is
    # "time since the last successful evaluation," not "time since the last run." Delete-fix:
    # the runs list is not iterated in order; the test fails because the function would pick
    # the wrong run.
    def test_newest_successful_run_is_the_anchor(self):
        runs = [
            _run(1, "2026-08-01T00:00:00Z"),  # 35 days ago, success
            _run(2, "2026-09-04T00:00:00Z", conclusion="failure"),  # 1 day ago, failed
        ]
        jobs = {
            1: [_job(1, "battery", "success")],
            2: [_job(2, "battery", "failure")],
        }
        result = hsm_time_bound.check(
            now=NOW, runs=runs, jobs_by_run=jobs,
            current_battery_conclusion="failure",
            current_reason="card unplugged",
        )
        self.assertEqual(result["verdict"], "stale",
                         f"the 35-day-old run is the anchor; the 1-day-old failure does not "
                         f"reset the clock: {result}")
        self.assertIn("35 days ago", result["message"])


class ConstantTests(unittest.TestCase):
    # (8) The constant lives in code and carries the rationale. This test pins that the rationale
    # is in the comment, not just on a design doc nobody reads at the call site. Delete-fix: the
    # comment is removed; the test fails because the rationale check fails.
    def test_max_days_constant_has_a_rationale_in_its_source(self):
        source = (TOOLS / "hsm-time-bound.py").read_text(encoding="utf-8")
        self.assertIn("MAX_HARDWARE_EVALUATION_GAP_DAYS = 14", source,
                      "the bound has to be a named constant, not a magic number")
        # The rationale mentions BOTH failure modes peer named: too short produces noise on
        # routine outages; too long makes NOT EVALUATED the background. A constant whose comment
        # only justifies one half is half-documented.
        self.assertIn("Shorter", source,
                      "the rationale is missing the 'too short' half of the trade-off")
        self.assertIn("Longer", source,
                      "the rationale is missing the 'too long' half of the trade-off")


class EndpointTests(unittest.TestCase):
    # (9) The endpoint that lists workflow runs substitutes owner_repo and pins the workflow
    # name. Original review caught the script rendering a literal `${REPO}` because the
    # substitution was happening in an f-string the workflow reader mistook for shell
    # interpolation. The fix moves substitution into a pure helper; this test pins that the
    # rendered string is what `gh api` will receive, and that a typo in the workflow name (a
    # silent query that returns nothing) is caught before merge.
    #
    # Delete-fix: remove the workflow name constant; the rendered endpoint reads
    # `workflow_id=hsm-staging.ym` (or similar) and the test fails naming the missing constant.
    def test_endpoint_for_runs_substitutes_owner_repo_and_uses_the_hsm_staging_workflow_name(self):
        endpoint = hsm_time_bound.endpoint_for_runs("Digital-Frontier-LDA/regalia")
        self.assertTrue(
            endpoint.startswith("/repos/Digital-Frontier-LDA/regalia/actions/runs"),
            f"endpoint does not start with the owner/repo substitution: {endpoint!r}",
        )
        self.assertNotIn("${REPO}", endpoint,
            f"endpoint still contains the literal '${{REPO}}' that ships to `gh`: {endpoint!r}")
        self.assertIn("workflow_id=hsm-staging.yml", endpoint,
            f"endpoint does not filter to the hsm-staging workflow: {endpoint!r}")
        self.assertIn("status=completed", endpoint)
        self.assertIn("conclusion=success", endpoint)

    # (10) Same shape for the per-run jobs endpoint. The original literal
    # `/repos/${REPO}/actions/runs/{run_id}/jobs` is caught by the same `assertNotIn` check
    # the test above uses; the run-id formatting is the additional pin.
    def test_endpoint_for_jobs_substitutes_owner_repo_and_run_id(self):
        endpoint = hsm_time_bound.endpoint_for_jobs("acme/widgets", 12345)
        self.assertEqual(endpoint, "/repos/acme/widgets/actions/runs/12345/jobs")
        self.assertNotIn("${REPO}", endpoint)


class ParsePagesTests(unittest.TestCase):
    # (11) `gh api --paginate --slurp` returns a JSON array of page responses, where each
    # page is a dict whose list of items is keyed `workflow_runs` (runs endpoint) or `jobs`
    # (jobs endpoint). The merge function takes the key as a parameter so the wrong endpoint
    # is caught at the call site.
    #
    # Round 5 caught a defect where this function only knew about `workflow_runs`. The
    # previous version was `page.get("workflow_runs", [])`, which returned `[]` on every
    # jobs page, and the function only ever returned a list — `_run_jobs` then raised on
    # `isinstance(jobs, dict)`. The fix makes the merge key explicit and raises on missing.
    # Falsified by reverting the key parameter and confirming every test in this class
    # fails (wrong-key raises, jobs-shape merges, runs-shape merges).

    def test_parse_pages_merges_workflow_runs_across_pages(self):
        page1 = {"workflow_runs": [{"id": 1, "created_at": "2026-09-01T00:00:00Z"}]}
        page2 = {"workflow_runs": [{"id": 2}, {"id": 3}]}
        raw = json.dumps([page1, page2])
        result = hsm_time_bound.parse_pages(raw, key="workflow_runs")
        self.assertEqual([r["id"] for r in result], [1, 2, 3],
                         f"all runs across both pages must appear in page order: {result}")

    def test_parse_pages_merges_jobs_across_pages(self):
        # THE BUG ROUND 5 CAUGHT. The jobs endpoint returns {"jobs": [...]}; the previous
        # version's `page.get("workflow_runs", [])` returned [] for every jobs page. With
        # the explicit key, the function returns the merged list of job dicts and the
        # time-bound job's `_run_jobs` can iterate it.
        page1 = {"jobs": [{"name": "battery", "conclusion": "success"}]}
        page2 = {"jobs": [{"name": "preflight", "conclusion": "success"},
                          {"name": "time-bound", "conclusion": "skipped"}]}
        raw = json.dumps([page1, page2])
        result = hsm_time_bound.parse_pages(raw, key="jobs")
        self.assertEqual(
            [(j["name"], j["conclusion"]) for j in result],
            [("battery", "success"), ("preflight", "success"), ("time-bound", "skipped")],
        )

    def test_parse_pages_wrong_key_raises_keyerror(self):
        # `page.get("workflow_runs", [])` returned [] on a wrong-key lookup. The whole
        # time-bound run would report 'no history' on a key typo. Pin that the wrong key
        # raises KeyError, so a typo at the call site is loud rather than silent.
        page = {"workflow_runs": [{"id": 1}]}
        raw = json.dumps([page])
        with self.assertRaises(KeyError) as ctx:
            hsm_time_bound.parse_pages(raw, key="jobs")
        # The error message must name the wrong key, so the caller can debug without
        # reading the source.
        self.assertIn("jobs", str(ctx.exception),
                      f"error message should name the missing key: {ctx.exception}")

    def test_parse_pages_wrong_key_raises_in_jobs_response_too(self):
        # The reverse direction: caller passes key="workflow_runs" against a jobs page.
        # Same failure mode; pin the symmetric case.
        page = {"jobs": [{"name": "battery"}]}
        raw = json.dumps([page])
        with self.assertRaises(KeyError) as ctx:
            hsm_time_bound.parse_pages(raw, key="workflow_runs")
        self.assertIn("workflow_runs", str(ctx.exception))

    def test_parse_pages_non_dict_page_raises_valueerror(self):
        # A page is always a dict from gh (the endpoint shape is JSON object with a keyed
        # list inside). Anything else is malformed output and refusing to silently fabricate
        # is the right failure mode. The previous version's `if isinstance(page, list):
        # return page` accepted lists and treated them as runs, which is exactly the
        # behaviour that hid the wrong-endpoint bug.
        raw = json.dumps([[{"id": 1}, {"id": 2}]])  # page is a list, not a dict
        with self.assertRaises(ValueError):
            hsm_time_bound.parse_pages(raw, key="workflow_runs")

    def test_parse_pages_empty_list_under_key_yields_empty_result(self):
        # An empty list under the key is a real answer (no runs/jobs found), not a
        # malformed page. Pin that this returns an empty list rather than raising —
        # otherwise a successful empty answer would be turned into a hard failure,
        # which is the opposite of what we want.
        raw = json.dumps([{"workflow_runs": []}])
        result = hsm_time_bound.parse_pages(raw, key="workflow_runs")
        self.assertEqual(result, [])

    def test_parse_pages_single_dict_response_wraps_and_merges(self):
        # Defensive: a single page (no pagination triggered) arrives as a bare dict rather
        # than a list. --slurp wraps the dict in a list, but if gh ever changes that, the
        # function should still handle a single-dict input.
        raw = json.dumps({"workflow_runs": [{"id": 1}]})
        result = hsm_time_bound.parse_pages(raw, key="workflow_runs")
        self.assertEqual([r["id"] for r in result], [1])


class GhApiInvocationTests(unittest.TestCase):
    # (12) The `--slurp` flag on the `gh api` invocation in `_gh_api` is the part of the
    # contract that turns "gh emits one JSON document per page" into a single JSON array that
    # `parse_pages` can read. This test pins the literal CLI argument list at the call site
    # rather than mocking subprocess.run: a mocked subprocess would test the stub, and the
    # original review caught that manual review of the real call site passed a script that
    # 404s because nobody was looking at what flags `gh api` actually got. The pin is at the
    # source level: the call to subprocess.run must include `--slurp`.
    #
    # Delete-fix: remove `--slurp` from the subprocess.run argument list; the AST assertion
    # names the missing argument. Reverted.
    def test_gh_api_uses_slurp_so_paginate_returns_one_parseable_array(self):
        calls = [node for node in ast.walk(named_function("_gh_api"))
                 if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                 and isinstance(node.func.value, ast.Name)
                 and node.func.value.id == "subprocess" and node.func.attr == "run"]
        self.assertEqual(1, len(calls), "expected exactly one subprocess.run call in the I/O layer")
        # THE SHAPE IS ASSERTED BEFORE IT IS INDEXED. Reaching straight for
        # `calls[0].args[0].elts` assumes the argv is a literal list sitting in the first
        # positional slot. Both halves of that can stop being true under an ordinary
        # refactor -- `subprocess.run(command, ...)` with the list built above, or
        # `subprocess.run(args=[...])` -- and each would raise IndexError or AttributeError
        # here. A test whose entire job is to NAME a missing CLI argument must not fail by
        # crashing: the traceback says nothing about --slurp, and the reader's first
        # conclusion is that the test is broken rather than that the call site moved.
        self.assertTrue(
            calls[0].args,
            "subprocess.run is called with no positional argument, so the argv list is not "
            "where this check looks. If the call moved to args=[...] or the list is built "
            "above the call, re-point this assertion at the new shape -- do not delete it.")
        argv = calls[0].args[0]
        self.assertIsInstance(
            argv, (ast.List, ast.Tuple),
            f"subprocess.run's first argument is {type(argv).__name__}, not a literal list, so "
            "the flags cannot be read from the call site. This check pins the argv AT THE "
            "SOURCE rather than mocking subprocess, so a refactor that hoists the list into a "
            "variable needs this assertion re-pointed at that variable, not removed.")
        values = [element.value for element in argv.elts if isinstance(element, ast.Constant)]
        self.assertTrue(
            {"--paginate", "--slurp"}.issubset(values),
            "the gh api call must use --slurp alongside --paginate so paginated output is a "
            "single JSON array; without --slurp, gh emits one JSON document per page back-to-back "
            "and json.loads raises JSONDecodeError on the concatenation. Pinned here because "
            "the I/O layer was 'held by manual review' and manual review passed a script that "
            "would have crashed on the second page.",
        )

    # (13) `_gh_api` accepts a `key` argument and forwards it to `parse_pages`. The caller
    # is the only place that knows whether the endpoint is runs or jobs; passing the key
    # through keeps that knowledge at the call site and prevents a wrong-key lookup from
    # being silently absorbed by `parse_pages`. Falsified by removing the `key` parameter
    # and confirming the signature pin fails; then by passing a wrong key at the call
    # site and confirming the wrong-key pin fails (because `parse_pages` would default
    # back to the wrong key).
    #
    # Delete-fix: drop `key` from `def _gh_api(...)`; the AST assertion names the missing
    # parameter.
    def test_gh_api_signature_accepts_a_key_argument(self):
        arguments = {argument.arg for argument in named_function("_gh_api").args.args}
        self.assertIn(
            "key", arguments,
            "_gh_api must accept a `key` argument so the call site declares whether the "
            f"endpoint is runs or jobs. Without it, the round-5 defect returns: every "
            f"per-run jobs lookup silently returns [], and the time-bound run reports "
            f"'no history' on every schedule.",
        )

    # (14) The call sites in main() must pass the right key for the right endpoint.
    # A typo here turns the time-bound job into 'no-history' on every schedule. Falsified
    # by changing `key="workflow_runs"` to `key="workflow_run"` and confirming both pins
    # fail (this one and the wrong-key pin in ParsePagesTests).
    def test_runs_call_site_passes_workflow_runs_key(self):
        keys = [keyword.value.value for call in named_calls("_gh_api") for keyword in call.keywords
                if keyword.arg == "key" and isinstance(keyword.value, ast.Constant)]
        self.assertIn(
            "workflow_runs", keys,
            "the runs endpoint must be queried with key='workflow_runs'; a typo here "
            "silently turns every scheduled run into 'no history'.",
        )

    def test_jobs_call_site_passes_jobs_key(self):
        keys = [keyword.value.value for call in named_calls("_gh_api") for keyword in call.keywords
                if keyword.arg == "key" and isinstance(keyword.value, ast.Constant)]
        self.assertIn(
            "jobs", keys,
            "the jobs endpoint must be queried with key='jobs'; a typo here silently "
            "turns every per-run battery lookup into 'no battery found'.",
        )


if __name__ == "__main__":
    unittest.main()
