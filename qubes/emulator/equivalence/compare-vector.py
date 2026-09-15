#!/usr/bin/env python3
"""compare-vector.py — compare one profile's run-vector.py output with expected.json (#36).

Every deterministic and semantic field is compared, and every field that differs, is missing or
was not expected is NAMED with both values. The transcript section is never compared: it records
tool versions, which may legitimately differ between profiles. What must not differ is an output.

    compare-vector.py expected.json result.json
        exit 0 when every field matches, 1 naming each field that does not

    compare-vector.py expected.json result.json --must-differ bip39.akash_address,...
        the NEGATIVE CONTROL. Exit 0 only if the comparison FAILS and every named field is among
        the differences. A comparison that cannot fail proves nothing about two profiles agreeing,
        so a perturbed run has to be shown failing, on the field the perturbation reaches.
"""
import argparse
import json
import sys

SECTIONS = ("deterministic", "semantic")


def differences(expected, actual):
    found = []
    for section in SECTIONS:
        want, have = expected.get(section, {}), actual.get(section, {})
        for field in sorted(set(want) | set(have)):
            name = "%s.%s" % (section, field)
            if field not in have:
                found.append((field, "MISSING   %s: expected %r, the profile produced nothing" % (name, want[field])))
            elif field not in want:
                found.append((field, "UNEXPECTED %s: %r is not in expected.json" % (name, have[field])))
            elif want[field] != have[field]:
                found.append((field, "DIFFERS   %s: expected %r, got %r" % (name, want[field], have[field])))
    return found


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("expected")
    ap.add_argument("actual")
    ap.add_argument("--must-differ", default="", help="comma-separated fields a perturbed run must change")
    a = ap.parse_args()
    expected, actual = json.load(open(a.expected)), json.load(open(a.actual))

    # The instrument must be able to see something. An expected file with no deterministic field, or
    # a semantic field that is not true, would compare "equal" while pinning nothing.
    if not expected.get("deterministic") or not all(value is True for value in expected.get("semantic", {}).values()):
        sys.exit("expected.json pins no deterministic output, or holds a semantic check that is not true")

    profile = actual.get("transcript", {}).get("profile", "unlabelled profile")
    found = differences(expected, actual)
    for _, line in found:
        print(line)

    if a.must_differ:
        required = [field.strip() for field in a.must_differ.split(",") if field.strip()]
        differing = {field for field, _ in found}
        missed = [field for field in required if field not in differing]
        if not found:
            print("NEGATIVE CONTROL FAILED: the perturbed %s run matched expected.json exactly, so this comparison cannot tell the profiles apart" % profile)
            return 1
        if missed:
            print("NEGATIVE CONTROL FAILED: the comparison failed, but not on %s — it is not detecting the perturbation it was given" % ", ".join(missed))
            return 1
        print("negative control OK: the perturbed %s run differs on %s" % (profile, ", ".join(required)))
        return 0

    if found:
        print("EQUIVALENCE FAILED for %s: %d field(s) differ from expected.json" % (profile, len(found)))
        return 1
    print("equivalence OK for %s: %d deterministic and %d semantic fields match expected.json" % (
        profile, len(expected["deterministic"]), len(expected["semantic"])))
    return 0


if __name__ == "__main__":
    sys.exit(main())
