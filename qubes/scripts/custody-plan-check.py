#!/usr/bin/env python3
"""custody-plan-check.py — check where the k-of-n share cases go, against the site rules.

  custody-plan-check.py plan.toml
  custody-plan-check.py --new plan.toml       # guided: asks one question at a time, checks as you go
  custody-plan-check.py --example             # print a fictional plan to start from

The plan names regions and who can reach each site, never secrets. It still says where the cases
are, so keep the real one private (next to the directory, not in a public repository). The rules
(CUSTODY-SITES.md) are public and generic:

  1. exactly n sites for a k-of-n scheme (2 <= k <= n <= 16);
  2. at most n - k sites in any one region or hazard zone, so losing it still leaves k;
  3. nobody (a person or an organisation) can reach k sites on their own, except the principal:
     it is their secret, so reaching k is a WARN naming the defence (the holders' in-person rule);
  4. whoever holds the directory (who holds which case, where) reaches no site;
  5. any two actors who together reach k are reported, so that pair is a deliberate choice (pairs
     with the principal are not: in life every holder hands them a share anyway).
  6. traces: sites marked logged (a bank, a datacenter) record every opening. If k sites could be
     opened without any log, that is a WARN; otherwise the report says how many logged sites any
     recovery must touch.

Every line reads OK, WARN or FAIL; the last line is PLAN OK or PLAN FAILED (exit 1).
"""
import argparse
import itertools
import re
import sys

EXAMPLE = """\
# A FICTIONAL custody plan: the shape to copy, not real places. Keep the real one private.
scheme = "shamir-4-of-6"
# Whose secret it is: in life the holders hand shares to them, so they may recover with any holder.
principal = "principal"
# The people who hold the directory (who holds which case, where). They must reach no site.
directory_holders = ["executor"]

[[site]]
id = 1
kind = "principal's home safe"
region = "capital"               # the area one disaster (earthquake, flood, fire) can take out
zones = ["capital-fault"]        # optional extra hazard zones that cross regions
reach = ["principal"]            # everyone who can open it without asking a holder

[[site]]
id = 2
kind = "datacenter lock box"
region = "capital"
logged = true                    # every opening leaves a record
zones = ["capital-fault"]
reach = ["principal", "technical-director", "datacenter-a-staff"]

[[site]]
id = 3
kind = "datacenter lock box"
region = "north"
logged = true
reach = ["principal", "technical-director", "datacenter-b-staff"]

[[site]]
id = 4
kind = "bank box, company name"
region = "north"
logged = true
reach = ["principal", "bank-north"]

[[site]]
id = 5
kind = "bank box, company name"
region = "centre"
logged = true
reach = ["principal", "bank-centre"]

[[site]]
id = 6
kind = "the principal's trusted relative"
region = "centre"
reach = ["principal", "relative"]
"""


def fail_usage(msg):
    print("Error: %s" % msg, file=sys.stderr)
    sys.exit(2)


def load(path):
    # TOML, read by the standard library (3.11+): no package to add to the air-gapped image.
    import tomllib
    try:
        with open(path, "rb") as f:
            return tomllib.load(f)
    except (OSError, tomllib.TOMLDecodeError) as e:
        fail_usage("cannot read %s: %s" % (path, e))


def check(plan):
    """Return a list of (level, message); level is OK, WARN or FAIL."""
    out = []
    if not isinstance(plan, dict):
        return [("FAIL", "the plan is not a table with scheme, directory_holders and [[site]] entries")]

    m = re.fullmatch(r"shamir-([0-9]+)-of-([0-9]+)", str(plan.get("scheme", "")))
    k, n = (int(m.group(1)), int(m.group(2))) if m else (0, 0)
    if not m or not (2 <= k <= n <= 16):
        return [("FAIL", "scheme must be shamir-<k>-of-<n> with 2 <= k <= n <= 16 (got %r)" % plan.get("scheme"))]
    out.append(("OK", "scheme %d-of-%d: any %d sites recover, losing %d is survivable" % (k, n, k, n - k)))

    sites = plan.get("site")
    if not isinstance(sites, list) or not all(isinstance(s, dict) for s in sites):
        return out + [("FAIL", "the plan needs one [[site]] table per share")]
    ids = [str(s.get("id")) for s in sites]
    if len(sites) != n:
        out.append(("FAIL", "%d sites for %d shares: every share needs exactly one site" % (len(sites), n)))
    else:
        out.append(("OK", "%d sites, one per share" % n))
    if len(set(ids)) != len(ids):
        out.append(("FAIL", "site ids repeat: %s" % ", ".join(sorted(i for i in set(ids) if ids.count(i) > 1))))

    # Rule 2: regions and hazard zones.
    areas = {}
    for s in sites:
        sid = str(s.get("id"))
        region = s.get("region")
        if not region:
            out.append(("FAIL", "site %s has no region" % sid))
            continue
        for area in [str(region)] + [str(z) for z in (s.get("zones") or [])]:
            areas.setdefault(area, []).append(sid)
    for area in sorted(areas):
        held = areas[area]
        if len(held) > n - k:
            out.append(("FAIL", "%s holds %d sites (%s): losing it leaves %d, fewer than %d"
                        % (area, len(held), ", ".join(held), n - len(held), k)))
        else:
            out.append(("OK", "%s holds %d site(s) (%s): losing it leaves %d" % (area, len(held), ", ".join(held), n - len(held))))

    # Rule 3: who reaches what.
    reach = {}
    for s in sites:
        sid = str(s.get("id"))
        actors = [a for a in (s.get("reach") or []) if str(a).strip()]
        if not actors:
            out.append(("FAIL", "site %s lists nobody in reach: someone opens every site; name them" % sid))
        for a in actors:
            reach.setdefault(str(a), set()).add(sid)
    principal = str(plan.get("principal") or "")
    for a in sorted(reach):
        got = sorted(reach[a])
        if len(got) >= k and a == principal:
            # It is their secret: in life they may reach every site. Coercing them is the risk that
            # remains, and the defence is the holders' in-person rule with the shared question.
            out.append(("WARN", "%s (the principal) reaches %d sites (%s), k or more by design: the defence against "
                        "coercing them is the holders' in-person rule and the shared question" % (a, len(got), ", ".join(got))))
        elif len(got) >= k:
            out.append(("FAIL", "%s alone reaches %d sites (%s): k is %d" % (a, len(got), ", ".join(got), k)))
        else:
            out.append(("OK", "%s reaches %d site(s) (%s), below k" % (a, len(got), ", ".join(got))))

    # Rule 4: the directory holders reach nothing.
    holders = [str(h) for h in (plan.get("directory_holders") or [])]
    if not holders:
        out.append(("WARN", "no directory_holders listed: after a death, who knows where the cases are?"))
    for h in holders:
        if h in reach:
            out.append(("FAIL", "%s holds the directory AND reaches site(s) %s: nobody holds both"
                        % (h, ", ".join(sorted(reach[h])))))
        else:
            out.append(("OK", "%s holds the directory and reaches no site" % h))

    # Rule 5: pairs that together reach k. The principal is left out: in life every holder hands them
    # a share anyway, so a pair with the principal adds nothing. Alone they are still rule 3.
    if principal:
        out.append(("OK", "%s is the principal: pairs with them are not listed (they may recover with any holder)" % principal))
    for a, b in itertools.combinations(sorted(x for x in reach if x != principal), 2):
        both = reach[a] | reach[b]
        if len(both) >= k and len(reach[a]) < k and len(reach[b]) < k:
            out.append(("WARN", "%s and %s together reach %d sites (%s): make that pair a deliberate choice"
                        % (a, b, len(both), ", ".join(sorted(both)))))

    # Rule 6: traces. A bank or a datacenter logs every opening; a home safe or a relative does not.
    unlogged = sorted(str(x.get("id")) for x in sites if x.get("logged") is not True)
    if len(unlogged) >= k:
        out.append(("WARN", "%d sites keep no access log (%s): k of them could be opened without a trace; "
                    "mark logged = true where a bank or datacenter records each opening" % (len(unlogged), ", ".join(unlogged))))
    else:
        out.append(("OK", "any recovery touches at least %d logged site(s): only %d site(s) (%s) open without a trace"
                    % (k - len(unlogged), len(unlogged), ", ".join(unlogged) or "none")))
    return out


def ask(prompt, default=None):
    """One question on the terminal; Enter takes the default."""
    shown = "%s [%s]: " % (prompt, default) if default not in (None, "") else "%s: " % prompt
    try:
        answer = input(shown).strip()
    except EOFError:
        fail_usage("input ended before the plan was complete; nothing was written")
    return answer or ("" if default is None else str(default))


def names(text):
    return [x.strip() for x in text.split(",") if x.strip()]


def toml_str(v):
    # JSON string escapes are valid TOML basic-string escapes.
    import json
    return json.dumps(str(v), ensure_ascii=False)


def to_toml(plan):
    lines = ["# Custody plan: PRIVATE. Keep it with the directory, never in a public repository.",
             "scheme = %s" % toml_str(plan["scheme"])]
    if plan.get("principal"):
        lines.append("principal = %s" % toml_str(plan["principal"]))
    lines.append("directory_holders = [%s]" % ", ".join(toml_str(h) for h in plan["directory_holders"]))
    for site in plan["site"]:
        lines += ["", "[[site]]", "id = %d" % site["id"], "kind = %s" % toml_str(site["kind"]),
                  "region = %s" % toml_str(site["region"])]
        if site.get("zones"):
            lines.append("zones = [%s]" % ", ".join(toml_str(z) for z in site["zones"]))
        lines.append("reach = [%s]" % ", ".join(toml_str(r) for r in site["reach"]))
        lines.append("logged = %s" % ("true" if site.get("logged") else "false"))
        if site.get("station"):
            lines.append("station = %s" % toml_str(site["station"]))
    return "\n".join(lines) + "\n"


def interactive(path):
    """Build a plan one question at a time, with the rule behind each question, then check it."""
    import os
    if os.path.exists(path):
        fail_usage("%s exists; choose a new file (nothing was changed)" % path)
    print("Custody plan, step by step. Enter keeps the value in [brackets].")
    print("The answers say where the cases go: the file you write is PRIVATE.\n")
    print("1. The scheme. Any k of the n cases recover the secret; up to n - k can be lost.")
    while True:
        k, n = ask("   k (cases needed to recover)", 4), ask("   n (cases in total)", 6)
        if k.isdigit() and n.isdigit() and 2 <= int(k) <= int(n) <= 16:
            k, n = int(k), int(n)
            break
        print("   k and n must be whole numbers with 2 <= k <= n <= 16.")
    print("   So: at most %d case(s) per region, and nobody may reach %d on their own.\n" % (n - k, k))
    print("2. The principal: whose secret it is. In life, holders hand a share only to them, in person.")
    principal = ask("   principal (a role, not a name)", "principal")
    print("\n3. The directory: the list of who holds which case, where. Whoever keeps it must reach NO case.")
    holders = names(ask("   who keeps the directory (roles, comma-separated)", "executor"))
    sites, regions, reach = [], {}, {}
    print("\n4. The sites, one per case. For each: what it is, the region one disaster could take out,")
    print("   and EVERYONE who can open it without asking its holder (staff, a bank, whoever has a key).")
    for i in range(1, n + 1):
        print("\n   Site %d of %d" % (i, n))
        kind = ask("   what is it (e.g. bank box, datacenter lock box, relative)")
        region = ask("   region (the area one earthquake, flood or fire could take out)")
        zones = names(ask("   hazard zones it shares with other regions (optional, comma-separated)", ""))
        who = []
        while not who:
            who = names(ask("   who can open it (roles, comma-separated)"))
        logged = ask("   does it keep a log of every opening, like a bank or a datacenter? (y/N)", "n").lower().startswith("y")
        station = ask("   nearest station or road, to plan a collection trip (optional)", "")
        site = {"id": i, "kind": kind or "site %d" % i, "region": region or "unknown",
                "zones": zones, "reach": who, "logged": logged, "station": station}
        sites.append(site)
        for area in [site["region"]] + zones:
            regions.setdefault(area, []).append(i)
            if len(regions[area]) > n - k:
                print("   \033[31mFAIL\033[0m %s now holds %d sites: losing it would leave fewer than %d."
                      % (area, len(regions[area]), k))
        for actor in who:
            reach.setdefault(actor, set()).add(i)
            if len(reach[actor]) >= k and actor != principal:
                print("   \033[31mFAIL\033[0m %s now reaches %d sites: k is %d." % (actor, len(reach[actor]), k))
            if actor in holders:
                print("   \033[31mFAIL\033[0m %s keeps the directory and now reaches a site." % actor)
    plan = {"scheme": "shamir-%d-of-%d" % (k, n), "principal": principal,
            "directory_holders": holders, "site": sites}
    print("\n5. The check.\n")
    results = check(plan)
    report(results)
    # Created exclusively, already 0600: never readable by others for a moment, and a file or
    # symlink that appeared since the check above is refused rather than followed or truncated.
    try:
        fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0), 0o600)
    except OSError as e:
        fail_usage("cannot create %s: %s (nothing was written)" % (path, e.strerror))
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(to_toml(plan))
    print("\nWritten to %s (mode 0600). Re-check it any time: custody-plan-check.py %s" % (path, path))
    return 1 if any(level == "FAIL" for level, _ in results) else 0


def report(results):
    colour = {"OK": "\033[32m", "WARN": "\033[33m", "FAIL": "\033[31m"}
    for level, msg in results:
        print("  %s%-4s\033[0m %s" % (colour[level], level, msg))
    bad = any(level == "FAIL" for level, _ in results)
    print()
    print("\033[31mPLAN FAILED\033[0m — fix the FAIL items before any case leaves the ceremony."
          if bad else "\033[32mPLAN OK\033[0m — every site rule holds; WARN items are choices to confirm.")


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("plan", nargs="?", help="the custody plan (TOML)")
    ap.add_argument("--example", action="store_true", help="print a fictional plan and exit")
    ap.add_argument("--new", metavar="PLAN", help="build a new plan step by step, then check it")
    a = ap.parse_args()
    if a.example:
        sys.stdout.write(EXAMPLE)
        return 0
    if a.new:
        return interactive(a.new)
    if not a.plan:
        fail_usage("give a plan file, or --example")
    results = check(load(a.plan))
    report(results)
    return 1 if any(level == "FAIL" for level, _ in results) else 0


if __name__ == "__main__":
    sys.exit(main())
