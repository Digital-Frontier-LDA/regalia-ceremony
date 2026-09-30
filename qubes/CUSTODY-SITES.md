# Choosing where the share cases go

A k-of-n ceremony ends with n sealed cases, each holding one share. **Where they go decides whether the
scheme survives a disaster and resists coercion.** This file is the public, generic checklist. The
actual places, and who holds each case, are the *directory*: keep that private (encrypted, and sealed
with the executor), never in a public repository and never inside a case.

`scripts/custody-plan-check.py` checks a plan against rules 1–5 below. The easiest start is the guided
mode, which asks one question at a time, explains the rule behind it, flags a problem as soon as it
appears, and writes the plan (mode 0600):

```bash
/opt/vault-ceremony/custody-plan-check.py --new plan.toml     # guided
/opt/vault-ceremony/custody-plan-check.py plan.toml           # re-check after any change
/opt/vault-ceremony/custody-plan-check.py --example           # a fictional plan to copy
```

Keep the filled-in file private, next to the directory. Every line reads OK, WARN or FAIL; the last line is PLAN OK or PLAN FAILED.

## The rules the checker enforces

1. **One site per share:** exactly n sites.
2. **At most n − k sites per region.** A *region* is what one disaster can take out: an earthquake
   zone, a flood plain, a city. Losing it must still leave k cases. Hazards that cross regions (a fault
   line through two cities) go in `zones`, which count the same way.
3. **Nobody reaches k sites alone.** List everyone who can open each site *without asking its holder*:
   the holder, a datacenter's staff, a bank, whoever has the key. An organisation counts as one actor.
   If one actor reaches k, coercing (or compromising) that one actor recovers the secret.
4. **Whoever holds the directory reaches no site.** Otherwise one person knows where every case is and
   already holds one.
5. **Pairs that together reach k are reported** as WARN, so each such pair is a choice you made on
   purpose. Pairs with the principal are not reported: in life every holder hands them a share anyway.

## What to weigh when choosing sites (not checked by the tool)

- **Hazards.** Map each candidate to its seismic zone, flood plain and wildfire exposure. Prefer
  sites off the fault line that threatens your largest city; a town between two cities may still sit
  in one of their hazard zones.
- **Institutions versus people.** A datacenter lock box or a bank box survives the holder moving,
  retiring or dying; a person can be briefed on the in-person rule and asked the shared question.
  Mix both.
- **Who can open it after a death.** A bank box in the company's name: ask the bank who may open it
  when the signatory dies or is incapacitated, and make sure the executor can without being a
  signatory in life (a signatory executor could take a share early).
- **Access overlap.** One technical person with keys to two datacenters reaches two sites: count it
  (rule 3), and keep it well below k.
- **Travel.** Put every site within a day's reach of public transport or a single road corridor, so
  the principal or the executor can collect k cases in one trip. Note the station for each site in the
  private directory.
- **Nobody's home in the same region as another site of theirs.** A share at the home of someone who
  already reaches a site in that region adds to both rule 2 and rule 3.
- **Change is a physical move.** Moving a case (for example, from a bank box to a notary deposit) is
  one sealed case changing place: update the directory and the seal registry, and re-run the checker.
  It is not a new ceremony.

## After placing the cases

- Record each case's seal serial against its site in the private seal-custody file (see
  `seal-registry.example.yaml`).
- Check the seals on a schedule (e.g. yearly), and log each check.
- Re-run `custody-plan-check.py` whenever a site, a holder or who has access changes.
