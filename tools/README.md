# Bench tooling

The scripts the staging batteries and drills run: reader resolution by serial, the bench lock,
posture restore, the scenario matrix, forensic capture and decode, and the transcript redactor.
They need OpenSC and a SmartCard-HSM (a Pico HSM for staging, a Nitrokey HSM 2 for production).

## The staging registry is a default-deny list

`hsm-staging-registry.json` decides which card may be **wiped, re-personalised or reflashed**.
Every serial that is not listed as `staging` — unlisted, `prod`, or a registry that cannot be read —
answers `protected`, and the tools refuse. The copy here lists only the Pico HSM staging devices this
repository already documents.

**On a real bench, this file is not the authority.** Point `HSM_STAGING_REGISTRY_FILE` at the
operator's own registry, kept with the hardware rather than in a repository, so that a repository
compromise cannot grant permission to wipe a card:

```sh
export HSM_STAGING_REGISTRY_FILE=/etc/regalia/hsm-staging-registry.json
```

Never add a production device to the copy in this repository.

### Two kinds, identified by what each card can prove

`pico-hsm2` entries carry `board_id` (the RP2350 OTP chip id, read over SWD) and `debug_probe`,
because that is how the flash tools address the board. A Nitrokey HSM 2 has neither: its hardware
identity is **C.DevAut in EF 2F02**, so `nitrokey-hsm2` entries carry `devaut_chr` and
`devaut_sha256` instead, and are refused if they carry a board id.

```json
{ "id": "nitrokey-hsm2-a", "role": "staging", "kind": "nitrokey-hsm2",
  "token_serial": "DENK0404144", "devaut_chr": "DENK040414400000",
  "devaut_sha256": "1b7763b7…9aa4" }
```

`qubes/scripts/hsm-devaut-read.sh` prints that digest, with `opensc-tool` alone.

**The pin is checked against the CARD before a wipe.** `hsm_assert_staging` answers "may a card
with this serial be wiped"; it cannot answer "is the card in front of me that card", because a
serial is self-reported and a substituted genuine Nitrokey reports whatever its issuer put there.
`hsm_assert_staging_card` does both — the role gate, then `hsm_assert_devaut_pinned`, which reads
EF 2F02 and compares. No pin, no reader, no readable certificate and a different digest are all
refusals. A Pico entry has no pin and passes through: its identity is proven over SWD by
`hsm_verify_board_over_probe`, the same idea one bus over.

**Leaving the list is enforced, not remembered.** Registering a future-production unit means
automation may erase it on schedule, so `hsm-host-role/files/commission-card.sh` refuses to
commission a card the registry still lists as `staging`. The last step of qualifying a unit is
removing its entry in a reviewed change.

## What the scripts reach for

They call each other by path. Four that this repository originally shipped without — and that
`qubes/emulator/tests/test-tool-helper-paths.sh` now checks for — are the ones a bench run hits
only once it is already underway:

| script | what stops working without it |
| --- | --- |
| `hsm-capacity-check.sh` | `hsm-bug6-powerloss.sh` REFUSES to start on a card at its object limit. A full card fails writes with the same message as a broken build: on 2026-08-10 that produced two consecutive wrong diagnoses before anyone counted the objects. |
| `hsm-forensic-capture.py` | the pyserial capture every trace depends on. `stty`+`cat` is not a fallback — it mis-clocks the Debug Probe's UART bridge and yields a confident verdict from an unreadable trace. |
| `hsm-reboot-soak.sh` | the soak `hsm-usb-delay-sweep.sh` runs per arm; without it the sweep has nothing to measure. |
| `hsm-ahb-transition-watch.sh` | the AHB sampler the soak's recovery ladder uses to record *when* the bus stopped answering rather than only that it had. |

The rule this encodes: a script that reaches outside the repository it ships in fails on a bench,
mid-run, after touching a card — naming a file the operator can see referenced in the tree they are
standing in. The test opens every helper name the scripts ask for.

## The rest of the bench toolkit

The firmware-investigation scripts came across with them, so the toolkit is complete here rather
than split across two repositories: `hsm-quiesce.sh` (the identity-and-role interlock the flash
tools' comments already pointed at), `hsm-firmware-invariants.sh` (+ its suite in
`qubes/emulator/tests/`), `hsm-identify-firmware.sh`, `hsm-wedge-hunt.sh`,
`hsm-capture-then-recover.sh`, `hsm-bug6-hunt-physical.sh`, `hsm-rtt-log.sh` and
`hsm-powman-dbgmode.sh`.

They drive a Pico HSM over SWD with a debug probe and are the tools the RP2350 wedge and Bug 6
investigations were done with; `hardware/` documents what they found.
