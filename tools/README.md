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
