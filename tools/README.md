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
