# Ceremony execution profiles

All real ceremonies use the same scripts, key algorithms, 4-of-6 recovery
thresholds, two-person approvals, output verification, and teardown. A profile
changes only how the operating system proves isolation and how it is destroyed.
The profile is detected from platform evidence; an operator-supplied label is not
accepted as evidence.

| Profile | Detection evidence | Persistent state | Required disposal |
|---|---|---|---|
| `qubes-disposable` | QubesDB reports `/qubes-vm-persistence=none` | none by design | shut down the DispVM and verify dom0 removed it |
| `qubes-vault` | QubesDB reports `AppVM` and `rw-only` persistence | `/rw` and private volume | retain teardown report, shut down, then delete the qube/volumes after evidence export |
| `debian-live` | Debian OS plus overlay/aufs root backed by live media | overlay upper layer and RAM | power off; remove and physically control the boot/output media |

A normally installed Debian system is unsupported. The guest cannot prove that
an installation is “fresh” or will later be thrown away. Run Debian from
read-only live media with an overlay root, or run that live environment inside a
Qubes DisposableVM.

## Invariants

Before a token or share is exposed, the combined preflight requires:

- no IPv4/IPv6 route or global-scope interface;
- no active swap, usable hibernation path, core dumps, or shell history;
- volatile journaling and no active automount/crash-reporting services;
- only the expected writable root/runtime tmpfs mounts;
- a plausible offline clock, with RTC comparison where available;
- `/dev/shm` tmpfs for all secret-bearing files;
- required pinned tools and runtime modules, sufficient kernel entropy, and
  explicitly selected peripherals through the separate go/no-go gate;
- USB/local-only printing and no mounted output media while secrets are live.

For Qubes, dom0 must additionally run `preflight-dom0.sh`. This proves no NetVM,
fixed memory, no dom0 swap, and the intended qube class. The in-guest and dom0
checks are complementary and neither substitutes for the other.

## Secret-bearing paths and processes

The inventory is identical for all three profiles; only the persistence column
above changes:

| Location/process | Secret exposure | Control |
|---|---|---|
| `/dev/shm/ceremony.*` | keys, PIN files, shares, QR/PDF staging, wrapped exports | mode 0700 tmpfs; complete directory removed by the exit trap |
| CUPS client and `/var/spool/cups` | plaintext paper share jobs | USB/local queue allowlist; wait for print, `cancel -x`, residue scan |
| shell, editor, and child-tool processes | stdin/environment/PIN and key buffers | history unset, core limit zero, hardened editor, no secret argv; power off after run |
| `pcscd`, OpenSC, and YubiKey middleware | PIN and APDU/session state in memory | isolated guest, bounded calls, token removal and power-off |
| operator-selected paper, metal, HSM, and optical outputs | intended durable secret material | reconstruct/read-back verification, seal registry, two-person custody |
| `$HOME`, `/tmp`, `/var/tmp` | accidental copies, editor files, logs | volatile profile controls plus teardown canary scan |

No network service, host clipboard, shared folder, host-agent socket, or mounted
general-purpose filesystem is an allowed output path.

## Teardown evidence

On a real run, `ceremony.sh` creates a random 32-byte residue canary in its tmpfs
workdir and records the initial mount set. Its exit trap calls
`ceremony-teardown.py`, which removes the complete workdir, rejects mounts added
during the ceremony, and searches the user home, temporary directories, and CUPS
spool for the canary. Set `CEREMONY_EVIDENCE_DIR` to an already prepared evidence
destination to retain the JSON report; otherwise it is printed.

The report is evidence of checked software-visible paths, not a claim of physical
erasure. It cannot prove erasure from RAM remnants, SSD flash translation layers,
printer memory, firmware, or written optical media. After a passing report:

1. power-cycle the printer and tokens;
2. eject, label, seal, and inventory every intended output medium;
3. shut down rather than suspend the guest;
4. destroy the DispVM, or delete the persistent vault and its storage volumes;
5. treat a failed or incomplete scan as contamination and invoke incident handling.

Simulation sets `CEREMONY_SIMULATE=1`; it is visibly reported and never counts as
profile or teardown evidence.
