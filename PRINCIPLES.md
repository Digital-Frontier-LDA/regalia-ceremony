# Guiding principles, by lifecycle phase

The design philosophy behind this tooling, in the order you meet it — from the ceremony that
creates a key to the years of operation that follow. Each principle is a constraint the scripts and
runbooks enforce, not advice.

## Ceremony — before anything exists

- **The seed is the only irreplaceable thing.** It is split into Shamir shares on metal (a 4-of-6
  scheme); everything else is derived from it or re-creatable. Protect this and nothing else at this
  level.
- **Always import, never generate a root key on-card.** A key born on the card cannot be backed up,
  cannot be reconstructed from shares, and would differ on every device. Import a seed-derived key
  so any card can be reproduced.
- **The DKEK is a disposable transport wrapper, not custody material.** It exists only because the
  card's `unwrapKey` demands a key domain. Use it, then destroy it — losing it costs nothing, and a
  DKEK that no longer exists can never end up sitting beside a PIN.
- **Every device gets its own PIN and its own DKEK.** Nothing is shared across the fleet, so a
  compromise at one site stays at one site.
- **No single custodian can recover anything alone.** Recovery requires a threshold of independently
  held shares.

## Day 0 — provisioning

- **The DKEK never touches a host that has PIN access.** Enforced at deploy time, not by a paragraph
  in a runbook.
- **One device serves every role** — SOPS, GPG/PGP, SSH, X.509 CA, wallet signing. One device to
  provision, escrow, and replace.
- **Two devices, in two locations.** Devices ship keyless: each unwraps a ceremony-wrapped blob in
  place at its rack, so no shared key-domain is required and no key travels in the clear.
- **Provisioning is a script, not a performance.** A ceremony only its author can run is not a
  procedure.

## Day 1 — first service

- **Measure throughput per key type before assigning a workload.** There is no single "card speed":
  RSA decrypt and P-256 ECDSA can differ by more than an order of magnitude on the same device.
- **Bound the loss before enabling the key.** Per-transaction and daily caps, enforced in-process
  and fail-closed. Every argument for putting funds or infrastructure on one device rests on that
  bound holding.
- **Exactly one host holds a usable authentication at any time.** That active credential *is* the
  active-signer token (per-device PINs today; moving to threshold public-key authentication).

## Day 2 — operations, which is most of the life

- **Hardware is disposable; the seed is not.** Any card can die and be replaced with no loss, and
  replacement must not require the original device.
- **Rotation is a first-class operation** — and on this hardware it means *re-provisioning* a device,
  because token-resident private keys cannot be deleted. Budget for it rather than discovering it.
- **Redundancy is disaster recovery, not high availability.** If the primary site dies, service
  stops until a custodian activates the standby. Two hot signers on one account is worse than an
  outage.
- **Every claim the system makes about itself is verifiable by a command** — and every gate is proven
  to go red on a known-bad input before it is trusted green.
- **No staging measurement informs a production decision.** A Pico HSM is a fully capable
  SmartCard-HSM used for staging by choice; it is a different firmware implementation from the
  production Nitrokey HSM 2, and the two have been observed to diverge. Re-measure on production
  hardware before trusting a result for production.
