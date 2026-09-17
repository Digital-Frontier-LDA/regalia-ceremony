# SmartCard-HSM trust anchor

`DESRCACC100001` is the CardContact **Scheme Root CA** certificate (CVC, BSI TR-03110,
brainpoolP256r1, valid 2012-11-09 to 2032-11-08). Every genuine SmartCard-HSM, the Nitrokey
HSM 2 included, carries in EF 2F02 a device certificate issued by a Device Issuer CA that this root
certifies. This directory is the `--trust-dir` for `qubes/scripts/cvc-devaut-verify.py`; the file is
named by its CHR, as the verifier expects.

| | |
|---|---|
| sha256 | `453a391015c5fbb60116c838ed613591828bf62ac8a1aca276ce4e60525ec3e3` |
| source | `SmartCardHSM.rootCerts.DESRCACC100001` in CardContact's `lib/smartcardhsm.js`, fetched over HTTPS from `https://www.openscdp.org/scripts/sc-hsm/jsdoc/symbols/src/lib_smartcardhsm.js.html` on 2026-09-17 |
| corroboration | the real chain of Nitrokey HSM 2 `DENK0404144` (device `DENK040414400000`, issuer `DEDINK0400001`) verifies against it, and fails against the same certificate with its public point replaced. Both are asserted on every run by `GoldenNitrokeyDevautTest` in `qubes/emulator/tests/test_cvc_devaut_verify.py`. |

**Do not add the Device Issuer CA here.** `DEDINK0400001` travels on the card itself, in EF 2F02
after the device certificate. Placing a card-supplied issuer certificate in the trust directory is
fine for a single verification, because the verifier still checks it against this root, but only
the root is an anchor.

CardContact publishes no detached signature for this certificate. The corroboration above is the
reason to trust it. If it ever changes, the change must come with new corroboration.

This directory is also what `qubes/scripts/hsm-key-attestation-verify.py --trust-dir` validates a
device certificate against before it will report a key attestation: an attestation checked under
an unvalidated device certificate proves nothing, so that tool refuses without either this
directory or an explicit assertion that the same bytes were validated earlier.
