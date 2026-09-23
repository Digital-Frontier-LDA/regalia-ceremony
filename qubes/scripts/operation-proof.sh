#!/usr/bin/env bash
# operation-proof.sh — prove a freshly provisioned key PERFORMS its operation, with the operator's PIN,
# and record the proof for `ceremony-manifest.py record` (regalia#28 criterion 3).
#
#   operation-proof.sh --operation sign|decrypt|key-agreement --backend yubikey-piv|nitrokey-pkcs11
#                      --serial SERIAL --object-id ID [--device-id MANIFEST_DEVICE_ID] --out PROOF.json
#                      [--module PKCS11_MODULE] [--pin-fd N]
#
# --operation is what `ceremony-manifest.py plan` prints for the binding (the wizard reads it from
# piv-steps). It is never guessed: a signing key proven by a round trip would carry weaker evidence
# than it could, and `record` refuses that.
#
# WHY THIS EXISTS. Everything the ceremony recorded about a key before this was the device's REPORT
# of it: serial, slot, algorithm, origin, PIN and touch policy, the exported public key. None of that
# shows the key works. A slot regenerated after its export was captured, a PIN that is not the one
# the custodian was given, or an object PKCS#11 will not sign with all qualify on the reports alone,
# and the daemon finds out at its first production request — the one moment nobody is at the table.
#
# WHAT IT DOES, per binding, right after generation (YubiKey: the wizard's m) step runs it) or right
# after commission-card.sh (Nitrokey, at the rack):
#   1. finds the token BY SERIAL in the PKCS#11 slot list — never by position; with two tokens
#      attached, "slot 0" is whichever enumerated first;
#   2. reads the key's public half from the token, and has ceremony-manifest.py draw a fresh 32-byte
#      challenge for it:
#        sign           name the mechanism (raw ECDSA over the curve-sized digest, or SHA256-RSA-PKCS);
#        decrypt        RSA-OAEP-encrypt the challenge to the exported key EXACTLY as the daemon wraps
#                       (regalia-kms internal/keywrap: OAEP SHA-1, MGF1-SHA-1, no label);
#        key-agreement  make an ephemeral keypair on the key's curve;
#   3. asks for the PIN ONCE and has the token answer with pkcs11-tool: --sign; or --decrypt
#      RSA-PKCS-OAEP with --hash-algorithm SHA-1 --mgf MGF1-SHA1 (the daemon's CKM_RSA_PKCS_OAEP
#      parameters); or --derive ECDH1-DERIVE against the ephemeral public key (the daemon's
#      CKM_ECDH1_DERIVE, CKD_NULL);
#   4. has ceremony-manifest.py check the answer and write the proof — or refuse and write nothing.
#      A signature is verified against the exported key, and `record` verifies it AGAIN later. A
#      decrypt or ECDH answer is COMPARED here, live, and that is the only time it can be: whoever
#      made the ciphertext or the ephemeral key knows the right answer, so nothing written afterwards
#      could prove the token gave it. That proof is labelled `live-round-trip` — attested at ceremony
#      time, not re-verifiable — and keeps no plaintext.
#
# ONE TOOL FOR BOTH BACKENDS: pkcs11-tool (opensc, already on the image). The YubiKey is reached
# through Yubico's PKCS#11 module, ykcs11 (packages.txt), because ykman has no command that signs
# caller-chosen data. ykcs11 names each PIV slot's key by a fixed CKA_ID (9a=01, 9c=02, 9d=03, 9e=04,
# retired 82..95 = 05..18), and reports the YubiKey's serial as the token serial.
#
# THE PIN. Read from the terminal with echo off (or from --pin-fd N, for a caller that already holds
# it). It is never on a command line, never printed and never written: pkcs11-tool is given the
# literal `--pin env:REGALIA_OPPROOF_PIN`, which OpenSC resolves from its environment, and that
# variable is set for the one pkcs11-tool process only. ps and /proc/<pid>/cmdline show the name,
# never the value. One wrong PIN SPENDS A RETRY on the token, so there is exactly one attempt: no
# loop, no automatic retry.
#
# NO VERDICT LEAVES THIS SCRIPT. A signature proof carries challenge, signature and key, and whether
# they verify is recomputed by whoever reads them. A round-trip proof carries the key, the ciphertext or
# ephemeral public key, and the challenge's SHA-256 — never the challenge, never the shared secret.
set -uo pipefail
umask 077

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MANIFEST_TOOL="$HERE/ceremony-manifest.py"
OPERATION="" BACKEND="" SERIAL="" OBJECT_ID="" DEVICE_ID="" OUT="" MODULE="" PIN_FD=""

die(){ printf 'operation-proof: REFUSED: %s\n' "$*" >&2; exit 1; }
need(){ [ -n "${2-}" ] || die "$1 needs a value"; }

while [ $# -gt 0 ]; do
  case "$1" in
    --operation) need "$1" "${2-}"; OPERATION="$2"; shift 2;;
    --backend)   need "$1" "${2-}"; BACKEND="$2"; shift 2;;
    --serial)    need "$1" "${2-}"; SERIAL="$2"; shift 2;;
    --object-id) need "$1" "${2-}"; OBJECT_ID="$(printf '%s' "$2" | tr 'A-F' 'a-f')"; shift 2;;
    --device-id) need "$1" "${2-}"; DEVICE_ID="$2"; shift 2;;
    --out)       need "$1" "${2-}"; OUT="$2"; shift 2;;
    --module)    need "$1" "${2-}"; MODULE="$2"; shift 2;;
    --pin-fd)    need "$1" "${2-}"; PIN_FD="$2"; shift 2;;
    # A PIN option is refused BY NAME rather than as "unknown": whoever tries it is about to put a PIN
    # on a command line, and should be told that is the thing not to do.
    --pin|-p|--pin=*) die "the PIN is never taken on the command line — it is asked for with echo off, or read from --pin-fd";;
    -h|--help) sed -n '2,6p' "$0"; exit 0;;
    *) die "unknown argument: $1";;
  esac
done
[ -n "$OPERATION" ] && [ -n "$BACKEND" ] && [ -n "$SERIAL" ] && [ -n "$OBJECT_ID" ] && [ -n "$OUT" ] \
  || die "--operation, --backend, --serial, --object-id and --out are all required"
case "$OPERATION" in sign|decrypt|key-agreement) ;; *) die "--operation must be sign, decrypt or key-agreement";; esac
case "$SERIAL" in *[!A-Za-z0-9._-]*) die "--serial '$SERIAL' is not a serial";; esac
case "$PIN_FD" in ''|[0-9]|[1-9][0-9]) ;; *) die "--pin-fd takes a file-descriptor number";; esac

# ---- the PKCS#11 module and object id for this backend -------------------------------------------
# An explicit --module (or the env override) is the caller's business, but it must exist: a path to
# nothing makes every lookup below answer "no such token", which reads as the wrong problem.
first_file(){ local c; for c in "$@"; do [ -f "$c" ] && { printf '%s' "$c"; return 0; }; done; return 1; }
case "$BACKEND" in
  yubikey-piv)
    [ -n "$MODULE" ] || MODULE="${CEREMONY_YKCS11_MODULE:-}"
    [ -n "$MODULE" ] || MODULE="$(first_file /usr/lib/*/libykcs11.so.2 /usr/lib/*/libykcs11.so /usr/lib/libykcs11.so \
                                    /usr/local/lib/libykcs11.so /opt/homebrew/lib/libykcs11.dylib)" \
      || die "no ykcs11 PKCS#11 module found (install the ykcs11 package, or set CEREMONY_YKCS11_MODULE)"
    case "$OBJECT_ID" in
      9a) P11_ID=01;; 9c) P11_ID=02;; 9d) P11_ID=03;; 9e) P11_ID=04;;
      8[2-9]|9[0-5]) P11_ID="$(printf '%02x' $(( 16#$OBJECT_ID - 16#82 + 5 )))";;
      *) die "--object-id $OBJECT_ID is not a PIV key slot (9a, 9c, 9d, 9e, 82-95)";;
    esac
    case "$SERIAL" in *[!0-9]*) die "a YubiKey serial is digits only";; esac ;;
  nitrokey-pkcs11)
    [ -n "$MODULE" ] || MODULE="${CEREMONY_PKCS11_MODULE:-${HSM_PKCS11_MODULE:-}}"
    [ -n "$MODULE" ] || MODULE="$(first_file /usr/lib/*/opensc-pkcs11.so /usr/lib/opensc-pkcs11.so \
                                    /usr/local/lib/opensc-pkcs11.so /opt/homebrew/lib/opensc-pkcs11.so)" \
      || die "no opensc-pkcs11 module found (set CEREMONY_PKCS11_MODULE)"
    case "$OBJECT_ID" in ''|*[!0-9a-f]*) die "--object-id $OBJECT_ID is not a PKCS#11 hex id";; esac
    P11_ID="$OBJECT_ID" ;;
  *) die "--backend must be yubikey-piv or nitrokey-pkcs11";;
esac
[ -f "$MODULE" ] || die "PKCS#11 module $MODULE does not exist"
command -v pkcs11-tool >/dev/null 2>&1 || die "pkcs11-tool (opensc) is not installed"

# Every token command is bounded, the way the rest of the card tooling is: a wedged reader must end
# the step, not hang the ceremony with a PIN in memory.
p11(){ perl -e 'alarm shift; exec @ARGV' 60 pkcs11-tool --module "$MODULE" "$@"; }

# In RAM when the host has it (the vault's /dev/shm), as the ceremony's own workdir is. The PIN is never
# in $W. What is — challenge, ciphertext, signature, public keys — is public or throwaway, except a round
# trip's plaintext challenge, the ephemeral private key and the token's answer, which are single-use
# values that protect nothing once the proof is written; they are removed on exit all the same, and
# never reach the proof.
W="$(mktemp -d "${CEREMONY_OPPROOF_TMP:-${TMPDIR:-/dev/shm}}/opproof.XXXXXX" 2>/dev/null || mktemp -d)" \
  || die "cannot create a work directory"
trap 'rm -rf "$W"; unset PIN REGALIA_OPPROOF_PIN' EXIT

# ---- 1. the token, by serial ----------------------------------------------------------------------
# Parsed like tools/hsm-reader-select.sh's hsm_slot_table (that file is not on the vault image): the
# slot ID is the number in "Slot 1 (0x4)", and it is the ID — not the position — that --slot takes.
slots="$(p11 --list-token-slots 2>/dev/null)" || die "cannot list the PKCS#11 token slots of $MODULE"
SLOT_ID="" n=0 cur=""
while IFS= read -r line; do
  case "$line" in
    "Slot "*"(0x"*")"*) cur="${line#*(}"; cur="${cur%%)*}";;
    *"serial num"*:*)
      s="${line#*:}"; s="$(printf '%s' "$s" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')"
      if [ -n "$cur" ] && [ "$s" = "$SERIAL" ]; then SLOT_ID="$cur"; n=$((n + 1)); fi
      cur="";;
  esac
done <<< "$slots"
[ "$n" -eq 1 ] || die "serial $SERIAL matches $n PKCS#11 tokens on $MODULE — refusing to guess which to sign with"

# ---- 2. its public key, the challenge, the mechanism ----------------------------------------------
p11 --slot "$SLOT_ID" --read-object --type pubkey --id "$P11_ID" --output-file "$W/pub.der" >/dev/null 2>&1 \
  && [ -s "$W/pub.der" ] || die "no public key at object $OBJECT_ID (PKCS#11 id $P11_ID) on serial $SERIAL"
case "$OPERATION" in
  sign)          prep=(--challenge-out "$W/challenge" --to-sign-out "$W/to-sign");     expect="ECDSA SHA256-RSA-PKCS";;
  decrypt)       prep=(--challenge-out "$W/challenge" --ciphertext-out "$W/ciphertext"); expect="RSA-PKCS-OAEP";;
  key-agreement) prep=(--ephemeral-out "$W/ephemeral.pem" --peer-out "$W/peer.der");    expect="ECDH1-DERIVE";;
esac
mechanism="$(python3 "$MANIFEST_TOOL" proof-prepare --operation "$OPERATION" --public-key "$W/pub.der" "${prep[@]}")" \
  || exit 1
case " $expect " in *" $mechanism "*) ;; *) die "unexpected mechanism '$mechanism' for --operation $OPERATION";; esac

# ---- 3. the PIN, once, and the token's answer -------------------------------------------------------
if [ -n "$PIN_FD" ]; then
  IFS= read -r PIN <&"$PIN_FD" || die "no PIN on file descriptor $PIN_FD"
else
  printf '   %s serial %s object %s — enter its PIN (not shown; ONE attempt, a wrong PIN spends a retry): ' \
    "$BACKEND" "$SERIAL" "$OBJECT_ID" >&2
  IFS= read -rs PIN || die "no PIN entered"
  printf '\n' >&2
fi
[ -n "$PIN" ] || die "an empty PIN was entered — nothing was sent to the token, no retry was spent"

# The value goes into the environment of THIS ONE pkcs11-tool process only (a prefix assignment is
# not exported to the shell), and the command line carries the variable's NAME.
case "$OPERATION" in
  sign)          act=(--sign --mechanism "$mechanism" --input-file "$W/to-sign" --signature-format openssl);;
  # The daemon's unwrap: CKM_RSA_PKCS_OAEP with SHA-1 and MGF1-SHA1, no label (regalia-kms
  # internal/backend/nitrokey/pkcs11_driver.go oaepParameters, piv_driver.go OAEPOptions).
  decrypt)       act=(--decrypt --mechanism "$mechanism" --hash-algorithm SHA-1 --mgf MGF1-SHA1
                      --input-file "$W/ciphertext");;
  # The daemon's Derive: CKM_ECDH1_DERIVE, CKD_NULL, against the peer's point (given here as its SPKI).
  key-agreement) act=(--derive --mechanism "$mechanism" --input-file "$W/peer.der");;
esac
sig_log="$(REGALIA_OPPROOF_PIN="$PIN" perl -e 'alarm shift; exec @ARGV' 60 pkcs11-tool --module "$MODULE" \
             --slot "$SLOT_ID" --login --pin env:REGALIA_OPPROOF_PIN --id "$P11_ID" "${act[@]}" \
             --output-file "$W/answer" 2>&1)"
rc=$?
unset PIN
if [ "$rc" -ne 0 ] || [ ! -s "$W/answer" ]; then
  # Name the failure, not pkcs11-tool's trailing "Aborting." (the same lesson as hsm-staging-ci.sh).
  why="$(printf '%s\n' "$sig_log" | grep -aoE 'CKR_[A-Z_]+' | head -1)"
  case "$why" in
    CKR_PIN_INCORRECT) die "the token refused the PIN (CKR_PIN_INCORRECT) — ONE RETRY WAS SPENT. Check the PIN before trying again.";;
    CKR_PIN_LOCKED)    die "the token's PIN is LOCKED (CKR_PIN_LOCKED) — this key cannot be qualified.";;
    *) die "the token did not $OPERATION (${why:-pkcs11-tool exit $rc}) — no proof, so this binding is not operation-verified";;
  esac
fi

# ---- 4. check now, write the proof ----------------------------------------------------------------
proof_args=(--operation "$OPERATION" --backend "$BACKEND" --serial "$SERIAL" --object-id "$OBJECT_ID"
            --public-key "$W/pub.der" --out "$OUT")
case "$OPERATION" in
  sign)          proof_args+=(--challenge "$W/challenge" --signature "$W/answer");;
  decrypt)       proof_args+=(--challenge "$W/challenge" --ciphertext "$W/ciphertext" --token-output "$W/answer");;
  key-agreement) proof_args+=(--ephemeral-key "$W/ephemeral.pem" --token-output "$W/answer");;
esac
[ -n "$DEVICE_ID" ] && proof_args+=(--device-id "$DEVICE_ID")
python3 "$MANIFEST_TOOL" operation-proof "${proof_args[@]}"
