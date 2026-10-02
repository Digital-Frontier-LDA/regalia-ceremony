#!/usr/bin/env bash
# go-nogo.sh — the one readiness check for the air-gapped vault qube. Read-only; touches NO key
# material. Run it on the bench and again IMMEDIATELY before a ceremony; it ends in one verdict.
#
#   /opt/vault-ceremony/go-nogo.sh                     # everything, hardware advisory
#   /opt/vault-ceremony/go-nogo.sh --need yubikey,hsm,sle4442,printer,drives,supplies
#   /opt/vault-ceremony/go-nogo.sh --need printer,drives      # a paper+archive-only run
#   /opt/vault-ceremony/go-nogo.sh --env-only          # environment only (what ceremony.sh runs)
#
# In order:
#   1. Environment: air-gap, leak controls, execution profile, tools, what is attached.
#   2. Self-tests: every tool's own --selftest, and each printed form renders. Always a FAIL on
#      failure: a broken tool is broken whatever this ceremony needs.
#   3. Hardware: capability probes that catch the day-of surprises (a reader that can't talk to the
#      card, a YubiKey one wrong PIN from PUK lockout, a network printer, a read-only DVD drive).
#      These are hard gates only for the devices named in --need; the rest are advisory.
#   4. Supplies (--need supplies): yes/no questions with a number in each.
#
# Every line reads OK, WARN or FAIL; the last line is GO or NO-GO. Any FAIL is a NO-GO.
#
# --need takes a comma list of: yubikey hsm sle4442 printer drives supplies.
# --env-only runs step 1 and ends in PREFLIGHT OK / PREFLIGHT FAILED; ceremony.sh runs it before
# any secret is in RAM. (This used to be a separate preflight.sh; one script, one verdict.)
set -uo pipefail
# ASCII RANGES. A check here that says [0-9] means ten digits, and [a-z] twenty-six letters. In a
# UTF-8 locale bash matches a bracket range by the locale's collation instead: [0-9] also takes
# full-width and Arabic-Indic digits, [a-z0-9] takes accented letters, and a negated range such as
# *[!0-9]* no longer catches them (measured: bash 5.2, glibc 2.41, en_US.UTF-8). Only the collation is
# pinned, so text stays UTF-8 and lengths are still counted in characters. LC_ALL overrides
# LC_COLLATE, so it is moved away first, into every other category it was deciding.
if [ -n "${LC_ALL:-}" ]; then
  for _lc in LANG LC_CTYPE LC_NUMERIC LC_TIME LC_MONETARY LC_MESSAGES LC_PAPER LC_NAME LC_ADDRESS \
             LC_TELEPHONE LC_MEASUREMENT LC_IDENTIFICATION; do export "$_lc=$LC_ALL"; done
  unset LC_ALL _lc
fi
export LC_COLLATE=C
# The vault-tools image keeps its pinned tools in /opt/vault-bin (sops, shamir, sle4442-manager)
# and the hash-pinned Python packages in the /opt/vault-ceremony/venv interpreter. /etc/profile.d
# puts both on PATH for LOGIN shells only; the xterm a disposable opens is not one, so add them here.
for _d in /opt/vault-bin /opt/vault-ceremony/venv/bin; do
  case ":$PATH:" in *":$_d:"*) ;; *) [ -d "$_d" ] && PATH="$_d:$PATH" ;; esac
done
unset _d
# No dirname: the air-gap tests run this with a PATH holding only a handful of tools.
_self="${BASH_SOURCE[0]}"; case "$_self" in */*) ;; *) _self="./$_self";; esac
HERE="$(cd "${_self%/*}" && pwd)"; unset _self

NEED=""
ENV_ONLY=0
while [ $# -gt 0 ]; do
  case "$1" in
    # A bare --need must not clear what an earlier --need asked for: that would skip a required
    # device's checks and could end in GO.
    --need|--need=) if [ "$1" = --need ] && [ $# -ge 2 ] && [ -n "$2" ] && [ "${2#-}" = "$2" ]; then NEED="$2"; shift 2
                    else echo "Error: --need needs a device list (known: yubikey hsm sle4442 printer drives supplies)" >&2; exit 2; fi;;
    --need=*) NEED="${1#--need=}"; shift;;
    --env-only) ENV_ONLY=1; shift;;
    -h|--help) sed -n '2,21p' "$0"; exit 0;;
    *) echo "unknown arg: $1" >&2; exit 2;;
  esac
done
# Validate --need tokens. An UNRECOGNISED token (typo like 'sle442') would otherwise make
# `needs <device>` silently false -> that device's check is skipped -> a false GO. For a
# set-once ceremony that is unacceptable: reject unknown tokens hard, before any probe.
KNOWN_NEEDS="yubikey hsm sle4442 printer drives supplies"
if [ -n "$NEED" ]; then
  IFS=',' read -r -a _need_arr <<< "$NEED"
  for _t in "${_need_arr[@]}"; do
    [ -z "$_t" ] && continue
    case " $KNOWN_NEEDS " in
      *" $_t "*) : ;;
      *) echo "Error: --need has an unrecognised device '$_t'. Known: $KNOWN_NEEDS" >&2
         echo "(A typo would silently skip that device's check and produce a false GO.)" >&2
         exit 2;;
    esac
  done
fi
needs(){ case ",$NEED," in *",$1,"*) return 0;; *) return 1;; esac; }

stop=0
# One style for the whole report, the one preflight.sh used: OK / WARN / FAIL, and any FAIL is a NO-GO.
ok()   { printf '  \033[32mOK\033[0m   %s\n' "$1"; }
warn() { printf '  \033[33mWARN\033[0m %s\n' "$1"; }
bad()  { printf '  \033[31mFAIL\033[0m %s\n' "$1"; stop=1; }
hdr()  { printf '== %s ==\n' "$1"; }
# gate: FAIL only when the device is in --need; otherwise a WARN
gate() { if needs "$2"; then bad "$1"; else warn "$1 (not required by --need)"; fi; }

# ============================== 1. ENVIRONMENT ==============================
hdr "Air-gap"
# The vault qube must have NO network path. A default route means it is NOT air-gapped.
# Fail CLOSED: if the route tool itself is missing, the `ip ... 2>/dev/null` calls below
# would emit nothing and we'd wrongly conclude "air-gapped". Demand `ip` before trusting it.
if ! command -v ip >/dev/null 2>&1; then
  bad "iproute2/'ip' is missing — cannot verify the air-gap. Install iproute2 and retry."
elif [ -n "$(ip -4 route show default 2>/dev/null)" ]; then
  bad "a default route exists — this qube has network. Set netvm to none and retry."
elif [ -n "$(ip -6 route show default 2>/dev/null)" ]; then
  bad "an IPv6 default route exists — this qube has network."
else
  ok "no default route (air-gapped)."
fi
# A live non-loopback interface carrying a global-scope address IS a network path — peers on
# the directly-connected subnet are reachable even with NO default route pushed. For a set-once,
# real-money ceremony that must FAIL CLOSED, not merely WARN. (Loopback is scope host, so a
# genuinely air-gapped qube with only `lo` has no global-scope address and passes.)
if grep -q "inet " <<< "$(command -v ip >/dev/null 2>&1 && ip -4 addr show scope global 2>/dev/null)"; then
  bad "a global-scope IPv4 address is present on a live interface — this qube has a network path (a reachable subnet) even without a default route. Set netvm to none and retry."
elif grep -q "inet6 " <<< "$(command -v ip >/dev/null 2>&1 && ip -6 addr show scope global 2>/dev/null)"; then
  bad "a global-scope IPv6 address is present on a live interface — this qube has a network path even without a default route. Set netvm to none and retry."
fi

hdr "Leak controls"
# Swap: anonymous (and tmpfs) pages can be paged to disk and survive. For real seeds the
# vault qube must have NO swap. We can only check from inside the qube.
# In SIMULATE mode (container/CI test) the swap seen is the host/VM's — a container cannot
# swapoff it. Downgrade to WARN so the emulator suites can run; on the REAL qube (no
# CEREMONY_SIMULATE) this stays a hard FAIL. CEREMONY_SIMULATE is already the acknowledged
# test flag (it also disables guard_no_stubs), and the real ceremony never sets it.
swap_bad() {
  if [ "${CEREMONY_SIMULATE:-}" = 1 ]; then
    warn "swap is ACTIVE — cannot swapoff a container/VM's host swap in SIMULATE mode (on the real vault qube this is a hard FAIL)."
  else
    bad "$1"
  fi
}
if [ -r /proc/swaps ]; then
  if [ "$(grep -c . /proc/swaps)" -gt 1 ]; then swap_bad "swap is ACTIVE — secrets could hit disk. Run: swapoff -a (and set the qube's swap off)."
  else ok "no active swap (/proc/swaps empty)."; fi
elif command -v swapon >/dev/null 2>&1; then
  if [ -n "$(swapon --noheadings --show=NAME 2>/dev/null)" ]; then swap_bad "swap is ACTIVE — run swapoff -a."; else ok "no active swap."; fi
else
  warn "cannot determine swap state here (no /proc/swaps, no swapon) — verify swap is off on the vault qube."
fi
# /dev/shm must be a tmpfs (the ceremony workdir lives there).
if grep -qs "[[:space:]]/dev/shm[[:space:]]tmpfs[[:space:]]" /proc/mounts 2>/dev/null; then ok "/dev/shm is tmpfs (RAM workdir)."
elif [ -r /proc/mounts ]; then bad "/dev/shm is not tmpfs — the RAM workdir guarantee fails."
else warn "cannot verify /dev/shm is tmpfs here (not Linux) — it is on the vault qube."; fi
# Shell history off
if [ -n "${HISTFILE:-}" ]; then
  if [ "${CEREMONY_SIMULATE:-}" = 1 ]; then warn "HISTFILE is set ($HISTFILE) — real ceremonies fail this control."
  else bad "HISTFILE is set ($HISTFILE) — unset it before the ceremony."; fi
else ok "HISTFILE unset."; fi
# Core dumps off
cl="$(ulimit -c 2>/dev/null || echo '?')"
if [ "$cl" = 0 ]; then ok "core dumps disabled (ulimit -c 0)."
elif [ "${CEREMONY_SIMULATE:-}" = 1 ]; then warn "core dump limit is '$cl' — real ceremonies fail this control."
else bad "core dump limit is '$cl' — run ulimit -c 0 before the ceremony."; fi

hdr "Execution profile"
if [ "${CEREMONY_SIMULATE:-}" = 1 ]; then
  warn "execution-profile proof skipped in explicitly simulated test mode."
elif [ ! -x "$HERE/preflight-environment.py" ]; then
  bad "preflight-environment.py is missing or not executable — cannot prove a supported disposable profile."
elif [ ! -x "$HERE/ceremony-teardown.py" ]; then
  bad "ceremony-teardown.py is missing or not executable — cannot prove cleanup after secret exposure."
elif ! profile_out="$("$HERE/preflight-environment.py" 2>&1)"; then
  bad "execution profile is unsafe or unsupported:"
  printf '%s\n' "$profile_out" | sed 's/^/       /'
else
  ok "$(printf '%s\n' "$profile_out" | head -1)"
  printf '%s\n' "$profile_out" | grep '^WARN ' | sed 's/^/       /' || true
fi

# THE SAME INTERPRETER THE CEREMONY WILL USE. ceremony.sh resolves the ceremony venv through
# tools/ceremony-python.sh; without doing the same here, this check reports on whichever python3
# happened to be on PATH when preflight ran — a different interpreter than the one that runs step
# 3c. It would then either green-light a ceremony whose python cannot import the module (the exact
# mid-ceremony failure this check exists to prevent, with the money already exposed) or refuse one
# that would have worked. Measured 2026-09-22: under `sudo`, secure_path drops the venv and this
# reported both modules missing on a host where the ceremony would have found them.
#
# prefer, not require: a host with no venv anywhere must still reach the import check below and
# fail THERE, with the message that says what to do about it.
_cp="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)/tools/ceremony-python.sh"
if [ -r "$_cp" ]; then
  # shellcheck source=/dev/null
  . "$_cp"
  ceremony_python_prefer mnemonic shamir_mnemonic
fi
unset _cp

hdr "Tools"
for t in ip age sops age-plugin-yubikey pkcs11-tool sc-hsm-tool ykman ssss-split shamir qrencode zbarimg gpg sha256sum python3; do
  if command -v "$t" >/dev/null 2>&1; then ok "$t"; else bad "$t not found (check the template build)"; fi
done
# `command -v python3` passing does NOT prove the seed backup will run. Ceremony step 3
# option c (bip39-slip39-backup.py — the FUNDING/derivation seed's only Option-B backup)
# does `from mnemonic import Mnemonic` + `import shamir_mnemonic` at RUNTIME. On the
# air-gapped qube there is no pip to recover a missing package, so prove the imports resolve
# HERE, before keys are in RAM — not mid-ceremony after the money is exposed.
if command -v python3 >/dev/null 2>&1; then
  for m in mnemonic shamir_mnemonic; do
    if python3 -c "import $m" >/dev/null 2>&1; then ok "python3 module '$m'"
    else bad "python3 cannot import '$m' — the BIP39<->SLIP-39 seed backup (step 3c) will fail; bake the wheel into the vault-tools image (no pip on the air-gapped qube)."; fi
  done
fi
# The M-DISC archive (step 4) burns with growisofs (or xorriso). Missing means no archival
# copy AND no way to install it on the air-gapped qube — catch it before the ceremony.
if command -v growisofs >/dev/null 2>&1 || command -v xorriso >/dev/null 2>&1; then ok "optical burner (growisofs/xorriso)"
else bad "no growisofs/xorriso — cannot burn the archive disc; add it to the template build."; fi

hdr "Smartcard reader / tokens"
if command -v opensc-tool >/dev/null 2>&1; then
  # Count the numbered reader rows. With nothing attached opensc-tool prints "No smart card
  # readers found." — the old test grepped for "reader", matched that sentence and reported a
  # reader present (owner's first disposable, 2026-09-25).
  readers="$(timeout 5 opensc-tool -l 2>/dev/null | grep -E '^[0-9]+[[:space:]]' || true)"
  if [ -n "$readers" ]; then
    ok "$(grep -c . <<< "$readers") PC/SC reader(s) visible (opensc-tool -l)."
  else
    warn "no smart-card reader or token seen — attach it with 'qvm-usb attach' from dom0."
  fi
  # The HSM itself, named: Nitrokey HSM 2 and Pico HSM both present as SmartCard-HSM readers.
  # Only rows whose Card column is "Yes": a reader with no token answering is not an HSM.
  hsms="$(grep -iE 'nitrokey hsm|smartcard-hsm|pico' <<< "$readers" | grep -E '^[0-9]+[[:space:]]+Yes[[:space:]]' \
          | sed -E 's/^[0-9]+[[:space:]]+Yes[[:space:]]+//; s/[[:space:]]+/ /g' || true)"
  if [ -n "$hsms" ]; then
    ok "HSM token(s) present: $(tr '\n' ';' <<< "$hsms" | sed 's/;$//')"
  elif grep -qiE 'nitrokey hsm|smartcard-hsm|pico' <<< "$readers"; then
    warn "an HSM reader is attached but no token answers in it — re-seat it (detach/attach with qvm-usb)."
  else
    warn "no Nitrokey HSM or Pico HSM seen — attach it with 'qvm-usb attach' if this ceremony uses one."
  fi
else
  warn "opensc-tool not found — install opensc (reader check skipped)."
fi
if command -v ykman >/dev/null 2>&1; then
  if [ -n "$(timeout 5 ykman list 2>/dev/null)" ]; then ok "a YubiKey is present (ykman list)."
  else warn "no YubiKey seen — attach it if this ceremony needs one."; fi
fi

hdr "Printer (paper backup)"
if command -v lpstat >/dev/null 2>&1; then
  if [ -n "$(lpstat -p 2>/dev/null)" ]; then
    ok "CUPS queue(s) present:"; lpstat -p 2>/dev/null | sed 's/^/       /'
    # ALLOWLIST (matches ceremony.sh pick_printer): only usb:// (or a local file:/cups-pdf:/
    # absolute-path/empty device-uri) is safe. A blocklist would miss smb://, bluetooth://, …
    # and send plaintext shares over the wire. Anything NOT on the allowlist is a network printer.
    # Anchor on the URI (text after the final ': '), not a colon-free queue name: CUPS
    # queue names may contain a colon, and [^:]+ would discard such a line, letting a
    # networked printer slip past. Names contain no spaces, so ': ' is only the boundary.
    net="$(lpstat -v 2>/dev/null | grep -E 'device for .+: ' | grep -vE 'device for .+: (usb://|file:|cups-pdf:|/|$)' || true)"
    if [ -n "$net" ]; then
      bad "a NETWORK printer queue exists — remove it; print only over usb://."
      printf '%s\n' "$net" | sed 's/^/       /'
    else ok "no network printer queues (usb/local only)."; fi
  else warn "no CUPS print queue — add the USB laser printer (no network, no internal storage) if you'll print paper shares."; fi
else warn "lp/lpstat not installed — paper steps will only write files."; fi

hdr "Optical drives (archive disc)"
drives=$(ls /dev/sr* 2>/dev/null | wc -l | tr -d ' ')
if [ "$drives" -ge 2 ]; then ok "$drives optical drives present — burn on one, read back on another (write capability: checked with --need drives)."
elif [ "$drives" -eq 1 ]; then ok "1 optical drive present (its write capability is checked with --need drives); the burn is read back on it (ADR-0002 D9)."
else warn "no /dev/sr* optical drive seen — attach the internal/external DVD writer for the archive disc."; fi

hdr "Chip cards (SLE-4442)"
# The chip-card step needs the manager AND pyscard; the manager exits at import without pyscard,
# which would surface only at the step, with a share already in RAM.
if command -v sle4442-manager >/dev/null 2>&1 && python3 -c "import smartcard" >/dev/null 2>&1; then
  ok "sle4442-manager + pyscard"
else bad "sle4442-manager or python3-pyscard missing — the SLE-4442 chip-card step cannot run; rebuild the template."; fi

hdr "Camera (scan the printed QR back)"
if command -v zbarcam >/dev/null 2>&1; then
  if ls /dev/video* >/dev/null 2>&1; then ok "zbarcam + a camera ($(ls /dev/video* | head -1))"
  else warn "no /dev/video* — attach the webcam with 'qvm-usb attach' to scan the printed sheets back (or scan them with zbarimg from a photo)."; fi
else warn "zbarcam not installed — printed QR sheets cannot be scanned back here."; fi

hdr "Entropy"
ent=$(cat /proc/sys/kernel/random/entropy_avail 2>/dev/null || echo 0)
if [ "$ent" -ge 256 ]; then ok "entropy_avail=$ent"
elif [ "${CEREMONY_SIMULATE:-}" = 1 ]; then warn "low entropy ($ent) — real ceremonies fail this control."
else bad "low entropy ($ent) — wait and re-run go-nogo.sh before generating keys."; fi


if [ "$ENV_ONLY" = 1 ]; then
  echo
  if [ "$stop" -eq 0 ]; then
    printf '\033[32mPREFLIGHT OK\033[0m — the environment is safe. Run go-nogo.sh with --need before the ceremony.\n'
  else
    printf '\033[31mPREFLIGHT FAILED\033[0m — do NOT start the ceremony until the FAIL items are resolved.\n'
  fi
  exit "$stop"
fi

# ============================== 2. SELF-TESTS ===============================
# Each tool's own --selftest (dice fairness tests, entropy mixing, QR split and scan-back, seed to
# PKCS#12), and a render of every printed form, so nobody has to run them one by one. They run on
# built-in test vectors, never on real material, and write only to a RAM directory removed on exit.
hdr "Self-tests (each tool checks itself on test data)"
st_dir="$(mktemp -d /dev/shm/go-nogo.XXXXXX 2>/dev/null || mktemp -d)"
trap 'rm -rf "$st_dir"' EXIT
selftest() { # <label> <expected line> <command...>
  local label="$1" want="$2" out; shift 2
  if out="$(timeout 120 "$@" 2>&1)" && grep -q "$want" <<< "$out"; then
    ok "$label: $(grep "$want" <<< "$out" | head -1)"
  else
    bad "$label self-test FAILED — this tool is broken in the template; rebuild it:"
    printf '%s\n' "$out" | tail -5 | sed 's/^/       /'
  fi
}
selftest "dice-entropy"   "selftest: OK" python3 "$HERE/dice-entropy.py" --selftest
selftest "entropy-mix"    "selftest: OK" python3 "$HERE/entropy-mix.py" --selftest
selftest "payload-qr"     "selftest: OK" python3 "$HERE/payload-qr.py" --selftest
selftest "seed-to-pkcs12" "selftest: OK" python3 "$HERE/seed-to-pkcs12.py" --selftest
# The breakglass key is born in the ceremony as a post-quantum age key (age >= 1.3, -pq). A throwaway
# key is captured in memory and discarded unread (a here-string, not a pipe: pipefail + grep -q).
if grep -q '^AGE-SECRET-KEY-PQ-1' <<< "$(age-keygen -pq 2>/dev/null)"; then
  ok "age $(age --version 2>/dev/null) makes post-quantum keys (the breakglass key, step 3 option g)"
else
  bad "age cannot make a post-quantum key (needs >= 1.3; found $(age --version 2>/dev/null || echo none)): rebuild the template"
fi
# The printed forms: each must produce a PostScript file with at least one page.
render() { # <label> <script> <args...>
  local label="$1" script="$2" out f="$st_dir/$2.ps"; shift 2
  if out="$(timeout 60 python3 "$HERE/$script" "$@" -o "$f" 2>&1)" && [ "$(grep -c '^showpage' "$f" 2>/dev/null)" -ge 1 ]; then
    ok "$label renders ($(grep -c '^showpage' "$f") page(s))"
  else
    bad "$label does NOT render — the ceremony would stop at the print step:"
    printf '%s\n' "$out" | tail -5 | sed 's/^/       /'
  fi
}
render "share form (words)"  share-form.py --label test --kind words --count 20
render "case label"          case-label.py
render "PIN card"            pin-card-form.py
# The HSM's random generator (ceremony step 1 mixes it in). Reading random bytes touches no key;
# a FAIL only when --need hsm, since a bench run may have no HSM attached. The same 60 s bound as
# ceremony.sh: a token that hangs mid-exchange must not stall the report before its verdict.
if timeout 60 python3 "$HERE/hsm-random.py" --out "$st_dir/h.bin" >"$st_dir/h.out" 2>&1 && [ "$(wc -c < "$st_dir/h.bin" 2>/dev/null)" = 32 ]; then
  ok "$(head -1 "$st_dir/h.out")"
elif [ "${CEREMONY_SIMULATE:-}" = 1 ]; then
  # The emulator's HSM is a PKCS#11 software token with no card reader; there is nothing to read.
  warn "no HSM gave random bytes: $(tail -1 "$st_dir/h.out") — skipped in simulated test mode (on the real vault qube, a FAIL with --need hsm)"
else
  gate "no HSM gave random bytes (hsm-random.py): $(tail -1 "$st_dir/h.out")" hsm
fi

# ============================== 3. HARDWARE =================================

hdr "Smartcard reader can actually talk to a card"
if command -v opensc-tool >/dev/null 2>&1; then
  atr="$(timeout 6 opensc-tool --atr 2>/dev/null | tr -d ' \n')"
  if [ -n "$atr" ]; then ok "a card answered (ATR ${atr})"
  else gate "no card ATR — reader sees no card, or the reader can't read this card type" sle4442; fi
else
  gate "opensc-tool missing — cannot probe the reader" sle4442
fi

if needs sle4442; then
  hdr "SLE-4442 memory card (PC/SC pseudo-APDU SELECT)"
  # FF A4 00 00 01 06 selects card type SLE4442; 90 00 means the reader supports it.
  if command -v opensc-tool >/dev/null 2>&1 && \
     grep -qiE 'SW1=0x90|90 00|9000|Normal processing' <<< "$(timeout 6 opensc-tool -s 'FF:A4:00:00:01:06' 2>/dev/null)"; then
    ok "reader+card answered the SLE-4442 SELECT (memory-card support confirmed)"
    # READ SECURITY MEMORY — FF B1 00 00 04 returns <error-counter> FF FF FF (the PSC reads
    # back as FF, so this exposes NO secret and, unlike PRESENT PSC, does NOT touch the
    # counter). A wrong PSC clears one counter bit (0x07 -> 0x03 -> 0x01 -> 0x00); attempts
    # left = popcount(byte0 & 0x07). 0 = already LOCKED (can't store a share at all); 1 = one
    # PSC slip during the store PERMANENTLY bricks the card. Catch a near-locked card here,
    # exactly like the YubiKey PIV PIN-retry gate below, before any key-touching step.
    # Read the counter in the SAME reader session as the SELECT_CARD_TYPE: a real
    # synchronous-memory reader (Identiv/SCM) only answers FF B1 when the FF A4 select
    # precedes it in one opensc-tool invocation. A separate FF B1 session (no select)
    # returns no parsable counter on such hardware -> the near-lock FAIL would silently
    # degrade to the manual-confirm WARN below. The vpicc emulator answers FF B1
    # unconditionally, so this ordering is transparent under test yet correct on metal.
    secmem="$(timeout 6 opensc-tool -s 'FF:A4:00:00:01:06' -s 'FF:B1:00:00:04' 2>/dev/null)"
    # Match the FF B1 data line by its LEADING 4 hex bytes only. Real opensc-tool renders
    # response data through util_hex_dump_asc, which appends an ASCII sidebar column after the
    # hex ('07 FF FF FF ....'); anchoring the match to end-of-line ([[:space:]]*$) would fail
    # to match that real output, leave ctr_hex empty, and silently degrade the near-lock FAIL
    # to a WARN -> a false GO on a card one PSC slip from permanent lockout. No trailing anchor;
    # awk takes the first field (byte0 = the error counter).
    ctr_hex="$(printf '%s\n' "$secmem" | grep -ioE '^[[:space:]]*[0-9a-f]{2}( [0-9a-f]{2}){3}([[:space:]]|$)' | head -1 | awk '{print $1}')"
    if [ -z "$ctr_hex" ]; then
      warn "could not read the SLE-4442 error counter (FF B1) — confirm PSC attempts-left manually before storing a share (3 wrong = locked forever)"
    else
      ctr=$((16#$ctr_hex)); low=$((ctr & 0x07)); att=0
      for _b in 1 2 4; do [ $((low & _b)) -ne 0 ] && att=$((att+1)); done
      case "$att" in
        0) bad "SLE-4442 is LOCKED (PSC attempts left = 0) — it cannot store a share. Use another card." ;;
        1) bad "SLE-4442 attempts left = 1 — one wrong PSC permanently locks it (cannot store the share). Use a fresh card, or verify the PSC before the store." ;;
        2) warn "SLE-4442 attempts left = 2 — low; enter the PSC carefully (3 wrong total = locked forever)" ;;
        *) ok "SLE-4442 attempts left = $att (error counter healthy)" ;;
      esac
    fi
  else
    bad "the reader did NOT accept the SLE-4442 SELECT — many CCID readers can't do synchronous memory cards. Use a reader that supports SLE4442 (e.g. Identiv/SCM)."
  fi
fi

if needs hsm; then
  hdr "SmartCard-HSM (Nitrokey HSM 2 or Pico HSM) present + PKCS#11 visible"
  # Gate on the FUNDING-KEY HSM specifically, not the generic words 'token'/'present'. Any
  # OpenSC-visible PKCS#11 token (notably the YubiKey PIV, which this same ceremony needs for
  # the ops-identity step and enumerates through opensc-pkcs11.so) prints 'token label'/
  # 'token state: present' lines — an over-broad match would say GO on the YubiKey alone
  # while the funding-key HSM is absent. Require the SmartCard-HSM/Nitrokey HSM 2 marker:
  #   * a fresh device advertises the 'SmartCard-HSM' token label/model;
  #   * an already-initialised device (and the SoftHSM2 emulator) carries the 'akash-funding'
  #     token the ceremony creates.
  # A YubiKey PIV / generic token matches neither, so it can no longer produce a false GO.
  #
  # The label alone is NOT enough (owner's vault, 2026-09-29): OpenSC shows 'SmartCard-HSM' only as
  # a FALLBACK when the device has no label of its own (pkcs15-sc-hsm.c). A Nitrokey initialised
  # with a label, and every Pico HSM ('Pico-HSM', manufacturer 'Pol Henarejos'), show their own —
  # so a working HSM read NO-GO. What is fixed is the card type OpenSC's driver detects:
  # `opensc-tool -r N -n` names a SmartCard-HSM applet 'SmartCard-HSM …' on both devices (checked
  # on a Pico: 'SmartCard-HSM version 6.6'); a YubiKey is 'PIV-II card'. Find the first reader
  # whose card is that type, and read the PIN counters from THAT reader below.
  hsm_reader=""
  if command -v opensc-tool >/dev/null 2>&1; then
    while read -r n _; do
      case "$(timeout 8 opensc-tool -r "$n" -n 2>/dev/null)" in
        SmartCard-HSM*) hsm_reader="$n"; break;;
      esac
    done < <(timeout 5 opensc-tool -l 2>/dev/null | grep -E '^[0-9]+[[:space:]]+Yes[[:space:]]' || true)
  fi
  if [ -n "$hsm_reader" ] || { command -v pkcs11-tool >/dev/null 2>&1 && \
     grep -qiE 'SmartCard-HSM|akash-funding' <<< "$(timeout 8 pkcs11-tool --list-slots 2>/dev/null)"; }; then
    ok "the funding-key HSM (SmartCard-HSM) is present${hsm_reader:+ in reader $hsm_reader}"
    timeout 8 pkcs11-tool --list-slots 2>/dev/null | grep -iE 'Slot|token label|SmartCard-HSM|akash-funding|present' | sed 's/^/     /'
    # PIN-retry gate — the piece the presence probe above CANNOT see. Prior handling can
    # leave the user-PIN retry counter at 1 (two earlier mistyped PINs); the token still
    # lists as 'present', so without this the gate says GO. Then the first keygen `--login`
    # with a single PIN typo BLOCKS the user PIN, and if the SO-PIN is not on hand (or is
    # also exhausted) the device is permanently BRICKED and the born-in-HSM funding key is
    # lost — the exact failure the checklist below warns about. Read the counter and FAIL on
    # 0/1, exactly like the SLE-4442 (FF B1) and YubiKey PIV gates. sc-hsm-tool with no
    # operation prints 'SO-PIN tries left : N' and 'User PIN tries left : N'; it only READS
    # the state (consumes no attempt). Match the USER-PIN line specifically — a keygen `--login`
    # spends the USER PIN, so that is the counter that governs the brick risk. (Do NOT match the
    # SO-PIN line: a healthy SO-PIN counter would mask a near-locked user PIN and yield a false GO.)
    if command -v sc-hsm-tool >/dev/null 2>&1; then
      hsm_info="$(timeout 8 sc-hsm-tool ${hsm_reader:+-r "$hsm_reader"} 2>/dev/null)"
      hsm_ret="$(printf '%s\n' "$hsm_info" | grep -iE 'User PIN tries left' | grep -oE '[0-9]+' | head -1)"
      case "${hsm_ret:-}" in
        ''|*[!0-9]*) warn "could not read the SmartCard-HSM PIN retry counter — confirm it manually before keygen (a blocked user PIN needs the SO-PIN; repeated wrong PIN/SO-PIN BRICKS the HSM and loses the funding key)";;
        0)  bad "SmartCard-HSM PIN retries = 0 — the user PIN is BLOCKED; unblock with the SO-PIN before proceeding (a wrong SO-PIN also bricks the HSM).";;
        1)  bad "SmartCard-HSM PIN retries = 1 — one wrong PIN blocks it. Verify/reset the user PIN before the keygen step (a bricked HSM loses the born-in-HSM funding key).";;
        2)  warn "SmartCard-HSM PIN retries = 2 — low; enter the PIN carefully (repeated wrong PINs brick the HSM).";;
        *)  ok "SmartCard-HSM PIN retries = $hsm_ret";;
      esac
      # SO-PIN counter — checked SEPARATELY from the user PIN above, never folded into the same
      # grep (that is what would let a healthy SO-PIN mask a near-locked user PIN). It matters on
      # its own: the SO-PIN is the ONLY way to unblock a blocked user PIN, and it CANNOT itself be
      # unblocked — "Blocking the SO-PIN will prevent any further token initialization or PIN
      # unblock" (OpenSC SmartCardHSM wiki). Block both and the funding key is gone unless a DKEK
      # backup exists. The published counter is also inconsistent — the wiki text says 15 while its
      # own pkcs15-tool dump shows 3 — so READ IT OFF THE DEVICE and trust that, not the docs.
      so_ret="$(printf '%s\n' "$hsm_info" | grep -iE 'SO-PIN tries left' | grep -oE '[0-9]+' | head -1)"
      case "${so_ret:-}" in
        ''|*[!0-9]*) warn "could not read the SmartCard-HSM SO-PIN retry counter — read it off the device before the ceremony; the docs disagree (15 vs 3) and a blocked SO-PIN can never be unblocked.";;
        0)  bad "SmartCard-HSM SO-PIN tries left = 0 — the SO-PIN is BLOCKED and cannot be unblocked. This token can no longer re-initialise or unblock its user PIN; do NOT generate a funding key on it.";;
        1|2) bad "SmartCard-HSM SO-PIN tries left = $so_ret — critically low, and the SO-PIN cannot be unblocked. Resolve before keygen: exhausting it removes the only recovery path for a blocked user PIN.";;
        *)  ok "SmartCard-HSM SO-PIN tries left = $so_ret (device-reported; docs are inconsistent, this is the authority)";;
      esac
    else
      warn "sc-hsm-tool missing — cannot read the SmartCard-HSM PIN retry counter; confirm it manually before keygen (wrong PINs can BRICK the HSM)."
    fi
  else
    bad "no SmartCard-HSM funding token visible — attach the Nitrokey HSM 2 or Pico HSM (qvm-usb attach) and confirm pcscd is running. (A YubiKey PIV or other PKCS#11 token does NOT satisfy this gate.)"
  fi
fi

if needs yubikey; then
  hdr "YubiKey present + PIV not near PUK lockout"
  if [ -n "$(command -v ykman >/dev/null 2>&1 && timeout 8 ykman list 2>/dev/null)" ]; then
    ok "a YubiKey is present"
    retries="$(timeout 8 ykman piv info 2>/dev/null | grep -iE 'PIN tries|tries remaining' | grep -oE '[0-9]+' | head -1)"
    case "${retries:-}" in
      ''|*[!0-9]*) warn "could not read PIV PIN retry counter — confirm it manually (avoid PUK lockout)";;
      0)  bad "PIV PIN retries = 0 — the PIN is BLOCKED; unblock with the PUK before proceeding";;
      1)  bad "PIV PIN retries = 1 — one wrong PIN locks it. Reset/verify the PIN before the ceremony.";;
      2)  warn "PIV PIN retries = 2 — low; verify the PIN carefully";;
      *)  ok "PIV PIN retries = $retries";;
    esac
  else
    bad "no YubiKey present — attach it (qvm-usb attach) for the ops-identity step."
  fi
fi

if needs printer; then
  hdr "Printer present + USB-only (no plaintext over the wire)"
  if [ -n "$(command -v lpstat >/dev/null 2>&1 && lpstat -p 2>/dev/null)" ]; then
    # ALLOWLIST (matches ceremony.sh pick_printer): only usb:// (or a local file:/cups-pdf:/
    # absolute-path/empty device-uri) is safe. A blocklist would miss smb://, bluetooth://,
    # ipps://, … and let a plaintext share leave the air-gapped qube. Any device-uri that is
    # NOT on the allowlist is a network printer -> FAIL.
    # Anchor on the URI (text after the final ': '), not a colon-free queue name: CUPS
    # queue names may legally contain a colon (e.g. "office:2"), and a name matched with
    # [^:]+ would discard such a line entirely — letting a networked printer slip past.
    # Queue names contain no spaces, so ': ' appears only at the name/URI boundary; a
    # greedy .+ therefore anchors on that boundary regardless of colons in the name.
    net="$(lpstat -v 2>/dev/null | grep -E 'device for .+: ' | grep -vE 'device for .+: (usb://|file:|cups-pdf:|/|$)' || true)"
    if [ -n "$net" ]; then
      bad "a NETWORK printer queue exists — remove it; print shares only over usb:// (or cups-pdf for a rehearsal)."
      printf '%s\n' "$net" | sed 's/^/     /'
    else
      ok "a USB/local print queue is present:"; lpstat -v 2>/dev/null | sed 's/^/     /'
    fi
  else
    bad "no CUPS print queue — add the USB laser printer before the paper steps."
  fi
fi

if needs drives; then
  hdr "An optical WRITER for the archive disc (+ readback)"
  # GONOGO_OPTICAL_GLOB overrides the device glob for tests only; defaults to the real nodes.
  optglob="${GONOGO_OPTICAL_GLOB:-/dev/sr*}"
  n=$(ls $optglob 2>/dev/null | wc -l | tr -d ' ')
  # One writer is enough (ADR-0002 D9): the burn is read back on the same drive once its tray is
  # pushed shut. A second drive, or a read-only one reached through qvm-block (CEREMONY_VERIFY_DEV),
  # is used for the readback when present, but is not required.
  vdev="${CEREMONY_VERIFY_DEV:-}"
  if [ "$n" -ge 1 ]; then
    case "$vdev" in
      "") if [ "$n" -ge 2 ]; then ok "$n optical drives present (/dev/sr*) — the readback uses another one"
          else ok "1 optical drive — burn, push the tray shut, read back on the same drive (ADR-0002 D9)"; fi ;;
      /dev/sr*)
        # a configured optical readback drive must be here now; step_archive would point at it
        # present = among the drives enumerated above (the same list the count came from)
        vpresent=0
        for d in $optglob; do [ "${d##*/}" = "${vdev##*/}" ] && vpresent=1; done
        if [ "$vpresent" = 1 ]; then ok "the readback uses $vdev (CEREMONY_VERIFY_DEV)"
        else bad "CEREMONY_VERIFY_DEV=$vdev is not attached — the burn could not be read back as instructed. Attach it or unset CEREMONY_VERIFY_DEV."; fi ;;
      *) ok "the readback uses $vdev (qvm-block, attached at the verify step)" ;;
    esac
    # Presence is NOT capability, and a total writer COUNT is not enough either. A read-only
    # DVD-ROM reader exposes a /dev/srN node exactly like a writer, so two DVD-ROM readers count
    # as 2 nodes here yet cannot burn. Worse, step_archive HARDCODES `growisofs -Z /dev/sr0`, so
    # the ONE drive that must be a writer is sr0 specifically — a writer sitting on sr1 while sr0
    # is a read-only reader still fails the burn mid-ceremony. The kernel lists drives in
    # /proc/sys/dev/cdrom/info most-recently-registered first (the REVERSE of /dev/srN), one 1/0
    # column per drive, with a 'drive name:' header row naming each column (e.g. 'sr1  sr0'). So
    # 'Can write DVD-R:  1  0' with that header means the writer is sr1 and sr0 is read-only —
    # counting the lone '1' and calling GO is the exact false pass this gate must not emit. Map
    # the burn node (sr0, overridable via GONOGO_BURN_DRIVE to mirror step_archive) to its column
    # via the 'drive name:' row, then read THAT column of 'Can write DVD-R:'. Distinguish: burn
    # drive is a writer -> GO; burn drive is read-only (writer elsewhere or none) -> FAIL; header
    # row absent but some writer exists -> WARN (can't map, confirm by hand); table unreadable /
    # no DVD-write row -> WARN, exactly like the other counter probes above.
    # GONOGO_CDROM_INFO overrides the table path for tests only; defaults to the real proc file.
    cdinfo="${GONOGO_CDROM_INFO:-/proc/sys/dev/cdrom/info}"
    burnnode="${GONOGO_BURN_DRIVE:-${CEREMONY_BURN_DEV:-/dev/sr0}}"; burnbase="${burnnode##*/}"
    if [ -r "$cdinfo" ] && grep -qiE '^Can write DVD-R:' "$cdinfo"; then
      # Value fields of the 'Can write DVD-R:' row (tabs -> spaces), one per attached drive.
      wrow=$(grep -iE '^Can write DVD-R:' "$cdinfo" | head -1 | sed 's/^[^:]*://' | tr '\t' ' ')
      writers=$(printf '%s' "$wrow" | tr -s ' ' '\n' | grep -c '^1$')
      # 1-based column index of the burn node in the 'drive name:' header (empty if no such row).
      col=$(grep -iE '^drive name:' "$cdinfo" | head -1 | sed 's/^[^:]*://' | tr '\t' ' ' \
            | awk -v b="$burnbase" '!seen {for(i=1;i<=NF;i++) if($i==b){print i; seen=1; break}}')
      if [ -n "$col" ]; then
        can=$(printf '%s' "$wrow" | awk -v c="$col" '{print $c}')
        if [ "${can:-0}" = "1" ]; then
          ok "the burn drive $burnnode advertises a DVD writer profile (writers=$writers) — the archive burn can run"
        elif [ "${writers:-0}" -ge 1 ]; then
          bad "the ceremony burns to $burnnode but THAT drive is read-only — the DVD writer is on another node (writers=$writers, kernel lists drives reversed vs /dev/srN). \`growisofs -Z $burnnode\` will fail. Swap so $burnnode IS the writer (or point the burn at the writer)."
        else
          bad "optical drives are present but NONE can WRITE (read-only DVD-ROM) — the archive burn (growisofs -Z) will fail. Attach a DVD WRITER, not a DVD-ROM reader."
        fi
      elif [ "${writers:-0}" -ge 1 ]; then
        warn "a DVD writer is present (writers=$writers) but the capability table has no 'drive name:' row to confirm it is the burn drive $burnnode — verify by hand that $burnnode is the writer before the burn."
      else
        bad "optical drives are present but NONE can WRITE (read-only DVD-ROM) — the archive burn (growisofs -Z) will fail. Attach a DVD WRITER, not a DVD-ROM reader."
      fi
    else
      warn "could not read optical write-capability table ($cdinfo) — confirm at least one drive is a DVD WRITER before the burn (a read-only DVD-ROM cannot burn a share)."
    fi
  else bad "no /dev/sr* optical drive — attach the DVD writer."; fi
fi

# SUPPLIES — the part no probe can see. The old free-text "decisions to confirm" sheet was open to
# interpretation (owner, 2026-09-29), and most of it is now decided by the code: step 0 GENERATES the
# PINs, PUK and management key; touch policy is fixed to never (a KMS YubiKey is PIN-only, nobody is
# there to touch it); the DKEK custodian split applies only to the born-in-HSM option, which the
# ceremony does not use. What is left is physical and countable, so each item is ONE yes/no question
# with a number in it, and any "no" is a FAIL. Needs a terminal: a scripted run cannot count discs.
if needs supplies; then
  n="${CEREMONY_SHARES:-6}"
  # The same rule ceremony.sh's check_scheme applies (2..16), written canonically: "0" would skip
  # every question silently, and "010" is octal to $(( )) (8, not 10).
  if [[ "$n" =~ ^[1-9][0-9]?$ ]] && [ "$n" -ge 2 ] && [ "$n" -le 16 ]; then :; else
    bad "CEREMONY_SHARES='$n' must be a whole number of shares from 2 to 16 (the ceremony's k-of-n)"; n=0
  fi
  hdr "Supplies on the table — count them (${n} shares)"
  if [ "$n" -gt 0 ] && { : </dev/tty; } 2>/dev/null; then
    supply(){ local a; read -r -p "   $1 [y/N] " a </dev/tty
      case "$a" in y|Y) ok "$1";; *) bad "NOT CONFIRMED: $1";; esac; }
    supply "At least $((n + 2)) BLANK archive discs (Verbatim AZO DVD-R or M-DISC): one per case, two spare?"
    supply "$n holographic seal stickers, with their serials written in the seal registry BEFORE today?"
    supply "Two six-sided dice (for 25 throws of two)?"
    supply "A black pen, one blank paper PIN card (three pages), and THREE tamper-evident envelopes: one per page (the KMS host recovery card is sealed apart)?"
    supply "A FULL paper tray (50 sheets or more) in the printer, and toner that does not report low?"
  elif [ "$n" -gt 0 ]; then
    bad "supplies must be confirmed at a terminal (no /dev/tty): run go-nogo.sh interactively"
  fi
fi

echo
if [ "$stop" -eq 0 ]; then
  printf '\033[32mGO\033[0m — every required check passed. Proceed with the ceremony steps by hand.\n'
  exit 0
else
  printf '\033[31mNO-GO\033[0m — do NOT start any key-touching step until the FAIL items are resolved.\n'
  exit 1
fi
