#!/usr/bin/env bash
# go-nogo.sh — single GO / NO-GO gate to run on the air-gapped vault qube IMMEDIATELY
# before a ceremony. Read-only; touches NO key material. It runs preflight.sh and then
# turns the "this hardware is missing" WARNINGS into HARD gates for exactly the devices
# THIS ceremony needs, plus capability probes that catch the day-of surprises (a reader
# that can't talk to the card, a YubiKey one wrong PIN from PUK lockout, a network printer,
# a single optical drive). Ends in one verdict so you never start a key-touching step with
# a setup that was going to fail three commands in.
#
#   /opt/vault-ceremony/go-nogo.sh --need yubikey,hsm,sle4442,printer,drives
#   /opt/vault-ceremony/go-nogo.sh --need printer,drives      # a paper+archive-only run
#
# --need takes a comma list of: yubikey hsm sle4442 printer drives. Anything not listed is
# checked best-effort (warn only). With nothing listed, every probe is advisory.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"

NEED=""
while [ $# -gt 0 ]; do
  case "$1" in
    --need) NEED="$2"; shift 2;;
    --need=*) NEED="${1#--need=}"; shift;;
    -h|--help) sed -n '2,20p' "$0"; exit 0;;
    *) echo "unknown arg: $1" >&2; exit 2;;
  esac
done
# Validate --need tokens. An UNRECOGNISED token (typo like 'sle442') would otherwise make
# `needs <device>` silently false -> that device's check is skipped -> a false GO. For a
# set-once ceremony that is unacceptable: reject unknown tokens hard, before any probe.
KNOWN_NEEDS="yubikey hsm sle4442 printer drives"
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
ok()   { printf '  \033[32mGO\033[0m   %s\n' "$1"; }
warn() { printf '  \033[33m..\033[0m   %s\n' "$1"; }
bad()  { printf '  \033[31mSTOP\033[0m %s\n' "$1"; stop=1; }
hdr()  { printf '\n\033[1m== %s ==\033[0m\n' "$1"; }
# gate: FAIL only when the device is in --need; otherwise advisory
gate() { if needs "$2"; then bad "$1"; else warn "$1 (not required by --need)"; fi; }

hdr "Base preflight (air-gap, leak controls, tools)"
if "$HERE/preflight.sh" >/tmp/go-nogo-preflight.$$ 2>&1; then
  ok "preflight.sh passed"
  # Surface preflight's non-fatal advisories. preflight.sh ALWAYS colorizes them
  # (`  \033[33mWARN\033[0m ...`, no isatty/NO_COLOR guard), so the ESC[33m sequence sits
  # BETWEEN the two-space prefix and the word WARN. Grepping the raw bytes for `  (WARN|FAIL)`
  # (two spaces immediately followed by WARN) matches NOTHING, silently dropping every
  # pass-with-warnings advisory (low entropy, HISTFILE set, core-dump limit, no print queue)
  # from the one consolidated gate the operator relies on. Strip ANSI first, THEN anchor.
  _esc="$(printf '\033')"
  sed "s/${_esc}\[[0-9;]*m//g" /tmp/go-nogo-preflight.$$ | grep -E '  (WARN|FAIL)' | sed 's/^/     /' || true
else
  bad "preflight.sh FAILED — air-gap or a core control is wrong (full output below)"
  sed 's/^/     /' /tmp/go-nogo-preflight.$$
fi
rm -f /tmp/go-nogo-preflight.$$

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
    # returns no parsable counter on such hardware -> the near-lock STOP would silently
    # degrade to the manual-confirm WARN below. The vpicc emulator answers FF B1
    # unconditionally, so this ordering is transparent under test yet correct on metal.
    secmem="$(timeout 6 opensc-tool -s 'FF:A4:00:00:01:06' -s 'FF:B1:00:00:04' 2>/dev/null)"
    # Match the FF B1 data line by its LEADING 4 hex bytes only. Real opensc-tool renders
    # response data through util_hex_dump_asc, which appends an ASCII sidebar column after the
    # hex ('07 FF FF FF ....'); anchoring the match to end-of-line ([[:space:]]*$) would fail
    # to match that real output, leave ctr_hex empty, and silently degrade the near-lock STOP
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
  hdr "SmartCard-HSM (Nitrokey HSM 2) present + PKCS#11 visible"
  # Gate on the FUNDING-KEY HSM specifically, not the generic words 'token'/'present'. Any
  # OpenSC-visible PKCS#11 token (notably the YubiKey PIV, which this same ceremony needs for
  # the ops-identity step and enumerates through opensc-pkcs11.so) prints 'token label'/
  # 'token state: present' lines — an over-broad match would say GO on the YubiKey alone
  # while the funding-key HSM is absent. Require the SmartCard-HSM/Nitrokey HSM 2 marker:
  #   * a fresh device advertises the 'SmartCard-HSM' token label/model;
  #   * an already-initialised device (and the SoftHSM2 emulator) carries the 'akash-funding'
  #     token the ceremony creates.
  # A YubiKey PIV / generic token matches neither, so it can no longer produce a false GO.
  if command -v pkcs11-tool >/dev/null 2>&1 && \
     grep -qiE 'SmartCard-HSM|akash-funding' <<< "$(timeout 8 pkcs11-tool --list-slots 2>/dev/null)"; then
    ok "the funding-key HSM (SmartCard-HSM) is present"
    timeout 8 pkcs11-tool --list-slots 2>/dev/null | grep -iE 'Slot|token label|SmartCard-HSM|akash-funding|present' | sed 's/^/     /'
    # PIN-retry gate — the piece the presence probe above CANNOT see. Prior handling can
    # leave the user-PIN retry counter at 1 (two earlier mistyped PINs); the token still
    # lists as 'present', so without this the gate says GO. Then the first keygen `--login`
    # with a single PIN typo BLOCKS the user PIN, and if the SO-PIN is not on hand (or is
    # also exhausted) the device is permanently BRICKED and the born-in-HSM funding key is
    # lost — the exact failure the checklist below warns about. Read the counter and STOP on
    # 0/1, exactly like the SLE-4442 (FF B1) and YubiKey PIV gates. sc-hsm-tool with no
    # operation prints 'SO-PIN tries left : N' and 'User PIN tries left : N'; it only READS
    # the state (consumes no attempt). Match the USER-PIN line specifically — a keygen `--login`
    # spends the USER PIN, so that is the counter that governs the brick risk. (Do NOT match the
    # SO-PIN line: a healthy SO-PIN counter would mask a near-locked user PIN and yield a false GO.)
    if command -v sc-hsm-tool >/dev/null 2>&1; then
      hsm_ret="$(timeout 8 sc-hsm-tool 2>/dev/null | grep -iE 'User PIN tries left' | grep -oE '[0-9]+' | head -1)"
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
      so_ret="$(timeout 8 sc-hsm-tool 2>/dev/null | grep -iE 'SO-PIN tries left' | grep -oE '[0-9]+' | head -1)"
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
    bad "no SmartCard-HSM funding token visible — attach the Nitrokey HSM 2 (qvm-usb attach) and confirm pcscd is running. (A YubiKey PIV or other PKCS#11 token does NOT satisfy this gate.)"
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
    # NOT on the allowlist is a network printer -> STOP.
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
    bad "no CUPS print queue — add the USB Brother laser before the paper steps."
  fi
fi

if needs drives; then
  hdr "Two optical drives for M-DISC burn + cross-drive verify"
  # GONOGO_OPTICAL_GLOB overrides the device glob for tests only; defaults to the real nodes.
  optglob="${GONOGO_OPTICAL_GLOB:-/dev/sr*}"
  n=$(ls $optglob 2>/dev/null | wc -l | tr -d ' ')
  if [ "$n" -ge 2 ]; then
    ok "$n optical drives present (/dev/sr*)"
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
    # drive is a writer -> GO; burn drive is read-only (writer elsewhere or none) -> STOP; header
    # row absent but some writer exists -> WARN (can't map, confirm by hand); table unreadable /
    # no DVD-write row -> WARN, exactly like the other counter probes above.
    # GONOGO_CDROM_INFO overrides the table path for tests only; defaults to the real proc file.
    cdinfo="${GONOGO_CDROM_INFO:-/proc/sys/dev/cdrom/info}"
    burnnode="${GONOGO_BURN_DRIVE:-/dev/sr0}"; burnbase="${burnnode##*/}"
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
          ok "the burn drive $burnnode advertises a DVD writer profile (writers=$writers) — the M-DISC burn can run"
        elif [ "${writers:-0}" -ge 1 ]; then
          bad "the ceremony burns to $burnnode but THAT drive is read-only — the DVD writer is on another node (writers=$writers, kernel lists drives reversed vs /dev/srN). \`growisofs -Z $burnnode\` will fail. Swap so $burnnode IS the writer (or point the burn at the writer)."
        else
          bad "optical drives are present but NONE can WRITE (read-only DVD-ROM) — the M-DISC burn (growisofs -Z) will fail. Attach a DVD/M-DISC WRITER, not a DVD-ROM reader."
        fi
      elif [ "${writers:-0}" -ge 1 ]; then
        warn "a DVD writer is present (writers=$writers) but the capability table has no 'drive name:' row to confirm it is the burn drive $burnnode — verify by hand that $burnnode is the writer before the burn."
      else
        bad "optical drives are present but NONE can WRITE (read-only DVD-ROM) — the M-DISC burn (growisofs -Z) will fail. Attach a DVD/M-DISC WRITER, not a DVD-ROM reader."
      fi
    else
      warn "could not read optical write-capability table ($cdinfo) — confirm at least one drive is a DVD/M-DISC WRITER before the burn (a read-only DVD-ROM cannot burn a share)."
    fi
  elif [ "$n" -eq 1 ]; then bad "only 1 optical drive — you cannot cross-drive verify the burn. Attach the second drive."
  else bad "no /dev/sr* optical drive — attach the M-DISC writer(s)."; fi
fi

hdr "Operator decisions to CONFIRM before touching keys (do not improvise these)"
cat <<'SHEET'
  These are decided in advance and verified now — NOT chosen at the prompt:
    [ ] HSM SO-PIN + user PIN written down (sealed); retry counters understood
        (wrong SO-PIN/PIN repeatedly BRICKS the SmartCard-HSM — no recovery).
    [ ] DKEK 4-of-6 password-share custodians + transfer method agreed.
    [ ] YubiKey PIV PIN + PUK + management key chosen; touch policy = ALWAYS.
    [ ] SLE-4442 PSC (and whether you change it from FFFFFF) decided; 3 wrong = locked.
    [ ] Funding address will be recorded on paper AND verified on-chain afterwards.
    [ ] M-DISC media on hand (DVD M-DISC, not DVD+R); 2 drives; spare blanks.
    [ ] Printer page memory will be power-cycled after printing.
SHEET

echo
if [ "$stop" -eq 0 ]; then
  printf '\033[1;32m================  GO  ================\033[0m\n'
  printf 'All required checks passed. Proceed with the ceremony steps by hand.\n'
  exit 0
else
  printf '\033[1;31m==============  NO-GO  ==============\033[0m\n'
  printf 'Resolve every STOP item above BEFORE starting any key-touching step.\n'
  exit 1
fi
