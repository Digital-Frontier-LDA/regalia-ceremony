#!/usr/bin/env bash
# emu-boot.sh — sourceable library that boots every hardware emulator in the CURRENT Linux
# session (no container). Used by run-tests.sh (native, on the Qubes box or a CI runner) and
# by the optional Docker entrypoint. Idempotent. Needs root for pcscd/cups/mknod.
#
#   source emu-boot.sh ; boot_all
#
# Honours:
#   EMU_RUN          runtime/state dir            (default /run/vault-emu, falls back to TMPDIR)
#   EMU_BIN          dir holding the emulator bins (default: this script's dir)
#   SOFTHSM2_CONF    SoftHSM2 config path
# Writes EMU_* exports to "$EMU_RUN/env.sh" for the harnesses to source.

# resolve the emulator bin dir from this script's location unless caller set EMU_BIN
if [ -z "${EMU_BIN:-}" ]; then
  EMU_BIN="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
fi
export EMU_BIN

# pick a writable runtime dir
if [ -z "${EMU_RUN:-}" ]; then
  if mkdir -p /run/vault-emu 2>/dev/null && [ -w /run/vault-emu ]; then
    EMU_RUN=/run/vault-emu
  else
    EMU_RUN="${TMPDIR:-/tmp}/vault-emu"
  fi
fi
mkdir -p "$EMU_RUN"
export EMU_RUN
RUN="$EMU_RUN"

emu_log(){ printf '\033[36m[emu]\033[0m %s\n' "$*"; }
emu_warn(){ printf '\033[33m[emu] %s\033[0m\n' "$*"; }

# emu_refuse_on_real_readers: fail (and say why) when a real smart-card reader or token is attached,
# read from sysfs WITHOUT talking to pcscd. Booting kills and restarts pcscd, which takes every token
# away from whoever is using it (regalia-ceremony#104). Two ways a reader is seen:
#   - a USB interface of class 0b (CCID): readers, YubiKeys, Nitrokeys;
#   - a device whose idVendor:idProduct is in libccid's reader list, whatever its class: pcscd drives
#     those too, and some declare a vendor-specific class (ff) that the first check cannot see.
# The list fails closed (regalia-hfz): when a USB device is attached and the list cannot be read or
# parsed, the boot is refused, since nothing then says the device is not a reader.
# EMU_CCID_LIST_UNCHECKED=1 boots without the list check (the class-0b check still runs).
# REGALIA_BENCH=1 says the bench belongs to this run. EMU_SYSFS_USB and EMU_CCID_PLIST exist for the test.
emu_ccid_plist() {
  local f
  for f in ${EMU_CCID_PLIST:+"$EMU_CCID_PLIST"} /etc/libccid_Info.plist \
           /usr/lib/pcsc/drivers/ifd-ccid.bundle/Contents/Info.plist \
           /usr/libexec/SmartCardServices/drivers/ifd-ccid.bundle/Contents/Info.plist; do
    [ -r "$f" ] && { printf '%s\n' "$f"; return 0; }
    [ -n "${EMU_CCID_PLIST:-}" ] && return 1   # a path named for the test is the only one read
  done
  return 1
}
# emu_ccid_pairs <plist>: one vvvv:pppp per listed reader (lower case, no 0x); exit 1 unless the vendor and
# product arrays are both present, non-empty and the same length, so a malformed list never reads as "none".
emu_ccid_pairs() {
  awk '
    /<key>ifdVendorID<\/key>/  { mode = "v"; sv = 1; next }
    /<key>ifdProductID<\/key>/ { mode = "p"; sp = 1; next }
    /<key>/                    { mode = "" }
    /<\/array>/                { if (mode != "") { line = $0; sub(/<\/array>.*/, "", line); grab(line) } mode = ""; next }
    mode != ""                 { grab($0) }
    function grab(line,   m) {
      while (match(line, /<string>[^<]*<\/string>/)) {
        m = tolower(substr(line, RSTART + 8, RLENGTH - 17)); sub(/^0x/, "", m)
        while (length(m) < 4) m = "0" m
        if (mode == "v") v[nv++] = m; else p[np++] = m
        line = substr(line, RSTART + RLENGTH)
      }
    }
    END { if (!sv || !sp || nv == 0 || nv != np) exit 1; for (i = 0; i < nv; i++) print v[i] ":" p[i] }
  ' "$1"
}
emu_refuse_on_real_readers() {
  local sys="${EMU_SYSFS_USB:-/sys/bus/usb/devices}" f d id ccid="" listed="" devs="" plist pairs why=""
  for f in "$sys"/*/bInterfaceClass; do
    [ -r "$f" ] && [ "$(cat "$f" 2>/dev/null)" = 0b ] && ccid="$ccid ${f%/bInterfaceClass}"
  done
  for d in "$sys"/*/; do
    d="${d%/}"
    [ -r "$d/idVendor" ] && [ -r "$d/idProduct" ] || continue
    devs="$devs $d=$(tr 'A-F' 'a-f' < "$d/idVendor"):$(tr 'A-F' 'a-f' < "$d/idProduct")"
  done
  if [ -n "$devs" ] && [ "${EMU_CCID_LIST_UNCHECKED:-}" != 1 ]; then
    if ! plist="$(emu_ccid_plist)"; then
      why="no readable libccid reader list (EMU_CCID_PLIST, /etc/libccid_Info.plist, ifd-ccid.bundle), so the attached USB devices cannot be cleared"
    elif ! pairs="$(emu_ccid_pairs "$plist")"; then
      why="libccid's reader list $plist could not be parsed (its vendor and product arrays), so the attached USB devices cannot be cleared"
    else
      for id in $devs; do
        printf '%s\n' "$pairs" | grep -qx "${id#*=}" && listed="$listed ${id%%=*} (${id#*=})"
      done
    fi
  fi
  [ -z "$ccid$listed$why" ] || [ "${REGALIA_BENCH:-}" = 1 ] && return 0
  [ -z "$ccid" ] || echo ">> REFUSING to boot the emulator daemons: a smart-card interface is attached here (${ccid# })."
  [ -z "$listed" ] || echo ">> REFUSING to boot the emulator daemons: a reader libccid drives is attached here (${listed# })."
  [ -z "$why" ] || echo ">> REFUSING to boot the emulator daemons: $why."
  echo "   Booting KILLS this machine's pcscd and starts the emulator's own: every session using a token"
  echo "   here loses it. Use the emulator container or a machine without readers. REGALIA_BENCH=1 does"
  echo "   that kill anyway; set it only when the whole bench is yours. --models-only is safe."
  [ -n "$why" ] && echo "   EMU_CCID_LIST_UNCHECKED=1 boots without the reader list (the class-0b check still runs)."
  return 1
}

# --- 1. PC/SC daemon + virtual reader (vpcd) ----------------------------------------
start_pcsc() {
  emu_log "starting pcscd + vpcd virtual reader"
  pkill -x pcscd 2>/dev/null || true
  sleep 0.3
  # vsmartcard-vpcd drops a reader.conf.d entry; pcscd loads libvpcd which LISTENS on
  # 35963/35964 for a vpicc to connect.
  pcscd --disable-polkit >/dev/null 2>&1 || pcscd >/dev/null 2>&1 || emu_warn "pcscd failed to start (need root + vsmartcard-vpcd)"
  sleep 0.6
}

# --- 2. SLE-4442 emulated card (connects to vpcd) -----------------------------------
start_sle4442() {
  emu_log "starting SLE-4442 vpicc (PSC=FFFFFF, state=$RUN/sle4442.state)"
  "$EMU_BIN/sle4442-vpicc.py" --port 35963 --psc FFFFFF \
      --state "$RUN/sle4442.state" >"$RUN/sle4442.log" 2>&1 &
  echo $! > "$RUN/sle4442.pid"
  sleep 0.7
}

# --- 3. SoftHSM2 token (the Nitrokey HSM 2 PKCS#11 stand-in) -------------------------
start_softhsm() {
  emu_log "configuring SoftHSM2"
  : "${SOFTHSM2_CONF:=$RUN/softhsm2.conf}"
  export SOFTHSM2_CONF
  local tokdir="$RUN/softhsm-tokens"
  mkdir -p "$tokdir"
  cat > "$SOFTHSM2_CONF" <<EOF
directories.tokendir = $tokdir
objectstore.backend = file
log.level = ERROR
slots.removable = false
EOF
  local mod
  mod="$(ls /usr/lib/softhsm/libsofthsm2.so /usr/lib/*/softhsm/libsofthsm2.so 2>/dev/null | head -1)"
  echo "export SOFTHSM2_CONF=$SOFTHSM2_CONF"        >  "$RUN/env.sh"
  echo "export EMU_PKCS11_MODULE=$mod"              >> "$RUN/env.sh"
  echo "export EMU_VPCD_PORT=35963"                 >> "$RUN/env.sh"
}

# --- 4. CUPS + cups-pdf print queue (the Brother+CUPS stand-in) ----------------------
start_cups() {
  emu_log "starting CUPS with a cups-pdf queue"
  local outdir="$RUN/pdf-out"
  mkdir -p "$outdir"; chmod 1777 "$outdir" 2>/dev/null || true
  if [ -f /etc/cups/cups-pdf.conf ]; then
    sed -i 's#^Out .*#Out '"$outdir"'#' /etc/cups/cups-pdf.conf 2>/dev/null \
      && { grep -q '^Out ' /etc/cups/cups-pdf.conf || echo "Out $outdir" >> /etc/cups/cups-pdf.conf; } \
      || emu_warn "could not edit cups-pdf.conf (need root)"
  fi
  pgrep -x cupsd >/dev/null 2>&1 || /usr/sbin/cupsd 2>/dev/null || emu_warn "cupsd failed to start (need root + cups)"
  sleep 0.8
  if ! lpstat -p vault-pdf >/dev/null 2>&1; then
    local model ppd
    model="$(lpinfo -m 2>/dev/null | grep -iE 'cups-pdf|/pdf' | head -1 | awk '{print $1}')"
    ppd="$(ls /usr/share/ppd/cups-pdf/*.ppd /usr/share/cups/model/CUPS-PDF*.ppd \
              /usr/share/ppd/CUPS-PDF*.ppd 2>/dev/null | head -1)"
    if [ -n "$model" ] && lpadmin -p vault-pdf -v cups-pdf:/ -E -m "$model" 2>>"$RUN/cups.log"; then :
    elif [ -n "$ppd" ] && lpadmin -p vault-pdf -v cups-pdf:/ -E -P "$ppd" 2>>"$RUN/cups.log"; then :
    elif lpadmin -p vault-pdf -v cups-pdf:/ -E -m everywhere 2>>"$RUN/cups.log"; then :
    else lpadmin -p vault-pdf -v cups-pdf:/ -E -m raw 2>>"$RUN/cups.log" || emu_warn "could not create cups-pdf queue"; fi
    cupsenable vault-pdf 2>/dev/null || true
    cupsaccept vault-pdf 2>/dev/null || true
    lpadmin -d vault-pdf 2>/dev/null || true
  fi
  echo "export EMU_PRINTER=vault-pdf"               >> "$RUN/env.sh"
  echo "export EMU_PDF_OUTDIR=$outdir"              >> "$RUN/env.sh"
}

# --- 5. fake optical drives (so the go/no-go "2 drives" gate is exercisable) ---------
start_optical() {
  emu_log "creating two emulated optical drives (/dev/sr0, /dev/sr1)"
  for n in 0 1; do
    [ -e "/dev/sr$n" ] || mknod "/dev/sr$n" b 11 "$n" 2>/dev/null || emu_warn "cannot create /dev/sr$n (need root); drives gate will be advisory"
  done
  # The mknod'd nodes don't register in /proc/sys/dev/cdrom/info, so go-nogo's write-capability probe
  # can't see them as WRITERS and the day-of "drives" gate would wrongly STOP (NO-GO) on a CI runner with
  # no real optical hardware. Emulate a kernel capability table advertising BOTH sr0+sr1 as DVD writers (a
  # ready day-of state) and point go-nogo at it via GONOGO_CDROM_INFO. Per-case tests that need a read-only
  # pair set their own GONOGO_CDROM_INFO, which overrides this default.
  cdinfo="$RUN/cdrom-info"
  {
    printf 'CD-ROM information, Id: cdrom.c 3.20 2003/12/17\n\n'
    printf 'drive name:\t\tsr1\tsr0\n'
    printf 'Can write CD-R:\t\t1\t1\n'
    printf 'Can write DVD-R:\t\t1\t1\n'
    printf 'Can write DVD-RAM:\t0\t0\n'
  } > "$cdinfo" 2>/dev/null || emu_warn "could not write cdrom-info fixture"
  echo "export EMU_OPTICAL_DIR=$RUN/optical"        >> "$RUN/env.sh"
  echo "export GONOGO_CDROM_INFO=$cdinfo"           >> "$RUN/env.sh"
}

boot_all() {
  emu_refuse_on_real_readers || return 1
  start_pcsc
  start_sle4442
  start_softhsm
  start_cups
  start_optical
  emu_log "emulators up. environment written to $RUN/env.sh:"
  sed 's/^/      /' "$RUN/env.sh"
  emu_log "PC/SC readers:"; opensc-tool -l 2>/dev/null | sed 's/^/      /' || true
}

stop_all() {
  [ -f "$RUN/sle4442.pid" ] && kill "$(cat "$RUN/sle4442.pid")" 2>/dev/null || true
  pkill -x pcscd 2>/dev/null || true
}
