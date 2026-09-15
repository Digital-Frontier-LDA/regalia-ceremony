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
