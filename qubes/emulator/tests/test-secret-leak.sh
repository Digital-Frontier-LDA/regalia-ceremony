#!/usr/bin/env bash
# test-secret-leak.sh — adversarial check that NO secret is ever exposed in a log, on
# stdout, on disk with loose perms, or on the process command line, across the secret-
# handling paths (DKEK, Shamir shares + recombination source, age identity, SLE-4442 PSC).
#
# Runs natively (ssss + age + python3); the parts needing pcscd/qrencode self-skip. The
# vpicc per-APDU log redaction is covered by tests/test_sle4442_model.py (TestSecretLeak).
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
# Honor the env the runners set (CEREMONY_SCRIPTS/EMU_BIN) so this works both from a repo
# checkout AND from the baked image, where scripts live at /opt/vault-ceremony/scripts and
# emulator bins at /opt/vault-emu/bin — not the repo-relative layout.
BIN="${EMU_BIN:-$HERE/../bin}"
SCRIPTS="${CEREMONY_SCRIPTS:-$HERE/../../scripts}"
export PATH="$BIN:$PATH"

pass=0; fail=0; skip=0
P(){ printf '  \033[32mPASS\033[0m %s\n' "$1"; pass=$((pass+1)); }
F(){ printf '  \033[31mFAIL\033[0m %s\n' "$1"; fail=$((fail+1)); }
S(){ printf '  \033[33mSKIP\033[0m %s\n' "$1"; skip=$((skip+1)); }
hdr(){ printf '\n\033[1m### %s\033[0m\n' "$1"; }

W="$(mktemp -d)"; trap 'rm -rf "$W"' EXIT
mode_of(){ stat -f '%Lp' "$1" 2>/dev/null || stat -c '%a' "$1" 2>/dev/null; }   # mac|linux
grouporworld(){ local m; m="$(mode_of "$1")"; m="${m: -2}"; [ "$m" = "00" ] && return 1 || return 0; }

# =====================================================================================
hdr "DKEK (sc-hsm-tool model): the share password is never printed or stored; dkek.pbe is 0600"
export EMU_SCHSM_STATE="$W/schsm"
out="$(sc-hsm-tool --create-dkek-share "$W/dkek.pbe" --pwd-shares-threshold 4 --pwd-shares-total 6 2>&1)"
# Rebuild the password the model split, from four of the printed shares, with the model's own
# arithmetic — then look for it. A rebuild that yields nothing would make both checks below pass
# on no evidence, so its shape is asserted first.
PW="$(OUT="$out" python3 -c '
import importlib.machinery, importlib.util, os, re, sys
loader = importlib.machinery.SourceFileLoader("schsm", sys.argv[1])
m = importlib.util.module_from_spec(importlib.util.spec_from_loader("schsm", loader))
loader.exec_module(m)
out = os.environ["OUT"]
prime = m._hex_in(re.search(r"^Prime +: *([0-9a-f:]+)$", out, re.M).group(1))
ids = [int(i) for i in re.findall(r"^Share ID +: *([0-9]+)$", out, re.M)]
values = [m._hex_in(v) for v in re.findall(r"^Share value +: *([0-9a-f:]+)$", out, re.M)]
print(m._minimal_bytes(m._reconstruct(prime, list(zip(ids, values))[:4])).hex())
' "$BIN/sc-hsm-tool" 2>/dev/null)"
if [ "${#PW}" != 16 ]; then
  F "could not rebuild the 8-byte share password from the printed shares (got ${#PW} hex digits)"
else
  PW_COLON="$(sed 's/../&:/g; s/:$//' <<< "$PW")"
  if grep -qiF -e "$PW" -e "$PW_COLON" <<< "$out"; then
    F "the DKEK share PASSWORD appears in stdout!"
  else
    P "DKEK share password never printed on stdout (only the split shares are)"
  fi
  if grep -rqiF -e "$PW" -e "$PW_COLON" "$W" 2>/dev/null; then
    F "the DKEK share PASSWORD was written to a file under the workdir!"
  else
    P "DKEK share password is not stored in any file"
  fi
fi
if ls "$EMU_SCHSM_STATE"/dkek-share-* >/dev/null 2>&1; then
  F "creating a password-share file left a stash in the state dir: $(ls "$EMU_SCHSM_STATE"/dkek-share-*)"
else
  P "creating a password-share file stashes nothing that could open it without the shares"
fi
grouporworld "$W/dkek.pbe" && F "dkek.pbe is group/world readable ($(mode_of "$W/dkek.pbe"))" \
                           || P "dkek.pbe is 0600"

# =====================================================================================
hdr "Shamir shares (recombination source): a single share never contains the plaintext secret"
if command -v ssss-split >/dev/null 2>&1; then
  MARK="TOPSECRET-seed-$$-do-not-leak"
  printf '%s' "$MARK" | ssss-split -t 4 -n 6 -q > "$W/shares.txt" 2>/dev/null
  if grep -qF "$MARK" "$W/shares.txt"; then
    F "the plaintext secret appears inside the Shamir share file!"
  else
    P "no Shamir share contains the plaintext secret (threshold transform intact)"
  fi
  # recombination output goes to stderr and is NOT auto-persisted by any ceremony script
  REC="$(sed -n '1p;3p;4p;6p' "$W/shares.txt" | ssss-combine -t 4 -q 2>&1)"
  [ "$REC" = "$MARK" ] && P "recombination reproduces the secret only in-memory (caller-controlled)" \
                       || F "recombination did not reproduce the secret"
  # prove no file under the workdir captured the reconstructed plaintext
  if grep -rqF "$MARK" "$W" 2>/dev/null; then F "reconstructed secret was written to a file under the workdir!"; \
  else P "reconstructed secret is not persisted to any file"; fi
else
  S "ssss not installed — share-plaintext check skipped"
fi

# =====================================================================================
hdr "age 'ops' identity: private key file is 0600 and never echoed to stdout"
if command -v age-keygen >/dev/null 2>&1; then
  export EMU_AGE_IDENTITY_DIR="$W/age"
  recip="$(age-plugin-yubikey --generate 2>/dev/null | tail -1)"
  idfile="$EMU_AGE_IDENTITY_DIR/ops-identity.txt"
  if [ -s "$idfile" ]; then
    grouporworld "$idfile" && F "age identity (private key) is group/world readable ($(mode_of "$idfile"))" \
                           || P "age identity file is 0600"
    # the SECRET line is AGE-SECRET-KEY-...; it must never be on stdout (only the public age1 recipient)
    secret="$(grep -oE 'AGE-SECRET-KEY-[0-9A-Z]+' "$idfile" | head -1)"
    full="$(age-plugin-yubikey --generate 2>/dev/null)"   # capture full stdout
    if [ -n "$secret" ] && grep -qF "$secret" <<< "$full"; then
      F "the age PRIVATE key was printed to stdout!"
    else
      P "only the public age recipient is printed (private key stays in the 0600 file)"
    fi
    case "$recip" in age1*) P "recipient is the public age1… value";; *) F "no public recipient";; esac
  else
    F "no age identity file produced"
  fi
else
  S "age-keygen not installed — age identity checks skipped"
fi

# =====================================================================================
hdr "SLE-4442 PSC: resolvable off-argv (env / file), and a non-default argv PSC warns"
# pyscard may be absent on this host, so exec ONLY resolve_psc out of the manager source
# (it has no pyscard dependency) and confirm the env path returns the PSC without argv.
psc_env="$(SLE4442_PSC=AABBCC T="$HERE" python3 - <<'PY' 2>/dev/null
import importlib.util, os, sys, re
origin = os.path.join(os.environ["T"], "..", "bin", "sle4442-manager")
src = open(origin).read()
ns = {"os": os, "sys": sys}
exec(compile(re.search(r"DEFAULT_PSC = .*?return psc or DEFAULT_PSC", src, re.S).group(0), "m", "exec"), ns)
class A: pass
a = A(); a.psc=None; a.psc_file=None
print(ns["resolve_psc"](a))
PY
)"
if [ "$psc_env" = "AABBCC" ]; then P "PSC resolves from SLE4442_PSC env (never placed on argv)"; else F "env PSC did not resolve (got '$psc_env')"; fi

# =====================================================================================
hdr "SLIP-39 backup + metal-stamp: secret --out files are 0600 even under a loose umask"
if python3 -c "import mnemonic, shamir_mnemonic" 2>/dev/null; then
  OLDUMASK="$(umask)"; umask 022   # adversarial: a loose umask must NOT leak the secret file
  MN="$(python3 -c "from mnemonic import Mnemonic; print(Mnemonic('english').generate(128))")"
  printf '%s' "$MN" > "$W/seed.in"
  if python3 "$SCRIPTS/bip39-slip39-backup.py" --in "$W/seed.in" --threshold 2 --shares 3 --out "$W/slip39.out" 2>/dev/null; then
    grouporworld "$W/slip39.out" && F "SLIP-39 backup file is group/world readable under umask 022 ($(mode_of "$W/slip39.out"))" \
                                 || P "SLIP-39 backup file is 0600 despite umask 022"
    grep -qF "$MN" "$W/slip39.out" && F "plaintext mnemonic present in the SLIP-39 share file!" \
                                   || P "SLIP-39 share file does not contain the plaintext mnemonic"
    SHARE="$(grep -E '^[a-z]+( [a-z]+){15,}$' "$W/slip39.out" | head -1)"
    if [ -n "$SHARE" ]; then
      printf '%s' "$SHARE" > "$W/share.in"
      python3 "$SCRIPTS/metal-stamp-worksheet.py" --in "$W/share.in" --out "$W/stamp.out" 2>/dev/null \
        && { grouporworld "$W/stamp.out" && F "metal-stamp worksheet file is group/world readable ($(mode_of "$W/stamp.out"))" \
                                         || P "metal-stamp worksheet file is 0600 despite umask 022"; } \
        || S "metal-stamp run failed"
    fi
  else
    S "bip39-slip39-backup run failed (deps?)"
  fi
  umask "$OLDUMASK"
else
  S "mnemonic/shamir_mnemonic not installed — SLIP-39/metal-stamp perm checks skipped"
fi

# =====================================================================================
hdr "metal-stamp-worksheet: default stdout path WARNS on a TTY before emitting the secret share (parity with bip39-slip39-backup / slip39-mint)"
# The worksheet's 4-letter UPPERCASE prefixes ARE the SLIP-39 share (per the module docstring),
# so the wizard-recommended `metal-stamp-worksheet.py --in <share>` (no --out) streams SECRET
# material straight to stdout. Its siblings bip39-slip39-backup.py and slip39-mint.py both guard
# that identical path with `if sys.stderr.isatty(): stderr.write("WARNING: ...stdout...")` so the
# operator is told not to log/screenshot before the share lands on a scrollback/tee/recording.
# Assert metal-stamp does the same. We force stderr.isatty()==True by attaching a pty to fd 2.
if python3 -c "import mnemonic, shamir_mnemonic" 2>/dev/null; then
  # produce a REAL SLIP-39 share to feed the worksheet
  MS_MN="$(python3 -c "from mnemonic import Mnemonic; print(Mnemonic('english').generate(128))")"
  printf '%s' "$MS_MN" > "$W/ms-seed.in"
  python3 "$SCRIPTS/bip39-slip39-backup.py" --in "$W/ms-seed.in" --threshold 2 --shares 3 --out "$W/ms-slip39.out" 2>/dev/null
  MS_SHARE="$(grep -E '^[a-z]+( [a-z]+){15,}$' "$W/ms-slip39.out" 2>/dev/null | head -1)"
  if [ -n "$MS_SHARE" ]; then
    printf '%s' "$MS_SHARE" > "$W/ms-share.in"
    # pty runner: exec <script> --in <share> with stderr on a pty (isatty True) and capture stderr.
    cat > "$W/pty-stderr.py" <<'PY'
import os, pty, select, subprocess, sys
script, infile = sys.argv[1], sys.argv[2]
m_out, s_out = pty.openpty()
m_err, s_err = pty.openpty()
p = subprocess.Popen([sys.executable, script, "--in", infile], stdout=s_out, stderr=s_err)
os.close(s_out); os.close(s_err)
buf = {m_out: b"", m_err: b""}
fds = [m_out, m_err]
while fds:
    r, _, _ = select.select(fds, [], [], 5)
    if not r:
        break
    for fd in r:
        try:
            chunk = os.read(fd, 4096)
        except OSError:
            chunk = b""
        if not chunk:
            fds.remove(fd); os.close(fd); continue
        buf[fd] += chunk
p.wait()
err = buf[m_err].decode(errors="replace")
# require an isatty-gated warning about SECRET material going to stdout (parity with siblings)
sys.exit(0 if ("WARNING" in err and "stdout" in err) else 1)
PY
    # (a) stderr IS a tty -> MUST warn before emitting the share
    if python3 "$W/pty-stderr.py" "$SCRIPTS/metal-stamp-worksheet.py" "$W/ms-share.in" 2>/dev/null; then
      P "metal-stamp-worksheet warns on a TTY before writing the secret share to stdout"
    else
      F "metal-stamp-worksheet writes the SLIP-39 share to stdout with NO TTY warning (siblings warn: 'WARNING: writing SECRET material to stdout')"
    fi
    # (b) parity: stderr NOT a tty (piped) -> no warning, so pipelines/redirections stay clean
    ms_warn_piped="$(python3 "$SCRIPTS/metal-stamp-worksheet.py" --in "$W/ms-share.in" 2>&1 >/dev/null)"
    case "$ms_warn_piped" in
      *WARNING*) F "metal-stamp-worksheet warns even when stderr is not a TTY (should gate on isatty)";;
      *)         P "metal-stamp-worksheet stays quiet on stderr when not a TTY (isatty-gated, parity with siblings)";;
    esac
  else
    S "no SLIP-39 share produced to drive the metal-stamp TTY-warning check"
  fi
else
  S "mnemonic/shamir_mnemonic not installed — metal-stamp TTY-warning check skipped"
fi

# =====================================================================================
hdr "SLIP-39 backup + metal-stamp: a PRE-EXISTING loose --out file is tightened BEFORE the secret is written (no read window)"
# The final-perms check above passes even for the buggy pattern, because chmod(0600) runs
# AFTER the write completes. The real leak is the WINDOW: os.open(O_CREAT|O_TRUNC) IGNORES
# its mode arg for an already-existing file, so a --out that was pre-created 0644 (attacker-
# planted, or a leftover from a prior run) stays 0644 while the SLIP-39 shares of the funding
# seed are streamed onto it — any local user can read the seed until the trailing chmod. The
# fix is to fchmod(fd, 0600) (or O_EXCL) immediately after open, before any write. We prove it
# WHITE-BOX: interpose on os.fdopen (called right after os.open, before write) and read the
# fd's on-disk mode at that instant; group/world bits there = the seed is exposed mid-write.
if python3 -c "import mnemonic, shamir_mnemonic" 2>/dev/null; then
  MN2="$(python3 -c "from mnemonic import Mnemonic; print(Mnemonic('english').generate(128))")"
  printf '%s' "$MN2" > "$W/seed2.in"
  wb_check() {  # $1=script  $2..=argv (must include --out <path>)
    EMU_WB_SCRIPT="$1" python3 - "$@" <<'PY'
import importlib.util, os, sys
script = os.environ["EMU_WB_SCRIPT"]
argv = sys.argv[2:]                       # sys.argv[1] is the script path (dup of $1)
out = argv[argv.index("--out") + 1]
open(out, "w").close(); os.chmod(out, 0o644)   # adversary pre-plants a loose --out file
spec = importlib.util.spec_from_file_location("wb_mod", script)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)              # __name__ != __main__ so main() does NOT auto-run
real_fdopen = os.fdopen; cap = {}
def spy(fd, *a, **k):
    cap["mode"] = os.fstat(fd).st_mode & 0o777   # perms at write time (post-open, pre-write)
    return real_fdopen(fd, *a, **k)
os.fdopen = spy
sys.argv = [script] + argv
try:
    mod.main()
except SystemExit as e:
    if e.code not in (0, None):
        sys.stderr.write("main() exited %r\n" % (e.code,)); sys.exit(2)
finally:
    os.fdopen = real_fdopen
m = cap.get("mode")
if m is None:
    sys.stderr.write("os.fdopen was never called (no --out write path exercised)\n"); sys.exit(2)
sys.exit(1 if (m & 0o077) else 0)         # nonzero => group/world readable while writing
PY
  }
  if wb_check "$SCRIPTS/bip39-slip39-backup.py" --in "$W/seed2.in" --threshold 2 --shares 3 --out "$W/wb-slip39.out"; then
    P "bip39-slip39-backup: pre-existing loose --out is 0600 BEFORE the seed shares are written (no mid-write read window)"
  else
    F "bip39-slip39-backup: a pre-existing 0644 --out stays group/world readable WHILE the funding-seed shares are written (open() ignored its mode; chmod runs only after the write)"
  fi
  WB_SHARE="$(grep -E '^[a-z]+( [a-z]+){15,}$' "$W/wb-slip39.out" 2>/dev/null | head -1)"
  if [ -n "$WB_SHARE" ]; then
    printf '%s' "$WB_SHARE" > "$W/wb-share.in"
    if wb_check "$SCRIPTS/metal-stamp-worksheet.py" --in "$W/wb-share.in" --out "$W/wb-stamp.out"; then
      P "metal-stamp-worksheet: pre-existing loose --out is 0600 BEFORE the share is written (no mid-write read window)"
    else
      F "metal-stamp-worksheet: a pre-existing 0644 --out stays group/world readable WHILE the share is written"
    fi
  else
    S "no SLIP-39 share produced to drive the metal-stamp window check"
  fi
else
  S "mnemonic/shamir_mnemonic not installed — --out write-window checks skipped"
fi

# =====================================================================================
hdr "ceremony.sh process-hygiene invariants (no secret to history / core dump / loose file)"
CER="$SCRIPTS/ceremony.sh"
CER_CODE="$(python3 "$HERE/source_lexing.py" shell "$CER")" \
  || { echo "source lexer failed" >&2; exit 2; }
grep -q 'unset HISTFILE' <<<"$CER_CODE"   && P "HISTFILE unset (no secrets to shell history)"        || F "HISTFILE not unset"
grep -q 'set +o history' <<<"$CER_CODE"   && P "interactive history disabled"                          || F "history not disabled"
grep -q 'ulimit -c 0' <<<"$CER_CODE"      && P "core dumps disabled (no seed memory in a crash dump)" || F "core dumps not disabled"
grep -q 'umask 077' <<<"$CER_CODE"        && P "umask 077 (wizard-created files are 0600)"            || F "no tight umask"
grep -q 'shred -u' <<<"$CER_CODE"         && P "workdir is shredded on exit"                          || F "workdir not shredded"
grep -q '/dev/shm' <<<"$CER_CODE"         && P "secret workdir is tmpfs (/dev/shm, RAM-only)"         || F "workdir not tmpfs"
# the wizard must move secrets file -> tool, never echo them: QR is built from the file
# (qrencode -r <file>), and the only `cat` of the secret is redirected into the tmpfs
# printout file, not the terminal.
grep -q 'qrencode .* -r "\$secret_file"' <<<"$CER_CODE" \
  && P "secret -> QR via qrencode -r <file> (never echoed to build the QR)" \
  || F "qrencode is not reading the secret from a file — possible echo path"
# the wizard PURGES the CUPS spool after printing so the plaintext share doesn't linger.
# Must be `cancel -x -a` (purge job DATA files): a bare `cancel -a` only cancels active jobs
# and leaves COMPLETED job data (the rendered plaintext) on disk under PreserveJobFiles.
grep -q 'cancel -x -a' <<<"$CER_CODE" \
  && P "CUPS spool is purged after printing (cancel -x -a) — completed job data deleted, no plaintext share left on disk" \
  || F "spool not purged with 'cancel -x -a' — a bare 'cancel -a' leaves completed job data (plaintext share) in /var/spool/cups"

# =====================================================================================
hdr "sle4442-manager 'info' does not dump card memory (a stored share) to stdout"
SLE_CODE="$(python3 "$HERE/source_lexing.py" python "$BIN/sle4442-manager")" \
  || { echo "source lexer failed" >&2; exit 2; }
if grep -qE 'main\[0:16\]|FF B0 00 00 10' <<<"$SLE_CODE"; then
  F "info still reads/prints main-memory contents — a stored secret would leak to stdout"
else
  P "info shows only status (counter/protection), never memory contents"
fi

# =====================================================================================
hdr "vpicc log redaction"
P "covered by tests/test_sle4442_model.py::TestSecretLeak (PSC / written / read-back redacted)"

# =====================================================================================
hdr "sops-edit-airgap.sh: REFUSES (exits non-zero) when /dev/shm is not tmpfs — no on-disk decrypt"
# When /dev/shm is not a tmpfs mount, `sops edit` would write the DECRYPTED vault (custodial
# seeds) to a disk-backed temp file. This wrapper must FAIL CLOSED like ceremony.sh init_work
# and preflight.sh — never fall through to `exec sops edit`. We drive the real wrapper with a
# fake `sops` (a canary that proves whether exec was reached) and a controlled mounts file.
SEA="$SCRIPTS/sops-edit-airgap.sh"
if [ -x "$SEA" ]; then
  FAKEBIN="$W/fakebin"; mkdir -p "$FAKEBIN"
  CANARY="$W/sops-was-exec.canary"
  cat > "$FAKEBIN/sops" <<EOF
#!/usr/bin/env bash
# fake sops: record that 'sops edit' was reached (would have decrypted to \$TMPDIR)
: > "$CANARY"
exit 0
EOF
  chmod +x "$FAKEBIN/sops"
  NOTMPFS="$W/mounts-no-tmpfs"; printf '%s\n' \
    "proc /proc proc rw 0 0" "/dev/sda1 / ext4 rw 0 0" > "$NOTMPFS"
  YESTMPFS="$W/mounts-tmpfs"; printf '%s\n' \
    "proc /proc proc rw 0 0" "tmpfs /dev/shm tmpfs rw 0 0" > "$YESTMPFS"

  # (a) not tmpfs, no escape hatch -> MUST refuse (non-zero) and MUST NOT exec sops.
  # Explicitly clear CEREMONY_ALLOW_NONTMPFS: run-tests.sh exports it globally (the test/sim
  # opt-in), but THIS case asserts the fail-closed path, which requires the opt-in to be OFF.
  rm -f "$CANARY"
  env -u CEREMONY_ALLOW_NONTMPFS PATH="$FAKEBIN:$PATH" SOPS_EDIT_MOUNTS_FILE="$NOTMPFS" \
    bash "$SEA" "$W/vault.sops.yaml" >/dev/null 2>&1
  rc=$?
  if [ "$rc" -ne 0 ] && [ ! -e "$CANARY" ]; then
    P "refuses (exit $rc) and does not exec 'sops edit' when /dev/shm is not tmpfs"
  else
    F "FELL OPEN: rc=$rc, canary $( [ -e "$CANARY" ] && echo present || echo absent ) — decrypted vault could hit disk"
  fi

  # (b) tmpfs present -> proceeds (exec reached) with TMPDIR forced to /dev/shm
  rm -f "$CANARY"
  PATH="$FAKEBIN:$PATH" SOPS_EDIT_MOUNTS_FILE="$YESTMPFS" \
    bash "$SEA" "$W/vault.sops.yaml" >/dev/null 2>&1
  [ -e "$CANARY" ] && P "proceeds to 'sops edit' when /dev/shm IS tmpfs (happy path intact)" \
                   || F "refused even though /dev/shm is tmpfs — happy path broken"

  # (c) not tmpfs but explicit test/sim opt-in -> proceeds with a warning (same policy as ceremony.sh)
  rm -f "$CANARY"
  PATH="$FAKEBIN:$PATH" SOPS_EDIT_MOUNTS_FILE="$NOTMPFS" CEREMONY_ALLOW_NONTMPFS=1 \
    bash "$SEA" "$W/vault.sops.yaml" >/dev/null 2>&1
  [ -e "$CANARY" ] && P "CEREMONY_ALLOW_NONTMPFS=1 opt-in proceeds (test/sim escape hatch)" \
                   || F "escape hatch did not proceed"
else
  S "sops-edit-airgap.sh not found/executable — refusal check skipped"
fi

# =====================================================================================
hdr "sops-edit-airgap.sh: REFUSES when NO hardened editor (vim/nano) is available — never launches an unhardened editor on the decrypted vault"
# The tmpfs guard keeps sops' OWN temp file in RAM, but if neither vim nor nano is present
# the wrapper must NOT fall through to `exec sops edit` with the operator's ambient editor
# (e.g. traditional vi/nvi), which writes a crash-recovery copy of the DECRYPTED custodial
# seeds to /var/tmp/vi.recover on the persistent private volume — TMPDIR=/dev/shm only
# redirects sops' temp file, not the editor's recovery dir. Fail CLOSED, exactly like the
# /dev/shm check above. We drive the real wrapper with an ISOLATED PATH that contains ONLY
# grep + bash + a fake sops canary (so vim AND nano are guaranteed absent) and a
# tmpfs-present mounts file (so the /dev/shm guard passes and we reach the editor branch).
if [ -x "$SEA" ]; then
  ISOBIN="$W/isobin"; mkdir -p "$ISOBIN"
  ICANARY="$W/sops-was-exec-noeditor.canary"
  cat > "$ISOBIN/sops" <<EOF
#!/usr/bin/env bash
# fake sops: record that 'sops edit' was reached with an unhardened/ambient editor
: > "$ICANARY"
exit 0
EOF
  chmod +x "$ISOBIN/sops"
  # provide ONLY the non-editor tools the wrapper needs, so vim/nano cannot be resolved
  ln -sf "$(command -v grep)" "$ISOBIN/grep"
  ln -sf "$(command -v bash)" "$ISOBIN/bash"
  rm -f "$ICANARY"
  PATH="$ISOBIN" SOPS_EDIT_MOUNTS_FILE="$YESTMPFS" \
    "$ISOBIN/bash" "$SEA" "$W/vault.sops.yaml" >/dev/null 2>&1
  rc=$?
  if [ "$rc" -ne 0 ] && [ ! -e "$ICANARY" ]; then
    P "refuses (exit $rc) and does not exec 'sops edit' when neither vim nor nano is available"
  else
    F "FELL OPEN: rc=$rc, canary $( [ -e "$ICANARY" ] && echo present || echo absent ) — an unhardened editor could write a recovery copy of the decrypted vault to disk"
  fi
else
  S "sops-edit-airgap.sh not found/executable — no-hardened-editor refusal check skipped"
fi

# =====================================================================================
hdr "pkcs11-tool shim: HSM PIN is passed off-argv (never on the real binary's command line)"
# The shim auto-supplies EMU_HSM_PIN for --login during tests. It MUST NOT place the PIN
# value as an argv token on the real OpenSC binary (visible via ps/ /proc/<pid>/cmdline).
# We drive the shim with a recorder standing in for the real pkcs11-tool (EMU_PKCS11_REAL)
# and assert the literal PIN never appears in the child's captured argv.
SHIM="$BIN/pkcs11-tool"
if [ -x "$SHIM" ]; then
  RECDIR="$W/pkcs11rec"; mkdir -p "$RECDIR"
  ARGV_FILE="$RECDIR/argv"
  REC="$RECDIR/real-pkcs11-tool"
  cat > "$REC" <<EOF
#!/usr/bin/env bash
# recorder: dump argv (one token per line) so the test can inspect what the shim passed
: > "$ARGV_FILE"
for a in "\$@"; do printf '%s\n' "\$a" >> "$ARGV_FILE"; done
exit 0
EOF
  chmod +x "$REC"
  SECRET_PIN="648219-do-not-leak-$$"
  EMU_PKCS11_REAL="$REC" EMU_HSM_PIN="$SECRET_PIN" EMU_PKCS11_MODULE="" \
    bash "$SHIM" --login --sign --id 01 -m ECDSA -i /dev/null -o "$W/ignore.sig" >/dev/null 2>&1 || true
  if [ ! -s "$ARGV_FILE" ]; then
    F "recorder captured no argv — shim did not forward to EMU_PKCS11_REAL"
  elif grep -qxF "$SECRET_PIN" "$ARGV_FILE"; then
    F "the HSM PIN value is present as an argv token on the real pkcs11-tool command line!"
  else
    P "HSM PIN never appears as an argv token (passed off-argv)"
    # and confirm login still gets a PIN reference so the fix didn't just drop auth
    grep -q -- '--pin' "$ARGV_FILE" \
      && P "a --pin reference is still supplied for --login (auth preserved, value off-argv)" \
      || F "no --pin reference forwarded — login would fail"
  fi
else
  S "pkcs11-tool shim not found/executable — PIN-on-argv check skipped"
fi

# =====================================================================================
hdr "ceremony.sh init_work: FAILS CLOSED when mktemp -d cannot create the RAM workdir (never continues with an empty WORK that writes secrets to the on-disk root FS)"
# If mktemp -d fails (chosen base — /dev/shm tmpfs or the TMPDIR fallback — momentarily
# full/unwritable), WORK must NOT be left empty while the menu keeps running. An empty WORK
# makes step 2 write '$WORK/dkek.pbe' etc. to '/dkek.pbe' on the persistent, on-disk ROOT FS,
# and cleanup()'s `[ -n "$WORK" ]` guard then skips all shredding. Both core guarantees
# (RAM-only workdir + shred-on-exit) would silently break. init_work must fail closed —
# exit non-zero and NEVER fall through — exactly like the sops-edit-airgap.sh guard above.
CER="$SCRIPTS/ceremony.sh"
if [ -f "$CER" ]; then
  FAILMKTEMP="$W/failmktemp"; mkdir -p "$FAILMKTEMP"
  cat > "$FAILMKTEMP/mktemp" <<'EOF'
#!/usr/bin/env bash
# fake mktemp: simulate a full/unwritable base (e.g. tmpfs full) — fail like real mktemp does
echo "mktemp: failed to create directory: No space left on device" >&2
exit 1
EOF
  chmod +x "$FAILMKTEMP/mktemp"
  # (a) mktemp fails -> init_work MUST exit non-zero and MUST NOT continue with an empty WORK.
  # Drive it in a subshell (bash -c) so its exit does not kill this harness; the AFTER_INIT
  # marker is printed ONLY if init_work returned instead of exiting (the fail-open bug).
  initout="$(PATH="$FAILMKTEMP:$PATH" CEREMONY_ALLOW_NONTMPFS=1 TMPDIR="$W" bash -c '
    set -uo pipefail
    source "$1" 2>/dev/null
    init_work
    printf "AFTER_INIT_REACHED work=[%s]\n" "${WORK:-}"
  ' _ "$CER" 2>&1)"
  irc=$?
  if grep -q 'AFTER_INIT_REACHED' <<< "$initout"; then
    F "init_work FELL THROUGH after mktemp -d failed (WORK empty) — the ceremony would write DKEK/secret material to the on-disk root FS and skip shredding"
  elif [ "$irc" -ne 0 ]; then
    P "init_work fails closed (exit $irc) when mktemp -d cannot create the RAM workdir — no secrets written off-tmpfs"
  else
    F "init_work exited 0 without creating a workdir (unexpected)"
  fi
  # (b) happy path intact: when mktemp works, init_work creates a real 0700 workdir.
  okout="$(CEREMONY_ALLOW_NONTMPFS=1 TMPDIR="$W" bash -c '
    set -uo pipefail
    source "$1" 2>/dev/null
    init_work >/dev/null 2>&1
    if [ -n "${WORK:-}" ] && [ -d "$WORK" ]; then printf "OK mode=%s\n" "$(stat -f %Lp "$WORK" 2>/dev/null || stat -c %a "$WORK" 2>/dev/null)"; fi
    rm -rf "${WORK:-}"
  ' _ "$CER" 2>&1)"
  case "$okout" in
    OK*) P "init_work creates a real workdir on the happy path ($okout)";;
    *)   F "init_work did not create a usable workdir when mktemp works (got '$okout')";;
  esac
else
  S "ceremony.sh not found — init_work fail-closed check skipped"
fi

# =====================================================================================
hdr "RESULT"
printf '  %d passed, %d failed, %d skipped\n' "$pass" "$fail" "$skip"
[ "$fail" -eq 0 ] && { echo "  NO SECRET LEAK DETECTED across the tested paths"; exit 0; } || { echo "  SECRET LEAK(S) FOUND"; exit 1; }
