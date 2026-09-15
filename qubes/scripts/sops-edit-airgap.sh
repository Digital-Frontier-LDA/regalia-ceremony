#!/usr/bin/env bash
# sops-edit-airgap.sh — `sops edit` with a hardened editor so the decrypted temp file and
# the editor's own swap/backup/undo files stay in tmpfs and are never written to disk.
#
#   sops-edit-airgap.sh example-service:infra/ansible/vault.sops.yaml
#
# Run on the air-gapped vault qube. Without this, $EDITOR (vim/nano) can leave a .swp /
# backup / undo / crash copy of the DECRYPTED secret outside tmpfs.

set -uo pipefail
[ $# -ge 1 ] || { echo "usage: sops-edit-airgap.sh <file.sops.yaml>"; exit 2; }
command -v sops >/dev/null || { echo "sops not found"; exit 2; }

# tmpfs scratch for sops' decrypted temp file. Without a RAM-backed TMPDIR, `sops edit`
# writes the DECRYPTED vault (custodial seeds) to a disk-backed temp file — on a Qubes
# AppVM that is the persistent private volume, so the plaintext survives shutdown. Fail
# CLOSED, exactly like ceremony.sh init_work and preflight.sh: refuse rather than fall
# through to `exec sops edit`. Tests/sims opt in to a non-tmpfs TMPDIR via CEREMONY_ALLOW_NONTMPFS=1.
mounts_file="${SOPS_EDIT_MOUNTS_FILE:-/proc/mounts}"
if grep -qs "[[:space:]]/dev/shm[[:space:]]tmpfs[[:space:]]" "$mounts_file" 2>/dev/null; then
  export TMPDIR=/dev/shm
elif [ "${CEREMONY_ALLOW_NONTMPFS:-}" = 1 ]; then
  echo "WARNING: /dev/shm is not tmpfs — using ${TMPDIR:-/tmp} (NOT RAM-backed). Test/sim only." >&2
else
  echo "ERROR: /dev/shm is not a tmpfs mount — refusing 'sops edit' (the decrypted vault would hit disk)." >&2
  echo "On the Qubes vault qube /dev/shm is tmpfs; run there. (Tests set CEREMONY_ALLOW_NONTMPFS=1.)" >&2
  exit 1
fi

# vim with NO swap, NO backup, NO persistent undo, NO viminfo/history, NO plugins.
if command -v vim >/dev/null 2>&1; then
  export EDITOR='vim -n -i NONE -u NONE +"set noswapfile nobackup nowritebackup noundofile viminfo="'
elif command -v nano >/dev/null 2>&1; then
  export EDITOR='nano -R'   # -R: restricted (no backups, no reading/writing other files)
else
  # No hardenable editor. Fall CLOSED rather than launch the operator's ambient editor
  # (e.g. traditional vi/nvi), which would write a crash-recovery copy of the DECRYPTED
  # vault (custodial seeds) to /var/tmp/vi.recover on the persistent private volume —
  # TMPDIR=/dev/shm only redirects sops' own temp file, not the editor's recovery dir.
  echo "ERROR: neither vim nor nano is available — refusing 'sops edit' with an unhardened editor" >&2
  echo "       (an ambient editor could leave a recovery/backup copy of the decrypted vault on disk)." >&2
  echo "Install vim or nano on the vault qube and re-run." >&2
  exit 1
fi
exec sops edit "$@"
