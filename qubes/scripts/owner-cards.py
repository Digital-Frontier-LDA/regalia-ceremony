#!/usr/bin/env python3
"""owner-cards.py — the OWNER pair's YubiKeys (ADR-0002 D30.7): each card's OpenPGP keys generated ON the card, its
certificate built from them, and the facts the root-signed card record names (regalia-ceremony#111 step 2).

    python3 -Es owner-cards.py enroll --role owner-main|owner-backup --yubikey-serial N --name NAME --email ADDR \
                                      --breakglass-recipient FILE --out DIR [--replace]
    python3 -Es owner-cards.py cards --main FACTS --backup FACTS --out DIR

Per card (enroll), in this order, which the D30.6 bench measurements on YubiKey 35718625 fixed (regalia-kms-24):
  0. Only the owner card is attached: pcscd sees exactly one reader, the YubiKey's (a Nitrokey or the laptop's reader is
     refused), and gpg's own scdaemon, configured for pcscd only (pcsc-shared, disable-ccid: its CCID driver took a
     Nitrokey on the bench, regalia-kms-24), reaches the OpenPGP card with the typed serial (scd serialno). Checked
     before anything is generated.
  1. SIG Ed25519, DEC X25519 and AUT Ed25519 generated on the card (yubikit), firmware 5.2.3 or later, the PINs typed and
     never the factory defaults; a card that already holds a key is refused unless --replace and its serial typed again.
  2. The card released, and gpg builds the certificate from the card's own keys ("existing key from card", 14): the
     primary is SIG [SC], DEC an encryption subkey [E], AUT an authentication subkey [A]. The PIN goes only to gpg's
     command fd, never its argv. The exported certificate is then parsed packet by packet: its primary must hold exactly
     the card's SIG key, one subkey exactly its DEC key, one exactly its AUT key, and no other subkey.
  3. The card again: each key's certificate fingerprint and creation time written to it (gpg's "existing key" does not,
     and OpenSC then shows no key at all, so the KMS's PKCS#11 path could not use it), and touch FIXED on all three
     slots (D30.7). Only THEN each slot attested, so the attestation names the certificate's fingerprint: every leaf must
     say generated on the card (5.2 = 1), this serial (5.7), the slot's fingerprint (5.4), its creation time (5.5) and
     touch fixed (5.8 = 02), and carry the slot's key.
  4. Written to --out, every name serial-qualified (so both cards can share one directory) and each checked absent
     BEFORE the card is touched: owner-card-<serial>.gpg (the public certificate), .rev.age (gpg's revocation
     certificate, pre-signed, so anyone holding it could revoke the owner certificate: encrypted to the break-glass
     recipient, the sealed-recovery place, its plaintext never outside the RAM GnuPG home, which is removed; the facts
     keep its SHA-256 only, d9 on #140), .sig/.dec/.aut.attest.der and .att.der (each slot's attestation and the card's attestation CA,
     every leaf verified against it), and .json, the facts.
cards then joins the two cards' facts into the card record's --cards input (owner_keys, ownerauth_recipients,
ssh_signers) and owner-cards.gpg (both certificates, as ceremony.sh step a imports them). It re-proves each card from
the files beside its facts (each attestation's digest recomputed, each leaf verified against the card's CA and its
claims re-read against the facts), so a hand-edited facts file carries nothing (d9 on #140).

CURRENT LIMITATIONS (2026-10-05):
  * Built and tested against a stand-in card and a stand-in for gpg's card dialogue only. The real dialogue (the
    command-fd answers) is the one regalia-kms-24 measured on the bench, but this script's run of it on a real card is
    not yet proven: a bench run on a staging YubiKey comes before any ceremony.
  * The attestation chain to Yubico's root is not checked here, only each leaf's claims and keys: regalia-kms's reader
    (#400) checks the chain at genesis. A card that fails any check is left with its keys; reset its OpenPGP applet
    (ykman openpgp reset) before it is used again.
  * No ceremony.sh step runs it yet (#111 step 2); card-record has no step either.
"""
import argparse
import base64
import contextlib
import datetime
import getpass
import hashlib
import importlib.machinery
import importlib.util
import json
import os
import re
import shutil
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
_loader = importlib.machinery.SourceFileLoader("offline_keys", os.path.join(HERE, "offline-keys.py"))
ok = importlib.util.module_from_spec(importlib.util.spec_from_loader("offline_keys", _loader))
_loader.exec_module(ok)
Refused, require, canonical = ok.Refused, ok.require, ok.canonical

SCHEMA_FACTS = "regalia.owner-card/v1"
TOOL = "owner-cards.py/1"
MIN_FIRMWARE = (5, 2, 3)                     # Ed25519/X25519 on the OpenPGP applet, and attestation
DEFAULT_ADMIN_PIN, DEFAULT_USER_PIN = "12345678", "123456"
SLOTS = ("sig", "dec", "aut")
ATTEST_OID = "1.3.6.1.4.1.41482.5."           # Yubico's OpenPGP attestation extensions, measured on YubiKey 35718625
GENERATED, TOUCH_FIXED = 1, 2


def stamp(now=None):
    return (now or datetime.datetime.now(datetime.timezone.utc)).strftime("%Y-%m-%dT%H:%M:%SZ")


# ---- the certificate, read from its own packets ---------------------------------------------------------------------

def packets(data):
    """The OpenPGP packets of `data` (binary, RFC 4880 4.2): [(tag, body)]. Old and new headers; no partial lengths."""
    out, at = [], 0
    while at < len(data):
        head = data[at]
        require(head & 0x80, "not an OpenPGP packet at byte %d" % at)
        if head & 0x40:                                        # new format
            tag, first = head & 0x3F, data[at + 1]
            if first < 192:
                size, at = first, at + 2
            elif first < 224:
                size, at = ((first - 192) << 8) + data[at + 2] + 192, at + 3
            else:
                require(first == 255, "a partial-length packet: refused")
                size, at = int.from_bytes(data[at + 2:at + 6], "big"), at + 6
        else:                                                  # old format
            tag, kind = (head >> 2) & 0x0F, head & 0x03
            require(kind != 3, "an indeterminate-length packet: refused")
            width = 1 << kind
            size, at = int.from_bytes(data[at + 1:at + 1 + width], "big"), at + 1 + width
        require(at + size <= len(data), "a packet runs past the end")
        out.append((tag, data[at:at + size]))
        at += size
    return out


def key_packet(body):
    """A v4 public-key packet's facts: {created, alg, point (64 hex, the 32-byte key), fingerprint (40 upper hex)}.
    Only the ECC forms the cards make: EdDSA (22) and ECDH (18) on 25519, the point 0x40-prefixed."""
    require(body[:1] == b"\x04", "not a version 4 key")
    created, alg = int.from_bytes(body[1:5], "big"), body[5]
    require(alg in (18, 22), "a key of algorithm %d, not EdDSA or ECDH" % alg)
    oid_len = body[6]
    at = 7 + oid_len
    bits = int.from_bytes(body[at:at + 2], "big")
    mpi = body[at + 2:at + 2 + (bits + 7) // 8]
    require(len(mpi) == 33 and mpi[0] == 0x40, "the key is not a 0x40-prefixed 32-byte point")
    fingerprint = hashlib.sha1(b"\x99" + len(body).to_bytes(2, "big") + body).hexdigest().upper()
    return {"created": created, "alg": alg, "point": mpi[1:].hex(), "fingerprint": fingerprint}


def certificate_keys(export, capabilities):
    """The certificate `export` (gpg --export, binary): {"sig": primary, "dec": the [E] subkey, "aut": the [A] subkey},
    each key_packet's facts. `capabilities` maps fingerprint -> gpg's capability letters (its colon listing): the
    primary must sign and certify, exactly one subkey encrypt, exactly one authenticate, and there is no other subkey."""
    found = packets(export)
    primaries = [key_packet(body) for tag, body in found if tag == 6]
    subkeys = [key_packet(body) for tag, body in found if tag == 14]
    require(len(primaries) == 1, "the certificate has %d primary keys, not one" % len(primaries))
    primary = primaries[0]
    require(primary["alg"] == 22 and set("sc") <= set(capabilities.get(primary["fingerprint"], "")),
            "the primary is not an EdDSA key that signs and certifies")
    enc = [k for k in subkeys if capabilities.get(k["fingerprint"], "") == "e" and k["alg"] == 18]
    aut = [k for k in subkeys if capabilities.get(k["fingerprint"], "") == "a" and k["alg"] == 22]
    require(len(enc) == 1 and len(aut) == 1 and len(subkeys) == 2,
            "the certificate's subkeys are not exactly one ECDH encryption subkey and one EdDSA authentication subkey")
    return {"sig": primary, "dec": enc[0], "aut": aut[0]}


def gpg_capabilities(home, run=subprocess.run):
    listing = run(["gpg", "--homedir", home, "--batch", "--with-colons", "--fixed-list-mode", "--list-keys"],
                  capture_output=True, text=True, check=True).stdout
    caps, last = {}, None
    for line in listing.splitlines():
        fields = line.split(":")
        if fields[0] in ("pub", "sub"):
            last = "".join(sorted(c for c in fields[11] if c.islower()))   # the key's own; upper case is the certificate's
        elif fields[0] == "fpr" and last is not None:
            caps[fields[9]] = last
            last = None
    return caps


def ssh_line(point_hex):
    blob = b"".join(len(p).to_bytes(4, "big") + p for p in (b"ssh-ed25519", bytes.fromhex(point_hex)))
    return "ssh-ed25519 " + base64.b64encode(blob).decode()


# ---- the card ---------------------------------------------------------------------------------------------------------

def only_this_reader(names, serial):
    """The smart-card readers pcscd sees: exactly one, the YubiKey's. Any other card or CCID reader (a Nitrokey, the
    laptop's own reader) is refused, since scdaemon may take it instead (regalia-kms-24's bench run, 2026-10-05)."""
    others = [n for n in names if "yubico" not in n.lower()]
    require(not others and len(names) == 1, "attach only owner card %s: pcscd also sees %s. Remove every other smart card and "
            "reader first" % (serial, ", ".join(others or names[1:]) or "nothing"))


def aid_serial(aid):
    """The serial in an OpenPGP card's application ID (RID D276000124, application 01): its four BCD serial bytes, as the
    YubiKey's decimal serial. Anything else (another applet, a Nitrokey HSM's) is refused."""
    aid = aid.strip().upper()
    require(re.fullmatch(r"D27600012401[0-9A-F]{20}", aid) is not None, "the card scdaemon reaches is not an OpenPGP card (%s)" % (aid or "none"))
    return aid[20:28].lstrip("0")


def card_seen_by_gpg(home, serial, run=subprocess.run):
    """The card gpg's scdaemon reaches, by its own `scd serialno`: the owner card typed, before any dialogue."""
    done = run(["gpg-connect-agent", "--homedir", home, "scd serialno", "/bye"], capture_output=True, text=True)
    aids = [line.split()[2] for line in done.stdout.splitlines() if line.startswith("S SERIALNO ")]
    require(aids, "scdaemon reaches no card (%s): is owner card %s attached, and pcscd running?" % ((done.stdout + done.stderr).strip()[-120:], serial))
    seen = aid_serial(aids[0])
    require(seen == serial, "scdaemon reaches card %s, not owner card %s: remove every other card and reader" % (seen, serial))


@contextlib.contextmanager
def open_card(serial):
    """The one YubiKey attached, which must be `serial`, and the only smart-card reader pcscd sees: (its OpenPGP session,
    its firmware version)."""
    from smartcard.System import readers
    from ykman.device import list_all_devices
    from yubikit.core.smartcard import SmartCardConnection
    from yubikit.openpgp import OpenPgpSession
    only_this_reader([str(r) for r in readers()], serial)
    devices = list_all_devices()
    require(len(devices) == 1, "%d YubiKeys are attached: attach only owner card %s (scdaemon takes the first card)" % (len(devices), serial))
    device, info = devices[0]
    require(str(info.serial) == serial, "the YubiKey attached is %s, not the %s typed" % (info.serial, serial))
    with device.open_connection(SmartCardConnection) as connection:
        yield OpenPgpSession(connection), "%d.%d.%d" % tuple(info.version)[:3]


def _ask(prompt):
    with open("/dev/tty") as tty:
        sys.stderr.write(prompt)
        sys.stderr.flush()
        return tty.readline().strip()


def _ask_secret(prompt):
    return getpass.getpass(prompt)


def raw_public(public_key):
    from cryptography.hazmat.primitives import serialization
    return public_key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()


def outputs(out, serial):
    """Every file and directory enroll makes for `serial` in `out`, by name: all checked absent before the card changes."""
    base = os.path.join(out, "owner-card-%s" % serial)
    named = {"facts": base + ".json", "gpg": base + ".gpg", "rev": base + ".rev.age", "att": base + ".att.der", "home": base + ".gnupg"}
    named.update({slot: "%s.%s.attest.der" % (base, slot) for slot in SLOTS})
    return named


def verify_leaf(leaf_der, ca_der, slot):
    """The slot's attestation signed by the card's attestation CA (the chain above it is regalia-kms#400's)."""
    from cryptography import x509
    try:
        x509.load_der_x509_certificate(leaf_der).verify_directly_issued_by(x509.load_der_x509_certificate(ca_der))
    except Exception as error:              # noqa: BLE001 - any failure is a refusal by name
        raise Refused("the %s attestation is not signed by the card's attestation CA (%s)" % (slot.upper(), error)) from None


def attestation_claims(der, slot, serial):
    """A slot's attestation certificate, read: {key, generated, serial, fingerprint, created, touch} from its subject
    key and Yubico's extensions (DER values as the card writes them)."""
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    cert = x509.load_der_x509_certificate(der)
    names = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    require(names and names[0].value == "YubiKey OPGP Attestation " + slot.upper(), "the %s attestation is not for the %s slot" % (slot, slot.upper()))

    def ext(n):
        try:
            return cert.extensions.get_extension_for_oid(x509.ObjectIdentifier(ATTEST_OID + str(n))).value.value
        except x509.ExtensionNotFound:
            raise Refused("the %s attestation has no extension 41482.5.%d" % (slot, n)) from None

    def integer(value):
        require(value[:1] == b"\x02" and value[1] == len(value) - 2, "an attestation INTEGER is malformed")
        return int.from_bytes(value[2:], "big")

    def octets(value, size):
        require(value[:1] == b"\x04" and value[1] == size and len(value) == size + 2, "an attestation OCTET STRING is malformed")
        return value[2:]
    return {"key": raw_public(cert.public_key()), "generated": integer(ext(2)), "serial": str(integer(ext(7))),
            "fingerprint": octets(ext(4), 20).hex().upper(), "created": int.from_bytes(octets(ext(5), 4), "big"),
            "touch": octets(ext(8), 1)[0]}


def build_certificate(home, name, email, user_pin, run=subprocess.Popen):
    """gpg builds the certificate from the inserted card's keys (the dialogue regalia-kms-24 measured, gpg 2.4.7): the
    primary from SIG, then DEC and AUT added as subkeys. The PIN is answered on the command fd, never in argv."""
    def dialogue(args, answers):
        proc = run(["gpg", "--homedir", home, "--no-tty", "--expert", "--status-fd", "1", "--command-fd", "0",
                    "--pinentry-mode", "loopback"] + args, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                   text=True, bufsize=1)
        created = None
        for line in proc.stdout:
            parts = line.split()
            if len(parts) >= 3 and parts[0] == "[GNUPG:]" and parts[1] in ("GET_LINE", "GET_BOOL", "GET_HIDDEN"):
                question = parts[2]
                if question == "passphrase.enter":
                    answer = user_pin
                else:
                    queue = answers.get(question)
                    if not queue and question in answers:
                        raise Refused("gpg asked %s again: it did not take the answer, most likely because scdaemon found no key on "
                                      "the card (another card or reader taken instead?). Nothing more is sent" % question)
                    require(queue, "gpg asked %s, which this dialogue does not answer: nothing more is sent" % question)
                    answer = queue.pop(0)
                proc.stdin.write(answer + "\n")
                proc.stdin.flush()
            elif len(parts) >= 4 and parts[:2] == ["[GNUPG:]", "KEY_CREATED"]:
                created = parts[3]
        require(proc.wait() == 0 and created, "gpg did not create the key (%s)" % " ".join(args[:1]))
        return created
    primary = dialogue(["--full-generate-key"], {"keygen.algo": ["14"], "keygen.cardkey": ["1"], "keygen.flags": ["Q"],
                                                 "keygen.valid": ["0"], "keygen.name": [name], "keygen.email": [email],
                                                 "keygen.comment": [""]})
    dialogue(["--edit-key", primary], {"keyedit.prompt": ["addkey", "save"], "keygen.algo": ["14"], "keygen.cardkey": ["2"],
                                       "keygen.flags": ["Q"], "keygen.valid": ["0"]})
    # AUT's default capabilities on a card key are S and A: S toggled off leaves A (toggling S then A gave none: 24)
    dialogue(["--edit-key", primary], {"keyedit.prompt": ["addkey", "save"], "keygen.algo": ["14"], "keygen.cardkey": ["3"],
                                       "keygen.flags": ["S", "Q"], "keygen.valid": ["0"]})
    return primary


def _agent_stop(home, run=subprocess.run):
    run(["gpg-connect-agent", "--homedir", home, "SCD RESET", "/bye"], capture_output=True)
    run(["gpgconf", "--homedir", home, "--kill", "all"], capture_output=True)


def enroll(role, serial, name, email, out, recipient_file, replace=False, ask=_ask, ask_secret=_ask_secret, card=open_card,
           build=build_certificate, run=subprocess.run, now=None, seen=card_seen_by_gpg):
    """One owner card, enrolled (see the docstring): returns its facts."""
    from yubikit.openpgp import KEY_REF, KEY_STATUS, OID, UIF
    serial = str(serial)
    require(role in ok.CARD_ROLES, "--role is owner-main or owner-backup")
    require(re.fullmatch(r"[1-9][0-9]{0,9}", serial) is not None, "--yubikey-serial is the owner card's decimal serial")
    require(serial not in ok.BENCH_YUBIKEYS, "YubiKey %s is a bench card: the ceremony never uses a bench serial (D28.5, D30)" % serial)
    require(os.path.isdir(out), "--out %s is not a directory" % out)
    named = outputs(out, serial)
    present = sorted(path for path in named.values() if os.path.lexists(path))
    require(not present, "%s already exist%s: nothing is overwritten, and the card was not touched"
            % (", ".join(present), "s" if len(present) == 1 else ""))
    recipient = ok._age_recipient(recipient_file)              # the break-glass recipient, judged before the card changes
    admin = ask_secret("Admin PIN of owner card %s: " % serial)
    user = ask_secret("User PIN of owner card %s: " % serial)
    require(admin != DEFAULT_ADMIN_PIN and user != DEFAULT_USER_PIN,
            "a PIN typed is the factory default: set the card's admin and user PINs first (ykman openpgp access), "
            "or anyone holding it could re-key it")
    # gpg's own home first, and the card ITS scdaemon reaches checked before anything is generated: through pcscd only,
    # never scdaemon's own CCID driver, which took a Nitrokey's reader instead on the bench (regalia-kms-24, 2026-10-05)
    home = named["home"]
    os.mkdir(home, 0o700)
    with open(os.path.join(home, "scdaemon.conf"), "w") as f:
        f.write("pcsc-shared\ndisable-ccid\n")
    reached = False
    try:
        seen(home, serial)
        reached = True
    finally:
        _agent_stop(home, run)                    # the card free again for yubikit
        if not reached:
            shutil.rmtree(home, True)             # nothing was generated: no leftover to block a rerun
    refs = {"sig": KEY_REF.SIG, "dec": KEY_REF.DEC, "aut": KEY_REF.AUT}
    curves = {"sig": OID.Ed25519, "dec": OID.X25519, "aut": OID.Ed25519}
    # 1. the keys, generated on the card
    generating = False
    try:
        with card(serial) as (session, firmware):
            version = tuple(int(x) for x in str(firmware).split(".")[:3])
            require(version >= MIN_FIRMWARE, "owner card %s runs firmware %s; the owner keys need %s or later: nothing was changed"
                    % (serial, firmware, ".".join(str(x) for x in MIN_FIRMWARE)))
            try:
                session.verify_pin(user)
                session.verify_admin(admin)
            except Exception as error:          # noqa: BLE001 - a wrong PIN costs a retry: said, never retried here
                raise Refused("owner card %s refused a PIN (%s): nothing was changed; each failure spends one of its three tries"
                              % (serial, error)) from None
            info = session.get_key_information()
            held = [slot for slot in SLOTS if info[refs[slot]] != KEY_STATUS.NONE]
            if held:
                require(replace, "owner card %s already holds %s: refused; replacing them takes --replace" % (serial, ", ".join(s.upper() for s in held)))
                require(ask("Owner card %s already holds keys. Type its serial to replace them: " % serial) == serial,
                        "the serial typed is not %s: nothing was changed" % serial)
            fixed = [slot for slot in SLOTS if session.get_uif(refs[slot]) in (UIF.FIXED, UIF.CACHED_FIXED)]
            require(not fixed, "owner card %s has a fixed touch policy on %s, which only a reset undoes: reset its OpenPGP applet "
                    "(ykman openpgp reset), set its PINs, then retry. Nothing was changed" % (serial, ", ".join(s.upper() for s in fixed)))
            generating = True                    # from here on a failure may leave new keys on the card
            publics = {slot: raw_public(session.generate_ec_key(refs[slot], curves[slot])) for slot in SLOTS}
    except Exception as error:              # noqa: BLE001 - before any key, the card is unchanged: no leftover blocks a rerun
        shutil.rmtree(home, True)
        if generating:
            raise Refused("%s. Owner card %s may now hold NEW keys: reset its OpenPGP applet (ykman openpgp reset) before it is "
                          "used again" % (str(error).rstrip("."), serial)) from None
        raise
    try:
        return _after_generation(role, serial, name, email, named, admin, user, publics, refs, card, build, run, now, recipient, seen)
    except Exception as error:              # noqa: BLE001 - whatever stopped it, the card now holds new keys
        raise Refused("%s. Owner card %s now holds NEW keys: reset its OpenPGP applet (ykman openpgp reset) before it is used "
                      "again" % (str(error).rstrip("."), serial)) from None


def _after_generation(role, serial, name, email, named, admin, user, publics, refs, card, build, run, now, recipient, seen):
    """Steps 2-4 of enroll, once the card holds its new keys."""
    from yubikit.openpgp import KEY_REF, UIF
    # 2. the certificate, by gpg from the card's own keys, then read back from its packets
    home = named["home"]
    try:
        primary = build(home, name, email, user)
        export = run(["gpg", "--homedir", home, "--batch", "--export", primary], capture_output=True, check=True).stdout
        keys = certificate_keys(export, gpg_capabilities(home, run))
    finally:
        _agent_stop(home, run)
    for slot in SLOTS:
        require(keys[slot]["point"] == publics[slot], "the certificate's %s key is not the one owner card %s generated: nothing "
                "was written" % (slot.upper(), serial))
    revocation_path = os.path.join(home, "openpgp-revocs.d", "%s.rev" % primary)
    require(os.path.isfile(revocation_path), "gpg wrote no revocation certificate for %s" % primary)
    with open(revocation_path, "rb") as f:
        revocation = f.read()
    sealed_revocation = _age_encrypt(revocation, recipient, named["rev"] + ".tmp", run)
    require(keys["sig"]["fingerprint"] == primary, "gpg's new key %s is not the certificate's primary %s" % (primary, keys["sig"]["fingerprint"]))
    # 3. the fingerprints and times written, touch fixed, and only then each slot attested
    attestations = {}
    with card(serial) as (session, firmware):
        session.verify_admin(admin)
        for slot in SLOTS:
            session.set_fingerprint(refs[slot], bytes.fromhex(keys[slot]["fingerprint"]))
            session.set_generation_time(refs[slot], keys[slot]["created"])
            session.set_uif(refs[slot], UIF.FIXED)
        written = session.get_application_related_data().discretionary.fingerprints
        for slot in SLOTS:
            require((written.get(refs[slot]) or b"").hex().upper() == keys[slot]["fingerprint"],
                    "owner card %s did not keep the %s fingerprint" % (serial, slot.upper()))
            require(session.get_uif(refs[slot]) == UIF.FIXED, "owner card %s did not take a FIXED touch policy on %s" % (serial, slot.upper()))
        for slot in SLOTS:
            attestations[slot] = _der(session.attest_key(refs[slot]))
        card_ca = _der(session.get_certificate(KEY_REF.ATT))
    for slot in SLOTS:
        verify_leaf(attestations[slot], card_ca, slot)
        claims = attestation_claims(attestations[slot], slot, serial)
        problems = [what for what, good in (
            ("not generated on the card", claims["generated"] == GENERATED), ("another serial %s" % claims["serial"], claims["serial"] == serial),
            ("another key", claims["key"] == publics[slot]), ("another fingerprint", claims["fingerprint"] == keys[slot]["fingerprint"]),
            ("another creation time", claims["created"] == keys[slot]["created"]), ("touch not fixed", claims["touch"] == TOUCH_FIXED)) if not good]
        require(not problems, "owner card %s's %s attestation says %s: nothing was written" % (serial, slot.upper(), ", ".join(problems)))
    # 4. the files
    files = {named["gpg"]: export, named["att"]: card_ca, named["rev"]: sealed_revocation}
    files.update({named[slot]: attestations[slot] for slot in SLOTS})
    for path, data in files.items():
        _write_new(path, data)
    shutil.rmtree(home)
    facts = {"schema": SCHEMA_FACTS, "role": role, "serial": serial, "firmware": firmware, "primary": keys["sig"]["fingerprint"],
             "keys": {slot: {"key": publics[slot], "fingerprint": keys[slot]["fingerprint"], "created": keys[slot]["created"]} for slot in SLOTS},
             "ssh": ssh_line(publics["aut"]), "touch": "fixed", "revocation_sha256": hashlib.sha256(revocation).hexdigest(),
             "attestation_sha256": {slot: hashlib.sha256(attestations[slot]).hexdigest() for slot in SLOTS},
             "tool": TOOL, "at": stamp(now)}
    _write_new(named["facts"], canonical(facts) + b"\n")
    return facts


def _age_encrypt(plain, recipient, tmp, run=subprocess.run):
    """`plain` encrypted with age to `recipient`, on age's stdin, never in a file of ours: the ciphertext (`tmp` is age's
    output, removed after it is read)."""
    try:
        done = run(["age", "-r", recipient, "-o", tmp], input=plain, capture_output=True)
        require(done.returncode == 0, "age could not encrypt to the break-glass recipient: %s" % done.stderr.decode(errors="replace").strip()[-200:])
        with open(tmp, "rb") as f:
            sealed = f.read()
    finally:
        if os.path.lexists(tmp):
            os.unlink(tmp)
    require(sealed.startswith(b"age-encryption.org/v1") and plain not in sealed, "age wrote no age file, or one with the plaintext in it")
    return sealed


def _der(cert):
    from cryptography.hazmat.primitives import serialization
    return cert if isinstance(cert, bytes) else cert.public_bytes(serialization.Encoding.DER)


def _write_new(path, data):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644)
    with os.fdopen(fd, "wb") as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())


def cards(main_path, backup_path, out):
    """The two cards' facts joined: cards.json (the card record's --cards input) and owner-cards.gpg (both certificates)."""
    facts = []
    for path, role in ((main_path, "owner-main"), (backup_path, "owner-backup")):
        with open(path, "rb") as f:
            entry = json.loads(f.read(1 << 20))
        require(entry.get("schema") == SCHEMA_FACTS and entry.get("role") == role, "%s is not %s's facts" % (path, role))
        named = outputs(os.path.dirname(os.path.abspath(path)), entry["serial"])
        with open(named["gpg"], "rb") as f:
            entry["_export"] = f.read()
        # the facts re-proved from the files beside them, never taken on their word (d9 on #140)
        with open(named["att"], "rb") as f:
            card_ca = f.read()
        for slot in SLOTS:
            with open(named[slot], "rb") as f:
                der = f.read()
            require(hashlib.sha256(der).hexdigest() == entry["attestation_sha256"][slot],
                    "%s's %s attestation is not the file beside it" % (path, slot.upper()))
            verify_leaf(der, card_ca, slot)
            claims = attestation_claims(der, slot, entry["serial"])
            require(claims["generated"] == GENERATED and claims["serial"] == entry["serial"] and claims["touch"] == TOUCH_FIXED
                    and claims["key"] == entry["keys"][slot]["key"] and claims["fingerprint"] == entry["keys"][slot]["fingerprint"]
                    and claims["created"] == entry["keys"][slot]["created"],
                    "%s's %s attestation does not say what its facts say" % (path, slot.upper()))
        require(entry["primary"] == entry["keys"]["sig"]["fingerprint"] and entry["ssh"] == ssh_line(entry["keys"]["aut"]["key"]),
                "%s's primary or SSH key is not its SIG or AUT key" % path)
        facts.append(entry)
    require(facts[0]["serial"] != facts[1]["serial"], "owner-main and owner-backup are one card (%s)" % facts[0]["serial"])
    joined = {"owner_keys": [{"role": e["role"], "serial": e["serial"], "alg": "ed25519", "key": e["keys"]["sig"]["key"], "attested": True,
                              "attestation_sha256": e["attestation_sha256"]} for e in facts],
              "ownerauth_recipients": [{"serial": e["serial"], "primary": e["primary"], "subkey": e["keys"]["dec"]["fingerprint"]} for e in facts],
              "ssh_signers": [{"serial": e["serial"], "key": e["ssh"]} for e in facts]}
    _write_new(os.path.join(out, "cards.json"), canonical(joined) + b"\n")
    _write_new(os.path.join(out, "owner-cards.gpg"), b"".join(e["_export"] for e in facts))
    return joined


def main(argv=None):
    parser = argparse.ArgumentParser(prog="owner-cards.py", description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="command", required=True)
    e = sub.add_parser("enroll")
    e.add_argument("--role", required=True, choices=ok.CARD_ROLES)
    e.add_argument("--yubikey-serial", required=True)
    e.add_argument("--name", required=True, help="the certificate's user ID name")
    e.add_argument("--email", required=True)
    e.add_argument("--breakglass-recipient", required=True, metavar="FILE",
                   help="a FILE holding the break-glass age recipient (one age1pq1… line): gpg's revocation certificate is sealed to it")
    e.add_argument("--out", required=True)
    e.add_argument("--replace", action="store_true", help="the card holds keys: replace them (the serial is typed again)")
    c = sub.add_parser("cards")
    c.add_argument("--main", required=True)
    c.add_argument("--backup", required=True)
    c.add_argument("--out", required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "enroll":
            facts = enroll(args.role, args.yubikey_serial, args.name, args.email, args.out, args.breakglass_recipient, args.replace)
            print("ENROLLED %s card %s: primary %s, touch fixed on SIG, DEC and AUT, each attested generated on the card"
                  % (facts["role"], facts["serial"], facts["primary"]))
        else:
            joined = cards(args.main, args.backup, args.out)
            print("CARDS %s: cards.json and owner-cards.gpg written" % ", ".join(k["serial"] for k in joined["owner_keys"]))
    except (Refused, OSError, ValueError, KeyError, subprocess.CalledProcessError) as error:
        print("owner-cards: REFUSED: %s" % error, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
