/*
 * hsm-auto-import.js — unattended PKCS#12 import into a SmartCard-HSM, driven by the
 * scsh3 ScriptRunner (headless). Invoked by hsm-auto-import.sh; not meant to be run by hand.
 *
 * WHY THIS EXISTS: the ceremony runbook long said the PKCS#12 import was the one step "no CLI
 * can drive", because the documented route is the Key Manager GUI. That is not true. The scsh3
 * distribution ships `scriptrunner` (de.cardcontact.scdp.engine.ScriptRunner), a headless JS
 * engine with the SAME require("scsh/sc-hsm/…") module tree the GUI uses. Everything the GUI
 * plug-in does is reachable from a script.
 *
 * WHY createDKEKKeyDomain AND NOT --initialize: measured on a real Pico HSM, every
 * `sc-hsm-tool --initialize` drops the device off the USB bus; only a physical replug brings it
 * back. Since --initialize is what reserves the DKEK key domains, any sequence containing it
 * cannot run unattended. createDKEKKeyDomain (APDU 80 52 01) establishes a domain over APDU with
 * no re-init, so --initialize becomes one-time provisioning (like flashing the UF2) and
 * everything after it automates. See PROOF-OF-WORKS.md "How far the automation actually goes".
 *
 * SECRET HYGIENE: every secret is read from a FILE whose path arrives via the environment.
 * Nothing secret is ever inlined in this script, placed on argv, or printed. An earlier throwaway
 * draft of this script had the PKCS#12 password hardcoded as a literal; that is exactly the
 * defect this file exists to not repeat.
 *
 * Required environment:
 *   HSM_P12          path to the PKCS#12 container
 *   HSM_P12_PW_FILE  path to a file containing ONLY the container password
 *   HSM_DKEK_SHARE   path to the .pbe DKEK share
 *   HSM_DKEK_PW_FILE path to a file containing ONLY the DKEK share password
 *   HSM_USER_PIN_FILE path to a file containing ONLY the user PIN
 * Optional:
 *   HSM_KEY_DOMAIN   key domain number (default 0)
 *   HSM_DKEK_SHARES  shares the domain expects (default 1)
 *   HSM_LABEL        label for the imported key (default akash-funding)
 */

/* This file does NOT run under Node or in a browser. It is executed by the scsh3 ScriptRunner
 * (a Rhino-based engine), which injects its own globals. Declare them so the monorepo ESLint
 * config still lints this file for real defects instead of drowning in no-undef, and so the
 * file is not simply added to an ignore list where genuine errors would go unnoticed. */
/* global print, Card, Key, KeyStore, ByteString, ASCII, HEX, java, _scsh3 */

var DKEK = require("scsh/sc-hsm/DKEK").DKEK;
var SmartCardHSM = require("scsh/sc-hsm/SmartCardHSM").SmartCardHSM;
var PKIXCommon = require("scsh/x509/PKIXCommon").PKIXCommon;

// ---- helpers ---------------------------------------------------------------------------
function envOrDie(name) {
  var v = java.lang.System.getenv(name);
  if (v === null || String(v).length === 0) {
    throw new Error("FATAL: required environment variable " + name + " is unset");
  }
  return String(v);
}

function envOr(name, dflt) {
  var v = java.lang.System.getenv(name);
  return v === null || String(v).length === 0 ? dflt : String(v);
}

/* Read a secret from a file and return it as a trimmed JS string.
 * PKIXCommon.readFileFromDisk returns a ByteString. NOTE: `new ByteString(path, BASE64)` does
 * NOT read a file — it decodes the path STRING as base64 and silently yields garbage. That
 * mistake cost real debugging time; this helper is the only sanctioned way to read a secret. */
function secretFromFile(path, what) {
  var bs = PKIXCommon.readFileFromDisk(path);
  if (bs === null || bs.length === 0) {
    throw new Error("FATAL: " + what + " file is empty or unreadable: " + path);
  }
  return String(bs.toString(ASCII)).replace(/[\r\n\s]+$/, "");
}

// ---- inputs ----------------------------------------------------------------------------
var P12 = envOrDie("HSM_P12");
var P12_PW = secretFromFile(envOrDie("HSM_P12_PW_FILE"), "PKCS#12 password");
var DKEK_SHARE = envOrDie("HSM_DKEK_SHARE");
var DKEK_PW = secretFromFile(envOrDie("HSM_DKEK_PW_FILE"), "DKEK share password");
var USER_PIN = secretFromFile(envOrDie("HSM_USER_PIN_FILE"), "user PIN");
var KEY_DOMAIN = parseInt(envOr("HSM_KEY_DOMAIN", "0"), 10);
var DKEK_SHARES = parseInt(envOr("HSM_DKEK_SHARES", "1"), 10);
var LABEL = envOr("HSM_LABEL", "akash-funding");

// ---- connect ---------------------------------------------------------------------------
// HSM_READER selects WHICH card when more than one is attached. With a two-device fleet that is
// not a convenience: without it, `new Card(_scsh3.reader)` binds to whatever PC/SC enumerated
// first, so "provision device B" can silently re-provision device A. An import is destructive to
// the slot it lands in, and a non-deterministic target for a destructive operation is a defect.
var READER = envOr("HSM_READER", "");
var card = new Card(READER !== "" ? READER : _scsh3.reader);
print("STEP reader: " + (READER !== "" ? READER : "(default — only safe with ONE card attached)"));
var sc = new SmartCardHSM(card);
print("STEP connect: " + sc.getVersionInfo());

// PROVE WE ARE ON THE CARD WE WERE ASKED FOR, BEFORE SPENDING A PIN ATTEMPT.
//
// HSM_READER above is a reader NAME and scsh matches it by PREFIX, first hit wins. That is not
// merely imprecise — it can be IMPOSSIBLE to express the card you want. Measured 2026-09-03 with
// two Pico HSMs attached, PC/SC named them "…CCID Interface" and "…CCID Interface 01"; the first
// is a strict prefix of the second, so asking for the first card's EXACT full name returned the
// SECOND card's certificate. The fleet drill then verified card A's PIN against card B and
// unwrapped into it, which is where its SW=6982 came from — and it spent a retry on the wrong
// device to get there.
//
// So: read the device certificate (EF 2F02, read-only, no authentication) and refuse unless its
// holder reference carries the serial we were told to expect. This runs BEFORE verifyUserPIN, so
// a mis-selected card costs nothing.
var EXPECT_SERIAL = envOr("HSM_EXPECT_SERIAL", "");
if (EXPECT_SERIAL !== "") {
	var idblob = null;
	try { idblob = sc.readBinary(new ByteString("2F02", HEX)); } catch (e) { idblob = null; }
	if (idblob == null || idblob.length == 0) {
		throw new Error("REFUSING: expected card " + EXPECT_SERIAL + " but EF 2F02 is unreadable — cannot prove which device this is");
	}
	var idascii = idblob.toString(ASCII);
	if (idascii.indexOf(EXPECT_SERIAL) < 0) {
		throw new Error("REFUSING: connected to the WRONG CARD. Expected " + EXPECT_SERIAL +
			", but this device's certificate does not carry it. scsh selects readers by name PREFIX, " +
			"so when one reader name is a prefix of another the intended card cannot be addressed.");
	}
	print("STEP identity: confirmed " + EXPECT_SERIAL + " before authenticating");
}

sc.verifyUserPIN(new ByteString(USER_PIN, ASCII));
print("STEP auth: user PIN verified");

// ---- DKEK domain, WITHOUT --initialize ---------------------------------------------------
// createDKEKKeyDomain is the whole reason this path is automatable. If the domain already
// exists the card answers with a non-9000 SW; that is not fatal — we only need a domain that
// the share below can be imported into.
try {
  var dom = sc.createDKEKKeyDomain(KEY_DOMAIN, DKEK_SHARES, LABEL);
  print("STEP domain: created keyDomain=" + KEY_DOMAIN + " shares=" + DKEK_SHARES + " sw=" + (dom && dom.sw !== undefined ? dom.sw.toString(16) : "?"));
} catch (e) {
  print("STEP domain: createDKEKKeyDomain did not create a new domain (" + e + ") — continuing, a pre-existing domain is acceptable");
}

// Import the share into the domain. The password from `sc-hsm-tool --password env:VAR` is the
// LITERAL ASCII string, not hex bytes — passing it as HEX fails the decrypt.
var share = PKIXCommon.readFileFromDisk(DKEK_SHARE);
var sharePW = new ByteString(DKEK_PW, ASCII);
// A domain that is ALREADY complete rejects a further share (observed on the Pico HSM:
// SW=6986 "no current EF"). That is not fatal — it means this share, or an identical one, was
// already imported (e.g. by `sc-hsm-tool --import-dkek-share` during provisioning). What
// matters for the unwrap is only that the LOCAL DKEK below equals the CARD's, and the local
// one is rebuilt from this same share file either way.
var shareAccepted = false;
var outstanding;

// ASK BEFORE PUSHING. A domain that is already complete refuses a further share, and on a Pico HSM
// the REFUSAL ITSELF is the problem: SW=6985 after `sc-hsm-tool --import-dkek-share` had completed
// the domain left the session unable to UNWRAP (SW=6982), while the same card unwraps fine when
// the redundant import is never attempted (SW=6986 from a JS-completed domain is harmless).
// MEASURED 2026-09-21 on ESP41D722E2, fw 6.6 — the "seed-key import fails on a Pico" half of
// regalia#483, which had been read as an applet defect for four days.
//
// queryKeyDomainStatus answers with shares/outstanding, so the question is askable rather than
// discoverable by attempting the write. A card that will not answer it falls through to the import
// exactly as before.
var domainComplete = false;
try {
  var st = sc.queryKeyDomainStatus(KEY_DOMAIN);
  if (st && typeof st.outstanding !== "undefined") {
    domainComplete = (st.outstanding == 0) && (st.shares > 0);
    print("STEP dkek: domain status shares=" + st.shares + " outstanding=" + st.outstanding +
          (domainComplete ? " — already complete, not importing again" : ""));
  }
} catch (e) {
  print("STEP dkek: key domain status unavailable (" + e + ") — importing the share as usual");
}

if (domainComplete) {
  // The card holds a DKEK. The unwrap below only needs the LOCAL one to equal it, and the local
  // one is rebuilt from this same share file either way.
  shareAccepted = false;
  outstanding = 0;
} else {
try {
  var r = sc.importEncryptedKeyShare(share, sharePW, KEY_DOMAIN);
  print(
    "STEP dkek: imported share sw=" +
      (r.sw !== undefined ? r.sw.toString(16) : "?") +
      " shares=" +
      r.shares +
      " outstanding=" +
      r.outstanding +
      " kcv=" +
      (r.kcv ? r.kcv.toString(HEX) : "?")
  );
  outstanding = r.outstanding;
  shareAccepted = true;
} catch (e) {
  print("STEP dkek: card refused the share (" + e + ") — assuming the domain is already complete with THIS share");
}
}

// FAIL CLOSED, and deliberately OUTSIDE the catch above. A partially-satisfied domain must abort
// before wrapping, because the blob would then be encoded under a DIFFERENT DKEK than the card
// holds. Keeping this inside the try would let the already-complete tolerance swallow the very
// assertion that guards against it — see the "partially-satisfied DKEK domain must abort before
// wrapping" case in emulator/tests/test-hsm-auto-import.sh.
if (shareAccepted && outstanding !== undefined && outstanding > 0) {
  throw new Error("FATAL: DKEK domain still expects " + outstanding + " more share(s); the blob below would be encoded under a DIFFERENT DKEK");
}

// ---- container -> key --------------------------------------------------------------------
// KeyStore takes PLAIN JS strings for the path and password (not ByteString, not
// java.lang.String — both throw "Expected string argument").
var ks12 = new KeyStore("BC", "PKCS12", P12, P12_PW);
var aliases = ks12.getAliases();
if (aliases === null || aliases.length === 0) {
  throw new Error("FATAL: PKCS#12 container holds no aliases: " + P12);
}
var alias = aliases[0];
print("STEP container: alias=" + alias);

var key = new Key();
key.setType(Key.PRIVATE);
key.setID(alias);
ks12.getKey(key);
var pub = ks12.getCertificate(alias).getPublicKey();
print("STEP container: private key extracted, pubkey size=" + pub.getSize());

// ---- wrap under the DKEK and unwrap onto the card -----------------------------------------
// DKEK requires a PLAIN `new Crypto()`, which has .digest. sc.getCrypto() returns
// SmartCardHSMCrypto, which only wraps sign/encrypt/decrypt/verify and has NO .digest.
//
// CRITICAL: `new DKEK(crypto)` initialises the DKEK to 32 ZERO bytes. Encoding the key blob
// under that zero DKEK while the CARD holds the random share is a guaranteed mismatch, and the
// card rejects the resulting blob with SW=6400 — the exact failure recorded in PROOF-OF-WORKS.md
// and long misread as "the card rejects secp256k1". The blob MUST be encoded under the same DKEK
// value the card derived, so XOR the share in here (DKEK.importDKEKShare) exactly as the card did.
var dkek = new DKEK(new Crypto());
dkek.importDKEKShare(DKEK.decryptKeyShare(share, sharePW));
var blob = dkek.encodeKey(key, pub);
print("STEP wrap: keyblob=" + blob.length + " bytes under kcv=" + dkek.getKCV().toString(HEX));

var kid = sc.determineFreeKeyId();
print("STEP unwrap: target keyId=" + kid);
sc.unwrapKey(kid, blob);
print("STEP unwrap: OK into keyId=" + kid);

// ---- describe the key, or PKCS#11 cannot see it --------------------------------------------
// UNWRAP KEY stores the key (EF CCxx) and NOTHING ELSE. OpenSC's sc-hsm emulation enumerates
// private keys from their PKCS#15 description in EF C4xx, so a bare unwrap is invisible to every
// PKCS#11 consumer, logged in or not. MEASURED on a Nitrokey HSM 2 (DENK0404144, fw 4.1, JCOP 4,
// 2026-09-17): after IMPORT-OK the card held only CC01, `pkcs11-tool --login --list-objects` listed
// no private key, and the key could not be signed with. The Pico lists an unwrapped key anyway
// (with an empty label), which is why this was never caught there. CardContact's own
// HSMKeyStore.importECCKey writes this description immediately after unwrapKey; so does this.
var prkd = SmartCardHSM.buildPrkDforECC(kid, alias, pub.getSize());
sc.updateBinary(ByteString.valueOf((SmartCardHSM.PRKDPREFIX << 8) + kid), 0, prkd.getBytes());
print("STEP prkd: wrote PKCS#15 description C4" + ByteString.valueOf(kid).toString(HEX) + " label=" + alias);

// ---- read the imported key back to confirm the object exists ------------------------------
// SmartCardHSMKey has NO getPublicKey() (see SmartCardHSM.js:2565-2930 — only getId/getLabel/
// getSize/getType/sign/encrypt/decrypt). Calling it threw AFTER the unwrap had already
// succeeded, which made a working import look like a failed one. getSize()/getType() are the
// real API and are enough here: this is an existence check, not the proof.
//
// The proof deliberately lives OUTSIDE this script — the audited verify-hsm-control.py signs a
// fresh digest on the card and verifies it against the seed's pubkey — so the trust root is not
// this file. Note an UNWRAPPED key gets no CKO_PUBLIC_KEY companion object, so the pubkey cannot
// be read off the card at all; it has to come from the seed/container side.
// getType()/getSize() on a SmartCardHSMKey built directly from an id return undefined — they
// read a PKCS#15 description that is only populated by enumeration. So enumerate, and assert the
// new id is actually there: that is a genuine readback rather than a line that prints "undefined".
// enumerateKeys() RETURNS the PKCS#15 private-key descriptions, and an UNWRAPPED key has none —
// which is also why `pkcs11-tool --list-objects` shows imported keys with an empty label. Use the
// raw on-card id list (sc.idlist), which enumerateKeys() populates as a side effect, or a
// perfectly good import reads as missing.
sc.enumerateKeys();
var ids = sc.idlist;
var present = false;
for (var i = 0; i < ids.length; i++) {
  if (ids[i] == kid) {
    present = true;
  }
}
if (!present) {
  throw new Error("FATAL: unwrap reported OK but keyId=" + kid + " is not on the card (idlist=" + ids.join(",") + ")");
}
print("RESULT keyId=" + kid + " enumerated=true keysOnCard=" + ids.length);
print("IMPORT-OK");
