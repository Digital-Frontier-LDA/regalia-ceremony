/**
 * hsm-devaut-id.js — print a SmartCard-HSM's device identity: the DevAut CHR and a digest of the
 * device certificate. Read-only; touches no PIN and spends no retry attempt.
 *
 * WHY THIS EXISTS. Commissioning has to answer "is this OUR card", not "is this A genuine card" —
 * every real Nitrokey validates to the same CardContact root, so chain validation alone cannot
 * detect substitution, which is the attack colocation introduces.
 *
 * The identity lives in C.DevAut in read-only EF 2F02, as a Card Verifiable Certificate
 * (BSI TR-03110), NOT X.509 — so openssl cannot parse it and, more importantly, **`sc-hsm-tool`
 * never prints it**. An earlier version of commission-card.sh grepped `sc-hsm-tool` output for a
 * CHR; that check could never pass. It failed closed, which is the right direction, but a check
 * that cannot succeed makes commissioning impossible rather than safe.
 *
 *   cd $SCSH_HOME && ./scriptrunner path/to/hsm-devaut-id.js
 *
 * Output (stable, parseable):
 *   DEVAUT_CHR=<certificate holder reference>
 *   DEVAUT_CAR=<certificate authority reference>
 *   DEVAUT_SHA256=<hex digest of the whole EF 2F02 blob>
 *   DEVAUT_BYTES=<length>
 *   DEVAUT_HEX=<the whole EF 2F02 blob, hex>
 *
 * PIN THE SHA256, not just the CHR. The CHR is a name and names can collide or be chosen; the
 * digest covers the entire certificate including the device public key, so a substituted card
 * cannot reproduce it without the original's key material.
 *
 * DEVAUT_HEX exists so the blob can be verified OFFLINE by cvc-devaut-verify.py (pycvc — a
 * real TR-03110 parse plus signature-chain verification). That script is the AUTHORITATIVE
 * parse; the CHR/CAR extraction below is the convenience copy that keeps commissioning usable
 * on a host without the Python toolchain:
 *
 *   ./scriptrunner hsm-devaut-id.js | grep ^DEVAUT_HEX= | cut -d= -f2 > devaut.hex
 *   cvc-devaut-verify.py --hex devaut.hex --require-external-car [--trust-dir DIR]
 */

var SmartCardHSM = require("scsh/sc-hsm/SmartCardHSM").SmartCardHSM;

// PICK THE READER EXPLICITLY WHEN TOLD TO.
// With two SmartCard-HSMs attached, _scsh3.reader is whichever the shell defaults to. On
// 2026-09-03 that made hw_devaut report the OTHER card's identity — CHR=ESP41D722E200001 while
// the battery was pinned to ESP2202E14A — and the step PASSED, because a well-formed certificate
// from the wrong device still parses. A passing identity check on an unnamed card proves nothing.
var _rdr = java.lang.System.getenv("HSM_SCSH_READER");
var card = new Card((_rdr !== null && String(_rdr).length > 0) ? String(_rdr) : _scsh3.reader);
var sc = new SmartCardHSM(card);

var devaut;
try {
	devaut = sc.readBinary(new ByteString("2F02", HEX));
} catch (e) {
	print("DEVAUT_ERROR=" + e);
	throw e;
}

if (devaut == null || devaut.length == 0) {
	print("DEVAUT_ERROR=empty EF 2F02");
} else {
	// Pull the TR-03110 references out of the CVC by tag rather than by offset: the certificate
	// layout varies with key size, so a fixed offset would silently read the wrong bytes on a
	// different device — which is precisely the failure this check is meant to catch. KNOWN
	// LIMIT: this is a tag-SUBSTRING search and could still match inside a value field; the
	// authoritative parse is cvc-devaut-verify.py over DEVAUT_HEX (see header).
	//   5F20  Certificate Holder Reference (who this device IS)
	//   42    Certificate Authority Reference (who signed it)
	var hex = devaut.toString(HEX);

	function tlvAscii(tagHex) {
		var i = hex.indexOf(tagHex);
		if (i < 0) return "";
		var lenOff = i + tagHex.length;
		var len = parseInt(hex.substr(lenOff, 2), 16);
		if (isNaN(len) || len <= 0 || len > 64) return "";
		var val = hex.substr(lenOff + 2, len * 2);
		try {
			return new ByteString(val, HEX).toString(ASCII);
		} catch (e) {
			return "";
		}
	}

	var chr = tlvAscii("5F20");
	var car = tlvAscii("42");

	var sha = new ByteString(devaut.toString(HEX), HEX);
	var digest = new Crypto().digest(Crypto.SHA_256, sha);

	print("DEVAUT_CHR=" + chr);
	print("DEVAUT_CAR=" + car);
	print("DEVAUT_SHA256=" + digest.toString(HEX));
	print("DEVAUT_BYTES=" + devaut.length);
	print("DEVAUT_HEX=" + hex);
}
