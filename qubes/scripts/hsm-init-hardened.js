/**
 * hsm-init-hardened.js — initialise a SmartCard-HSM with PIN-RESET DISABLED.
 *
 * WHY THIS EXISTS. `sc-hsm-tool --initialize` hardcodes the RESET RETRY COUNTER option ON
 * (`param.options[1] = 0x01`, no CLI flag), and `C_InitToken` does the same. A card provisioned by
 * either is one where the SO-PIN alone sets a user PIN of the attacker's choosing and then uses
 * every key — MEASURED on hardware 2026-08-01, see doc/drills/2026-08-01-so-pin-reset.md.
 *
 * THE OPTIONS BYTE HAS TWO INDEPENDENT BITS, which is the part that matters and which the
 * `sc-hsm-tool` interface hides completely:
 *
 *   bit 0 (0x01)  RESET RETRY COUNTER enabled at all
 *   bit 5 (0x20)  PIN reset DISABLED   — SmartCardHSM.js: isPINResetEnabled() is (options & 0x20) == 0
 *
 * So there are THREE reachable postures IN SPEC, not two:
 *
 *   RRC on, reset allowed   the default. SO-PIN can CHANGE the user PIN -> SO-PIN takes the keys.
 *   RRC off entirely        <-- what this script builds by default (the ratified posture, PLAN.md
 *                           decision D3). SO-PIN cannot reach the keys, but an honest lockout is
 *                           UNRECOVERABLE: the card must be re-provisioned.
 *   RRC on, RESET-ONLY      in theory the best of both: SO-PIN can unblock a locked card (clearing
 *                           the error counter) but CANNOT set a new PIN value. IN PRACTICE THE
 *                           PICO HSM IGNORES BIT 5 — measured behaviourally 2026-08-01
 *                           (doc/drills/2026-08-01-rrc-disabled.md): a card initialised with
 *                           options 0x21 accepted the attacker's PIN reset exactly like an ordinary
 *                           RRC-enabled card. On the Pico, reset-only DOES NOT block the attack;
 *                           the "recoverable lockout" claim is therefore false on this hardware and
 *                           RRC-off is the only posture that actually closes it. Re-test on the
 *                           Nitrokey before ever selecting reset-only.
 *
 * DESTRUCTIVE. INITIALIZE DEVICE erases every key, certificate and file on the target. Only ever
 * point this at a scratch device.
 *
 *   SCSH_HOME=~/tools/scsh-3.18.77
 *   cd $SCSH_HOME && HSM_SO_PIN=... HSM_USER_PIN=... ./scriptrunner path/to/hsm-init-hardened.js
 */

var SmartCardHSM = require("scsh/sc-hsm/SmartCardHSM").SmartCardHSM;
var SmartCardHSMInitializer = require("scsh/sc-hsm/SmartCardHSM").SmartCardHSMInitializer;

function envOrDie(name) {
	var v = java.lang.System.getenv(name);
	if (v == null || String(v).length == 0) {
		throw new Error("environment variable " + name + " is required");
	}
	return String(v);
}

function envOr(name, dflt) {
	var v = java.lang.System.getenv(name);
	return (v == null || String(v).length == 0) ? dflt : String(v);
}

var SO_PIN      = envOrDie("HSM_SO_PIN");          // 16 hex digits
var USER_PIN    = envOrDie("HSM_USER_PIN");
var DKEK_SHARES = parseInt(envOr("HSM_DKEK_SHARES", "1"), 10);
var LABEL       = envOr("HSM_LABEL", "regalia");
var RETRIES     = parseInt(envOr("HSM_PIN_RETRIES", "3"), 10);

// Guard: the published pico-hsm example values must never reach a card that will hold anything.
// The ceremony has the same list; they are duplicated here because this script is runnable on its
// own and a guard that only exists upstream is not a guard.
var DEV_DEFAULTS = ["648219", "3537363231383830", "CHANGEME", "TODO", "FILL_IN"];
if (envOr("CEREMONY_MODE", "dev") == "prod") {
	for (var i = 0; i < DEV_DEFAULTS.length; i++) {
		if (SO_PIN == DEV_DEFAULTS[i] || USER_PIN == DEV_DEFAULTS[i]) {
			throw new Error("CEREMONY_MODE=prod and a PIN is a published dev default — refusing");
		}
	}
}

var card = new Card(envOr("HSM_READER", "") != "" ? envOr("HSM_READER", "") : _scsh3.reader);
var sc = new SmartCardHSM(card);
print("STEP connect: " + sc.getVersionInfo());

// PROVE WE ARE ON THE INTENDED CARD BEFORE WIPING IT.
//
// This script runs INITIALIZE DEVICE — it erases every key on whatever card it reaches. HSM_READER
// above is a reader NAME and scsh matches names by PREFIX, first hit wins, so when one attached
// reader's name is a prefix of another's the intended card cannot be addressed at all. Measured
// 2026-09-03 with two Pico HSMs: PC/SC named them "…CCID Interface" and "…CCID Interface 01", and
// asking for the first card's EXACT full name returned the SECOND card's certificate.
//
// Which card gets the bare name is not stable — the two swapped when the bench was replugged. So
// this cannot be left to luck: read the device certificate (EF 2F02, no authentication needed)
// and refuse unless it carries the serial we were told to expect.
var EXPECT_SERIAL = envOr("HSM_EXPECT_SERIAL", "");
if (EXPECT_SERIAL !== "") {
	var idblob = null;
	try { idblob = sc.readBinary(new ByteString("2F02", HEX)); } catch (e) { idblob = null; }
	if (idblob == null || idblob.length == 0) {
		// A BLANK CARD LEGITIMATELY HAS NO EF 2F02, and this script is how a blank card gets
		// initialised — that is the pico-hsm#137 deadlock. So absence cannot simply be fatal, or
		// this script could never provision the device it exists to provision. But absence is also
		// not permission: a WRONG card that happens to be blank is indistinguishable from the RIGHT
		// blank card by this method alone.
		//
		// So identity falls back to the one signal a blank card still has: its USB serial IS the
		// RP2350 OTP board id (verified on hardware). scsh cannot read USB descriptors, so the
		// SHELL WRAPPER must establish that and say so here. HSM_BOARD_VERIFIED is the wrapper's
		// attestation that it checked; HSM_EXPECT_BOARD records what it checked against.
		//
		// A bare "this card is expected to be blank" override was considered and REJECTED: it would
		// re-open the wipe-the-wrong-card hole it claims to close, because "blank" is a property of
		// the card in front of you, not evidence about WHICH card that is.
		if (envOr("HSM_EXPECT_BLANK", "") !== "") {
			throw new Error("REFUSING TO INITIALIZE: HSM_EXPECT_BLANK is not honoured. Asserting " +
				"that a card is blank says nothing about WHICH card it is, which is the only " +
				"question this guard exists to answer. Supply HSM_EXPECT_BOARD with the board id " +
				"and have the wrapper verify it (HSM_BOARD_VERIFIED=1).");
		}
		var expectBoard = envOr("HSM_EXPECT_BOARD", "");
		if (expectBoard === "" || envOr("HSM_BOARD_VERIFIED", "") !== "1") {
			throw new Error("REFUSING TO INITIALIZE: expected card " + EXPECT_SERIAL +
				" but EF 2F02 is absent, so this card cannot identify itself. That is normal for a " +
				"blank device — but then identity must come from the USB/OTP board id, which only " +
				"the shell wrapper can read. Re-run through the wrapper so it can set " +
				"HSM_EXPECT_BOARD and HSM_BOARD_VERIFIED=1, or initialise with EF 2F02 present.");
		}
		// CROSS-CHECK THE TWO THINGS THE CALLER SUPPLIED. HSM_EXPECT_SERIAL and HSM_EXPECT_BOARD
		// are not independent: the token serial is "ESP" + the LAST FOUR BYTES of the OTP board id
		// (OpenSC strips the 5-digit CVC sequence), so they must agree. Without this the wrapper
		// could verify board X while the caller believed it was initialising the card with serial
		// Y — a mismatched map or a stale env, and the guard passes on a device nobody asked for.
		// Two supplied values that disagree mean the CONFIG is wrong, and the only safe reading of
		// a wrong config is to stop.
		var wantSuffix = EXPECT_SERIAL.replace(/^ESP/i, "").toUpperCase();
		var gotSuffix  = expectBoard.slice(-wantSuffix.length).toUpperCase();
		if (wantSuffix === "" || gotSuffix !== wantSuffix) {
			throw new Error("REFUSING TO INITIALIZE: HSM_EXPECT_BOARD (" + expectBoard + ") does not " +
				"end in the bytes HSM_EXPECT_SERIAL (" + EXPECT_SERIAL + ") is derived from (" +
				wantSuffix + "). The two were supplied by the caller and must describe the SAME " +
				"device; disagreeing values mean the board map or the environment is wrong.");
		}
		print("STEP identity: EF 2F02 absent (blank device); proceeding on the wrapper's verified " +
			"USB/OTP board id " + expectBoard + ", which matches " + EXPECT_SERIAL);
	} else if (idblob.toString(ASCII).indexOf(EXPECT_SERIAL) < 0) {
		throw new Error("REFUSING TO INITIALIZE: connected to the WRONG CARD. Expected " +
			EXPECT_SERIAL + ", but this device's certificate does not carry it. scsh selects " +
			"readers by name PREFIX, so when one reader name is a prefix of another the intended " +
			"card cannot be addressed by name at all.");
	} else {
		print("STEP identity: confirmed " + EXPECT_SERIAL + " before initializing");
	}
}

var init = new SmartCardHSMInitializer(card);
init.setInitializationCode(new ByteString(SO_PIN, HEX));
init.setUserPIN(new ByteString(USER_PIN, ASCII));
init.setRetryCounterInitial(RETRIES);
init.setDKEKShares(DKEK_SHARES);
init.setLabel(LABEL);

// THE POINT OF THIS SCRIPT.
//   HSM_RRC_MODE=off (default) fully disables RRC — the posture ratified as D3 in PLAN.md. It is
//                    the ONLY mode measured to actually block the SO-PIN reset attack on the Pico
//                    (doc/drills/2026-08-01-rrc-disabled.md).
//   HSM_RRC_MODE=reset-only keeps RRC reachable but, per the scsh API, forbids PIN change — on
//                    paper. The Pico firmware silently drops options bit 5, so reset-only behaves
//                    exactly as RRC-enabled there (same drill). Retained ONLY for re-testing on a
//                    genuine Nitrokey/SmartCard-HSM; never select it on a Pico for custody.
var RRC_MODE = envOr("HSM_RRC_MODE", "off");
if (RRC_MODE == "off") {
	init.setResetRetryCounterMode(false);
} else {
	init.setResetRetryCounterMode(true);
	init.setResetRetryCounterResetOnlyMode(true);
}

// This line used to hardcode "RRC enabled, PIN-RESET DISABLED (reset-only)" regardless of the
// mode actually selected — so a run with HSM_RRC_MODE=off printed a description of a DIFFERENT
// posture next to the correct options value. Exactly the class of misleading output this repo
// keeps catching: the number was right, the words next to it were not.
print("STEP options: mode=" + RRC_MODE + " — options=0x" + init.options.toString(16));
init.initialize();
print("STEP initialize: done");

// Read the flags BACK off the card — but DO NOT trust what they say. The 2026-08-01 drill
// (doc/drills/2026-08-01-rrc-disabled.md) measured the scsh option readout LYING on the Pico:
// after a successful RRC-off initialisation, isResetRetryCounterEnabled() still returned true
// while the card behaviourally refused C_InitPIN. So these lines are printed for the record only;
// they can neither prove nor disprove the hardening. The ONLY verification that counts is
// behavioural: attempt `pkcs11-tool --login --login-type so --so-pin <SO> --init-pin --new-pin X`
// against the card and confirm it is REFUSED (CKR_GENERAL_ERROR), then confirm the original user
// PIN still opens it. See the drill for the exact commands.
// (Note: INITIALIZE DEVICE drops the Pico off the USB bus mid-command, so this block may never
// run — SCARD_E_NOT_TRANSACTED / CARD_REMOVED after initialize() is EXPECTED, not failure.)
var sc2 = new SmartCardHSM(card);
sc2.getFreeMemory();
print("NOTE  scsh readout follows — UNRELIABLE on the Pico (drill 2026-08-01):");
print("NOTE  isResetRetryCounterEnabled=" + sc2.isResetRetryCounterEnabled());
print("NOTE  isPINResetEnabled=" + sc2.isPINResetEnabled());

print("");
print("*** INIT COMPLETE — BUT NOT VERIFIED ***");
print("The scsh flag readout above is NOT evidence: it has been measured contradicting the card's");
print("actual behaviour (isResetRetryCounterEnabled() lies on the Pico). Do NOT record this card as");
print("hardened from this output alone. Verify BEHAVIOURALLY before custody:");
print("  pkcs11-tool --login --login-type so --so-pin <SO> --init-pin --new-pin 999999");
print("    -> must FAIL with CKR_GENERAL_ERROR (the SO-PIN reset attack is refused)");
print("  pkcs11-tool --login --pin 999999 --list-objects  -> must be REFUSED");
print("  pkcs11-tool --login --pin <original user PIN> --list-objects  -> must WORK");
print("Reference: doc/drills/2026-08-01-rrc-disabled.md");
