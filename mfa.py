"""PART 12 Step 2: TOTP two-factor authentication.

TOTP ONLY. There is no SMS second factor and there must never be one —
SMS is the factor that gets phished and SIM-swapped, and this account
holds a book of consumers' names, phones and health-insurance interest.

THE SHAPE OF A LOGIN, and why it is this shape:

  password ok + user is enrolled  -> NO session identity is issued. The
      user id is parked in `pending_mfa_user_id` and the browser is sent
      to /mfa/verify. A half-authenticated session therefore has no
      identity at all, and the request guard treats it as logged out.
      Issuing `user_id` first and "remembering to check MFA" in the guard
      is the classic way this feature ships broken.

  password ok + MFA required but NOT enrolled -> the session IS issued,
      and the guard pins them to /mfa/enroll until they finish. This is
      deliberate and it is what keeps enrollment reachable for the first
      admin, who by definition cannot have enrolled yet. They can reach
      nothing else, so the exposure is a user proving a password they
      already proved.

  password ok + MFA not required and not enrolled -> ordinary login.

THE SECRET IS NEVER STORED IN PLAINTEXT. It goes through
`leadflow.crypto` (AES-256-GCM under data/master.key), the same envelope
as every other stored credential. A read failure returns None and the
verification fails closed rather than admitting anyone.

RECOVERY CODES are hashed with the same scrypt KDF as passwords
(`auth.hash_password`), not a bare digest — they are typed by humans into
the same box as a TOTP code and are worth exactly as much as a password.
They are shown ONCE, at enrollment, and cannot be redisplayed; a lost set
is regenerated, which invalidates the old set.

REPLAY: a TOTP code is valid for a whole 30-second step, so the same six
digits work twice unless something remembers. `last_used_step` does.
"""
import base64
import binascii
import hashlib
import io
import logging
import secrets
from typing import Optional

from leadflow import crypto
from leadflow.db import utcnow
from leadflow.branding import PRODUCT_NAME

logger = logging.getLogger("leadflow.mfa")

ISSUER = PRODUCT_NAME

# Roles that must have MFA, always, with no setting able to turn it off.
ALWAYS_REQUIRED_ROLES = ("admin", "superadmin")

# Other roles are opt-in per account. Registered in leadflow/settings.py.
OPTIONAL_ROLE_SETTING = "mfa_required_va"

RECOVERY_CODE_COUNT = 10
RECOVERY_CODE_BYTES = 10          # -> 16 base32 chars, ~80 bits

# One step either side of now, i.e. +/-30s, absorbing ordinary clock drift
# between the phone and this machine without widening the window enough to
# matter.
VALID_WINDOW = 1


class MfaError(RuntimeError):
    """Enrollment or verification could not be completed."""


# ------------------------------------------------------------------ policy

def is_required(db, user):
    # type: (object, object) -> bool
    """Does this user's role require a second factor?

    Fails CLOSED for the always-required roles: if the optional-role
    setting cannot be read we return the safe answer for that role rather
    than letting a settings hiccup drop the requirement.
    """
    role = (user["role"] if not isinstance(user, str) else user) or ""
    if role in ALWAYS_REQUIRED_ROLES:
        return True
    try:
        from leadflow.settings import get_setting
        account_id = None if isinstance(user, str) else user["account_id"]
        return bool(get_setting(OPTIONAL_ROLE_SETTING, db=db,
                                account_id=account_id))
    except Exception:
        logger.exception("could not read %s; treating as not required",
                         OPTIONAL_ROLE_SETTING)
        return False


# ------------------------------------------------------------------ records

def get_record(db, user_id):
    # type: (object, int) -> Optional[dict]
    row = db.execute("SELECT * FROM user_mfa WHERE user_id = ?",
                     (user_id,)).fetchone()
    return dict(row) if row is not None else None


def is_enrolled(db, user_id):
    # type: (object, int) -> bool
    """True only for a CONFIRMED enrollment.

    A row with confirmed_at NULL is an enrollment someone started and
    abandoned. Treating that as enrolled would lock the user out with a
    secret they never scanned.
    """
    row = get_record(db, user_id)
    return bool(row and row["confirmed_at"])


def _secret_of(record):
    # type: (object) -> Optional[str]
    if not record or not record.get("secret"):
        return None
    try:
        return crypto.decrypt(record["secret"])
    except Exception:
        # A secret we cannot decrypt must not authenticate anyone.
        logger.exception("could not decrypt a stored MFA secret")
        return None


# --------------------------------------------------------------- enrollment

def begin_enrollment(db, user_id):
    # type: (object, int) -> str
    """Mint (or replace) an UNCONFIRMED secret and return it in the clear
    for display. Replacing is safe precisely because it is unconfirmed —
    it is the "I closed the tab, let me start again" path. A CONFIRMED
    enrollment is never silently overwritten."""
    import pyotp
    if is_enrolled(db, user_id):
        raise MfaError("this user already has two-factor authentication on")
    secret = pyotp.random_base32()
    with db:
        db.execute(
            "INSERT INTO user_mfa (user_id, secret, confirmed_at, created_at) "
            "VALUES (?,?,NULL,?) "
            "ON CONFLICT(user_id) DO UPDATE SET secret=excluded.secret, "
            "confirmed_at=NULL, created_at=excluded.created_at, "
            "last_used_step=NULL",
            (user_id, crypto.encrypt(secret), utcnow()))
    return secret


def provisioning_uri(secret, username, account_name=None):
    # type: (str, str, object) -> str
    """The otpauth:// URI an authenticator app consumes."""
    import pyotp
    label = username
    if account_name:
        label = "%s (%s)" % (username, account_name)
    return pyotp.TOTP(secret).provisioning_uri(name=label, issuer_name=ISSUER)


def qr_svg(uri):
    # type: (str) -> str
    """The provisioning URI as an inline SVG.

    Inline and locally generated on purpose: rendering it through a
    third-party chart URL — the usual shortcut — would hand the TOTP
    secret to that third party, and CLAUDE.md forbids CDNs anyway.
    Returns "" on failure so a QR problem degrades to the manual
    secret-entry path instead of breaking enrollment.
    """
    try:
        import qrcode
        import qrcode.image.svg
        img = qrcode.make(uri, image_factory=qrcode.image.svg.SvgPathImage)
        buf = io.BytesIO()
        img.save(buf)
        svg = buf.getvalue().decode("utf-8")
        # Strip the XML prolog: this is embedded in an HTML document.
        if svg.startswith("<?xml"):
            svg = svg.split("?>", 1)[1].strip()
        return svg
    except Exception:
        logger.exception("could not render the MFA QR code")
        return ""


def confirm_enrollment(db, user_id, code):
    # type: (object, int, str) -> list
    """Finish enrollment: the code must verify against the pending secret.

    Returns the PLAINTEXT recovery codes, which the caller must show once
    and never store. Only here does an enrollment become real — requiring
    a working code is what proves the user actually scanned the QR, and
    is the difference between MFA and a lockout.
    """
    record = get_record(db, user_id)
    if record is None:
        raise MfaError("start enrollment first")
    if record["confirmed_at"]:
        raise MfaError("this user already has two-factor authentication on")
    secret = _secret_of(record)
    if not secret:
        raise MfaError("the stored secret could not be read; start again")
    if not _totp_matches(secret, code):
        raise MfaError("that code is not right. Check your authenticator "
                       "app and try the current code.")

    codes = [_new_recovery_code() for _ in range(RECOVERY_CODE_COUNT)]
    now = utcnow()
    from leadflow.auth import hash_password
    with db:
        db.execute("UPDATE user_mfa SET confirmed_at = ?, "
                   "last_used_step = ? WHERE user_id = ?",
                   (now, _step_of(code, secret), user_id))
        db.execute("DELETE FROM mfa_recovery_codes WHERE user_id = ?",
                   (user_id,))
        for c in codes:
            db.execute(
                "INSERT INTO mfa_recovery_codes (user_id, code_hash, "
                "created_at) VALUES (?,?,?)",
                (user_id, hash_password(_normalize(c)), now))
    logger.info("MFA enrolled for user %s", user_id)
    return codes


def regenerate_recovery_codes(db, user_id):
    # type: (object, int) -> list
    """Replace the whole set. The old codes stop working immediately —
    that is the point when a printed sheet goes missing."""
    if not is_enrolled(db, user_id):
        raise MfaError("two-factor authentication is not on for this user")
    from leadflow.auth import hash_password
    codes = [_new_recovery_code() for _ in range(RECOVERY_CODE_COUNT)]
    now = utcnow()
    with db:
        db.execute("DELETE FROM mfa_recovery_codes WHERE user_id = ?",
                   (user_id,))
        for c in codes:
            db.execute(
                "INSERT INTO mfa_recovery_codes (user_id, code_hash, "
                "created_at) VALUES (?,?,?)",
                (user_id, hash_password(_normalize(c)), now))
    logger.info("MFA recovery codes regenerated for user %s", user_id)
    return codes


def disable(db, user_id):
    # type: (object, int) -> None
    """Turn MFA off and destroy the secret and every recovery code."""
    with db:
        db.execute("DELETE FROM mfa_recovery_codes WHERE user_id = ?",
                   (user_id,))
        db.execute("DELETE FROM user_mfa WHERE user_id = ?", (user_id,))
    logger.info("MFA disabled for user %s", user_id)


def recovery_codes_remaining(db, user_id):
    # type: (object, int) -> int
    return db.execute(
        "SELECT COUNT(*) AS n FROM mfa_recovery_codes "
        "WHERE user_id = ? AND used_at IS NULL", (user_id,)).fetchone()["n"]


# -------------------------------------------------------------- verification

def _normalize(code):
    # type: (str) -> str
    """Strip the spaces and dashes people type, and upper-case.

    Authenticator apps show '123 456' and recovery codes are printed with
    a dash; refusing those is a support ticket, not security.
    """
    return "".join((code or "").split()).replace("-", "").upper()


def _step_of(code, secret):
    # type: (str, str) -> Optional[int]
    """Which 30-second step a matching code belongs to (for replay)."""
    import time
    import pyotp
    totp = pyotp.TOTP(secret)
    now = int(time.time())
    for offset in range(-VALID_WINDOW, VALID_WINDOW + 1):
        at = now + offset * totp.interval
        if secrets.compare_digest(totp.at(at), _normalize(code)):
            return at // totp.interval
    return None


def _totp_matches(secret, code):
    # type: (str, str) -> bool
    import pyotp
    cleaned = _normalize(code)
    if not cleaned.isdigit():
        return False
    try:
        return bool(pyotp.TOTP(secret).verify(cleaned,
                                              valid_window=VALID_WINDOW))
    except Exception:
        logger.exception("TOTP verification blew up; refusing")
        return False


def _new_recovery_code():
    # type: () -> str
    """A single high-entropy code, hyphenated for legibility."""
    raw = base64.b32encode(secrets.token_bytes(RECOVERY_CODE_BYTES))
    text = raw.decode("ascii").rstrip("=")
    return "-".join([text[:4], text[4:8], text[8:12], text[12:16]])


def _consume_recovery_code(db, user_id, code):
    # type: (object, int, str) -> bool
    """Spend a recovery code. ONE USE, enforced by the used_at stamp
    written in the same transaction that accepts it."""
    from leadflow.auth import verify_password
    cleaned = _normalize(code)
    rows = db.execute(
        "SELECT id, code_hash FROM mfa_recovery_codes "
        "WHERE user_id = ? AND used_at IS NULL ORDER BY id", (user_id,)
    ).fetchall()
    for row in rows:
        if verify_password(cleaned, row["code_hash"]):
            with db:
                spent = db.execute(
                    "UPDATE mfa_recovery_codes SET used_at = ? "
                    "WHERE id = ? AND used_at IS NULL",
                    (utcnow(), row["id"])).rowcount
            if spent:
                logger.info("MFA recovery code used by user %s", user_id)
                return True
            return False    # raced: someone else spent it first
    return False


def verify(db, user_id, code, on_recovery=None):
    # type: (object, int, str, object) -> bool
    """Accept a TOTP code or a recovery code. Fails closed throughout.

    A TOTP code is refused when it belongs to a step already used, so the
    same six digits cannot be replayed inside their 30-second life.

    `on_recovery` is called with the number of codes still unspent when a
    RECOVERY code is what succeeded — bypassing TOTP is the event worth
    auditing, and only this function knows which factor answered. It is a
    callback rather than a richer return value because the bool is what
    every caller and test already depends on, and rather than an audit
    call inside this module because mfa.verify is also reachable outside
    a request, where there is no actor and no IP to record.
    """
    if not code or not str(code).strip():
        return False
    record = get_record(db, user_id)
    if not record or not record["confirmed_at"]:
        return False
    secret = _secret_of(record)
    if secret and _totp_matches(secret, code):
        step = _step_of(code, secret)
        if step is not None and record["last_used_step"] is not None \
                and int(record["last_used_step"]) >= int(step):
            logger.warning("replayed TOTP code refused for user %s", user_id)
            return False
        with db:
            db.execute("UPDATE user_mfa SET last_used_step = ? "
                       "WHERE user_id = ?", (step, user_id))
        return True
    if _consume_recovery_code(db, user_id, code):
        if on_recovery is not None:
            try:
                on_recovery(recovery_codes_remaining(db, user_id))
            except Exception:
                # An audit hook must never turn a valid second factor into
                # a failed login.
                logger.exception("the recovery-code callback failed")
        return True
    return False
