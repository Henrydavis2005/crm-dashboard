"""User auth: scrypt hashing, username+password login, two roles (admin|va),
request guard with VA route allowlist + the S1 attestation gate, public
/signup, account scoping helpers (current_account_id / account_scope)."""
import contextlib
import hmac
import logging
import os
import re
import threading
import time
from typing import Optional

from flask import (
    Blueprint, abort, flash, g, redirect, render_template, request, session,
    url_for,
)

from leadflow import acceptance, accounts, entitlements, mfa
from leadflow.db import get_db, utcnow
from leadflow.urls import safe_next
from leadflow.branding import PRODUCT_NAME

logger = logging.getLogger("leadflow.auth")

bp = Blueprint("auth", __name__)

_SCRYPT_N = 16384
_SCRYPT_R = 8
_SCRYPT_P = 1
_SCRYPT_DKLEN = 64

try:
    # hashlib.scrypt is missing on OpenSSL/LibreSSL builds without scrypt
    # support (e.g. macOS system Python); fall back to the cryptography
    # package's implementation of the same KDF (identical output).
    from hashlib import scrypt as _hashlib_scrypt

    def _scrypt(password, salt, n=_SCRYPT_N, r=_SCRYPT_R, p=_SCRYPT_P):
        # type: (bytes, bytes, int, int, int) -> bytes
        return _hashlib_scrypt(password, salt=salt, n=n, r=r, p=p,
                               dklen=_SCRYPT_DKLEN, maxmem=68 * 1024 * 1024)
except ImportError:  # pragma: no cover - depends on the interpreter build
    from cryptography.hazmat.primitives.kdf.scrypt import Scrypt as _Scrypt

    def _scrypt(password, salt, n=_SCRYPT_N, r=_SCRYPT_R, p=_SCRYPT_P):
        # type: (bytes, bytes, int, int, int) -> bytes
        return _Scrypt(salt=salt, length=_SCRYPT_DKLEN, n=n, r=r, p=p).derive(password)

MAX_FAILURES = 5
LOCK_SECONDS = 60

# in-memory login rate limiting: username -> {"failures": int, "locked_until": float}
_rate = {}

EXEMPT_PATHS = ("/login", "/setup", "/signup", "/healthz",
                # What the proxy chain sent, for reading while the HTTPS
                # redirect is looping. Nothing in it is ours or secret;
                # see routes_public.healthz_proxy.
                "/healthz/proxy",
                # PART 12: reachable with only a PARKED mfa id, i.e.
                # before any session identity exists.
                "/mfa/verify")
EXEMPT_PREFIXES = ("/u/", "/static/",
                   # PART 12 Step 4: the legal documents are readable by
                   # anyone. Requiring a login to read the terms you are
                   # being asked to accept at signup is circular, and
                   # these are published documents — there is nothing in
                   # them to protect.
                   "/legal/")

# PART 12 Step 5 account gate: a user whose ACCOUNT may not operate —
# awaiting approval or rejected — reaches ONLY these. /logout
# for the same reason it is in every other gate's list: a gate with no way
# out is a lockout.
ACCOUNT_GATE_ALLOWED_PATHS = ("/account-status", "/logout")

# PART 12 Step 4 document gate: a user who owes an acceptance of the
# current ToS or DPA reaches ONLY these until they accept. /logout is in
# the list for the same reason it is in the MFA list — a gate with no way
# out is a lockout.
ACCEPT_ALLOWED_PATHS = ("/accept", "/logout")

# PART 12 Step 9 agreement gate: an account with an unaccepted ACTIVE
# legal document reaches ONLY these. /legal/ is already public so the
# document itself is always readable, and /drafts/ has to stay open or
# the form loses what the user typed while sitting on the gate.
AGREEMENT_ALLOWED_PATHS = ("/agreement", "/logout")
AGREEMENT_ALLOWED_PREFIXES = ("/legal/", "/drafts/")

# BLOCK 1 STEP C: the BILLING PAUSE gate that used to sit here is GONE
# along with billing itself. B3 then removed suspension too, so there is
# no freeze at all: an account is pending, active, rejected or deleted,
# and the ACCOUNT STATUS gate two rungs ABOVE where this one stood is
# what refuses the first two — see `ACCOUNT_GATE_ALLOWED_PATHS` and
# `/account-status`. A second rung
# checking the same fact would be unreachable: the status gate lets
# `/account-status` through, so a duplicate check below it would redirect
# that page to itself.

# PART 12 MFA gate: a user who MUST enroll and has not reaches ONLY
# these. /logout is in the list on purpose — a gate with no way out is
# a lockout, and the first admin hits this gate before anyone has
# enrolled at all.
MFA_ENROLL_ALLOWED_PATHS = ("/mfa/enroll", "/mfa/recovery-codes",
                            "/logout")

# DIALER BLOCK 3: every route that can place a telephone call.
#
# The ONE enforcement point. A path matching this table is refused unless
# the session is a VA SEAT on an account with VA access — which means an
# admin cannot dial, the owner cannot dial, and a superadmin cannot dial,
# on any plan, ever. Dialing is the seat's capability, not the account's
# entitlement, and the entitlement is the same `entitlements.va_access`
# every other VA surface uses rather than a second flag that can drift.
#
# It is DATA and it is enumerated against the URL map:
# tests/test_dial_gate.py walks `app.url_map`, asserts every rule in the
# dial blueprint is matched here and that nothing else is, then drives
# each one as anonymous / admin / superadmin / unentitled VA and requires
# a refusal from all four. That test REPLACED tests/test_no_dial_path.py.
DIAL_ROUTES = [
    ("POST", re.compile(r"^/today/work/\d+/call$")),
]


def is_dial_route(method, path):
    # type: (str, str) -> bool
    for dial_method, pattern in DIAL_ROUTES:
        if method == dial_method and pattern.match(path):
            return True
    return False


_USERNAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.\-]{0,31}$")

# B3: signup asks for an email address and that address IS the login. The
# pattern is deliberately loose — one @, something either side, a dot in
# the domain, no spaces. A stricter regex rejects addresses that are valid
# (plus-tags, long TLDs, unusual local parts), and the only way to know an
# address really works is to send to it, which signup does not do.
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
EMAIL_MAX_LENGTH = 254

# --- VA route allowlist (SPEC B3) ------------------------------------------
# A VA session may reach ONLY these (method, path-regex) pairs; everything
# else renders the 403 page. This is DATA: later batches (B4/B5) append their
# call-log / callback / appointment POST endpoints here as they are built.
VA_ALLOWED = [
    ("GET", re.compile(r"^/today$")),
    ("GET", re.compile(r"^/leads/\d+$")),
    ("GET", re.compile(r"^/logout$")),
    ("POST", re.compile(r"^/logout$")),
    # PART 12 Step 4: the document gate blocks a VA exactly like anyone
    # else, and the gate runs BEFORE this allowlist — so leaving /accept
    # out would redirect every VA to a page that then 403s them. A gate
    # whose own page is forbidden is a lockout, not a gate.
    ("GET", re.compile(r"^/accept$")),
    ("POST", re.compile(r"^/accept$")),
    # PART 12 Step 9: same reasoning as /accept — the agreement gate runs
    # BEFORE this allowlist, so leaving its own page out would redirect
    # every VA into a 403.
    ("GET", re.compile(r"^/agreement$")),
    ("POST", re.compile(r"^/agreement$")),
    ("POST", re.compile(r"^/drafts/")),
    # PART 12 Step 5: same reasoning as /accept above. The ACCOUNT gate
    # also runs before this allowlist, so a VA on an account that may
    # not operate would be redirected to a page that then 403s them.
    ("GET", re.compile(r"^/account-status$")),
    # B4: call logging + appointments (Sold/Dead/Reopen stay admin-only).
    ("POST", re.compile(r"^/leads/\d+/call-log$")),
    ("POST", re.compile(r"^/leads/\d+/appointments$")),
    ("POST", re.compile(r"^/leads/\d+/appointments/\d+/outcome$")),
    # B9: THE SETTING SIDE MUST SEE ITS OWN SPLITS. "Both sides see the
    # row" is the block's requirement, and the setter is frequently a
    # `role='va'` seat — so without these three a VA could set every
    # appointment on the team and never see what any of them earned.
    #
    # READ ONLY, and that asymmetry is the point. Running, closing and
    # marking paid are the CLOSER's actions and stay off this list, so a
    # VA can see the money and cannot write it. Safe to expose because
    # `appointments.describe` is the only renderer and it returns a lead
    # REFERENCE, never a client name — a VA seat reading the team
    # calendar learns what it set and earned, and nothing about whose
    # client it was.
    ("GET", re.compile(r"^/appointments$")),
    ("GET", re.compile(r"^/appointments/team$")),
    ("GET", re.compile(r"^/appointments/mine$")),
    # R5: scripts console for today's queued leads (the log-call POST it
    # embeds is already allowed above).
    ("GET", re.compile(r"^/today/work/\d+$")),
    ("POST", re.compile(r"^/today/work/\d+/regenerate$")),
    # DIALER BLOCK 3: click-to-call. Listed here so a VA SESSION may reach
    # it at all; DIAL_ROUTES is what makes it VA-ONLY. Two tables doing
    # two different jobs — this one answers "may a VA touch this", that
    # one answers "may anyone else".
    ("POST", re.compile(r"^/today/work/\d+/call$")),
    # S7: the VA's own pay statement (the route pins VAs to themselves).
    ("GET", re.compile(r"^/pay/statement$")),
    # B10: the same statement as a PDF. A SEPARATE ENTRY because the
    # pattern above is anchored — `^/pay/statement$` does not match
    # `/pay/statement.pdf`, so without this a VA would 403 downloading
    # their own pay. `statements.may_read` is what decides WHOSE
    # statement; this only decides that a VA session may reach the route.
    ("GET", re.compile(r"^/pay/statement\.pdf$")),
    # Overflow pool: the VA works pool rows in the same day's queue, so
    # the console and its disposition POST are theirs. NOTHING ELSE about
    # the pool is: /overflow (upload, the pool list, the drop history) is
    # the account user's own tool and stays admin-only by omission.
    ("GET", re.compile(r"^/today/overflow/\d+$")),
    ("POST", re.compile(r"^/today/overflow/\d+/disposition$")),
]


def va_can_access(method, path):
    # type: (str, str) -> bool
    for allowed_method, pattern in VA_ALLOWED:
        if method == allowed_method and pattern.match(path):
            return True
    return False


# --- VA entitlement: the routing-layer gate --------------------------------
# Whole surfaces a NON-ENTITLED account may not reach. This is the ONE place
# the entitlement refuses a route; see leadflow/entitlements.py for what the
# the two plan flags mean and why access is the AND of them.
#
# BLOCKLIST, not an allowlist — the opposite shape to VA_ALLOWED above, on
# purpose. A VA is an untrusted session, so anything not named there is
# refused. A solo agent is a fully trusted account holder who is missing ONE
# product surface, so a new non-VA feature must NOT become invisible to them
# because somebody forgot to add it to a list. The drift risk that creates —
# a new VA route nobody adds HERE — is covered by a test that walks
# VA_ALLOWED and fails unless every entry is either gated below or named in
# VA_SHARED, so the two tables cannot silently disagree.
VA_GATED = [
    # B9: THE APPOINTMENT TRACKER IS A VA-PLAN SURFACE. Its whole subject
    # is the split between whoever SET an appointment and whoever CLOSED
    # it — which is the VA arrangement. A no-code account has no setter,
    # so it has no split, and the three pages would show it a rate
    # control for an arrangement it does not have.
    #
    # Both the write routes and the read routes are here: gating the
    # reads and leaving the writes open would let a non-entitled account
    # record splits it can never see.
    ("GET", re.compile(r"^/appointments$")),
    ("GET", re.compile(r"^/appointments/team$")),
    ("GET", re.compile(r"^/appointments/mine$")),
    ("POST", re.compile(r"^/appointments/")),
    # VA pay: the admin's per-VA pay view, and the VA's own statement.
    ("GET", re.compile(r"^/pay$")),
    ("GET", re.compile(r"^/pay/statement$")),
    # B10: the same statement as a PDF. A SEPARATE ENTRY because the
    # pattern above is anchored — `^/pay/statement$` does not match
    # `/pay/statement.pdf`, so without this a VA would 403 downloading
    # their own pay. `statements.may_read` is what decides WHOSE
    # statement; this only decides that a VA session may reach the route.
    ("GET", re.compile(r"^/pay/statement\.pdf$")),
    # VA profitability (ramp, cost per VA, the calling panel).
    ("GET", re.compile(r"^/profit$")),
    # The R5 scripts console — a script for a lead in TODAY'S QUEUE, which
    # a non-entitled account never has.
    ("GET", re.compile(r"^/today/work/\d+$")),
    ("POST", re.compile(r"^/today/work/\d+/regenerate$")),
    # The overflow pool exists only to backfill an empty VA QUEUE. No
    # queue, no pool: the console, the upload and the pool list all go.
    ("GET", re.compile(r"^/today/overflow/\d+$")),
    ("POST", re.compile(r"^/today/overflow/\d+/disposition$")),
    # DIALER BLOCK 3: click-to-call is a VA surface, so a non-entitled
    # account may not reach it. DIAL_ROUTES makes it VA-SEAT-only on top
    # of this; both are checked and neither is the other's backup.
    ("POST", re.compile(r"^/today/work/\d+/call$")),
    ("GET", re.compile(r"^/overflow")),
    ("POST", re.compile(r"^/overflow")),
    # Creating a VA login. This route hardcodes role='va' — it makes
    # nothing else — so gating it here costs a no-code account nothing and
    # keeps the check out of the handler.
    ("POST", re.compile(r"^/settings/users/add$")),
]

# VA_ALLOWED entries that are NOT VA surfaces — routes a VA may reach that
# a solo agent uses too, so the entitlement must leave them alone.
#
# /today is the one that matters and it is an EXPLICIT EXCEPTION, not an
# oversight: for an admin that page renders open tasks, appointment
# confirmations due and outcomes due — the agent's own daily work, none of
# it VA-related. Its VA half already sits behind `va_active`, which an
# ineligible account can never turn on, so the page is clean without any
# check here. DO NOT "fix" this into a block; doing so takes a solo agent's
# own task list away from them.
#
# The rest are the shared lead surfaces the pre-check proved a no-VA account
# already works end to end through: lead detail, call logging, appointments.
VA_SHARED = [
    ("GET", re.compile(r"^/today$")),
    ("GET", re.compile(r"^/leads/\d+$")),
    ("GET", re.compile(r"^/logout$")),
    ("POST", re.compile(r"^/logout$")),
    # Accepting the ToS/DPA is nobody's product surface — every user of
    # every account owes it, entitled or not. Same for being told why
    # your account cannot be used.
    ("GET", re.compile(r"^/accept$")),
    ("POST", re.compile(r"^/accept$")),
    ("GET", re.compile(r"^/agreement$")),
    ("POST", re.compile(r"^/agreement$")),
    ("POST", re.compile(r"^/drafts/")),
    ("GET", re.compile(r"^/account-status$")),
    ("POST", re.compile(r"^/leads/\d+/call-log$")),
    ("POST", re.compile(r"^/leads/\d+/appointments$")),
    ("POST", re.compile(r"^/leads/\d+/appointments/\d+/outcome$")),
]


def va_surface(method, path):
    # type: (str, str) -> bool
    """True when (method, path) is a VA-only surface — the routing-layer
    entitlement question."""
    for gated_method, pattern in VA_GATED:
        if method == gated_method and pattern.match(path):
            return True
    return False


def hash_password(password):
    # type: (str) -> str
    salt = os.urandom(16)
    digest = _scrypt(password.encode("utf-8"), salt)
    return "scrypt$%d$%d$%d$%s$%s" % (
        _SCRYPT_N, _SCRYPT_R, _SCRYPT_P, salt.hex(), digest.hex()
    )


def verify_password(password, stored):
    # type: (str, Optional[str]) -> bool
    if not stored:
        return False
    try:
        scheme, n, r, p, salt_hex, digest_hex = stored.split("$")
        if scheme != "scrypt":
            return False
        digest = _scrypt(password.encode("utf-8"), bytes.fromhex(salt_hex),
                         n=int(n), r=int(r), p=int(p))
        return hmac.compare_digest(digest.hex(), digest_hex)
    except (ValueError, TypeError):
        return False


# --- users table helpers ---------------------------------------------------

def has_users(db=None):
    # type: (object) -> bool
    if db is None:
        db = get_db()
    return db.execute("SELECT 1 FROM users LIMIT 1").fetchone() is not None


def get_user(db, user_id):
    # type: (object, Optional[int]) -> Optional[object]
    if not user_id:
        return None
    return db.execute(
        "SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()


def get_user_by_username(db, username):
    # type: (object, str) -> Optional[object]
    return db.execute(
        "SELECT * FROM users WHERE username = ? COLLATE NOCASE",
        ((username or "").strip(),)).fetchone()


def valid_username(username):
    # type: (str) -> bool
    return bool(_USERNAME_RE.match(username or ""))


def valid_email(address):
    # type: (str) -> bool
    """B3: good enough to be a login, not a claim that mail will arrive."""
    address = (address or "").strip()
    return (len(address) <= EMAIL_MAX_LENGTH
            and bool(_EMAIL_RE.match(address)))


def create_user(db, username, password=None, role="admin", account_id=1,
                password_hash=None, email=None):
    # type: (object, str, Optional[str], str, int, Optional[str], Optional[str]) -> int
    """Insert a user; pass password (hashed here) or a ready password_hash.
    Commits unless the caller already holds a transaction.

    `email` is B3's addition and stays OPTIONAL: assistant seats are
    created by a tenant with a username and no address, and inventing one
    for them would put a fake address in the column B10 mails statements
    to."""
    if password_hash is None:
        password_hash = hash_password(password or "")
    own = not db.in_transaction
    cur = db.execute(
        "INSERT INTO users (account_id, username, role, password_hash, "
        "email, enabled, created_at) VALUES (?,?,?,?,?,1,?)",
        (account_id, (username or "").strip(), role, password_hash,
         (email or "").strip() or None, utcnow()),
    )
    if own:
        db.commit()
    return cur.lastrowid


# S1: per-thread account override for background work (the worker wraps
# every per-tenant job in account_scope so deep helpers — settings,
# suppression, compliance, caps — resolve the right tenant without
# threading a parameter through every call).
_account_ctx = threading.local()


@contextlib.contextmanager
def account_scope(account_id):
    """Run a block under an explicit account (worker per-tenant jobs)."""
    prev = getattr(_account_ctx, "account_id", None)
    _account_ctx.account_id = int(account_id)
    try:
        yield
    finally:
        _account_ctx.account_id = prev


def current_account_id():
    # type: () -> int
    """Account scope for the current call: the logged-in user's account
    inside a request, else the account_scope() override (worker per-tenant
    jobs), else 1 (first boot / single-tenant scripts)."""
    try:
        user = getattr(g, "user", None)
    except RuntimeError:  # outside app/request context (worker thread)
        user = None
    if user:
        return int(user["account_id"])
    override = getattr(_account_ctx, "account_id", None)
    if override is not None:
        return int(override)
    return 1


def is_superadmin(user):
    # type: (object) -> bool
    """The platform operator. Its OWN flag on the USER row, deliberately
    not a role and deliberately not "is this account 1".

    Not a role, because `role` already drives VA_ALLOWED and a dozen
    `role == 'admin'` checks; adding a third value would have silently
    dropped the operator out of every one of them. Not an account check,
    because an assistant login created under the operator's own account is
    still an assistant — the account is not the person.

    Tolerates a row that predates the column so a stale session cannot
    500 the guard."""
    if not user:
        return False
    try:
        return bool(user["is_superadmin"])
    except (KeyError, IndexError, TypeError):
        return False


def get_account(db, account_id):
    return db.execute("SELECT * FROM accounts WHERE id = ?",
                      (account_id,)).fetchone()


def account_pending(db, account_id):
    # type: (object, int) -> bool
    """True when the account may NOT use the app — awaiting approval or
    rejected.

    Kept as a name because templates and older call sites read well with
    it, but it no longer holds an opinion of its own: leadflow/accounts.py
    owns the state machine and the fail-closed default. It used to answer
    "has the attestation been signed" and to read a missing row as ACTIVE,
    which is the wrong way to fail for a gate that now stands in front of
    sending."""
    return not accounts.is_active(db, account_id)


def _home_path(user):
    return "/today" if user and user["role"] == "va" else "/"


# --- login rate limiting (per-username) ------------------------------------

def _rate_key(username):
    return (username or "").strip().lower() or "(blank)"


def _lock_remaining(username):
    # type: (str) -> int
    entry = _rate.get(_rate_key(username))
    if not entry:
        return 0
    remaining = int(entry.get("locked_until", 0) - time.time())
    return remaining if remaining > 0 else 0


def _record_failure(username):
    entry = _rate.setdefault(_rate_key(username),
                             {"failures": 0, "locked_until": 0.0})
    entry["failures"] += 1
    if entry["failures"] >= MAX_FAILURES:
        entry["locked_until"] = time.time() + LOCK_SECONDS
        entry["failures"] = 0
        logger.warning("login locked for %ss: user %r", LOCK_SECONDS, username)


def _clear_failures(username):
    _rate.pop(_rate_key(username), None)


# --- signup rate limiting (per client IP, rolling hour) ---------------------

SIGNUP_MAX_PER_HOUR = 5
SIGNUP_WINDOW_SECONDS = 3600

# in-memory signup rate limiting: client ip -> [signup unix timestamps]
_signup_hits = {}


def _signup_ip():
    return (request.remote_addr or "").strip() or "(unknown)"


def _signup_allowed(ip):
    # type: (str) -> bool
    """True while the ip has fewer than SIGNUP_MAX_PER_HOUR successful
    signups inside the rolling window (same in-memory pattern as the
    login limiter)."""
    now = time.time()
    hits = [t for t in _signup_hits.get(ip, ())
            if now - t < SIGNUP_WINDOW_SECONDS]
    _signup_hits[ip] = hits
    return len(hits) < SIGNUP_MAX_PER_HOUR


def _record_signup(ip):
    _signup_hits.setdefault(ip, []).append(time.time())


def reset_rate_limit():
    """Testing helper: clear all in-memory rate-limit state (login +
    signup)."""
    _rate.clear()
    _signup_hits.clear()


def get_secret_key():
    # type: () -> bytes
    """Flask session secret from data/secret_key, generated at first boot."""
    from leadflow.db import data_dir
    path = data_dir() / "secret_key"
    if path.exists():
        with open(str(path), "rb") as f:
            return f.read()
    path.parent.mkdir(parents=True, exist_ok=True)
    key = os.urandom(32)
    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.write(fd, key)
    finally:
        os.close(fd)
    logger.info("generated new session secret key at %s", path)
    return key


# --- routes ----------------------------------------------------------------

def _auth_event(db, user, etype, detail=None):
    """Record a sign-in event against the user's OWN account.

    Scoped explicitly because there is no g.user yet at login time, and
    current_account_id() would fall back to account 1 — filing one
    tenant's sign-ins on another tenant's audit log.

    THE CALLER'S IP IS RECORDED. These are the events where "from where"
    is the whole point; a failed-login trail without it says almost
    nothing. It is the same thing already captured on document
    acceptances. If that is more than you want kept, this is the one
    place to change.

    NOTHING IS LOGGED FOR AN UNKNOWN USERNAME. /login is public and
    unauthenticated, so writing a row per attempt would let anyone fill
    this table — and an attempt on a username that does not exist belongs
    to no tenant, so there is no honest account to file it under. Those
    still reach the application log via the rate limiter.
    """
    if user is None:
        return None
    from leadflow.audit import log_event
    ip = (request.remote_addr or "").strip() or "(unknown)"
    parts = ["ip=%s" % ip]
    if detail:
        parts.append(detail)
    try:
        with account_scope(user["account_id"]):
            return log_event(db, None, etype, " ".join(parts),
                             user_id=user["id"])
    except Exception:
        logger.exception("could not record the %s event", etype)
        return None


@bp.route("/login", methods=["GET", "POST"])
def login():
    db = get_db()
    if not has_users(db):
        return redirect(url_for("auth.setup"))
    current = get_user(db, session.get("user_id"))
    if current is not None and current["enabled"]:
        return redirect(_home_path(current))
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        remaining = _lock_remaining(username)
        if remaining:
            _auth_event(db, get_user_by_username(db, username),
                        "login_locked", "locked for %ds" % remaining)
            flash("Too many attempts. Try again in %ds." % remaining, "error")
            return render_template("login.html"), 429
        password = request.form.get("password", "")
        user = get_user_by_username(db, username)
        if (user is not None and user["enabled"]
                and verify_password(password, user["password_hash"])):
            if user["role"] == "va" and not entitlements.va_access(
                    db, user["account_id"]):
                # SPEC B5, PART 13: VA logins are rejected unless the
                # account is BOTH eligible and active. Losing either one
                # closes the login, which is what makes a downgrade take
                # the assistants with it without deleting a single row.
                _clear_failures(username)
                _auth_event(db, user, "login_failed",
                            "correct password, refused: VA assistant is off")
                flash("VA assistant is disabled. Ask your admin.", "error")
                return render_template("login.html"), 403
            _clear_failures(username)
            session.clear()
            # PART 12: an ENROLLED user gets NO session identity here. The
            # id is parked and /mfa/verify issues `user_id` only after the
            # second factor lands, so a half-authenticated session cannot
            # reach anything even if a later guard check were missed.
            if mfa.is_enrolled(db, user["id"]):
                session["pending_mfa_user_id"] = user["id"]
                session["pending_mfa_next"] = request.args.get("next") or ""
                session.permanent = True
                # Not "login" yet: this session still has no identity.
                _auth_event(db, user, "login",
                            "password accepted, awaiting second factor")
                return redirect(url_for("auth.mfa_verify"))
            session["user_id"] = user["id"]
            session.permanent = True
            _auth_event(db, user, "login", "no second factor required")
            home = _home_path(user)
            return redirect(safe_next(request.args.get("next") or home,
                                      home))
        _record_failure(username)
        _auth_event(db, user, "login_failed", "wrong password")
        flash("Incorrect username or password.", "error")
        return render_template("login.html"), 401
    return render_template("login.html")


@bp.route("/setup", methods=["GET", "POST"])
def setup():
    db = get_db()
    if has_users(db):
        return redirect(url_for("auth.login"))
    if request.method == "POST":
        username = request.form.get("username", "").strip() or "admin"
        password = request.form.get("password", "")
        confirm = request.form.get("confirm", "")
        if not valid_username(username):
            flash("Username may only contain letters, numbers, dots, dashes "
                  "and underscores (max 32 characters).", "error")
            return render_template("setup.html"), 400
        if len(password) < 8:
            flash("Password must be at least 8 characters.", "error")
            return render_template("setup.html"), 400
        if password != confirm:
            flash("Passwords do not match.", "error")
            return render_template("setup.html"), 400
        user_id = create_user(db, username, password, role="admin")
        # PART 13: /setup runs exactly once, on an empty install, and the
        # user it creates IS the platform operator — there is nobody else
        # to grant the flag, and without it the superadmin console would be
        # unreachable on a fresh database. This is the ONLY place the app
        # writes is_superadmin; every other user, including one created
        # under this same account, takes the column default of 0.
        db.execute("UPDATE users SET is_superadmin = 1 WHERE id = ?",
                   (user_id,))
        db.commit()
        session.clear()
        session["user_id"] = user_id
        session.permanent = True
        flash("Admin account created. Welcome to %s." % PRODUCT_NAME,
              "success")
        return redirect("/")
    return render_template("setup.html")


@bp.route("/legal/<kind>")
def document_text(kind):
    """Read a legal document. PUBLIC on purpose — you cannot meaningfully
    accept the terms at signup if reading them requires the account the
    terms are for. /legal/ is in EXEMPT_PREFIXES for that reason.
    `kind` is validated against DOCUMENT_TYPES inside acceptance.document,
    so it can never reach the filesystem as a path fragment."""
    try:
        doc = acceptance.document(kind)
    except (acceptance.UnknownDocument, OSError, ValueError):
        abort(404)
    return render_template("legal_document.html", doc=doc)


def _signup_documents():
    """Every document the signup form must show, as Document tuples — the
    two per-user ones and the account-holder attestation, which PART 12
    Step 5 moved into signup. A document that will not load raises here
    rather than rendering a form whose checkbox agrees to nothing."""
    return [acceptance.document(kind) for kind in
            acceptance.PER_USER_DOCUMENTS + (acceptance.ACCOUNT_DOCUMENT,)]


def _document_list(kinds):
    """'Terms of Service and the Data Processing Addendum' — titles, not
    slugs, because this goes in front of a person."""
    titles = []
    for kind in kinds:
        try:
            titles.append(acceptance.document(kind).title)
        except Exception:
            titles.append(kind)
    if len(titles) < 2:
        return "".join(titles)
    return "%s and the %s" % (", ".join(titles[:-1]), titles[-1])


@bp.route("/signup", methods=["GET", "POST"])
def signup():
    """S1 + PART 12 Steps 4-5 + B3: public tenant signup.

    THREE FIELDS: name, email, password. B3 cut it to that. The email IS
    the login — it goes in `users.username` (the login handle, globally
    unique and case-insensitive) AND in `users.email` (what B10 mails a
    statement to), because asking somebody to invent a username and then
    remember which of two strings they log in with is a support ticket
    waiting to happen. The name becomes the account name and signs the
    attestation: one person, one name, typed once.

    NOTHING ELSE IS ASKED. No agency name, no plan, no licence — the
    operator approves the account and everything else is collected later
    by the person who needs it. An applicant cannot self-select anything
    that grants access.

    The attestation still blocks. It is a document the account holder
    agrees to, not a field they fill in, and dropping it would have been a
    legal regression dressed as a simplification.

    Order: credentials, then the documents, then a PENDING account + its
    admin user + the account's seeded defaults — every one of them in a
    single transaction, so no account exists that has not agreed to
    everything. The admin is logged in and the guard routes them to
    /account-status, where they wait for approval. /setup remains the
    first-boot bootstrap for account 1 only.
    """
    db = get_db()
    if request.method == "POST":
        ip = _signup_ip()
        if not _signup_allowed(ip):
            flash("Too many signups from this address — try again later.",
                  "error")
            return render_template("signup.html", form=request.form,
                                   documents=_signup_documents()), 429
        full_name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "")
        confirm = request.form.get("confirm", "")
        # The account is named after the person who signed up. There is no
        # separate agency field: an applicant naming their agency told the
        # operator nothing they could verify, and a team is an assignment
        # made here (leadflow/team.py), never a string a stranger typed.
        account_name = full_name
        username = email
        if not full_name:
            flash("Enter your full name.", "error")
            return render_template("signup.html", form=request.form,
                                   documents=_signup_documents()), 400
        if not valid_email(email):
            flash("Enter a valid email address — it will be your login.",
                  "error")
            return render_template("signup.html", form=request.form,
                                   documents=_signup_documents()), 400
        if get_user_by_username(db, username) is not None:
            # Logins are globally unique (COLLATE NOCASE).
            flash("An account already exists for that email address.",
                  "error")
            return render_template("signup.html", form=request.form,
                                   documents=_signup_documents()), 400
        if len(password) < 8:
            flash("Password must be at least 8 characters.", "error")
            return render_template("signup.html", form=request.form,
                                   documents=_signup_documents()), 400
        if password != confirm:
            flash("Passwords do not match.", "error")
            return render_template("signup.html", form=request.form,
                                   documents=_signup_documents()), 400
        # PART 12 Step 4: the ToS and the DPA are BLOCKING and are checked
        # HERE — above the INSERT, not after it — so a refusal leaves no
        # account behind. Each box is its own answer: they are separate
        # documents, neither is pre-checked, and agreeing to one is not
        # agreeing to the other. The acceptance rows go in the SAME
        # transaction as the account, so there is no instant at which an
        # account exists without them.
        # PER_USER_DOCUMENTS is EMPTY since Step 9 — the CSA in the
        # registry supersedes the tos/dpa files and is gated after login,
        # not at signup. The loop is kept rather than deleted so that
        # re-populating the tuple restores signup-time blocking with no
        # other change.
        missing = [kind for kind in acceptance.PER_USER_DOCUMENTS
                   if not request.form.get("accept_%s" % kind)]
        if missing:
            flash("You must accept the %s to create an account."
                  % _document_list(missing), "error")
            return render_template("signup.html", form=request.form,
                                   documents=_signup_documents()), 400
        # PART 12 Step 5: the account-holder attestation is signed HERE
        # too, with the same blocking rules. It used to be a second step
        # gated by accounts.status, but that column now means approval
        # state — so the attestation moved to the one moment every
        # document is agreed to, before any account row exists.
        if not request.form.get("accept_account_holder"):
            flash("You must accept the %s to create an account."
                  % acceptance.document(
                      acceptance.ACCOUNT_DOCUMENT).title, "error")
            return render_template("signup.html", form=request.form,
                                   documents=_signup_documents()), 400
        # B3: the name typed at the top of the form IS the signature. It
        # was already required to be the applicant's own full legal name,
        # and asking for it twice on one page only invites the two to
        # disagree — leaving an attestation signed by a name the account
        # is not held in.
        signed_name = full_name
        from leadflow.seed import seed_account  # deferred: avoid cycle
        with db:
            cur = db.execute(
                "INSERT INTO accounts (name, status, created_at, "
                "team_role) VALUES (?, 'pending', ?, 'agent')",
                (account_name, utcnow()))
            account_id = cur.lastrowid
            user_id = create_user(db, username, password, role="admin",
                                  account_id=account_id, email=email)
            seed_account(db, account_id)
            # BLOCK 1 STEP C: no trial clock is started, because there is
            # no billing. Accounts are free; what gates a new one is the
            # approval ladder (`accounts.status`), not a payment method.
            acceptance.record_signup_documents(db, account_id, user_id)
            acceptance.record(db, account_id, user_id,
                              acceptance.ACCOUNT_DOCUMENT,
                              signed_name=signed_name)
        # PART 13: the optional access code is GONE. Redeeming one was a
        # tenant-reachable route that set `va_eligible`, and eligibility is
        # now superadmin-only — a self-service grant is exactly what that
        # rule forbids. A new account is created ineligible, full stop, and
        # the operator grants VA from the superadmin console.
        from leadflow.audit import log_event
        # S1: the event is ABOUT the new tenant, so stamp it with the new
        # account. /signup has no g.user, so an unscoped log_event would
        # fall back to account 1 and publish this tenant's account name and
        # admin username on the FIRST tenant's dashboard activity feed.
        with account_scope(account_id):
            log_event(db, None, "account_signup",
                      "account %d (%s) created by %s; awaiting approval"
                      % (account_id, account_name, username), user_id=user_id)
            # PART 12 Step 8: the acceptances themselves were only evented
            # on the /accept route, so the ones collected AT SIGNUP — which
            # is every document a new tenant ever agrees to — left no audit
            # row at all. Same etype, so both paths read alike.
            log_event(db, None, "documents_accepted",
                      "accepted at signup: %s" % ", ".join(
                          "%s v%s" % (kind, acceptance.current_version(kind))
                          for kind in (acceptance.PER_USER_DOCUMENTS
                                       + (acceptance.ACCOUNT_DOCUMENT,))),
                      user_id=user_id)
        _record_signup(ip)
        session.clear()
        session["user_id"] = user_id
        session.permanent = True
        accounts.notify_owner_of_signup(db, account_id, account_name,
                                        username)
        return redirect("/account-status")
    return render_template("signup.html", form={},
                           documents=_signup_documents())


@bp.route("/attest", methods=["GET", "POST"])
def attest():
    """S1 attestation gate: a pending account's admin must sign (checkbox +
    typed full name) before the account activates. Active accounts may view
    and re-sign voluntarily (account 1 is grandfathered active)."""
    db = get_db()
    user = get_user(db, session.get("user_id"))
    if user is None or not user["enabled"]:
        return redirect(url_for("auth.login", next="/attest"))
    g.user = dict(user)
    account = get_account(db, user["account_id"])
    doc = acceptance.document(acceptance.ACCOUNT_DOCUMENT)

    def _page(status, can_sign):
        return render_template(
            "attest.html", text=doc.text, version=doc.version,
            account=account, pending=account_pending(db, user["account_id"]),
            signed=acceptance.latest_for_account(db, user["account_id"]),
            can_sign=can_sign), status

    if request.method == "POST":
        if user["role"] != "admin":
            flash("Only the account admin can sign the attestation.", "error")
            return _page(403, False)
        if not request.form.get("agree"):
            flash("Check the agreement box to sign.", "error")
            return _page(400, True)
        try:
            acceptance.sign_account_document(db, user["account_id"],
                                             user["id"],
                                             request.form.get("signed_name"))
        except ValueError as exc:
            flash(str(exc).capitalize() + ".", "error")
            return _page(400, True)
        flash("Attestation signed — your account is active. Welcome to "
              "%s." % PRODUCT_NAME, "success")
        return redirect(_home_path(user))
    return _page(200, user["role"] == "admin")[0]


@bp.route("/account-status")
def account_status():
    """Where a user lands when their ACCOUNT may not operate.

    Read-only and deliberately dead-ended: there is nothing to click that
    changes the decision. A rejected applicant cannot re-apply by logging
    in again — no path here writes accounts.status, and
    leadflow/accounts.py is its only writer anywhere.
    """
    db = get_db()
    user = get_user(db, session.get("user_id"))
    if user is None or not user["enabled"]:
        return redirect(url_for("auth.login", next="/account-status"))
    g.user = dict(user)
    account = get_account(db, user["account_id"])
    state = accounts.status(db, user["account_id"])
    if state in accounts.USABLE:
        # Never park somebody on a gate they have already cleared.
        return redirect(_home_path(user))
    return render_template("account_status.html", account=account,
                           status=state, user=user)


@bp.route("/accept", methods=["GET", "POST"])
def accept():
    """PART 12 Step 4: accept the current ToS and DPA.

    Reached by the guard whenever a user owes an acceptance — at first
    login after signup only if something went wrong (signup records them
    inline), and for everyone the first time a version is bumped. The set
    of documents is recomputed on every request from what is OUTSTANDING,
    so a stale form cannot be replayed to accept a version that is no
    longer current: the POST re-derives the list and records only that.
    """
    db = get_db()
    user = get_user(db, session.get("user_id"))
    if user is None or not user["enabled"]:
        return redirect(url_for("auth.login", next="/accept"))
    g.user = dict(user)
    outstanding = acceptance.outstanding_for(db, user)
    if not outstanding:
        # Nothing owed: never leave someone parked on a gate they have
        # already cleared.
        return redirect(_home_path(user))
    documents = [acceptance.document(kind) for kind in outstanding]
    if request.method == "POST":
        missing = [kind for kind in outstanding
                   if not request.form.get("accept_%s" % kind)]
        if missing:
            flash("Check every box to continue — you must accept the %s."
                  % _document_list(missing), "error")
            return render_template("accept.html", documents=documents,
                                   user=user), 400
        from leadflow.audit import log_event
        with db:
            for kind in outstanding:
                acceptance.record(db, user["account_id"], user["id"], kind)
            log_event(db, None, "documents_accepted",
                      "accepted %s" % ", ".join(
                          "%s v%s" % (doc.kind, doc.version)
                          for doc in documents),
                      user_id=user["id"])
        flash("Thanks — that's recorded.", "success")
        return redirect(safe_next(request.form.get("next"),
                                  _home_path(user)))
    return render_template("accept.html", documents=documents, user=user)


@bp.route("/logout", methods=["GET", "POST"])
def logout():
    db = get_db()
    _auth_event(db, get_user(db, session.get("user_id")), "logout")
    session.clear()
    flash("Logged out.", "success")
    return redirect(url_for("auth.login"))


# --- PART 12: two-factor authentication ------------------------------------

@bp.route("/mfa/verify", methods=["GET", "POST"])
def mfa_verify():
    """Second step of login. Reached with a PARKED user id and no session
    identity, so everything here works off `pending_mfa_user_id` — never
    off g.user, which does not exist yet by design."""
    db = get_db()
    pending_id = session.get("pending_mfa_user_id")
    if not pending_id:
        return redirect(url_for("auth.login"))
    user = get_user(db, pending_id)
    if user is None or not user["enabled"]:
        session.clear()
        return redirect(url_for("auth.login"))

    if request.method == "POST":
        # The same lockout that guards the password step guards this one;
        # six digits are otherwise brute-forceable in an afternoon.
        remaining = _lock_remaining(user["username"])
        if remaining:
            flash("Too many attempts. Try again in %ds." % remaining, "error")
            return render_template("mfa_verify.html"), 429
        code = request.form.get("code", "")
        # A recovery code BYPASSES TOTP, which is the moment worth an
        # audit row of its own: it is what an attacker with a stolen
        # backup sheet would use, and what a locked-out owner would use.
        # The row carries the actor, their IP and how many codes are
        # left — never the code, and never its hash.
        def _spent(remaining):
            _auth_event(db, user, "mfa_recovery_used",
                        "recovery code accepted; %d unused code%s left"
                        % (remaining, "" if remaining == 1 else "s"))

        if mfa.verify(db, user["id"], code, on_recovery=_spent):
            _clear_failures(user["username"])
            _auth_event(db, user, "mfa_verified")
            nxt = session.get("pending_mfa_next") or ""
            session.clear()
            session["user_id"] = user["id"]
            session.permanent = True
            home = _home_path(user)
            left = mfa.recovery_codes_remaining(db, user["id"])
            if left <= 2:
                flash("Only %d recovery code%s left. Generate a new set "
                      "under Settings." % (left, "" if left == 1 else "s"),
                      "warning")
            return redirect(safe_next(nxt or home, home))
        _record_failure(user["username"])
        _auth_event(db, user, "mfa_failed")
        flash("That code is not right. Codes change every 30 seconds — "
              "try the current one, or use a recovery code.", "error")
        return render_template("mfa_verify.html"), 401
    return render_template("mfa_verify.html")


@bp.route("/mfa/enroll", methods=["GET", "POST"])
def mfa_enroll():
    """Set up a second factor. Reachable by any logged-in user; REQUIRED
    users are pinned here by the guard until they finish."""
    db = get_db()
    user = getattr(g, "user", None)
    if not user:
        return redirect(url_for("auth.login"))
    if mfa.is_enrolled(db, user["id"]):
        flash("Two-factor authentication is already on for your account.",
              "warning")
        return redirect("/settings#security")

    if request.method == "POST":
        try:
            codes = mfa.confirm_enrollment(db, user["id"],
                                           request.form.get("code", ""))
        except mfa.MfaError as exc:
            flash(str(exc), "error")
            return redirect("/mfa/enroll")
        # Shown ONCE, held in the session only until the next page renders.
        session["mfa_fresh_codes"] = codes
        from leadflow.audit import log_event
        log_event(db, None, "mfa_enrolled",
                  "user %s enrolled in TOTP" % user["username"],
                  user_id=user["id"])
        return redirect("/mfa/recovery-codes")

    record = mfa.get_record(db, user["id"])
    secret = None
    if record and not record["confirmed_at"]:
        # Resume an abandoned enrollment rather than minting a new secret,
        # so a refresh does not invalidate the QR they already scanned.
        secret = mfa._secret_of(record)
    if not secret:
        secret = mfa.begin_enrollment(db, user["id"])
    account = get_account(db, user["account_id"])
    uri = mfa.provisioning_uri(secret, user["username"],
                               account["name"] if account else None)
    return render_template("mfa_enroll.html", secret=secret,
                           qr_svg=mfa.qr_svg(uri), uri=uri,
                           required=mfa.is_required(db, user))


@bp.route("/mfa/recovery-codes")
def mfa_recovery_codes():
    """The one and only display of a fresh code set. Popping them out of
    the session means a refresh cannot show them again — which is the
    honest behaviour to teach, since we cannot show them again either."""
    codes = session.pop("mfa_fresh_codes", None)
    if not codes:
        flash("Recovery codes are shown only once. Generate a new set "
              "under Settings if you no longer have them.", "warning")
        return redirect("/settings#security")
    return render_template("mfa_recovery_codes.html", codes=codes)


def install_guard(app):
    """Register the before_request auth + role guard on the app."""

    @app.context_processor
    def _va_plan_nav():
        """What the templates need to HIDE a VA surface rather than merely
        refuse it — the nav and the Settings sections. Enforcement is the
        guard below; this only stops an account being SHOWN a door it
        cannot open. Never breaks a page render.

        Three values because the templates ask three different questions:
        `va_access` hides the features, `va_eligible` decides whether the
        tenant's own toggle renders at all, and `is_superadmin` gates the
        operator tab. An ineligible account must not even see the switch."""
        user = getattr(g, "user", None)
        blank = {"va_access": False, "va_eligible": False,
                 "is_superadmin": False}
        if not user:
            return blank
        try:
            db = get_db()
            return {"va_access": entitlements.va_access(
                        db, user["account_id"]),
                    "va_eligible": entitlements.is_eligible(
                        db, user["account_id"]),
                    "is_superadmin": is_superadmin(user)}
        except Exception:
            logger.exception("could not read the VA plan flags")
            return blank

    @app.before_request
    def _auth_guard():
        path = request.path
        if path in EXEMPT_PATHS or path.startswith(EXEMPT_PREFIXES):
            return None
        db = get_db()
        if not has_users(db):
            return redirect(url_for("auth.setup"))
        user = get_user(db, session.get("user_id"))
        if user is None or not user["enabled"]:
            if session.get("user_id") is not None:
                # A real login went stale (user deleted or disabled): drop
                # it. An ANONYMOUS session is left ALONE — it holds the C3
                # CSRF token that /login, /signup and /setup just rendered
                # into their forms, and the browser hits this guard by
                # itself between render and submit (its automatic
                # /favicon.ico fetch, a second tab, a stale bookmark).
                # Clearing there rotated the token mid-form and made every
                # browser login and signup fail with "Request blocked".
                session.clear()
            return redirect(url_for("auth.login", next=path))
        g.user = dict(user)
        # PART 12 MFA gate, FIRST of the gates on purpose. A user whose
        # role requires a second factor and who has not enrolled reaches
        # ONLY the enrollment pages until they finish. It sits ahead of
        # the attestation gate so an un-enrolled admin cannot transact
        # anything at all, including signing documents on the account's
        # behalf. Enrollment stays reachable by construction, which is
        # what keeps the FIRST admin — who cannot possibly be enrolled —
        # from being locked out.
        must_enroll = (mfa.is_required(db, user)
                       and not mfa.is_enrolled(db, user["id"]))
        if must_enroll and path not in MFA_ENROLL_ALLOWED_PATHS:
            return redirect("/mfa/enroll")
        # The enrollment flow runs from the enroll page to the ONE-TIME
        # display of the recovery codes, and `mfa_fresh_codes` is what
        # says it is still running: confirm_enrollment parks the codes
        # there and /mfa/recovery-codes pops them. It is in the condition
        # because the moment enrollment succeeds `must_enroll` goes false,
        # and without it the gates below took the codes page instead —
        # measured, and the worst version of this bug: the user is told
        # these are shown once and only once, and it is true, so the set
        # is simply gone.
        if ((must_enroll or session.get("mfa_fresh_codes"))
                and path in MFA_ENROLL_ALLOWED_PATHS):
            # AND NOTHING BELOW GETS A SAY. "Reaches ONLY the enrollment
            # pages" has to mean the enrollment pages are REACHED, and
            # every gate under this one is an allowlist that does not
            # contain /mfa/enroll — so each was free to redirect the user
            # straight back off it, into a page this gate then bounced to
            # /mfa/enroll again. Measured: an admin owing the current CSA
            # got /mfa/enroll -> /agreement -> /mfa/enroll until the
            # browser gave up with ERR_TOO_MANY_REDIRECTS. The account,
            # document and billing gates loop identically, and the VA
            # allowlist 403s the page rather than looping on it, which is
            # a lockout with no exit at all.
            #
            # Returning here does not weaken any of them: the user is on
            # one of three paths (enroll, recovery codes, logout) and
            # cannot transact anything from them. Every other path was
            # already refused above, so the gates below still cover the
            # whole app. They simply stop arguing about the one page
            # whose entire purpose is to end this state.
            return None
        # PART 12 Step 4 document gate. Version-pinned ToS + DPA, checked
        # per USER, ahead of the account-level attestation gate for the
        # same reason the MFA gate sits ahead of both: the documents bind
        # the person who is about to act, so they are settled before that
        # person does anything — including signing on the account's
        # behalf. A version bump therefore stops every existing user at
        # their next request, which is the whole point of pinning it.
        # PART 12 Step 5 ACCOUNT GATE. Ahead of the document gate on
        # purpose: an account that may not act at all should not be
        # nagged to accept a new version of terms it cannot use. This
        # REPLACED the old status gate that redirected to /attest —
        # `accounts.status` now means approval state, and the attestation
        # is signed at signup with the other two documents.
        #
        # It is an ALLOWLIST of statuses (accounts.USABLE), not a list of
        # bad ones, so a status added later is refused until somebody
        # deliberately lets it in. Fails closed: an unreadable row reads
        # as pending.
        # THE FIRST UNSATISFIED GATE WINS, AND EVERY LATER GATE YIELDS TO
        # ITS LANDING PAGE. That is the rule the MFA early return above
        # applies to one gate, and it has to hold for all of them or the
        # chain does not terminate: each gate is "if unsatisfied and path
        # not in MY allowlist, redirect to MY page", and no gate's page is
        # in the NEXT gate's allowlist. So with two unsatisfied at once,
        # each one's landing page is the other's forbidden path, and the
        # user bounces between them until the browser gives up.
        #
        # This is not hypothetical and it was not only the MFA pair. A
        # 26-entry HAR from production showed /mfa/enroll <-> /agreement
        # for a fresh admin, and the same structure was then found live
        # for /account-status <-> /agreement (a signed-up agent whose
        # account is still pending, with a CSA active — i.e. EVERY new
        # agent between signup and approval) and /accept <-> /agreement.
        # tests/test_first_login_gates.py enumerates every pair.
        #
        # So the gates below are evaluated as a SEQUENCE: the first one
        # that is unsatisfied decides the landing page, and if the request
        # is already ON that page — or on /logout, the universal exit — it
        # is rendered. Later gates are not consulted for a request the
        # earlier gate has claimed. Nothing weakens: on that page the user
        # can do exactly one thing (satisfy the gate, or leave), and every
        # OTHER path is still refused by whichever gate is first to object.
        #
        # ORDER IS THE PRODUCT DECISION and it is unchanged: account status
        # (may this account act at all?), then the per-user documents
        # (does this person accept the terms?), then the account-level
        # agreement (has the account signed the CSA?). MFA sits above all
        # three, and above this comment, because it is about who is at the
        # keyboard rather than what they may do.
        first_unsatisfied = None
        if not accounts.is_active(db, user["account_id"]):
            first_unsatisfied = ("/account-status", ACCOUNT_GATE_ALLOWED_PATHS,
                                 ())
        elif acceptance.outstanding_for(db, user):
            first_unsatisfied = ("/accept", ACCEPT_ALLOWED_PATHS, ())
        else:
            # PART 12 Step 9. THE agreement gate: one check, at the routing
            # layer, covering every path. Deliberately not a per-route
            # decorator — a route added tomorrow is gated because it is a
            # route, not because somebody remembered to annotate it.
            from leadflow import agreements
            if agreements.outstanding_for(db, user["account_id"]):
                first_unsatisfied = ("/agreement", AGREEMENT_ALLOWED_PATHS,
                                     AGREEMENT_ALLOWED_PREFIXES)
        if first_unsatisfied is not None:
            landing, allowed, prefixes = first_unsatisfied
            if path not in allowed and not path.startswith(prefixes):
                return redirect(landing)
            # On the landing page (or its allowed companions): render it,
            # and let NO later gate redirect it away — the yield that
            # makes the chain terminate.
            return None
        # BLOCK 1 STEP C: the BILLING PAUSE rung stood here and is gone
        # with billing. Suspending an account is the ACCOUNT STATUS gate
        # above, which already refuses every status but `active` and
        # renders /account-status; nothing about freezing an account
        # needed a second rung down here.
        # DIALER BLOCK 3. AHEAD of the VA allowlist, so the refusal for a
        # non-dialing session is this rule's rather than a side effect of
        # the allowlist not naming the route — an admin must be refused
        # HERE, by the seat check, and be seen to be.
        #
        # BLOCK 2 CHANGED WHAT "THE SEAT" MEANS. This read `role != 'va'`,
        # and `/settings/users/add` is a TENANT route that hardcodes
        # `role='va'` on the tenant's own account — so a customer could
        # create their own dialing seat and the CSA's "calling is not
        # available to customer accounts" was untrue of the code. The seat
        # is now `users.can_dial`, which only the superadmin console
        # writes. `can_dial` is checked with `.keys()` rather than
        # subscripted blind so a session opened against a row that
        # predates the column fails CLOSED instead of 500ing.
        if is_dial_route(request.method, path):
            # B7 NARROWED THIS. It asked `can_dial` alone; it now asks
            # `va_scope.may_dial`, which is that flag AND `role='va'` AND
            # a TEAM seat AND an account on the team under account 1.
            # A team manager's own personal assistant satisfies the first
            # two and must still never place a call.
            #
            # ONE predicate, called here and in dialer.py, so the routing
            # layer and the carrier path cannot disagree about who may
            # dial. Every rung inside it fails closed.
            from leadflow import va_scope
            if not va_scope.may_dial(db, user):
                logger.warning("refused a dial route (user=%s): %s",
                               user["id"], va_scope.refusal_reason(db, user))
                return render_template("403.html"), 403
            if not entitlements.va_access(db, user["account_id"]):
                logger.warning("refused a dial route to an unentitled "
                               "account (user=%s)", user["id"])
                return render_template("403.html"), 403

        if user["role"] == "va" and not va_can_access(request.method, path):
            return render_template("403.html"), 403
        # VA entitlement (migration 16). THE routing-layer check: one call,
        # one table (VA_GATED), covering every whole surface a no-code
        # account may not reach. A deep link redirects with a clear
        # message rather than 403ing — the surface is not forbidden to
        # them, it is not part of their plan, and the wording says so.
        # PART 13: the same single check, now over BOTH plan flags. One
        # call, one table (VA_GATED), one predicate — a surface is refused
        # when the account is not eligible OR the tenant has switched VA
        # off. The message distinguishes the two, because "you never had
        # this" and "you turned this off" have different fixes.
        if (va_surface(request.method, path)
                and not entitlements.va_access(db, user["account_id"])):
            if entitlements.is_eligible(db, user["account_id"]):
                flash("VA features are switched off for this account. "
                      "Turn them back on under Settings → VA.", "warning")
            else:
                flash("VA features aren't part of this account's plan.",
                      "warning")
            return redirect(_home_path(user))
        return None
