"""B4: per-state licensure — what an agent may work, and what they may not.

THE RULE, in one sentence: an account may only work a lead whose RESIDENT
STATE it holds an unexpired licence for, and an account holding no licence
at all may not take leads in at all.

MATCHED ON `leads.state`, NEVER ON THE AREA CODE. The area code is where a
phone number was issued, which stopped meaning where somebody lives when
numbers became portable — a Floridian who kept their Ohio mobile is an
Ohio area code and a Florida resident, and licensure follows residence.
`leadflow/tz.py` deliberately DOES fall back to the area code when it
cannot get a state, because guessing a timezone wrong costs a badly-timed
call and guessing a licence wrong is a regulatory matter. The two must not
be made to share a helper.

CHECKED AT READ, NOT ONLY AT WRITE. Nothing here is a stored flag. A
licence expires by the calendar, so a lead that was sendable yesterday is
not sendable today with no row having changed — a flag written when the
licence was saved would still say "covered" on the morning it lapsed.
Every caller asks `covers()` (or `covered_states()`, its cached-per-call
sibling) at the moment it needs the answer.

WHAT HAPPENS TO AN UNCOVERED LEAD: nothing. It stays in the agent's own
pipeline, marked with the reason, and is neither deleted nor handed to
anybody else. Routing it elsewhere would move a consumer's data between
tenants on the strength of a licence lookup, which is not a transfer
anyone consented to; deleting it would destroy the record of an inquiry
that really happened.

TWO SHAPES OF RECORD, ONE TABLE:
  - An AGENT's licence carries a number, an expiry and (optionally) a
    scan. The expiry drives warnings and blocking.
  - The OPERATOR's is a plain checklist: a state, and nothing else.
    `expires_on IS NULL` means "does not expire" and never warns or
    blocks. The DATA carries that distinction so there is one code path,
    not two.

THE PDF IS NEVER PARSED. It is stored under a randomised filename in a
gitignored directory, served back only to the account that uploaded it,
and no code in this application opens it. A licence scan is a photograph
of a government document; the only safe thing to do with one is keep it
where it was put.
"""
import datetime
import logging
import os
import pathlib
import re
import secrets

from leadflow.db import data_dir, utcnow

logger = logging.getLogger("leadflow.licensure")

# Two letters, upper case. Matches what `lead_import` normalises to and
# what the parser writes.
_STATE_RE = re.compile(r"^[A-Z]{2}$")

# For the operator's checklist and the agent's state picker. DC is here
# because insurance is licensed there; the territories are not, because
# nothing in this application has ever seen a lead from one and a picker
# offering a state nobody can work is a support question.
US_STATES = (
    "AL", "AK", "AZ", "AR", "CA", "CO", "CT", "DC", "DE", "FL", "GA", "HI",
    "ID", "IL", "IN", "IA", "KS", "KY", "LA", "ME", "MD", "MA", "MI", "MN",
    "MS", "MO", "MT", "NE", "NV", "NH", "NJ", "NM", "NY", "NC", "ND", "OH",
    "OK", "OR", "PA", "RI", "SC", "SD", "TN", "TX", "UT", "VT", "VA", "WA",
    "WV", "WI", "WY",
)

# How long before an expiry the UI starts warning. Warning is not
# blocking: the licence still covers leads until the day after it lapses.
WARN_DAYS = 45

# Uploads: a scan, not a document management system.
PDF_SUFFIX = ".pdf"
MAX_PDF_BYTES = 10 * 1024 * 1024

REASON_NO_LICENCE = "no_licence"
REASON_STATE_NOT_COVERED = "state_not_covered"
REASON_EXPIRED = "licence_expired"
REASON_UNKNOWN_STATE = "lead_has_no_state"

REASON_TEXT = {
    REASON_NO_LICENCE:
        "This account holds no licence yet, so no lead can be worked.",
    REASON_STATE_NOT_COVERED:
        "No licence on file for this lead's state.",
    REASON_EXPIRED:
        "The licence for this lead's state has expired.",
    REASON_UNKNOWN_STATE:
        "This lead has no resident state, so licensure cannot be checked.",
}


class LicenceError(ValueError):
    """A licence row that would be invalid."""


def normalise_state(value):
    # type: (object) -> object
    state = (value or "").strip().upper()
    return state if _STATE_RE.match(state) else None


def today(db=None):
    """The date licensure is judged against, from the app's own clock."""
    return utcnow()[:10]


# ---------------------------------------------------------------- storage

def licence_dir():
    """Where licence scans live: data/licenses/. `data/` is gitignored in
    its entirety, so nothing here is ever committed."""
    directory = data_dir() / "licenses"
    directory.mkdir(parents=True, exist_ok=True)
    return directory


def _random_filename():
    """A name that carries NOTHING. Not the account, not the state, not
    the original filename — a directory listing of licence scans should
    not itself be a list of who is licensed where, and an uploaded name
    is attacker-controlled text that would otherwise reach a filesystem
    path."""
    return "%s%s" % (secrets.token_urlsafe(24).replace("-", "_"), PDF_SUFFIX)


def store_pdf(data):
    # type: (bytes) -> str
    """Write a scan and return its filename. NEVER PARSED — the bytes go
    to disk exactly as received and nothing in this application opens
    them again except to hand them back."""
    if not data:
        raise LicenceError("the uploaded file was empty")
    if len(data) > MAX_PDF_BYTES:
        raise LicenceError("the file is larger than %d MB"
                           % (MAX_PDF_BYTES // (1024 * 1024)))
    name = _random_filename()
    target = licence_dir() / name
    handle = os.open(str(target), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(handle, "wb") as fh:
        fh.write(data)
    return name


def pdf_path(filename):
    # type: (object) -> object
    """Resolve a stored scan, refusing anything that is not a plain name
    inside the licence directory. The filename comes from a database row
    this application wrote, but the check costs nothing and a path that
    is only safe because of where it came from stops being safe the day
    somebody adds a second writer."""
    if not filename:
        return None
    name = pathlib.Path(str(filename)).name
    if name != str(filename) or not name.endswith(PDF_SUFFIX):
        logger.warning("refusing a licence path that is not a plain name")
        return None
    target = licence_dir() / name
    return target if target.exists() else None


def delete_pdf(filename):
    target = pdf_path(filename)
    if target is not None:
        try:
            target.unlink()
        except OSError:
            logger.exception("could not delete licence scan %s", filename)


# ------------------------------------------------------------- the rules

def licences(db, account_id):
    # type: (object, int) -> list
    """Every licence row for an account, state order."""
    return db.execute(
        "SELECT * FROM licenses WHERE account_id = ? ORDER BY state",
        (int(account_id),)).fetchall()


def is_expired(row, on=None):
    # type: (object, object) -> bool
    """NULL expiry NEVER expires — that is the operator's checklist row."""
    try:
        expires = row["expires_on"]
    except (IndexError, KeyError):
        return False
    if not expires:
        return False
    return str(expires) < (on or utcnow()[:10])


def expiring_soon(db, account_id, on=None, within_days=WARN_DAYS):
    # type: (object, int, object, int) -> list
    """Licences that lapse within the window and have not lapsed yet.

    WARNING IS NOT BLOCKING. A licence covers leads right up to the end of
    its expiry date; this list exists so nobody is surprised by the day it
    stops.
    """
    on = on or utcnow()[:10]
    try:
        limit = (datetime.date.fromisoformat(on)
                 + datetime.timedelta(days=within_days)).isoformat()
    except ValueError:  # pragma: no cover - `on` is always ISO
        return []
    rows = []
    for row in licences(db, account_id):
        expires = row["expires_on"]
        if expires and on <= str(expires) <= limit:
            rows.append(row)
    return rows


def expired(db, account_id, on=None):
    on = on or utcnow()[:10]
    return [r for r in licences(db, account_id) if is_expired(r, on)]


def covered_states(db, account_id, on=None):
    # type: (object, int, object) -> set
    """The states this account may work TODAY. Expired rows are absent.

    The set-shaped answer, for callers judging many leads at once (the VA
    queue build, the leads list). One query instead of one per row, and it
    cannot disagree with `covers` because `covers` is written in terms of
    it.
    """
    on = on or utcnow()[:10]
    return set(row["state"] for row in licences(db, account_id)
               if not is_expired(row, on))


def has_any_licence(db, account_id, on=None):
    # type: (object, int, object) -> bool
    """Is this account allowed to take leads in AT ALL.

    UNEXPIRED, deliberately. An account whose only licence lapsed is in
    the same position as one that never had one: it cannot lawfully work
    what it would be pulling in.
    """
    return bool(covered_states(db, account_id, on))


def covers(db, account_id, state, on=None):
    # type: (object, int, object, object) -> tuple
    """(allowed, reason) for ONE lead's resident state. THE predicate.

    Returns a reason on refusal, never a bare False: every caller of this
    puts the answer in front of a person, and "no" without "why" is a
    support ticket.
    """
    if not account_id:
        return (False, REASON_NO_LICENCE)
    on = on or utcnow()[:10]
    rows = licences(db, account_id)
    if not rows:
        return (False, REASON_NO_LICENCE)
    normalised = normalise_state(state)
    if normalised is None:
        return (False, REASON_UNKNOWN_STATE)
    match = None
    for row in rows:
        if row["state"] == normalised:
            match = row
            break
    if match is None:
        return (False, REASON_STATE_NOT_COVERED)
    if is_expired(match, on):
        return (False, REASON_EXPIRED)
    return (True, None)


def lead_is_workable(db, lead, on=None, account_id=None):
    # type: (object, object, object, object) -> tuple
    """`covers` for a lead ROW — reads `leads.state` and nothing else.

    Written as its own function so that every caller reaches licensure
    through a name that says which column it reads. A caller that passed
    `lead["phone"]` to `covers` would be checking the area code, which is
    the one thing B4 says never to do.

    Accepts a lead row OR a plain dict of one (`smtp_send` works with a
    dict), and an explicit `account_id` for the callers that have already
    resolved it.
    """
    def field(name):
        try:
            return lead[name]
        except (IndexError, KeyError, TypeError):
            return None

    return covers(db, account_id or field("account_id"), field("state"), on)


def refusal_text(reason, state=None):
    # type: (object, object) -> str
    text = REASON_TEXT.get(reason, "Licensure check failed.")
    if reason == REASON_STATE_NOT_COVERED and state:
        return "No licence on file for %s." % state
    if reason == REASON_EXPIRED and state:
        return "The %s licence has expired." % state
    return text


# ------------------------------------------------------------- the writer

def save_licence(db, account_id, state, license_number=None, expires_on=None,
                 pdf_filename=None, by_user_id=None):
    # type: (object, int, object, object, object, object, object) -> int
    """Create or update ONE state's licence. The only writer.

    `expires_on` NULL is the operator's checklist row and never expires;
    an agent's row is required to carry one by the ROUTE, not here, so
    that the checklist and the full record share a table and a code path.
    """
    account_id = int(account_id)
    normalised = normalise_state(state)
    if normalised is None:
        raise LicenceError("%r is not a two-letter state code" % (state,))
    if expires_on:
        try:
            datetime.date.fromisoformat(str(expires_on))
        except ValueError:
            raise LicenceError("expiry must be a date (YYYY-MM-DD)")
    else:
        expires_on = None
    now = utcnow()
    existing = db.execute(
        "SELECT * FROM licenses WHERE account_id = ? AND state = ?",
        (account_id, normalised)).fetchone()
    own = not db.in_transaction
    if existing is None:
        cur = db.execute(
            "INSERT INTO licenses (account_id, state, license_number, "
            "expires_on, pdf_filename, created_at, updated_at, created_by) "
            "VALUES (?,?,?,?,?,?,?,?)",
            (account_id, normalised, (license_number or "").strip() or None,
             expires_on, pdf_filename, now, now, by_user_id))
        licence_id = cur.lastrowid
        detail = "added %s" % normalised
    else:
        licence_id = existing["id"]
        # A new scan REPLACES the old one on disk. Keeping the previous
        # file would leave an unreferenced copy of a government document
        # in the directory forever.
        if pdf_filename and existing["pdf_filename"]:
            delete_pdf(existing["pdf_filename"])
        db.execute(
            "UPDATE licenses SET license_number = ?, expires_on = ?, "
            "pdf_filename = COALESCE(?, pdf_filename), updated_at = ? "
            "WHERE id = ?",
            ((license_number or "").strip() or None, expires_on,
             pdf_filename, now, licence_id))
        detail = "updated %s" % normalised
    _log(db, account_id, "licence_saved",
         "%s%s" % (detail, " (expires %s)" % expires_on if expires_on else ""),
         by_user_id)
    if own:
        db.commit()
    return licence_id


def delete_licence(db, account_id, licence_id, by_user_id=None):
    row = db.execute(
        "SELECT * FROM licenses WHERE id = ? AND account_id = ?",
        (int(licence_id), int(account_id))).fetchone()
    if row is None:
        return False
    own = not db.in_transaction
    db.execute("DELETE FROM licenses WHERE id = ?", (row["id"],))
    delete_pdf(row["pdf_filename"])
    _log(db, account_id, "licence_removed", "removed %s" % row["state"],
         by_user_id)
    if own:
        db.commit()
    return True


def _log(db, account_id, etype, detail, by_user_id):
    from leadflow.audit import log_event
    from leadflow.auth import account_scope
    with account_scope(int(account_id)):
        log_event(db, None, etype, detail, user_id=by_user_id)
