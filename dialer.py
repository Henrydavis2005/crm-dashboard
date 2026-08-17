"""DIALER BLOCK 3: the one place in Ancora that can place a telephone call.

READ THIS FIRST. PART 10 removed the internal calling system and
`tests/test_no_dial_path.py` existed to keep it removed, because the
Cloud Service Agreement seeded into `legal_documents` says, in the Order
Form that defines the product:

    "The Cloud Service does not place telephone calls. Phone numbers are
     displayed for the Customer to dial using their own systems."

THAT SENTENCE IS NOW INACCURATE. It is in the ACTIVE, signed, immutable
CSA (`csa-2.1-ancora-2026-08-14-v2`), and this module contradicts it.
Correcting it means bumping `seed.CSA_VERSION`, which publishes a new
version, stands the old one down and re-gates every tenant at their next
request. That is a deliberate act with a blast radius, so it is NOT done
here — it is reported. Nothing in this module should ship to a paying
tenant until it is.

WHAT THIS MODULE IS
  A gate ladder and a single REST call. Every rung is a HARD REFUSAL
  evaluated BEFORE Twilio is contacted, and `place_call` cannot be
  reached except through `check`, because `check` is what returns the
  permission token the call writer records.

THE SEAT, NOT THE PLAN. Dialing is the VA seat's capability. An admin on
a fully entitled account cannot dial, the operator cannot dial, and a
superadmin cannot dial. The routing-layer gate in `leadflow/auth.py`
(DIAL_ROUTES) is the single enforcement point; this module re-asks the
same question anyway, because a gate that only exists in the router is
one refactor away from being a gate that does not exist.

NO RECORDING, AND IT FAILS LOUDLY. Florida is a two-party-consent state.
`Record` is never sent to Twilio, and `refuse_recording_config` raises
on any setting or environment variable that looks like an attempt to
turn recording on — an app that silently ignores such a flag teaches an
operator that they set it successfully.

NO WEBHOOK, BY DESIGN. The call is placed with INLINE TwiML on the REST
request, so there is no public callback URL to stand up and
`public_base_url` stays unset. The cost is that Twilio has nowhere to
report the completed call's duration, so `dial_attempts.duration_seconds`
is NULL for now — see SPEC.
"""
import datetime
import logging
import os
import re
from typing import Optional

from leadflow.db import utcnow
from leadflow.phone import digits as phone_digits, to_e164

logger = logging.getLogger("leadflow.dialer")

# --------------------------------------------------------------- the rules

# The calling window, LEAD-LOCAL, as hard constants.
#
# Deliberately NOT the `quiet_start` / `quiet_end` settings, which happen
# to default to the same hours: those are the tenant's EMAIL window and a
# tenant may widen them. A calling window a tenant can widen is not a
# rule, it is a suggestion with a form field.
CALL_WINDOW_START_HOUR = 8
CALL_WINDOW_END_HOUR = 20

# Attempts allowed per NUMBER per lead-local day — per NUMBER, not per
# lead, because two leads can share a phone (a couple, a household, a
# recycled number) and three calls each is six calls to one handset.
MAX_ATTEMPTS_PER_NUMBER_PER_DAY = 3

# Env vars holding the Twilio credentials. NEVER committed: .env is
# gitignored and .env.example carries the names with empty values.
SID_ENV = "LEADFLOW_TWILIO_ACCOUNT_SID"
TOKEN_ENV = "LEADFLOW_TWILIO_AUTH_TOKEN"
FROM_ENV = "LEADFLOW_TWILIO_FROM_NUMBER"

TWILIO_API = "https://api.twilio.com/2010-04-01/Accounts/%s/Calls.json"
CALL_TIMEOUT_SECONDS = 20

# Anything that looks like somebody trying to switch recording on. The
# check is by NAME across settings and the environment, so a flag added
# later trips it without anybody remembering to extend a list of values.
_RECORDING_NAME = re.compile(r"record", re.IGNORECASE)


class DialRefused(RuntimeError):
    """A rung of the ladder said no. Carries the rung's name."""

    def __init__(self, rule, message):
        # type: (str, str) -> None
        RuntimeError.__init__(self, message)
        self.rule = rule
        self.message = message


class RecordingConfigured(RuntimeError):
    """Something tried to turn call recording on. Never caught."""


# ------------------------------------------------------------- the ladder

def refuse_recording_config(db=None, account_id=None):
    # type: (object, Optional[int]) -> None
    """Raise if anything in the environment or the settings asks for
    recording. Called on EVERY dial, not once at startup, because a
    setting can be written between one call and the next.

    Loud on purpose. Returning False here would let an operator believe
    they had enabled a feature that silently does nothing, and the day
    they rely on that belief is the day they think a call was recorded
    when it was not — or worse, assume it was not when they had reason to
    think it was.
    """
    for name in os.environ:
        if name.startswith("LEADFLOW_") and _RECORDING_NAME.search(name):
            if (os.environ.get(name) or "").strip().lower() in (
                    "", "0", "false", "no", "off"):
                continue
            raise RecordingConfigured(
                "%s is set. Ancora never records calls: Florida is a "
                "two-party-consent state and this app has no consent "
                "capture. Unset it before dialing." % name)
    if db is None:
        return
    try:
        rows = db.execute(
            "SELECT key, value FROM settings WHERE account_id = ? "
            "AND key LIKE '%record%'",
            (account_id,)).fetchall()
    except Exception:                       # pragma: no cover - defensive
        logger.exception("could not read settings while checking for a "
                         "recording flag; refusing to dial")
        raise RecordingConfigured(
            "could not prove call recording is off, so the call is refused")
    for row in rows:
        raw = (row["value"] or "").strip().lower()
        if raw not in ("", '""', "null", "0", "false", '"0"', '"false"'):
            raise RecordingConfigured(
                "setting %r is set. Ancora never records calls." % row["key"])


def in_call_window(tz_name, at=None):
    # type: (str, Optional[datetime.datetime]) -> bool
    """Is it 08:00-20:00 where the LEAD is? Never where the caller is."""
    from leadflow.tz import _ensure_aware_utc, _zone
    at = _ensure_aware_utc(at)
    local = at.astimezone(_zone(tz_name))
    return CALL_WINDOW_START_HOUR <= local.hour < CALL_WINDOW_END_HOUR


def window_note(tz_name, at=None):
    # type: (str, Optional[datetime.datetime]) -> str
    from leadflow.tz import _ensure_aware_utc, _zone
    at = _ensure_aware_utc(at)
    local = at.astimezone(_zone(tz_name))
    return ("It is %s where this lead is. Calling is %02d:00-%02d:00 their "
            "time." % (local.strftime("%H:%M"), CALL_WINDOW_START_HOUR,
                       CALL_WINDOW_END_HOUR))


def attempts_today(db, account_id, number, tz_name, at=None):
    # type: (object, int, str, str, Optional[datetime.datetime]) -> int
    """How many times THIS NUMBER has been dialled in its own local day.

    Keyed on the number rather than the lead. Two leads sharing a handset
    are two rows in `leads` and one person answering the phone.
    """
    from leadflow.tz import _ensure_aware_utc, _zone
    at = _ensure_aware_utc(at)
    zone = _zone(tz_name)
    local = at.astimezone(zone)
    start_local = local.replace(hour=0, minute=0, second=0, microsecond=0)
    start_utc = start_local.astimezone(datetime.timezone.utc)
    end_utc = (start_local + datetime.timedelta(days=1)).astimezone(
        datetime.timezone.utc)
    # B6: compared on DIGITS, not on the spelling. `dial_attempts` is
    # append-only by trigger, so rows written before the format change keep
    # their E.164 and no migration may rewrite them — a cap that matched on
    # the string would silently reset to zero for every number that had
    # been called before.
    row = db.execute(
        "SELECT COUNT(*) AS n FROM dial_attempts "
        "WHERE account_id = ? "
        "AND REPLACE(REPLACE(REPLACE(REPLACE(to_number, '+1', ''), "
        "'-', ''), '(', ''), ')', '') = ? "
        "AND created_at >= ? AND created_at < ? "
        # Refused attempts never reached a carrier and must not consume
        # somebody's three: a VA who clicked at 7:59am has not called.
        "AND outcome NOT LIKE 'refused:%'",
        (account_id, phone_digits(number) or number,
         start_utc.isoformat(timespec="seconds"),
         end_utc.isoformat(timespec="seconds"))).fetchone()
    return row["n"] if row else 0


def check(db, lead, user, at=None):
    # type: (object, object, object, Optional[datetime.datetime]) -> str
    """Every rung, in order. Returns the name of the rule that PERMITTED
    the call, which is what `dial_attempts.permitted_by` records — so the
    log answers "why was this allowed" and not merely "this happened".

    Raises DialRefused on the first rung that says no.
    """
    from leadflow import consent, entitlements, suppression

    # 0. Recording. First, because it is a property of the whole install
    #    rather than of this lead, and because it raises rather than
    #    refusing — it is not a rung the caller may handle.
    refuse_recording_config(db, lead["account_id"])

    # 1. The seat. Re-asked here even though auth.py already refused it at
    #    the routing layer.
    #
    #    BLOCK 2: this asked `role != 'va'`, and `/settings/users/add` is
    #    a TENANT route that hardcodes that role — so the answer to "is
    #    this a dialing seat" was a string a customer could write. Both
    #    layers now read `users.can_dial`, which only the superadmin
    #    console sets. The role is still required, so an operator who
    #    somehow set the flag on an admin still gets nowhere.
    #
    #    `.keys()` rather than a blind subscript: a session opened against
    #    a row that predates the column must fail CLOSED, not 500.
    #    B7 NARROWED IT AGAIN: `va_scope.may_dial` is the whole gate —
    #    the flag, the role, a TEAM seat, and an account on the team under
    #    account 1. A team manager's own personal assistant has a VA role
    #    and could be granted the flag; they must still never dial, and
    #    "FTA personal VAs do not dial" is that rung.
    from leadflow import va_scope
    if not va_scope.may_dial(db, user):
        logger.warning("dial refused at the carrier path (user=%s): %s",
                       (user["id"] if user is not None else None),
                       va_scope.refusal_reason(db, user))
        raise DialRefused("va_seat",
                          "Only a team assistant seat granted calling can "
                          "place calls.")
    # Tenant isolation BEFORE the entitlement, deliberately: "is this even
    # your lead" has to be settled before we read another account's plan
    # flags to answer a question about this seat.
    if user["account_id"] != lead["account_id"]:
        raise DialRefused("tenant_isolation",
                          "That lead belongs to another account.")
    if not entitlements.va_access(db, lead["account_id"]):
        raise DialRefused("va_entitlement",
                          "This account's plan does not include VA calling.")

    # 2. A number to call.
    number = (lead["phone"] or "").strip()
    if not number:
        raise DialRefused("no_number", "This lead has no phone number.")
    if lead["phone_bad"]:
        raise DialRefused("phone_bad",
                          "This number is marked wrong; it cannot be called.")

    # 3. D2 — revocation. Ahead of consent because it is the person's own
    #    later instruction and outranks whatever they agreed to before.
    # B8: no account scope. A revocation covers the person on every
    # account, so the lead's own tenant is not a narrowing here.
    revocation = suppression.revocation_for(
        db, email=lead["email"], phone=number)
    if revocation is not None:
        raise DialRefused("revoked",
                          suppression.revocation_note(revocation))
    if suppression.is_suppressed(db, email=lead["email"], phone=number,
                                 account_id=lead["account_id"]):
        raise DialRefused("suppressed",
                          "This contact is suppressed and cannot be called.")

    # 4. D1 — consent age.
    max_age = consent.max_age_days(db, account_id=lead["account_id"])
    if not consent.is_dialable(lead["consent_date"], max_age=max_age):
        raise DialRefused(
            "consent",
            consent.explain(lead["consent_date"], max_age=max_age))

    # 5. The lead's own local calling window.
    tz_name = lead["timezone"] or "America/New_York"
    if not in_call_window(tz_name, at=at):
        raise DialRefused("call_window", window_note(tz_name, at=at))

    # 6. Attempts, per NUMBER.
    used = attempts_today(db, lead["account_id"], number, tz_name, at=at)
    if used >= MAX_ATTEMPTS_PER_NUMBER_PER_DAY:
        raise DialRefused(
            "attempt_cap",
            "This number has already been called %d times today (the limit "
            "is %d). Note that the cap is per NUMBER, so another lead may "
            "share it." % (used, MAX_ATTEMPTS_PER_NUMBER_PER_DAY))

    # 7. The VA's own phone — the leg Twilio dials first.
    if not (user["phone"] or "").strip():
        raise DialRefused(
            "va_phone",
            "Your user record has no phone number, so there is nothing for "
            "the call to reach you on.")

    return "queue_click"


def refusal(db, lead, user, at=None):
    # type: (object, object, object, Optional[datetime.datetime]) -> Optional[DialRefused]
    """`check` as a question rather than an exception, for the template
    that decides whether the Call control renders enabled."""
    try:
        check(db, lead, user, at=at)
    except DialRefused as exc:
        return exc
    except RecordingConfigured as exc:
        return DialRefused("recording", str(exc))
    return None


# ---------------------------------------------------------------- placing

def credentials():
    # type: () -> tuple
    """(sid, token, from_number) from the environment. Never a default,
    never a settings row: a credential in the database is a credential in
    every backup of it."""
    sid = (os.environ.get(SID_ENV) or "").strip()
    token = (os.environ.get(TOKEN_ENV) or "").strip()
    number = (os.environ.get(FROM_ENV) or "").strip()
    missing = [name for name, value in
               ((SID_ENV, sid), (TOKEN_ENV, token), (FROM_ENV, number))
               if not value]
    if missing:
        raise DialRefused("twilio_config",
                          "Calling is not configured: %s is not set."
                          % ", ".join(missing))
    return sid, token, number


def _twiml(to_number, caller_id):
    # type: (str, str) -> str
    """Dial the LEAD once the VA's leg answers.

    Inline on the REST request, so Twilio needs no callback URL from us
    and `public_base_url` stays unset. `record` is absent and must stay
    absent — see the module docstring.
    """
    from xml.sax.saxutils import quoteattr, escape
    return ("<Response><Dial callerId=%s timeout=\"20\">%s</Dial></Response>"
            % (quoteattr(caller_id), escape(to_number)))


def place_call(db, lead, user, permitted_by, at=None):
    # type: (object, object, object, str, Optional[datetime.datetime]) -> dict
    """Ring the VA, then bridge them to the lead. ONE attempt, ONE row.

    The row is written whatever happens — permitted and placed, or
    permitted and failed at the carrier — because "we tried to call this
    person" is the fact the log exists to hold. A REFUSED attempt is
    written by the caller with an outcome of `refused:<rule>`.
    """
    import requests

    sid, token, from_number = credentials()
    # B6: the columns hold 000-000-0000. E.164 exists in exactly one place
    # — here, on the wire — because Twilio requires it and nothing else
    # does. `record_attempt` below logs the STORED spelling, so the log
    # and the lead row read alike.
    stored_number = (lead["phone"] or "").strip()
    to_number = to_e164(stored_number) or stored_number
    va_number = to_e164(user["phone"]) or (user["phone"] or "").strip()

    payload = {
        "From": from_number,
        "To": va_number,
        "Twiml": _twiml(to_number, from_number),
        "Timeout": "20",
        # NO `Record`. Not "Record=false" — absent. A false flag is a flag
        # somebody can flip; an absent parameter is a decision.
    }
    outcome, call_sid = "placed", None
    try:
        response = requests.post(TWILIO_API % sid, data=payload,
                                 auth=(sid, token),
                                 timeout=CALL_TIMEOUT_SECONDS)
        if response.status_code >= 400:
            outcome = "failed:http_%d" % response.status_code
            logger.error("twilio refused the call for lead %s: %s",
                         lead["id"], response.status_code)
        else:
            call_sid = (response.json() or {}).get("sid")
    except Exception as exc:                # pragma: no cover - network
        outcome = "failed:%s" % type(exc).__name__
        logger.exception("could not place a call for lead %s", lead["id"])

    record_attempt(db, lead, user, stored_number, from_number, permitted_by,
                   outcome, call_sid=call_sid, at=at)
    return {"outcome": outcome, "call_sid": call_sid}


def record_attempt(db, lead, user, to_number, from_number, permitted_by,
                   outcome, call_sid=None, duration_seconds=None, at=None):
    # type: (...) -> int
    """Append one row to the call log. The ONLY writer.

    `dial_attempts` is append-only by trigger, so this never updates and
    there is no second call that fills the row in later.
    """
    cur = db.execute(
        "INSERT INTO dial_attempts (account_id, lead_id, user_id, "
        " to_number, from_number, permitted_by, outcome, call_sid, "
        " duration_seconds, created_at) VALUES (?,?,?,?,?,?,?,?,?,?)",
        (lead["account_id"], lead["id"], user["id"] if user else None,
         to_number, from_number, permitted_by, outcome, call_sid,
         duration_seconds, (at or datetime.datetime.now(
             datetime.timezone.utc)).isoformat(timespec="seconds")
         if at is not None else utcnow()))
    logger.info("dial attempt lead=%s user=%s outcome=%s permitted_by=%s "
                "(number redacted)", lead["id"],
                user["id"] if user else None, outcome, permitted_by)
    return cur.lastrowid
