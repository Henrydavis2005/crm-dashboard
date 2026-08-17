"""Consent dates and the dialer's consent-age cutoff.

DIALER ONLY, and that boundary is the point of this module existing at
all. Nothing here is imported by `leadflow/outreach/` — not the
dispatcher, not the scheduler, not `smtp_send` — so an expired consent
date changes nothing about email. A lead whose consent aged out still
gets its sequence, still gets replies, still gets quotes. It stops being
DIALABLE, and that is the whole of it. tests/test_consent_date.py asserts
the import boundary directly, because a boundary nothing checks is a
comment.

WHY A DATE AT ALL. The calling system was removed once already over
tenant compliance exposure. It comes back with the rule enforced in code:
the app refuses to dial a lead it cannot show consent for, rather than
trusting anybody to have scrubbed the list. That means every lead needs a
date, every intake path has to produce one, and a path that cannot
produce one must REFUSE THE ROW — never stamp today's date on it, which
would manufacture the exact record the rule exists to require.

`leads.consent_date` is `YYYY-MM-DD` (CLAUDE.md: dates, not datetimes)
or NULL. NULL means "we do not know", which is treated exactly like an
expired date at the dialer and differently in the UI, because the two
have different fixes: an unknown date needs a source, an expired one
needs a fresh lead.

## 180 DAYS HERE IS NOT THE 45 DAYS IN `va_send`

`DEFAULT_MAX_AGE_DAYS = 180` is a COMPLIANCE ceiling: the outer limit past
which a prior express written consent is too old to rely on for a call at
all. Crossing it is a legal problem, and it is a SETTING because counsel
and carriers land in different places.

`va_send.SEND_MAX_AGE_DAYS = 45` is an OPERATIONAL floor for handing work
to an assistant — a seven-week-old inquiry is legally callable and
commercially cold. It is a CONSTANT because it is a judgement about how to
spend somebody's day, not about what the law permits.

A lead 60 days old is refused THERE and permitted HERE, and that is
correct. Making either read the other would start calls on four-month-old
leads or stop the dialer returning callbacks. Two names, two homes, two
reasons.
"""
import datetime
import logging
import re
from typing import Optional

logger = logging.getLogger("leadflow.consent")

# The cutoff, in days. SIX MONTHS by default, per tenant, editable in
# Settings. It is a setting rather than a constant because the number is a
# policy judgement that varies by carrier and by state, and a tenant who
# needs 90 must not have to fork the app to get it.
MAX_AGE_SETTING = "dialer_consent_max_age_days"
DEFAULT_MAX_AGE_DAYS = 180

# What `state_of` can return.
OK = "ok"
EXPIRED = "expired"
MISSING = "missing"

_ISO = re.compile(r"^(\d{4})-(\d{1,2})-(\d{1,2})")
_US = re.compile(r"^(\d{1,2})[/-](\d{1,2})[/-](\d{2}|\d{4})$")


def parse_date(raw, today=None):
    # type: (object, Optional[datetime.date]) -> Optional[str]
    """One CSV cell (or typed date) -> 'YYYY-MM-DD', or None if unusable.

    Accepts the formats a real export actually carries: ISO dates, ISO
    datetimes (the date half is taken), and US M/D/Y with either
    separator and a two- or four-digit year. US order, not day-first:
    these files come from US CRMs.

    REFUSES A FUTURE DATE, which is doing more work than it looks like.
    It is the check that catches a day-first file (13/01/2026 fails to
    parse; 01/13/2026 would be month 13), catches a two-digit year that
    landed in the wrong century, and — the reason it is here — makes
    "consent was obtained tomorrow" impossible to record. A date nobody
    can have obtained yet is not a date, it is a placeholder.
    """
    if raw is None:
        return None
    if isinstance(raw, datetime.datetime):
        candidate = raw.date()
    elif isinstance(raw, datetime.date):
        candidate = raw
    else:
        text = str(raw).strip()
        if not text:
            return None
        candidate = _parse_text(text)
        if candidate is None:
            return None
    today = today or datetime.date.today()
    if candidate > today:
        return None
    return candidate.isoformat()


def _parse_text(text):
    # type: (str) -> Optional[datetime.date]
    match = _ISO.match(text)
    if match:
        year, month, day = (int(g) for g in match.groups())
        return _safe_date(year, month, day)
    match = _US.match(text)
    if match:
        month, day, year = (int(g) for g in match.groups())
        if year < 100:
            # Two digits are always this century. The future check in
            # parse_date then rejects anything that lands ahead of today,
            # so a '99' cannot quietly become 2099.
            year += 2000
        return _safe_date(year, month, day)
    return None


def _safe_date(year, month, day):
    # type: (int, int, int) -> Optional[datetime.date]
    try:
        return datetime.date(year, month, day)
    except ValueError:
        return None      # month 13, day 32, Feb 30 — all land here


def date_of(timestamp):
    # type: (Optional[str]) -> Optional[str]
    """The date half of a stored UTC ISO timestamp, for the intake paths
    that derive consent from when the inquiry arrived."""
    if not timestamp:
        return None
    return parse_date(str(timestamp)[:10],
                      today=datetime.date.today())


def max_age_days(db=None, account_id=None):
    # type: (object, Optional[int]) -> int
    """The tenant's cutoff. FAILS CLOSED to the default rather than to no
    cutoff: a settings read that throws must not turn the compliance rule
    off, and 180 days is the conservative answer for everyone."""
    try:
        from leadflow.settings import get_setting
        value = int(get_setting(MAX_AGE_SETTING, db=db,
                                account_id=account_id))
    except Exception:
        logger.exception("could not read %s; using the %d-day default",
                         MAX_AGE_SETTING, DEFAULT_MAX_AGE_DAYS)
        return DEFAULT_MAX_AGE_DAYS
    if value < 1:
        logger.warning("%s is %r; using the %d-day default",
                       MAX_AGE_SETTING, value, DEFAULT_MAX_AGE_DAYS)
        return DEFAULT_MAX_AGE_DAYS
    return value


def age_days(consent_date, today=None):
    # type: (Optional[str], Optional[datetime.date]) -> Optional[int]
    """Whole days since consent, or None if there is no usable date."""
    if not consent_date:
        return None
    parsed = _parse_text(str(consent_date))
    if parsed is None:
        return None
    return ((today or datetime.date.today()) - parsed).days


def state_of(consent_date, max_age=None, today=None):
    # type: (Optional[str], Optional[int], Optional[datetime.date]) -> str
    """OK, EXPIRED or MISSING for one lead's consent date.

    A date that will not parse reads as MISSING, not OK. Every path that
    writes the column goes through `parse_date`, so an unparseable value
    is a row written before this block or by hand — either way the honest
    answer is that we do not know when consent was given.
    """
    age = age_days(consent_date, today=today)
    if age is None:
        return MISSING
    if max_age is None:
        max_age = DEFAULT_MAX_AGE_DAYS
    return EXPIRED if age >= max_age else OK


def is_dialable(consent_date, max_age=None, today=None):
    # type: (Optional[str], Optional[int], Optional[datetime.date]) -> bool
    """The one predicate the dialer will ask (block 3 wires the gate).

    Consent alone — this says nothing about suppression, quiet hours, the
    attempt cap or `phone_bad`, each of which has its own check and none
    of which belongs here.
    """
    return state_of(consent_date, max_age=max_age, today=today) == OK


def explain(consent_date, max_age=None, today=None):
    # type: (Optional[str], Optional[int], Optional[datetime.date]) -> Optional[str]
    """Why this lead cannot be called, in words a VA can act on. None
    when it can be."""
    if max_age is None:
        max_age = DEFAULT_MAX_AGE_DAYS
    state = state_of(consent_date, max_age=max_age, today=today)
    if state == OK:
        return None
    if state == MISSING:
        return "No consent date on this lead, so it cannot be called."
    return ("Consent is %d days old — past the %d-day limit, so this lead "
            "cannot be called." % (age_days(consent_date, today=today),
                                   max_age))
