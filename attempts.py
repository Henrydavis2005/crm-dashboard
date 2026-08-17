"""Guards on LOGGING a call attempt.

Dialing left the app when the internal calling system was removed: a VA
calls from Ringy and records the outcome here. That moved three protections
that used to live in the dialer's pre-dial gate ladder onto the LOGGING
route, because the log is now the only moment Ancora sees a call at all.

  1. QUIET HOURS. The 8am-8pm lead-local calling window. The dialer enforced
     it before placing a call; nothing enforced it on the log except for a
     lead that happened to be in today's VA queue, which left every other
     entry point (lead detail, search, a direct URL) unguarded.
  2. PER-LEAD DAILY CAP. New. A hard ceiling on attempts per lead per
     lead-local calendar day.
  3. DUPLICATE PROTECTION. The dialer's `DUPE_DIAL_SECONDS` window, ported
     unchanged in value, so a double-clicked submit cannot write two rows.

All three are enforced SERVER-SIDE in `check()`, which every attempt-logging
route calls before it writes anything. A refusal writes no interaction row.

WHY NOT INSIDE `interactions.log_call`: that function is also called by
`overflow._mirror_disposition`, which replays a promoting outcome onto a
freshly promoted lead. Those replays are bookkeeping, not new calls — they
must not be quiet-hours blocked at 9pm or counted against the day's cap.
The guard therefore sits at the ROUTE, which is the boundary where a human
is actually claiming to have made a call.

THE DAY BOUNDARY is the LEAD's local calendar day, from `leads.timezone`
(overflow rows carry the same column). That column is NOT NULL DEFAULT
'America/New_York' and is populated by `tz.lead_timezone`, which itself
falls back to America/New_York; `tz._zone` falls back again on an
unparseable value. So a lead whose timezone cannot be derived is treated as
EASTERN — the earliest US zone, which closes the calling window soonest and
rolls the day over soonest. That errs toward refusing an attempt rather than
allowing one.
"""
import datetime
import logging
from typing import Optional
from zoneinfo import ZoneInfo

from leadflow.tz import DEFAULT_TZ

logger = logging.getLogger("leadflow.attempts")

# Ported from the deleted twilio_client.DUPE_DIAL_SECONDS (same value 60).
# A lead may not have a second attempt logged by the SAME user this soon.
DEFAULT_DUPE_SECONDS = 60


def _int_setting(db, key, default, account_id=None):
    from leadflow.settings import get_setting
    try:
        return int(get_setting(key, db=db, account_id=account_id))
    except Exception:
        logger.exception("could not read %s; using %s", key, default)
        return default


def max_attempts_per_day(db, account_id=None):
    # type: (object, object) -> int
    """The per-lead daily attempt cap (default 3). Values below 1 are
    clamped to 1 — a cap of zero would mean the VA can never log anything,
    which is a misconfiguration rather than an intent."""
    return max(1, _int_setting(db, "max_attempts_per_lead_per_day", 3,
                               account_id))


def dupe_seconds(db, account_id=None):
    # type: (object, object) -> int
    """The double-submit window in seconds (default 60). Zero disables it."""
    return max(0, _int_setting(db, "attempt_dupe_seconds",
                               DEFAULT_DUPE_SECONDS, account_id))


def _zone(row):
    """The LEAD's zone. Works for a `leads` row and an `overflow_leads` row
    alike — both carry `timezone`. Never raises: an absent or unparseable
    value reads as Eastern, matching tz._zone's own fallback."""
    try:
        name = row["timezone"]
    except (IndexError, KeyError, TypeError):
        name = None
    try:
        return ZoneInfo(name or DEFAULT_TZ)
    except Exception:
        logger.warning("unknown lead timezone %r; using %s", name, DEFAULT_TZ)
        return ZoneInfo(DEFAULT_TZ)


def local_day_bounds(row, at=None):
    # type: (object, object) -> tuple
    """(start_utc_iso, end_utc_iso, local_date) for the LEAD's calendar day
    containing `at` (default now)."""
    if at is None:
        at = datetime.datetime.now(datetime.timezone.utc)
    zone = _zone(row)
    local = at.astimezone(zone)
    start_local = local.replace(hour=0, minute=0, second=0, microsecond=0)
    end_local = start_local + datetime.timedelta(days=1)

    def _iso(dt):
        return dt.astimezone(datetime.timezone.utc).isoformat(
            timespec="seconds")

    return _iso(start_local), _iso(end_local), local.date().isoformat()


def window_ok(db, row, at=None):
    # type: (object, object, object) -> bool
    """True when `at` is inside the lead-local calling window. Reuses
    `va.call_window_ok`, which reads the SAME quiet_start/quiet_end settings
    the email quiet window and the queue lock use — there is exactly one
    calling-window mechanism in this app."""
    from leadflow import va
    return va.call_window_ok(db, row, at=at)


def window_note(db, row, at=None):
    from leadflow import va
    return va.window_note(db, row, at=at)


def attempts_today(db, account_id, lead_id, at=None, overflow=False):
    # type: (object, int, int, object, bool) -> int
    """How many attempts are already logged against this lead (or pool row)
    in ITS OWN local calendar day."""
    start, end, _day = local_day_bounds(
        _row_for(db, account_id, lead_id, overflow), at=at)
    if overflow:
        return db.execute(
            "SELECT COUNT(*) AS c FROM overflow_attempts "
            "WHERE account_id = ? AND overflow_id = ? "
            "AND created_at >= ? AND created_at < ?",
            (account_id, lead_id, start, end)).fetchone()["c"]
    return db.execute(
        "SELECT COUNT(*) AS c FROM interactions "
        "WHERE account_id = ? AND lead_id = ? AND itype = 'call' "
        "AND created_at >= ? AND created_at < ?",
        (account_id, lead_id, start, end)).fetchone()["c"]


def _row_for(db, account_id, row_id, overflow):
    table = "overflow_leads" if overflow else "leads"
    return db.execute(
        "SELECT * FROM %s WHERE id = ? AND account_id = ?" % table,
        (row_id, account_id)).fetchone()


def _recent_by_user(db, account_id, row_id, user_id, at, overflow):
    """A same-user attempt inside the dupe window, or None."""
    seconds = dupe_seconds(db, account_id)
    if not seconds or user_id is None:
        return None
    cutoff = (at - datetime.timedelta(seconds=seconds)).isoformat(
        timespec="seconds")
    if overflow:
        return db.execute(
            "SELECT id FROM overflow_attempts WHERE account_id = ? "
            "AND overflow_id = ? AND user_id = ? AND created_at >= ? LIMIT 1",
            (account_id, row_id, user_id, cutoff)).fetchone()
    return db.execute(
        "SELECT id FROM interactions WHERE account_id = ? AND lead_id = ? "
        "AND user_id = ? AND itype = 'call' AND created_at >= ? LIMIT 1",
        (account_id, row_id, user_id, cutoff)).fetchone()


def check(db, row, user_id, at=None, overflow=False, account_id=None):
    # type: (object, object, object, object, bool, object) -> Optional[str]
    """THE guard. Returns None when the attempt may be logged, else a
    plain-English refusal to flash. Writes nothing either way EXCEPT the
    cap-block event (see below) — the caller writes nothing on a refusal.

    Order matters: the duplicate check comes FIRST so a double-click gets
    the honest "you just logged this" rather than a confusing cap message.
    """
    from leadflow.audit import log_event
    if at is None:
        at = datetime.datetime.now(datetime.timezone.utc)
    if account_id is None:
        from leadflow.auth import current_account_id
        account_id = current_account_id()
    row_id = row["id"]

    # 1. DOUBLE SUBMIT (ported from the dialer's DUPE_DIAL_SECONDS).
    if _recent_by_user(db, account_id, row_id, user_id, at, overflow) is not None:
        return ("You just logged an attempt on this lead — wait a moment "
                "before logging another.")

    # 2. QUIET HOURS, on EVERY attempt, from any entry point.
    if not window_ok(db, row, at=at):
        return ("Outside this lead's calling hours — %s. Nothing was logged."
                % window_note(db, row, at=at))

    # 3. PER-LEAD DAILY CAP, in the lead's own local day.
    cap = max_attempts_per_day(db, account_id)
    used = attempts_today(db, account_id, row_id, at=at, overflow=overflow)
    if used >= cap:
        _start, _end, day = local_day_bounds(row, at=at)
        # The block itself is a recorded fact: it is the evidence that the
        # cap did work, and TCPA-adjacent limits are worth an audit trail.
        # Overflow rows have no lead id, so their event carries none.
        log_event(db, None if overflow else row_id, "attempt_cap_blocked",
                  "%s attempt refused: %d of %d already logged on %s "
                  "(lead-local)" % ("overflow" if overflow else "call",
                                    used, cap, day),
                  user_id=user_id)
        return ("Daily call limit reached for this lead — %d attempt%s "
                "already logged today (%s, their local time). Nothing was "
                "logged." % (used, "" if used == 1 else "s", day))
    return None
