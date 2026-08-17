"""Appointment confirmations (SPEC PART 6 §T1).

**The app NEVER sends a text.** It reminds the AGENT to send a confirmation
message by hand from their own phone (texting lives in Ringy, outside the
app — R1), suggests the wording, and records that they did it. There is no
SMS integration anywhere in this module.

Two stamps on the appointment/scheduled `interactions` row carry the whole
feature:

- `confirmation_sent_at` — the agent pressed "Confirmed sent".
- `confirmation_notified_at` — the worker fired this appointment's ONE
  reminder notification (pure idempotency marker).

Everything else is DERIVED at read time. There is no confirmation task
table and no stored due-list: `pending_confirmations`, `unconfirmed_
upcoming` and `awaiting_outcome` are queries, so an appointment that moves,
gets cancelled or gets confirmed simply stops matching.

**Trigger math.** The reminder fires at the LATER of
  (a) `appt_confirm_anchor` (default 08:00) on the appointment's date in
      the LEAD's local timezone — never nag before the lead's morning, and
  (b) `appointment_at` minus `appt_confirm_lead_hours` (default 8) —
      never sit on a reminder until it is too late to matter.
A 10 AM appointment therefore triggers at 08:00 (8h earlier would be 2 AM);
an 8 PM appointment triggers at noon (the anchor would be 12h early). An
appointment booked AFTER its own trigger time is due immediately — that
falls straight out of the comparison, no special case.

**The anchor yields rather than suppress the reminder.** If the max lands
at or after the appointment itself the actionable window `[trigger,
appointment_at)` is empty and the reminder could never fire at all, so
(b) wins alone: a 6 AM appointment reminds at 10 PM the night before, an
8 AM one from midnight. The anchor is there to avoid nagging at 2 AM, not
to silence the feature — the fail-safe direction is early, never never.

EVERY query here is tenant-scoped by account_id (SPEC S1); account_id=None
resolves through `auth.current_account_id()` exactly like settings do.
Helpers never commit inside a caller's open transaction. Cross-package
imports are deferred inside the functions that use them.
"""
import datetime
import logging
import re
from typing import Optional
from zoneinfo import ZoneInfo

from leadflow.audit import log_event
from leadflow.db import utcnow

logger = logging.getLogger("leadflow.confirmations")

DEFAULT_TZ = "America/New_York"

# `appt_confirm_lead_hours` bounds. ONE WEEK is the ceiling: "hours before
# an appointment" is a same-day-to-next-day nudge, and a reminder more
# than a week out is not about this appointment any more — it is noise the
# agent will have forgotten by the time it matters. The hard reason a
# ceiling must exist at all is arithmetic: `appointment_at - timedelta(
# hours=N)` raises OverflowError from roughly 17.7 million hours up, and
# an unbounded value turned /today, the dashboard and every lead page into
# a 500. Both the settings form and `_lead_hours` enforce this range.
MIN_LEAD_HOURS = 1
MAX_LEAD_HOURS = 168
DEFAULT_LEAD_HOURS = 8

# Merge fields the confirmation template understands — the SINGLE source
# of truth. `_merge_values` builds exactly these keys (a test asserts the
# two agree) and the Settings help text is rendered from this tuple, so
# the list cannot drift away from what actually substitutes. Anything else
# in braces renders as an empty string — never a crash, never a raw brace.
MERGE_FIELDS = ("first_name", "name", "appointment_time", "agent_name",
                "phone", "state")

_MERGE_RE = re.compile(r"\{([A-Za-z_][A-Za-z0-9_]*)\}")


# ---------------------------------------------------------------- helpers

def _resolve_account(account_id):
    # type: (object) -> int
    if account_id is None:
        from leadflow.auth import current_account_id  # deferred: avoid cycle
        return current_account_id()
    return int(account_id)


def _setting(db, key, account_id):
    from leadflow.settings import get_setting  # deferred: avoid cycle
    return get_setting(key, db=db, account_id=account_id)


def _lead_zone(db, lead, account_id=None):
    """The LEAD's timezone (they are the one reading the text): their own
    `timezone` column, falling back to the account's my_timezone and then
    to America/New_York. Never raises."""
    name = None
    try:
        name = lead["timezone"]
    except (KeyError, IndexError, TypeError):
        name = None
    if name:
        try:
            return ZoneInfo(str(name))
        except Exception:
            logger.warning("unknown lead timezone %r; falling back", name)
    try:
        account_id = _resolve_account(account_id)
        return ZoneInfo(str(_setting(db, "my_timezone", account_id)
                            or DEFAULT_TZ))
    except Exception:
        return ZoneInfo(DEFAULT_TZ)


def _parse_utc(value):
    # type: (object) -> Optional[datetime.datetime]
    if isinstance(value, datetime.datetime):
        dt = value
    else:
        if not value:
            return None
        try:
            dt = datetime.datetime.fromisoformat(
                str(value).replace("Z", "+00:00"))
        except (ValueError, TypeError):
            return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=datetime.timezone.utc)
    return dt.astimezone(datetime.timezone.utc)


def _anchor_hm(db, account_id):
    """(hour, minute) from appt_confirm_anchor; 08:00 on anything odd."""
    raw = str(_setting(db, "appt_confirm_anchor", account_id) or "08:00")
    try:
        hour, minute = raw.split(":")[:2]
        hour, minute = int(hour), int(minute)
    except (ValueError, TypeError):
        logger.warning("bad appt_confirm_anchor %r; using 08:00", raw)
        return (8, 0)
    if not (0 <= hour <= 23 and 0 <= minute <= 59):
        logger.warning("out-of-range appt_confirm_anchor %r; using 08:00", raw)
        return (8, 0)
    return (hour, minute)


def _lead_hours(db, account_id):
    """`appt_confirm_lead_hours`, CLAMPED to [1, MAX_LEAD_HOURS].

    The settings form enforces the same ceiling, but this clamp is
    defensive on purpose: a value already stored — by an older build, a
    hand-edited settings row, an import — must never be able to 500 a
    page. `appointment_at - timedelta(hours=N)` raises OverflowError from
    about 17.7 million hours up, and `trigger_at` runs on /today, on the
    dashboard, on every lead page and inside the worker."""
    try:
        hours = int(_setting(db, "appt_confirm_lead_hours", account_id))
    except (TypeError, ValueError):
        return DEFAULT_LEAD_HOURS
    if hours < MIN_LEAD_HOURS:
        return DEFAULT_LEAD_HOURS
    return min(hours, MAX_LEAD_HOURS)


def _lead_name(lead, lead_id=None):
    name = ("%s %s" % (_get(lead, "first_name") or "",
                       _get(lead, "last_name") or "")).strip()
    return name or ("Lead #%s" % (lead_id if lead_id is not None
                                  else _get(lead, "lead_id")))


def _get(row, key, default=None):
    """sqlite3.Row and dict both, without KeyError."""
    try:
        value = row[key]
    except (KeyError, IndexError, TypeError):
        return default
    return default if value is None else value


def local_time_label(db, lead, appointment_at, account_id=None):
    # type: (object, object, object, object) -> str
    """The appointment in the LEAD's local clock with its zone
    abbreviation, e.g. '2:30 PM EDT'. Empty string on a bad timestamp."""
    dt = _parse_utc(appointment_at)
    if dt is None:
        return ""
    local = dt.astimezone(_lead_zone(db, lead, account_id=account_id))
    return ("%d:%02d %s %s" % (local.hour % 12 or 12, local.minute,
                               "AM" if local.hour < 12 else "PM",
                               local.tzname() or "")).strip()


def local_datetime_label(db, lead, appointment_at, account_id=None):
    # type: (object, object, object, object) -> str
    """Day + time in the lead's local clock, e.g. 'Wed Aug 13, 2:30 PM EDT'
    — what the agent needs to read on a list of appointments."""
    dt = _parse_utc(appointment_at)
    if dt is None:
        return ""
    local = dt.astimezone(_lead_zone(db, lead, account_id=account_id))
    return "%s %s %d, %s" % (
        local.strftime("%a"), local.strftime("%b"), local.day,
        local_time_label(db, lead, appointment_at, account_id=account_id))


# ---------------------------------------------------------------- trigger

def trigger_at(db, appointment_at, lead, account_id=None, created_at=None):
    # type: (object, object, object, object, object) -> Optional[str]
    """When the agent should be reminded to text this lead — UTC ISO.

    The LATER of the lead-local anchor time on the appointment's own date
    and `appointment_at` minus the lead-hours window (see the module
    docstring for the worked examples).

    **The anchor YIELDS when honouring it would mean never reminding at
    all.** The actionable interval is `[trigger, appointment_at)`, so a
    trigger at or after the appointment is an EMPTY window: the reminder
    could never fire and the appointment would silently roll straight
    into "needs an outcome". That is what an early-morning appointment
    hit — with the shipping defaults a 06:00 appointment computed a
    trigger two hours after itself. So when `max(...)` is not strictly
    before the appointment, the `appt - lead_hours` bound wins on its own
    (a 6 AM appointment reminds at 10 PM the night before; an 8 AM one
    from midnight), and if even that is not before the appointment — only
    reachable with a lead-hours value `_lead_hours` would never return —
    the appointment's own `created_at` wins, i.e. due the moment it was
    booked.

    The anchor exists to avoid nagging the lead at 2 AM, not to suppress
    the reminder entirely; the fail-safe direction is EARLY, never NEVER.

    Returns None only when appointment_at cannot be parsed."""
    account_id = _resolve_account(account_id)
    appt = _parse_utc(appointment_at)
    if appt is None:
        return None
    zone = _lead_zone(db, lead, account_id=account_id)
    local = appt.astimezone(zone)
    hour, minute = _anchor_hm(db, account_id)
    # The anchor lands on the appointment's LOCAL date. datetime.combine
    # with the zone attached resolves DST folds/gaps the way the lead's
    # own clock does.
    anchor = datetime.datetime.combine(
        local.date(), datetime.time(hour=hour, minute=minute), tzinfo=zone
    ).astimezone(datetime.timezone.utc)
    lead_window = appt - datetime.timedelta(hours=_lead_hours(db, account_id))
    trigger = max(anchor, lead_window)
    if trigger >= appt:
        trigger = lead_window
    if trigger >= appt:
        booked = _parse_utc(created_at)
        if booked is not None and booked < appt:
            trigger = booked
    return trigger.isoformat(timespec="seconds")


def _row_created_at(row):
    """The APPOINTMENT row's created_at. The list queries alias it so it
    cannot collide with the joined lead's own created_at; a bare
    interactions row passed straight to `is_due` still has `created_at`."""
    return (_get(row, "appointment_created_at")
            or _get(row, "created_at"))


def is_due(db, appointment_row, lead, now_dt=None, account_id=None):
    # type: (object, object, object, object, object) -> bool
    """True while this appointment's confirmation is ACTIONABLE: the
    trigger has passed and the appointment itself has not.

    An appointment booked AFTER its own trigger time is due immediately —
    that is just `now >= trigger`, no special case.

    The window is the HALF-OPEN interval `[trigger, appointment_at)` the
    whole feature is built on, and this helper is the one place that has
    to close it itself. The three list queries get the upper bound free
    from SQL (`appointment_at > now` for the confirmation lists,
    `<= now` for `awaiting_outcome`), so they flip cleanly at the
    appointment; `is_due` compared against the trigger alone and stayed
    True forever afterwards. Lead detail is its only caller, and it
    therefore kept offering "Text this from your phone, then mark it
    sent" — with a message naming a time that had already gone by — for
    exactly the appointments /today had already moved into "Appointments
    needing an outcome". A passed appointment needs an OUTCOME, not a
    confirmation text."""
    appointment_at = _get(appointment_row, "appointment_at")
    trigger = trigger_at(db, appointment_at, lead, account_id=account_id,
                         created_at=_row_created_at(appointment_row))
    if trigger is None:
        return False
    if now_dt is None:
        now_dt = datetime.datetime.now(datetime.timezone.utc)
    now_dt = _parse_utc(now_dt)
    appt = _parse_utc(appointment_at)
    if appt is not None and now_dt >= appt:
        return False
    return now_dt >= _parse_utc(trigger)


# ---------------------------------------------------------------- message

def _merge_values(db, lead, appointment_at, account_id):
    """The substitution map for one lead + appointment.

    Its keys ARE `MERGE_FIELDS` — that is asserted by a test, so neither
    the renderer nor the Settings help text can drift from the other."""
    first_name = _get(lead, "first_name") or ""
    last_name = _get(lead, "last_name") or ""
    return {
        "first_name": first_name,
        "name": ("%s %s" % (first_name, last_name)).strip(),
        "appointment_time": local_time_label(db, lead, appointment_at,
                                             account_id=account_id),
        "agent_name": str(_setting(db, "identity_name", account_id) or ""),
        "phone": _get(lead, "phone") or "",
        "state": _get(lead, "state") or "",
    }


def render_message(db, lead, appointment_at, account_id=None):
    # type: (object, object, object, object) -> str
    """Fill `appt_confirm_template` for one lead + appointment.

    The merge fields are `MERGE_FIELDS`. {agent_name} is the identity_name
    setting; {appointment_time} renders in the LEAD's local timezone with
    its zone abbreviation. Missing values — and any unknown field — render
    as an empty string, so a template never crashes and never leaks a raw
    brace."""
    account_id = _resolve_account(account_id)
    template = str(_setting(db, "appt_confirm_template", account_id) or "")
    values = _merge_values(db, lead, appointment_at, account_id)
    return _MERGE_RE.sub(lambda m: str(values.get(m.group(1), "")), template)


# ---------------------------------------------------------------- queries

# Outcome children that mean the appointment is NOT happening (T1). A
# `no_show` or `showed` child is an appointment that DID reach its time.
_TERMINAL_SQL = "('cancelled','rescheduled')"

_FUTURE_SCHEDULED_SQL = (
    "SELECT i.id, i.lead_id, i.appointment_at, i.confirmation_sent_at, "
    "i.confirmation_notified_at, i.note, "
    "i.created_at AS appointment_created_at, "
    "l.first_name, l.last_name, l.phone, l.state, l.timezone, "
    "l.pipeline_stage "
    "FROM interactions i JOIN leads l ON l.id = i.lead_id "
    "WHERE i.account_id = ? AND l.account_id = ? "
    "AND i.itype = 'appointment' AND i.disposition = 'scheduled' "
    "AND i.appointment_at IS NOT NULL AND i.appointment_at > ? "
    "AND i.confirmation_sent_at IS NULL "
    "AND NOT EXISTS (SELECT 1 FROM interactions o WHERE o.parent_id = i.id "
    "                AND o.disposition IN %s) "
    "ORDER BY i.appointment_at, i.id" % _TERMINAL_SQL
)


def _row_dict(db, row, account_id, now_dt):
    """One appointment row shaped for the UI (and for notify_due)."""
    appointment_at = row["appointment_at"]
    trigger = trigger_at(db, appointment_at, row, account_id=account_id,
                         created_at=_row_created_at(row))
    return {
        "id": row["id"],
        "appointment_id": row["id"],
        "lead_id": row["lead_id"],
        "lead_name": _lead_name(row, lead_id=row["lead_id"]),
        "phone": _get(row, "phone") or "",
        "state": _get(row, "state") or "",
        "pipeline_stage": _get(row, "pipeline_stage") or "",
        "appointment_at": appointment_at,
        "appointment_local": local_datetime_label(
            db, row, appointment_at, account_id=account_id),
        "appointment_time": local_time_label(
            db, row, appointment_at, account_id=account_id),
        "trigger_at": trigger,
        "due": bool(trigger is not None
                    and now_dt >= _parse_utc(trigger)),
        "confirmation_sent_at": _get(row, "confirmation_sent_at"),
        "confirmation_notified_at": _get(row, "confirmation_notified_at"),
        "message": render_message(db, row, appointment_at,
                                  account_id=account_id),
    }


def _future_rows(db, account_id, now_dt):
    now_iso = now_dt.isoformat(timespec="seconds")
    return db.execute(_FUTURE_SCHEDULED_SQL,
                      (account_id, account_id, now_iso)).fetchall()


def _now(now):
    if now is None:
        return datetime.datetime.now(datetime.timezone.utc)
    return _parse_utc(now)


DASHBOARD_HORIZON_DAYS = 14
DASHBOARD_LIMIT = 10
# The mirror of DASHBOARD_HORIZON_DAYS for the awaiting-outcome panel: how
# far BACK the dashboard summary looks. /today carries the unbounded list.
DASHBOARD_OUTCOME_FLOOR_DAYS = 14


def unconfirmed_upcoming(db, account_id=None, now=None, horizon_days=None,
                         limit=None):
    # type: (object, object, object, object, object) -> list
    """EVERY future scheduled appointment with no confirmation sent, due or
    not — the answer to "is an appointment approaching without a
    confirmation going out". Each row carries `due` so the UI can make the
    actionable ones urgent. Soonest first.

    `horizon_days` and `limit` exist for the DASHBOARD panel, which is a
    summary: 40 appointments spread over 40 days used to render 40 rows
    inside "Needs attention". Both are opt-in and neither can hide an
    ACTIONABLE row — every `due` row is kept regardless, and the cap only
    trims the not-yet-due tail. Callers that pass them must say so in the
    UI; `unconfirmed_upcoming_count` gives the untrimmed total for that.
    /today keeps the full unlimited list."""
    account_id = _resolve_account(account_id)
    now_dt = _now(now)
    rows = [_row_dict(db, row, account_id, now_dt)
            for row in _future_rows(db, account_id, now_dt)]
    if horizon_days is None and limit is None:
        return rows
    edge = None
    if horizon_days is not None:
        edge = now_dt + datetime.timedelta(days=int(horizon_days))
    kept = []
    for row in rows:
        if row["due"]:
            kept.append(row)       # actionable: never trimmed
            continue
        if edge is not None:
            appt = _parse_utc(row["appointment_at"])
            if appt is not None and appt > edge:
                continue
        if limit is not None and len(kept) >= int(limit):
            continue
        kept.append(row)
    return kept


def unconfirmed_upcoming_count(db, account_id=None, now=None):
    # type: (object, object, object) -> int
    """How many rows `unconfirmed_upcoming` would return untrimmed, so a
    capped surface can say "showing the next N of M" instead of silently
    dropping the tail."""
    account_id = _resolve_account(account_id)
    return len(_future_rows(db, account_id, _now(now)))


def pending_confirmations(db, account_id=None, now=None):
    # type: (object, object, object) -> list
    """The appointments that need a confirmation text RIGHT NOW: future,
    unconfirmed, not cancelled/rescheduled, and past their trigger time.
    Soonest appointment first."""
    return [row for row in unconfirmed_upcoming(db, account_id=account_id,
                                                now=now)
            if row["due"]]


def has_pending_confirmations(db, account_id=None, now=None):
    # type: (object, object, object) -> bool
    """Cheap EXISTS pre-check for the worker: does this tenant have ANY
    future scheduled appointment still lacking both stamps?

    It MUST apply the same terminal-outcome exclusion `pending_confirmations`
    applies. Without it, one cancelled-but-still-future unconfirmed
    appointment answered True on every 30-second tick forever while
    `notify_due` — which does apply the exclusion — found nothing to do.

    "Cheap" here means one small query over a tenant's own appointment
    rows, not an indexed lookup: `EXPLAIN QUERY PLAN` reports SCAN on
    `interactions` (only `(lead_id)` and `(user_id, created_at)` are
    indexed). At Ancora's scale that scan is free, and inventing an
    index to justify the adjective would be worse than saying so."""
    account_id = _resolve_account(account_id)
    now_iso = _now(now).isoformat(timespec="seconds")
    return db.execute(
        "SELECT 1 FROM interactions i JOIN leads l ON l.id = i.lead_id "
        "WHERE i.account_id = ? AND l.account_id = ? "
        "AND i.itype = 'appointment' AND i.disposition = 'scheduled' "
        "AND i.appointment_at IS NOT NULL AND i.appointment_at > ? "
        "AND i.confirmation_sent_at IS NULL "
        "AND i.confirmation_notified_at IS NULL "
        "AND NOT EXISTS (SELECT 1 FROM interactions o "
        "                WHERE o.parent_id = i.id "
        "                AND o.disposition IN %s) LIMIT 1" % _TERMINAL_SQL,
        (account_id, account_id, now_iso)).fetchone() is not None


def _awaiting_outcome_rows(db, account_id, now_dt, floor_days=None):
    """The raw rows behind awaiting_outcome, so the list and its count
    cannot drift apart (the same pairing unconfirmed_upcoming has)."""
    sql = (
        "SELECT i.id, i.lead_id, i.appointment_at, i.confirmation_sent_at, "
        "i.confirmation_notified_at, i.note, "
        "i.created_at AS appointment_created_at, "
        "l.first_name, l.last_name, l.phone, l.state, l.timezone, "
        "l.pipeline_stage "
        "FROM interactions i JOIN leads l ON l.id = i.lead_id "
        "WHERE i.account_id = ? AND l.account_id = ? "
        "AND i.itype = 'appointment' AND i.disposition = 'scheduled' "
        "AND i.appointment_at IS NOT NULL AND i.appointment_at <= ? "
        "AND NOT EXISTS (SELECT 1 FROM interactions o "
        "                WHERE o.parent_id = i.id) ")
    params = [account_id, account_id, now_dt.isoformat(timespec="seconds")]
    if floor_days is not None:
        floor = now_dt - datetime.timedelta(days=int(floor_days))
        sql += "AND i.appointment_at >= ? "
        params.append(floor.isoformat(timespec="seconds"))
    return db.execute(sql + "ORDER BY i.appointment_at, i.id",
                      tuple(params)).fetchall()


def awaiting_outcome(db, account_id=None, now=None, floor_days=None,
                     limit=None):
    # type: (object, object, object, object, object) -> list
    """Scheduled appointments whose time has PASSED with no outcome row of
    any kind. They stay flagged until the agent marks showed / no-showed /
    rescheduled / cancelled. Most overdue (oldest) first.

    `floor_days` and `limit` exist for the DASHBOARD panel, which is a
    SUMMARY: unbounded in both directions, one long-forgotten appointment
    per month buries the rest of "Needs attention" forever, and the panel's
    layout can never be judged. Both default to None, so /today keeps the
    complete list — the same split unconfirmed_upcoming already uses."""
    account_id = _resolve_account(account_id)
    now_dt = _now(now)
    rows = _awaiting_outcome_rows(db, account_id, now_dt,
                                  floor_days=floor_days)
    if limit is not None:
        rows = rows[:int(limit)]
    return [_row_dict(db, row, account_id, now_dt) for row in rows]


def awaiting_outcome_count(db, account_id=None, now=None):
    # type: (object, object, object) -> int
    """How many rows `awaiting_outcome` would return untrimmed and with no
    floor, so a capped surface can say "showing N of M" rather than
    silently dropping the tail."""
    account_id = _resolve_account(account_id)
    return len(_awaiting_outcome_rows(db, account_id, _now(now)))


# ---------------------------------------------------------------- writes

def mark_confirmed(db, appointment_id, user_id, account_id=None):
    # type: (object, int, Optional[int], object) -> bool
    """Record that the agent sent the confirmation text by hand.

    Tenant boundary: account_id is in the WHERE clause, so another
    account's appointment id can never be confirmed. Idempotent — an
    already-confirmed appointment returns False and changes nothing.
    Writes an `appointment_confirmed` event. Never commits inside a
    caller's open transaction."""
    account_id = _resolve_account(account_id)
    row = db.execute(
        "SELECT id, lead_id FROM interactions WHERE id = ? AND account_id = ? "
        "AND itype = 'appointment' AND disposition = 'scheduled' "
        "AND confirmation_sent_at IS NULL",
        (appointment_id, account_id)).fetchone()
    if row is None:
        return False
    own = not db.in_transaction
    stamp = utcnow()
    db.execute(
        "UPDATE interactions SET confirmation_sent_at = ? WHERE id = ? "
        "AND account_id = ? AND confirmation_sent_at IS NULL",
        (stamp, appointment_id, account_id))
    log_event(db, row["lead_id"], "appointment_confirmed",
              "confirmation text sent by hand for appointment %d"
              % appointment_id, user_id=user_id)
    if own:
        db.commit()
    logger.info("appointment %s confirmed by user=%s", appointment_id, user_id)
    return True


def notify_due(db, account_id):
    # type: (object, int) -> int
    """The worker pass: ONE owner reminder per appointment whose trigger
    has passed while it is still future, unconfirmed and un-notified.

    Safe to call every tick — `confirmation_notified_at` is stamped BEFORE
    the notification goes out, so a reminder can at worst be lost, never
    repeated. Cancelled/rescheduled appointments are excluded (they share
    the pending_confirmations query): reminding an agent to confirm an
    appointment that is not happening would be a bug, not a feature.
    Returns how many reminders fired."""
    account_id = _resolve_account(account_id)
    now_dt = _now(None)
    fired = 0
    for item in pending_confirmations(db, account_id=account_id, now=now_dt):
        if item["confirmation_notified_at"]:
            continue
        own = not db.in_transaction
        cur = db.execute(
            "UPDATE interactions SET confirmation_notified_at = ? "
            "WHERE id = ? AND account_id = ? "
            "AND confirmation_notified_at IS NULL",
            (utcnow(), item["appointment_id"], account_id))
        if own:
            db.commit()
        if not cur.rowcount:
            continue  # another tick/worker already claimed it
        body = ("Text %s to confirm today's appointment at %s — %s"
                % (item["lead_name"],
                   item["appointment_time"] or item["appointment_at"],
                   item["phone"] or "no phone on file"))
        try:
            from leadflow.notify import notify as owner_notify
            owner_notify(db, "task", body, lead_id=item["lead_id"])
        except ImportError:
            logger.warning(
                "leadflow.notify unavailable; confirmation reminder skipped")
        fired += 1
    if fired:
        logger.info("appointment confirmation reminders fired: %d "
                    "(account %s)", fired, account_id)
    return fired
