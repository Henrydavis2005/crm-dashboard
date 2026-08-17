"""Pipeline detection engine (SPEC R3): activity, protection, recovery flags.

Three pieces, all computed live:

- `last_activity(db, lead)` — the newest of: any interactions row except
  outbound email/text mirrors (outbound sends are not lead activity), any
  inbound message, hot_since (a hot stamp is itself activity). A logged
  call attempt is an interactions row, so it counts through the first
  clause.
- `is_claimed(db, lead)` — CLAIMED vs FAIR GAME. A lead is claimed iff ANY:
  a scheduled appointment with no showed/no_show outcome still in the
  future; the admin's own follow-up (followup_on >= today, my_timezone);
  an unworked LEGACY answered_callback with callback_on >= today;
  closed_state='sold'. A follow-up/callback DATE passing with no new
  protection = protection lapses automatically (the outcome protects, not
  the event). Never stored. C1: the `callback_requested` disposition does
  NOT claim — a lead who asked for a callback with nothing yet scheduled
  stays fair game for recovery; it is kept out of the VA queues by its open
  `callback_review` task instead (va._EXCLUDE_SQL), not by protection.
- `scan(db)` — the worker's 5-minute detection pass: hot-expiry
  maintenance, auto-clear of stale flags, and opening recovery_flags
  (fast_ghost | stale_quote | stale_engaged). One open/queued flag per lead
  (the partial unique index backs this); a fast_ghost upgrades an existing
  open/queued stale flag in place, never duplicates. Every rung of the scan
  keys on `closed_state IS NULL` / `is not None` rather than on the
  individual values, so a lead CLOSED FOR ANY REASON — sold, dead, or
  C2a's 'no_number' — is out: its hot stamp is cleared, its open flags are
  cleared ("lead closed"), and it is never a candidate for a new one.

Quiet-time math is done in UTC; day thresholds (stale_quote_days /
stale_days) are days, the ghost threshold (ghost_quiet_hours) is hours.
"""
import datetime
import logging
from typing import Optional
from zoneinfo import ZoneInfo

from leadflow.audit import log_event
from leadflow.db import utcnow

logger = logging.getLogger("leadflow.detection")

FLAG_KINDS = ("fast_ghost", "stale_quote", "stale_engaged")

# `last_activity` as a scalar SQL expression, correlated on a `leads` row
# aliased `l`, for the LIST views (/pipeline, /leads, the VA queue) that
# render a LAST ACTIVITY column for hundreds of leads at a time.
#
# It exists so those columns cannot drift from the engine that decides a
# lead has gone quiet: the same four sources, the same exclusions. Their
# own hand-rolled MAX() used to count OUR outbound — including messages
# still sitting PENDING, whose created_at is simply when the sequence was
# scheduled — so every lead read as freshly active and a lead flagged
# `stale_quote` for two days of silence showed "just now" beside the
# badge saying it had gone quiet.
#
# Multi-argument MAX() is SQLite's scalar max, which returns NULL if any
# argument is NULL: each source is COALESCEd to '' (which sorts below
# every ISO timestamp) and the '' result mapped back to NULL, matching
# last_activity()'s "no recorded activity at all" -> None.
LAST_ACTIVITY_SQL = (
    "NULLIF(MAX("
    "COALESCE((SELECT MAX(i.created_at) FROM interactions i"
    " WHERE i.lead_id = l.id"
    " AND NOT (i.itype IN ('email','text') AND i.direction = 'out')), ''),"
    "COALESCE((SELECT MAX(m.created_at) FROM messages m"
    " WHERE m.lead_id = l.id AND m.direction = 'in'), ''),"
    "COALESCE(l.hot_since, '')"
    "), '')"
)


# ---------------------------------------------------------------- helpers

def _parse_iso(value):
    # type: (object) -> Optional[datetime.datetime]
    if not value:
        return None
    try:
        dt = datetime.datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except (ValueError, TypeError):
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=datetime.timezone.utc)
    return dt


def _my_zone(db):
    from leadflow.settings import get_setting
    try:
        return ZoneInfo(get_setting("my_timezone", db=db))
    except Exception:
        return ZoneInfo("America/New_York")


def _today_local(db, now_dt=None):
    # type: (object, Optional[datetime.datetime]) -> str
    if now_dt is None:
        now_dt = datetime.datetime.now(datetime.timezone.utc)
    return now_dt.astimezone(_my_zone(db)).date().isoformat()


def _lead_row(db, lead):
    if isinstance(lead, int):
        return db.execute("SELECT * FROM leads WHERE id = ?",
                          (lead,)).fetchone()
    return lead


def _int_setting(db, key, default):
    from leadflow.settings import get_setting
    try:
        return int(get_setting(key, db=db))
    except Exception:
        return default


def _is_suppressed(db, lead):
    if db.execute("SELECT 1 FROM suppressions WHERE lead_id = ? LIMIT 1",
                  (lead["id"],)).fetchone() is not None:
        return True
    from leadflow.suppression import is_suppressed  # deferred: avoid cycles
    return is_suppressed(db, email=lead["email"], phone=lead["phone"],
                         account_id=lead["account_id"])


def _phone_usable(lead):
    return bool(lead["phone"]) and not lead["phone_bad"]


# ---------------------------------------------------------------- activity

def last_activity(db, lead):
    # type: (object, object) -> Optional[str]
    """The lead's newest activity stamp (UTC ISO string, or None): any
    interactions row created_at, any inbound message created_at, any DIALED
    CALL, hot_since.

    Outbound email/text MIRROR rows (itype email/text, direction 'out' —
    every real send writes one via interactions.mirror_message) are NOT
    lead activity (SPEC R3 accepted decision: outbound sends are not lead
    activity). Without this filter a lead in an active sequence could
    never go quiet: every sequence send would reset the ghost/stale timers
    and auto-clear open recovery flags.

    There used to be a fourth leg reading the `calls` table, because the
    in-app dialer wrote a row for the DIAL and none for the outcome — a VA
    could connect, log nothing, and the lead would ghost on schedule
    anyway. That leg is gone with the dialer: dialing happens in Ringy now
    and EVERY call reaches this app as a logged attempt, which the
    interactions leg above already counts. The signal is not lost, it
    arrives through the front door instead."""
    lead = _lead_row(db, lead)
    if lead is None:
        return None
    stamps = []
    row = db.execute(
        "SELECT MAX(created_at) AS t FROM interactions WHERE lead_id = ? "
        "AND NOT (itype IN ('email','text') AND direction = 'out')",
        (lead["id"],)).fetchone()
    if row and row["t"]:
        stamps.append(row["t"])
    row = db.execute(
        "SELECT MAX(created_at) AS t FROM messages "
        "WHERE lead_id = ? AND direction = 'in'", (lead["id"],)).fetchone()
    if row and row["t"]:
        stamps.append(row["t"])
    if lead["hot_since"]:
        stamps.append(lead["hot_since"])
    return max(stamps) if stamps else None


# ---------------------------------------------------------------- claimed

def is_claimed(db, lead, now_dt=None):
    # type: (object, object, Optional[datetime.datetime]) -> bool
    """CLAIMED vs FAIR GAME (SPEC R3), computed live, never stored."""
    lead = _lead_row(db, lead)
    if lead is None:
        return False
    if now_dt is None:
        now_dt = datetime.datetime.now(datetime.timezone.utc)
    if lead["closed_state"] == "sold":
        return True
    today = _today_local(db, now_dt)
    if lead["followup_on"] is not None and lead["followup_on"] >= today:
        return True
    # Latest scheduled appointment still ahead and with NO outcome child of
    # any kind. T1: the check is deliberately "any child row", not a list
    # of dispositions — the two terminal outcomes (`cancelled`,
    # `rescheduled`) release the claim exactly like showed/no_show do.
    # Without that a cancelled future appointment would protect the lead
    # from recovery until its original time passed, which is precisely
    # when it is most workable.
    appt = db.execute(
        "SELECT * FROM interactions WHERE lead_id = ? "
        "AND itype = 'appointment' AND disposition = 'scheduled' "
        "ORDER BY id DESC LIMIT 1", (lead["id"],)).fetchone()
    if appt is not None:
        has_outcome = db.execute(
            "SELECT 1 FROM interactions WHERE parent_id = ? LIMIT 1",
            (appt["id"],)).fetchone() is not None
        appt_dt = _parse_iso(appt["appointment_at"])
        if not has_outcome and appt_dt is not None and appt_dt >= now_dt:
            return True
    # Unworked LEGACY callback with callback_on >= today: the lead's
    # LATEST answered_callback counts as worked once ANY later call is
    # logged (the outcome protects, not the event). C1: deliberately still
    # ONLY answered_callback — the new callback_requested disposition never
    # claims a lead (no date, agent decides).
    cb = db.execute(
        "SELECT * FROM interactions WHERE lead_id = ? AND itype = 'call' "
        "AND disposition = 'answered_callback' "
        "ORDER BY id DESC LIMIT 1", (lead["id"],)).fetchone()
    if cb is not None and (cb["callback_on"] or "") >= today:
        worked = db.execute(
            "SELECT 1 FROM interactions WHERE lead_id = ? "
            "AND itype = 'call' AND id > ? LIMIT 1",
            (lead["id"], cb["id"])).fetchone() is not None
        if not worked:
            return True
    return False


# ---------------------------------------------------------------- the scan

def _active_flag(db, lead_id):
    return db.execute(
        "SELECT * FROM recovery_flags WHERE lead_id = ? "
        "AND status IN ('open','queued') ORDER BY id DESC LIMIT 1",
        (lead_id,)).fetchone()


def _clear_flag(db, flag, reason):
    db.execute(
        "UPDATE recovery_flags SET status = 'cleared', resolved_at = ? "
        "WHERE id = ? AND status IN ('open','queued')",
        (utcnow(), flag["id"]))
    log_event(db, flag["lead_id"], "recovery_flag_cleared",
              "%s flag cleared: %s" % (flag["kind"], reason))


def open_recovery_flag(db, lead_id, kind, reason, now_dt=None):
    # type: (object, int, str, str, Optional[object]) -> Optional[int]
    """Open a recovery flag for ONE lead outside the 5-minute scan, applying
    the SAME eligibility gates the scan applies (C1/C2 callback return).

    The scan can only flag what its own thresholds describe; an event that
    makes a lead workable RIGHT NOW — the agent dismissing a
    `callback_review` task without setting a follow-up — has to say so
    itself, or the lead sits outside every queue until the stale_engaged
    clock happens to fire days later.

    No-ops (returning None) when the lead is missing, closed, suppressed,
    claimed, phone-less, a referral, or already carries an open/queued flag
    (the partial unique index forbids a second one). Never commits inside a
    caller's open transaction. Returns the new flag id."""
    if kind not in FLAG_KINDS:
        raise ValueError("unknown recovery flag kind: %s" % kind)
    lead = db.execute("SELECT * FROM leads WHERE id = ?",
                      (lead_id,)).fetchone()
    if lead is None:
        return None
    if now_dt is None:
        now_dt = datetime.datetime.now(datetime.timezone.utc)
    if (lead["closed_state"] is not None
            or lead["referred_by"] is not None
            or not _phone_usable(lead)
            or _is_suppressed(db, lead)
            or is_claimed(db, lead, now_dt=now_dt)):
        return None
    if _active_flag(db, lead["id"]) is not None:
        return None
    own = not db.in_transaction
    now_iso = utcnow()
    cur = db.execute(
        "INSERT INTO recovery_flags (account_id, lead_id, kind, "
        "flagged_at, status, created_at) VALUES (?,?,?,?,'open',?)",
        (lead["account_id"], lead["id"], kind, now_iso, now_iso))
    log_event(db, lead["id"], "recovery_flagged", "%s (%s)" % (kind, reason))
    if own:
        db.commit()
    logger.info("recovery flag opened lead=%s kind=%s reason=%s",
                lead_id, kind, reason)
    return cur.lastrowid


def _quiet_hours(db, lead, now_dt):
    # type: (object, object, datetime.datetime) -> Optional[float]
    """Hours since the lead's last activity (UTC math); None = no activity."""
    last = _parse_iso(last_activity(db, lead))
    if last is None:
        return None
    return (now_dt - last).total_seconds() / 3600.0


def scan(db, now_dt=None, account_id=None):
    # type: (object, Optional[datetime.datetime], Optional[int]) -> dict
    """The R3 detection pass for ONE account (worker job, every 5 minutes,
    live mode only; S1: the worker calls this per active account).

    (a) hot expiry: clear hot_since when it is older than hot_expire_hours
        with no fresher hot signal (every hot signal refreshes hot_since, so
        the stamp itself is the freshest); ALSO clear it on claimed,
        suppressed or closed leads — hot never survives protection/closure.
    (b) open flags: fast_ghost / stale_quote / stale_engaged per SPEC
        thresholds, fair-game leads only, one open/queued flag per lead;
        fast_ghost upgrades an existing open/queued stale flag in place.
    (c) auto-clear open/queued flags when the lead becomes claimed, gets new
        activity after flagged_at, is suppressed/closed, loses its phone, or
        gets referred_by set.

    Returns counters {'hot_expired': n, 'flagged': n, 'cleared': n}.
    """
    from leadflow.auth import current_account_id  # deferred: avoid cycles
    if account_id is None:
        account_id = current_account_id()
    if now_dt is None:
        now_dt = datetime.datetime.now(datetime.timezone.utc)
    ghost_quiet_hours = _int_setting(db, "ghost_quiet_hours", 2)
    hot_expire_hours = _int_setting(db, "hot_expire_hours", 72)
    stale_quote_days = _int_setting(db, "stale_quote_days", 2)
    stale_days = _int_setting(db, "stale_days", 5)

    counters = {"hot_expired": 0, "flagged": 0, "cleared": 0}
    own = not db.in_transaction

    # -- (a) hot-expiry maintenance ---------------------------------------
    expire_cutoff = now_dt - datetime.timedelta(hours=hot_expire_hours)
    for lead in db.execute(
            "SELECT * FROM leads WHERE account_id = ? "
            "AND hot_since IS NOT NULL", (account_id,)).fetchall():
        hot_dt = _parse_iso(lead["hot_since"])
        reason = None
        if lead["closed_state"] is not None:
            reason = "lead closed"
        elif _is_suppressed(db, lead):
            reason = "lead suppressed"
        elif is_claimed(db, lead, now_dt=now_dt):
            reason = "lead claimed"
        elif hot_dt is None or hot_dt <= expire_cutoff:
            reason = "expired after %dh with no fresh hot signal" % (
                hot_expire_hours)
        if reason is not None:
            db.execute("UPDATE leads SET hot_since = NULL WHERE id = ?",
                       (lead["id"],))
            log_event(db, lead["id"], "hot_cleared", reason)
            counters["hot_expired"] += 1

    # -- (c) auto-clear open/queued flags ---------------------------------
    # (before opening new ones, so an upgrade never races a clear)
    for flag in db.execute(
            "SELECT * FROM recovery_flags WHERE account_id = ? "
            "AND status IN ('open','queued')", (account_id,)).fetchall():
        lead = db.execute("SELECT * FROM leads WHERE id = ?",
                          (flag["lead_id"],)).fetchone()
        if lead is None:
            _clear_flag(db, flag, "lead missing")
            counters["cleared"] += 1
            continue
        reason = None
        if lead["closed_state"] is not None:
            reason = "lead closed"
        elif _is_suppressed(db, lead):
            reason = "lead suppressed"
        elif is_claimed(db, lead, now_dt=now_dt):
            reason = "lead claimed"
        elif not lead["phone"] or lead["phone_bad"]:
            reason = "phone unusable"
        elif lead["referred_by"] is not None:
            reason = "referral firewall"
        else:
            last = last_activity(db, lead)
            if last is not None and last > flag["flagged_at"]:
                reason = "new activity after flag"
        if reason is not None:
            _clear_flag(db, flag, reason)
            counters["cleared"] += 1

    # -- (b) open flags ----------------------------------------------------
    # Candidates: hot leads (fast_ghost) + quote/engaged stages (stales).
    seen = set()
    candidates = []
    for lead in db.execute(
            "SELECT * FROM leads WHERE account_id = ? "
            "AND hot_since IS NOT NULL "
            "AND closed_state IS NULL", (account_id,)).fetchall():
        candidates.append(lead)
        seen.add(lead["id"])
    for lead in db.execute(
            "SELECT * FROM leads WHERE account_id = ? "
            "AND pipeline_stage IN ('quote','engaged') "
            "AND closed_state IS NULL", (account_id,)).fetchall():
        if lead["id"] not in seen:
            candidates.append(lead)

    for lead in candidates:
        # Shared gates: fair game, not suppressed/closed, phone usable, not
        # a referral (the firewall keeps referrals out of every queue).
        if (lead["referred_by"] is not None or not _phone_usable(lead)
                or _is_suppressed(db, lead)
                or is_claimed(db, lead, now_dt=now_dt)):
            continue
        quiet_h = _quiet_hours(db, lead, now_dt)
        if quiet_h is None:
            continue  # no recorded activity at all: nothing to go quiet from

        kind = None
        if lead["hot_since"] and quiet_h >= ghost_quiet_hours:
            kind = "fast_ghost"
        elif (lead["pipeline_stage"] == "quote"
                and quiet_h >= stale_quote_days * 24):
            kind = "stale_quote"
        elif (lead["pipeline_stage"] == "engaged"
                and quiet_h >= stale_days * 24):
            kind = "stale_engaged"
        if kind is None:
            continue

        active = _active_flag(db, lead["id"])
        if active is not None:
            if kind == "fast_ghost" and active["kind"] != "fast_ghost":
                # fast_ghost supersedes a stale flag: upgrade IN PLACE (the
                # partial unique index forbids a second open/queued row).
                db.execute(
                    "UPDATE recovery_flags SET kind = 'fast_ghost', "
                    "flagged_at = ? WHERE id = ?", (utcnow(), active["id"]))
                log_event(db, lead["id"], "recovery_flag_upgraded",
                          "%s upgraded to fast_ghost" % active["kind"])
                counters["flagged"] += 1
                # B6: the same-day queue insertion that stood here is
                # GONE with the rest of the automatic fill. The FLAG still
                # opens — it is what /needs-review and the dashboard read,
                # and "ghosted two days with nothing booked" is now the
                # first signal the AI ranks by on /send-to-va. What
                # changed is that noticing a ghost no longer puts somebody
                # on a call list without a person deciding to.
            continue  # never duplicate; repeat scans are no-ops

        now_iso = utcnow()
        db.execute(
            "INSERT INTO recovery_flags (account_id, lead_id, kind, "
            "flagged_at, status, created_at) VALUES (?,?,?,?,'open',?)",
            (lead["account_id"], lead["id"], kind, now_iso, now_iso))
        log_event(db, lead["id"], "recovery_flagged", kind)
        counters["flagged"] += 1

    if own:
        db.commit()
    if counters["hot_expired"] or counters["flagged"] or counters["cleared"]:
        logger.info("detection scan: %s", counters)
    return counters
