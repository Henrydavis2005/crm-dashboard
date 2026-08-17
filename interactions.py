"""Unified interactions: call logging, appointments, email/text mirror rows
(SPEC B4).

Every email actually sent or received also inserts a thin interactions row
(mirror_message, idempotent per message_id) at the choke points: smtp_send
success, dispatcher send, approvals send, gmail reply intake (bounce = no
mirror). Historical pre-R1 text rows mirror the same way. user_id is NULL
for system traffic and the approving admin's id for web-approved replies
(auto-filled from g.user inside a request context).

Helpers never commit inside a caller's open transaction (entry points do).
Cross-package imports are deferred inside the functions that use them.
"""
import datetime
import logging
from typing import Optional
from zoneinfo import ZoneInfo

from leadflow.audit import _request_user_id, log_event
from leadflow.db import utcnow

logger = logging.getLogger("leadflow.interactions")

# C1: the ACTIVE disposition set (8), in picker order. Internal values are
# stable — only labels changed — and three values are new.
CALL_DISPOSITIONS = (
    "no_answer",
    "voicemail",
    "bad_number",
    "answered_not_interested",
    "callback_requested",
    "appointment_set",
    "not_qualified",
    "answered_send_options",
    # A VERBAL DO-NOT-CALL. Deliberately NOT merged with
    # answered_not_interested: "not interested right now" is a soft close a
    # tenant may legitimately revisit, and its suppression is reversible.
    # "Stop calling me" is a legal instruction, and TCPA treats it exactly
    # like an email unsubscribe — so this one writes an IRREVERSIBLE
    # suppression that no UI can undo.
    "answered_do_not_call",
)

# C1: retired from the picker but still VALID FOR READING — pipeline
# precedence, detection.is_claimed, the callbacks-due tier and existing
# timelines all keep working on pre-C1 rows. log_call REJECTS these for new
# rows; no data migration rewrites them.
LEGACY_CALL_DISPOSITIONS = ("answered_interested", "answered_callback")

# Everything a read path may legitimately encounter on a call row.
ALL_CALL_DISPOSITIONS = CALL_DISPOSITIONS + LEGACY_CALL_DISPOSITIONS

# Dispositions that mean a human actually answered: they halt the sequence.
# bad_number is NOT one of them (the wrong person answered — emails
# continue); no_answer / voicemail obviously are not.
ANSWERED_DISPOSITIONS = (
    "answered_not_interested",
    "callback_requested",
    "appointment_set",
    "not_qualified",
    "answered_send_options",
    "answered_do_not_call",
    "answered_interested",   # legacy
    "answered_callback",     # legacy
)

# R2: manual positive-text heat scale (display labels live in the
# heat_label_* settings).
HEAT_LEVELS = ("mild", "warm", "hot")

# C1 UI labels for the disposition select, in picker order.
CALL_DISPOSITION_LABELS = [
    ("no_answer", "No Answer"),
    ("voicemail", "Voicemail Left"),
    ("bad_number", "Wrong Number"),
    ("answered_not_interested", "Not Interested"),
    ("callback_requested", "Callback Requested"),
    ("appointment_set", "Appointment Set"),
    ("not_qualified", "Not Qualified"),
    ("answered_send_options", "Send Options — agreed to emailed quotes"),
    ("answered_do_not_call", "Do not call — verbal opt-out"),
]

# Read-only labels (timelines render pre-C1 rows through these too).
LEGACY_CALL_DISPOSITION_LABELS = [
    ("answered_interested", "Answered – Interested (legacy)"),
    ("answered_callback", "Answered – Call back (legacy)"),
]

# Appointment child rows share the disposition column.
_APPOINTMENT_LABELS = [
    ("scheduled", "Scheduled"),
    ("showed", "Showed"),
    ("no_show", "No show"),
    ("rescheduled", "Rescheduled"),
    ("cancelled", "Cancelled"),
]

# T1: the four outcomes a scheduled appointment can be closed out with.
# showed / no_show keep their existing permissions (admin + VA); the two
# TERMINAL ones are closure decisions like Sold/Dead and are ADMIN ONLY
# (enforced in the route).
APPOINTMENT_OUTCOMES = ("showed", "no_show", "rescheduled", "cancelled")

# The outcomes that mean the appointment did NOT happen and is not coming
# back on this row. They drop the lead off the `appointment` pipeline rung
# (pipeline.compute_stage), release detection.is_claimed, and end the
# confirmation task (leadflow.confirmations). `no_show` is deliberately
# NOT one of them — a no-showed appointment still happened on the calendar
# and keeps the lead at `appointment` exactly as it always has.
TERMINAL_APPOINTMENT_OUTCOMES = ("cancelled", "rescheduled")

DISPOSITION_LABELS = dict(CALL_DISPOSITION_LABELS
                          + LEGACY_CALL_DISPOSITION_LABELS
                          + _APPOINTMENT_LABELS)

# C1: how a call disposition resolves an open/queued recovery flag (R4).
# Anything absent records the disposition itself, so callback_requested,
# not_qualified and bad_number are self-describing outcomes.
RECOVERY_OUTCOMES = {
    "no_answer": "no_contact",
    "voicemail": "no_contact",
    "appointment_set": "appointment",
}


def disposition_label(value):
    # type: (object) -> str
    """Human label for any interactions.disposition value (active call
    dispositions, legacy ones, appointment outcomes); unknown values render
    as themselves. Registered as the `disposition_label` Jinja filter."""
    if not value:
        return ""
    return DISPOSITION_LABELS.get(str(value), str(value))


def _my_zone(db):
    from leadflow.settings import get_setting
    try:
        return ZoneInfo(get_setting("my_timezone", db=db))
    except Exception:
        return ZoneInfo("America/New_York")


def _today_local(db):
    # type: (object) -> datetime.date
    return datetime.datetime.now(datetime.timezone.utc).astimezone(
        _my_zone(db)).date()


def _lead_name(lead):
    return ("%s %s" % (lead["first_name"] or "", lead["last_name"] or "")
            ).strip() or ("Lead #%d" % lead["id"])


def _appointment_utc(db, raw):
    # type: (object, object) -> str
    """C1: parse the Appointment Set datetime into a UTC ISO string.

    Accepts the datetime-local field's 'YYYY-MM-DDTHH:MM' (interpreted in
    my_timezone, per B4's manual appointment form) or any ISO datetime
    carrying an explicit offset. Raises ValueError when it is missing,
    unparseable, or in the past."""
    raw = (raw or "").strip()
    if not raw:
        raise ValueError("Appointment Set needs the appointment date and time")
    try:
        dt = datetime.datetime.fromisoformat(str(raw).replace("Z", "+00:00"))
    except (ValueError, TypeError):
        raise ValueError("appointment date and time must look like "
                         "YYYY-MM-DDTHH:MM")
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=_my_zone(db))
    if dt <= datetime.datetime.now(datetime.timezone.utc):
        raise ValueError("the appointment cannot be in the past")
    return dt.astimezone(datetime.timezone.utc).isoformat(timespec="seconds")


def _resolve_recovery_flag(db, lead, outcome, user_id=None):
    """R4: a call (or appointment) logged on a lead with an OPEN or QUEUED
    recovery flag resolves it — any caller: status 'done' + outcome +
    resolved_at, and leads.hot_since cleared so the lead does not
    immediately re-flag (stales need a fresh quiet period, ghosts a fresh
    hot signal). Open flags resolve too (accepted R3/R4 design change): a
    called lead is a handled lead — before the queue is built (or with it
    disabled) an admin call from the dashboard panel must end the flag,
    not leave it cycling through auto-clear + re-flag until hot expiry.
    Returns the flag row (pre-update) or None."""
    flag = db.execute(
        "SELECT * FROM recovery_flags WHERE lead_id = ? "
        "AND status IN ('open','queued') ORDER BY id DESC LIMIT 1",
        (lead["id"],)).fetchone()
    if flag is None:
        return None
    db.execute(
        "UPDATE recovery_flags SET status = 'done', outcome = ?, "
        "resolved_at = ? WHERE id = ?", (outcome, utcnow(), flag["id"]))
    db.execute("UPDATE leads SET hot_since = NULL WHERE id = ?",
               (lead["id"],))
    log_event(db, lead["id"], "recovery_worked",
              "%s flag done: %s" % (flag["kind"], outcome), user_id=user_id)
    return flag


def _lead_or_raise(db, lead_id):
    lead = db.execute("SELECT * FROM leads WHERE id = ?", (lead_id,)).fetchone()
    if lead is None:
        raise ValueError("unknown lead %s" % lead_id)
    return lead


def _insert(db, lead, itype, user_id=None, direction=None, disposition=None,
            note=None, callback_on=None, appointment_at=None, parent_id=None,
            message_id=None):
    cur = db.execute(
        "INSERT INTO interactions (account_id, lead_id, user_id, itype, "
        "direction, disposition, note, callback_on, appointment_at, "
        "parent_id, message_id, created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
        (lead["account_id"], lead["id"], user_id, itype, direction,
         disposition, note, callback_on, appointment_at, parent_id,
         message_id, utcnow()),
    )
    return cur.lastrowid


def _halt(db, lead_id, reason):
    """Halt via outreach.scheduler (deferred import), inline fallback."""
    try:
        from leadflow.outreach.scheduler import halt_lead
    except ImportError:
        halt_lead = None
    if halt_lead is not None:
        halt_lead(db, lead_id, reason)
        return
    db.execute("UPDATE leads SET sequence_halted = 1 WHERE id = ?", (lead_id,))
    db.execute(
        "UPDATE messages SET status = 'canceled' "
        "WHERE lead_id = ? AND direction = 'out' AND status = 'pending'",
        (lead_id,),
    )
    log_event(db, lead_id, "halted", "reason=%s" % reason)


def _recompute(db, lead_id):
    from leadflow.pipeline import recompute
    recompute(db, lead_id)


# ---------------------------------------------------------------------------
# Mirror rows (choke points call this)
# ---------------------------------------------------------------------------

def mirror_message(db, message_id, user_id=None):
    # type: (object, int, Optional[int]) -> Optional[int]
    """Insert a thin interactions mirror row for a sent/received email/text.

    Idempotent per message_id (safe to call from more than one choke point on
    the same send). user_id auto-fills from g.user inside a request context
    (the approving admin for web-approved replies); system/worker traffic
    records NULL. Recomputes the lead's pipeline stage. Returns the
    interactions row id (None when nothing was mirrored)."""
    msg = db.execute(
        "SELECT * FROM messages WHERE id = ?", (message_id,)).fetchone()
    if msg is None or msg["lead_id"] is None:
        return None
    if msg["channel"] not in ("email", "text"):
        return None
    existing = db.execute(
        "SELECT id FROM interactions WHERE message_id = ? LIMIT 1",
        (message_id,)).fetchone()
    if existing is not None:
        return existing["id"]
    lead = db.execute(
        "SELECT * FROM leads WHERE id = ?", (msg["lead_id"],)).fetchone()
    if lead is None:
        return None
    if user_id is None:
        user_id = _request_user_id()
    own = not db.in_transaction
    row_id = _insert(db, lead, msg["channel"], user_id=user_id,
                     direction=msg["direction"], message_id=message_id)
    _recompute(db, lead["id"])
    if own:
        db.commit()
    return row_id


# ---------------------------------------------------------------------------
# Call logging
# ---------------------------------------------------------------------------

def _is_assistant_seat(db, user_id):
    """Is the actor an assistant seat (B7)?

    Read from the USER ROW, never from the request: `log_call` is reached
    from the work console, the lead page and the overflow mirror, and a
    check that depended on which one would be a different rule per
    entrance. Fails to False — an unreadable actor is treated as the
    agent, which is the side that keeps the existing behaviour rather than
    silently softening a close.
    """
    if not user_id:
        return False
    try:
        row = db.execute("SELECT role FROM users WHERE id = ?",
                         (int(user_id),)).fetchone()
    except Exception:
        logger.exception("could not resolve the actor for lead logging")
        return False
    return bool(row) and row["role"] == "va"


def log_call(db, lead_id, user_id, disposition, note=None,
             appointment_at=None):
    # type: (object, int, Optional[int], str, Optional[str], Optional[str]) -> int
    """Log a phone call and apply its C1 disposition effects atomically.

    The eight ACTIVE outcomes:

    - no_answer / voicemail: log only; the sequence continues and the call
      counts as a retry attempt (va._attempt_count keys on these two).
    - bad_number ("Wrong Number"): leads.phone_bad=1 + event, pending queue
      rows evicted, VA queueing halted (the phone_bad exclusion). The lead
      becomes a Needs Review candidate (derived: phone_bad=1 AND
      closed_state IS NULL) and is NEVER recycled to the dialer. Emails and
      the sequence continue.
    - answered_not_interested ("Not Interested"): suppress (not_interested,
      reversible=1) — a soft close that evicts from the queues.
    - callback_requested ("Callback Requested"): NO date is collected and
      no callback_on is written (VAs never schedule). Halts the sequence,
      opens a `callback_review` task + a 'task' owner notification, and
      keeps the lead out of the VA queues while the task is open — but it
      does NOT claim the lead (detection.is_claimed ignores it), so
      recovery may still work it. The agent resolves it by setting a
      follow-up (which closes the task) or by dismissing the task.
    - appointment_set ("Appointment Set"): requires an appointment datetime
      (datetime-local in my_timezone, not past) and routes through the same
      write/notify path as a manual appointment — claim, halt, booking
      notification and the S8 Google Calendar mirror all behave identically.
    - not_qualified ("Not Qualified"): closed_state='dead' + halt + evict,
      event 'not_qualified'. Out of every active queue and all automation,
      tracked distinctly from Not Interested and from C2a's 'no_number'.
    - answered_send_options: quote signal (legacy stage feed) + ALWAYS a
      `run_quotes` task and an owner alert (ntype 'task'), deduped against
      an already-open one. Whether a recovery flag was open, and whether
      the day-6 step row survived the halt, no longer decide whether the
      agent hears about it. The task is what show_run_quotes reads, so it
      is also what puts the Run Quotes button back on the lead page.

    Legacy answered_interested / answered_callback are REJECTED here (read
    paths still accept them). ANY call clears leads.hot_since (accepted R3
    design change: a called lead is a handled lead). Then it recomputes the
    pipeline stage and marks today's va_queue row worked (B5). An OPEN or
    QUEUED recovery flag is resolved (R4) with the RECOVERY_OUTCOMES
    mapping. Raises ValueError on bad input. Returns the interactions row
    id.
    """
    if disposition in LEGACY_CALL_DISPOSITIONS:
        raise ValueError(
            "%s is a retired disposition and can no longer be logged — "
            "pick one of the current outcomes" % disposition)
    if disposition not in CALL_DISPOSITIONS:
        raise ValueError("unknown call disposition: %s" % disposition)
    lead = _lead_or_raise(db, lead_id)

    # Validate BEFORE any write: a bad appointment time must leave no row.
    appointment_utc = None
    if disposition == "appointment_set":
        appointment_utc = _appointment_utc(db, appointment_at)

    note = (note or "").strip() or None

    own = not db.in_transaction
    row_id = _insert(db, lead, "call", user_id=user_id,
                     disposition=disposition, note=note)

    # Mark the queue row worked FIRST: the branches below evict the lead's
    # pending queue row (mid-day eviction) — the VA's worked credit for
    # this very call must land before that.
    mark_queue_worked(db, lead_id, user_id)

    # R3 accepted design change: ANY call clears the hot stamp (a called
    # lead is a handled lead) — even when no flag has opened yet, the
    # lead must not ghost-flag 2h after the admin already called them.
    db.execute("UPDATE leads SET hot_since = NULL WHERE id = ?", (lead_id,))

    if disposition in ANSWERED_DISPOSITIONS:
        _halt(db, lead_id, "call logged: %s" % disposition)
    if disposition == "answered_send_options":
        # Quote signal into the legacy stage feed (engine-internal).
        db.execute(
            "UPDATE leads SET stage = 'quote' WHERE id = ? "
            "AND stage NOT IN ('booked','suppressed')", (lead_id,))
    if disposition == "answered_not_interested":
        from leadflow.suppression import suppress
        suppress(db, lead_id=lead_id, reason="not_interested", reversible=1,
                 note="call disposition answered_not_interested")
    if disposition == "answered_do_not_call":
        # IRREVERSIBLE, exactly like an email unsubscribe. A verbal DNC is
        # the same legal instruction, so it must not be weaker in this
        # system than clicking a link. `suppression.unsuppress` refuses a
        # row with reversible = 0, which is what makes both removal routes
        # (POST /leads/<id>/unsuppress and POST /suppressions/<id>/delete)
        # decline it — there is no UI path that can undo this.
        from leadflow.suppression import suppress
        suppress(db, lead_id=lead_id, reason="do_not_call", reversible=0,
                 note="call disposition answered_do_not_call "
                      "(verbal do-not-call request)")
        log_event(db, lead_id, "do_not_call",
                  "verbal do-not-call recorded on a call; contact "
                  "suppressed irreversibly", user_id=user_id)
    if disposition == "bad_number":
        # Texting is gone (R1): there are no pending text sends to cancel
        # anymore — bad_number flags the phone (emails continue) and stops
        # the VA side: evicted today, excluded from every later build by
        # the phone_bad clause in va._EXCLUDE_SQL.
        # C2a HOOK: Needs Review lists exactly these leads
        # (phone_bad = 1 AND closed_state IS NULL) — derived, no column.
        db.execute("UPDATE leads SET phone_bad = 1 WHERE id = ?", (lead_id,))
        log_event(db, lead_id, "bad_number", "phone marked bad",
                  user_id=user_id)
        from leadflow.va import evict_pending
        evict_pending(db, lead_id, "wrong number: phone marked bad")

    callback_task = None
    if disposition == "callback_requested":
        from leadflow.tasks import create_task
        callback_task = create_task(
            db, "callback_review", lead_id,
            "%s asked for a callback — set a follow-up" % _lead_name(lead))
        log_event(db, lead_id, "callback_requested",
                  "callback requested; review task %s opened for the agent"
                  % callback_task, user_id=user_id)

    if disposition == "not_qualified":
        # B7: SOFT WHEN AN ASSISTANT SAYS IT, HARD WHEN THE AGENT DOES.
        #
        # An assistant's read of a two-minute call is a signal, not a
        # verdict — closing the lead on it destroys the agent's own
        # judgement about their own client, and the agent is the one who
        # answers for it. So a VA's `not_qualified` records the
        # disposition, feeds the pipeline recompute below and shows up in
        # the VA updates feed; it does NOT set `closed_state`, and the
        # lead stays in the agent's pipeline for them to decide.
        #
        # An ADMIN logging the same disposition still closes it. This is
        # the only place the two differ, and it differs by WHO, not by
        # which button was pressed.
        #
        # Do-not-call and revocation are NOT in this category and never
        # become soft — see `answered_do_not_call` above. A verbal DNC is
        # a legal instruction from the person themselves, not somebody's
        # read of a conversation.
        if _is_assistant_seat(db, user_id):
            log_event(db, lead_id, "va_update",
                      "assistant marked this not qualified — the lead is "
                      "yours to close", user_id=user_id)
        else:
            db.execute("UPDATE leads SET closed_state = 'dead' WHERE id = ?",
                       (lead_id,))
            log_event(db, lead_id, "not_qualified",
                      "not qualified on a call; lead closed", user_id=user_id)
            from leadflow.va import evict_pending
            evict_pending(db, lead_id, "not qualified")

    appointment_row = None
    appointment_prior = None
    if disposition == "appointment_set":
        # The SAME write half a manual appointment uses: claim (via the
        # appointment interaction), halt, follow-up cleared, flag resolved.
        appointment_row, appointment_prior = _schedule_appointment_write(
            db, lead, user_id, appointment_utc, note=note)

    # R4: resolve a queued recovery flag (ghost/stale the VA just worked).
    # Called for its EFFECT — the return value is no longer read, because
    # the quote task below is unconditional (see the note there).
    _resolve_recovery_flag(
        db, lead, RECOVERY_OUTCOMES.get(disposition, disposition),
        user_id=user_id)
    quote_alert = None
    if disposition == "answered_send_options":
        # The lead agreed to emailed quotes: the ADMIN sends them by hand —
        # the app NEVER auto-sends after a VA contact. This raises the SAME
        # `run_quotes` task the day-6 dispatcher step raises, so the lead
        # page gets its Run Quotes button back (show_run_quotes reads this
        # task) and the dashboard/Today row gets the "Run quotes" link.
        #
        # It is UNCONDITIONAL, and that is the fix. It used to sit behind
        # `flag is not None`, so only a lead with an open recovery flag got
        # anything at all. On an ordinary volume lead the same call halts
        # the sequence, which cancels the still-pending day-6 quote row,
        # which makes _quote_row return None, which turns show_run_quotes
        # off — no task, no alert, AND no button, at the exact moment the
        # lead asked for quotes. The lead then sat until stale_quote fired
        # days later.
        #
        # Nothing here sends: Run Quotes still refuses any send with an
        # unfilled price field, and every figure is typed by the agent.
        from leadflow.tasks import create_task
        already_open = db.execute(
            "SELECT 1 FROM tasks WHERE lead_id = ? AND kind = 'run_quotes' "
            "AND status = 'open' LIMIT 1", (lead_id,)).fetchone() is not None
        if not already_open:
            # Same body the dispatcher writes, so one task kind means one
            # thing however it was raised.
            create_task(db, "run_quotes", lead_id,
                        "Run quotes for %s" % _lead_name(lead))
            quote_alert = ("%s agreed to emailed quotes — send them"
                           % _lead_name(lead))

    _recompute(db, lead_id)
    if own:
        db.commit()
    if quote_alert is not None:
        # After commit only: the notify email can hold SMTP for 30s.
        try:
            from leadflow.notify import notify as owner_notify
            owner_notify(db, "task", quote_alert, lead_id=lead_id)
        except ImportError:
            logger.warning(
                "leadflow.notify unavailable; run quotes alert skipped")
    if callback_task is not None:
        try:
            from leadflow.notify import notify as owner_notify
            owner_notify(db, "task",
                         "%s asked for a callback — set a follow-up"
                         % _lead_name(lead), lead_id=lead_id)
        except ImportError:
            logger.warning(
                "leadflow.notify unavailable; callback alert skipped")
    if appointment_row is not None:
        # Post-commit half (gcal mirror + booking notification), identical
        # to a manually scheduled appointment.
        _schedule_appointment_after(db, lead, appointment_row,
                                    appointment_utc, appointment_prior)
    logger.info("call logged lead=%s disposition=%s user=%s",
                lead_id, disposition, user_id)
    return row_id


def log_text(db, lead_id, user_id, heat, note=None):
    # type: (object, int, Optional[int], str, Optional[str]) -> int
    """Log a manual positive text (R2; texting happens in Ringy, outside the
    app — the admin logs ONLY positive lead texts, on a heat scale).

    heat is mild|warm|hot (display labels come from the heat_label_*
    settings). hot stamps leads.hot_since = now (drives ghost detection);
    mild/warm do not. Always recomputes the pipeline stage (mild -> engaged
    signal, warm/hot -> quote signal). No log = UNKNOWN — silence is never a
    negative signal. Raises ValueError on an unknown heat. Returns the
    interactions row id."""
    if heat not in HEAT_LEVELS:
        raise ValueError("unknown text heat: %s" % heat)
    lead = _lead_or_raise(db, lead_id)
    note = (note or "").strip() or None

    own = not db.in_transaction
    row_id = _insert(db, lead, "text_log", user_id=user_id,
                     disposition=heat, note=note)
    if heat == "hot":
        db.execute("UPDATE leads SET hot_since = ? WHERE id = ?",
                   (utcnow(), lead_id))
    _recompute(db, lead_id)
    if own:
        db.commit()
    logger.info("text logged lead=%s heat=%s user=%s", lead_id, heat, user_id)
    return row_id


# ---------------------------------------------------------------------------
# Follow-ups (R3, admin only)
# ---------------------------------------------------------------------------

def set_followup(db, lead_id, user_id, followup_on, note=None):
    # type: (object, int, Optional[int], str, Optional[str]) -> int
    """Set the admin's follow-up on a lead (R3): leads.followup_on (YYYY-MM-DD,
    not past in my_timezone) + followup_note, plus an interactions row
    (itype='followup', callback_on=date) for the timeline. While the date is
    >= today the lead is CLAIMED (detection.is_claimed). S4: a follow-up is
    a stop condition — it HALTS the sequence (pending sends canceled), but
    an open Run Quotes task stays open (the admin decides). C1: setting a
    follow-up is how the agent ANSWERS a Callback Requested disposition, so
    it closes the lead's open `callback_review` task — the lead returns to
    the VA queues protected by the follow-up instead of by the task. Raises
    ValueError on bad input. Returns the interactions row id."""
    lead = _lead_or_raise(db, lead_id)
    followup_on = (followup_on or "").strip()
    try:
        fu_date = datetime.date.fromisoformat(followup_on)
    except ValueError:
        raise ValueError("follow-up date must be YYYY-MM-DD")
    if fu_date < _today_local(db):
        raise ValueError("follow-up date cannot be in the past")
    note = (note or "").strip() or None

    own = not db.in_transaction
    db.execute(
        "UPDATE leads SET followup_on = ?, followup_note = ? WHERE id = ?",
        (followup_on, note, lead_id))
    row_id = _insert(db, lead, "followup", user_id=user_id, note=note,
                     callback_on=followup_on)
    _halt(db, lead_id, "follow-up set for %s" % followup_on)
    # C1: the agent has answered the callback request.
    from leadflow.tasks import close_callback_review
    close_callback_review(db, lead_id, "follow-up set for %s" % followup_on)
    _recompute(db, lead_id)
    if own:
        db.commit()
    logger.info("followup set lead=%s on=%s user=%s",
                lead_id, followup_on, user_id)
    return row_id


def clear_followup(db, lead_id, user_id=None, reason="cleared"):
    # type: (object, int, Optional[int], str) -> bool
    """Null leads.followup_on/followup_note (R3). Called by the Clear button
    and automatically when an appointment is logged or the lead is marked
    sold. Never commits inside a caller's open transaction. Returns True when
    a pending follow-up was actually cleared."""
    lead = _lead_or_raise(db, lead_id)
    if lead["followup_on"] is None and lead["followup_note"] is None:
        return False
    own = not db.in_transaction
    db.execute(
        "UPDATE leads SET followup_on = NULL, followup_note = NULL "
        "WHERE id = ?", (lead_id,))
    log_event(db, lead_id, "followup_cleared", reason, user_id=user_id)
    if own:
        db.commit()
    return True


def mark_queue_worked(db, lead_id, user_id):
    """Mark today's va_queue row for this lead worked (SPEC B5).

    Called from log_call inside its transaction (never commits here). The
    first caller sticks: an already-worked row keeps its worked_by. No-op
    when the lead is not in today's queue. Returns rows updated (0 or 1)."""
    from leadflow.va import mark_worked
    return mark_worked(db, lead_id, user_id)


def on_lead_sold(db, lead):
    """VA sold-bonus credit (SPEC B6, renamed in R-schema), called when an
    admin marks a lead sold.

    The user who logged this lead's FIRST answered_send_options call OR
    appointment/scheduled interaction (whichever is earliest) gets ONE
    `sold_credit` interactions row (note names who marked it). Idempotent:
    max one sold_credit per lead — Reopen + re-sell never double-credits.
    Returns the sold_credit row id (None when no credit applies)."""
    lead_id = lead["id"]
    if db.execute(
        "SELECT 1 FROM interactions WHERE lead_id = ? "
        "AND itype = 'sold_credit' LIMIT 1",
        (lead_id,)).fetchone() is not None:
        return None
    earliest = db.execute(
        "SELECT * FROM interactions WHERE lead_id = ? AND ("
        " (itype = 'call' AND disposition = 'answered_send_options') OR"
        " (itype = 'appointment' AND disposition = 'scheduled')) "
        "ORDER BY created_at, id LIMIT 1", (lead_id,)).fetchone()
    if earliest is None or earliest["user_id"] is None:
        return None  # no attributable logger (system/worker rows earn nothing)
    marker_id = _request_user_id()
    marker = None
    if marker_id is not None:
        row = db.execute("SELECT username FROM users WHERE id = ?",
                         (marker_id,)).fetchone()
        marker = row["username"] if row else None
    own = not db.in_transaction
    row_id = _insert(db, lead, "sold_credit", user_id=earliest["user_id"],
                     note="sold marked by %s" % (marker or "system"))
    if own:
        db.commit()
    logger.info("sold_credit lead=%s credited user=%s (marked by %s)",
                lead_id, earliest["user_id"], marker or "system")
    return row_id


# ---------------------------------------------------------------------------
# Appointments
# ---------------------------------------------------------------------------

def _gcal_after_schedule(db, lead, row_id, appointment_at):
    """S8: write the new appointment to Google Calendar POST-COMMIT.

    Silent degrade — any Google failure logs a 'gcal_sync_failed' event and
    never blocks the appointment; the worker's retry pass (gcal.
    retry_unsynced) picks up rows left without gcal_event_id. Skipped when
    the caller still holds a transaction (the retry pass covers those) or
    when the lead's account is not connected."""
    if db.in_transaction:
        return
    try:
        from leadflow import gcal
    except ImportError:
        return
    account_id = lead["account_id"]
    try:
        if not gcal.is_connected(db, account_id):
            return
        event_id = gcal.insert_event(
            db, account_id, gcal.event_title(_lead_name(lead)),
            appointment_at,
            description=gcal.lead_link(db, lead["id"],
                                       account_id=account_id))
        db.execute("UPDATE interactions SET gcal_event_id = ? WHERE id = ?",
                   (event_id, row_id))
        db.commit()
        logger.info("gcal event %s created for appointment %s (lead %s)",
                    event_id, row_id, lead["id"])
    except Exception as exc:
        logger.warning("gcal insert failed for appointment %s (lead %s): %s",
                       row_id, lead["id"], exc)
        try:
            log_event(db, lead["id"], "gcal_sync_failed",
                      "Google Calendar event insert failed for appointment "
                      "%d: %s (the worker will retry)" % (row_id, exc))
        except Exception:
            logger.exception("could not log gcal_sync_failed")


def _gcal_after_reschedule(db, lead, prior):
    """S8: a SECOND appointment on the lead leaves the prior outcome-less
    appointment's Google event in place — without this it would sit on the
    calendar looking current forever. Best-effort POST-COMMIT title patch
    with a '[rescheduled] ' prefix; same silent-degrade contract as
    _gcal_after_schedule (a failure changes nothing — the event just
    keeps its old title)."""
    if db.in_transaction or prior is None or not prior["gcal_event_id"]:
        return
    try:
        from leadflow import gcal
    except ImportError:
        return
    account_id = lead["account_id"]
    try:
        if not gcal.is_connected(db, account_id):
            return
        gcal.patch_event(
            db, account_id, prior["gcal_event_id"],
            {"summary": "[rescheduled] " + gcal.event_title(
                _lead_name(lead))})
        logger.info("gcal event %s marked [rescheduled] (lead %s)",
                    prior["gcal_event_id"], lead["id"])
    except Exception as exc:
        logger.warning("gcal reschedule patch failed for appointment %s "
                       "(lead %s): %s", prior["id"], lead["id"], exc)


def _gcal_after_cancel(db, lead, parent):
    """T1: a CANCELLED appointment deletes its Google event POST-COMMIT.

    This is exactly the hook SPEC S8 left waiting for "the future cancel
    feature" — until T1 the app had no cancel action, so gcal.delete_event
    had no caller. Same silent-degrade contract as every other S8 write:
    a failure logs `gcal_sync_failed` and never blocks the outcome, and a
    caller still holding a transaction skips it.

    interactions.gcal_event_id is deliberately KEPT on the row after the
    delete. Clearing it would make the worker's retry_unsynced pass treat
    the appointment as never-synced and recreate the event."""
    if db.in_transaction or not parent["gcal_event_id"]:
        return
    try:
        from leadflow import gcal
    except ImportError:
        return
    account_id = lead["account_id"]
    try:
        if not gcal.is_connected(db, account_id):
            return
        gcal.delete_event(db, account_id, parent["gcal_event_id"])
        logger.info("gcal event %s deleted for cancelled appointment %s "
                    "(lead %s)", parent["gcal_event_id"], parent["id"],
                    lead["id"])
    except Exception as exc:
        logger.warning("gcal delete failed for appointment %s (lead %s): %s",
                       parent["id"], lead["id"], exc)
        try:
            log_event(db, lead["id"], "gcal_sync_failed",
                      "Google Calendar event delete failed for cancelled "
                      "appointment %d: %s" % (parent["id"], exc))
        except Exception:
            logger.exception("could not log gcal_sync_failed")


def _gcal_after_outcome(db, lead, parent, disposition):
    """S8: patch the linked Google event's title with the outcome prefix
    (showed -> check, no_show -> cross) POST-COMMIT. Same silent-degrade
    contract as _gcal_after_schedule; no linked event -> nothing to do
    (the retry pass writes outcome-prefixed titles itself)."""
    if db.in_transaction or not parent["gcal_event_id"]:
        return
    try:
        from leadflow import gcal
    except ImportError:
        return
    account_id = lead["account_id"]
    try:
        if not gcal.is_connected(db, account_id):
            return
        gcal.patch_event(
            db, account_id, parent["gcal_event_id"],
            {"summary": gcal.event_title(_lead_name(lead),
                                         outcome=disposition)})
    except Exception as exc:
        logger.warning("gcal patch failed for appointment %s (lead %s): %s",
                       parent["id"], lead["id"], exc)
        try:
            log_event(db, lead["id"], "gcal_sync_failed",
                      "Google Calendar title update failed for appointment "
                      "%d: %s" % (parent["id"], exc))
        except Exception:
            logger.exception("could not log gcal_sync_failed")


def _schedule_appointment_write(db, lead, user_id, appointment_at, note=None):
    # type: (object, object, Optional[int], str, Optional[str]) -> tuple
    """The DB half of scheduling an appointment (never commits): the
    appointment/scheduled row, the halt, the superseded follow-up, and the
    recovery-flag resolution. Returns (row_id, prior_open_row) — the caller
    passes both to _schedule_appointment_after once the transaction is
    committed. Shared by schedule_appointment and log_call's
    appointment_set disposition so both behave identically (C1)."""
    lead_id = lead["id"]
    # Captured BEFORE the new row lands: the lead's latest still-open
    # appointment, which this booking SUPERSEDES. ANY open scheduled row
    # counts — the lookup used to require `gcal_event_id IS NOT NULL`
    # (it existed only for the S8 title patch), so an appointment that
    # never reached Google was never superseded at all.
    prior_open = db.execute(
        "SELECT i.id, i.gcal_event_id FROM interactions i "
        "WHERE i.lead_id = ? AND i.itype = 'appointment' "
        "AND i.disposition = 'scheduled' "
        "AND NOT EXISTS (SELECT 1 FROM interactions o "
        " WHERE o.parent_id = i.id "
        " AND o.disposition IN ('showed','no_show','rescheduled',"
        "                       'cancelled')) "
        "ORDER BY i.id DESC LIMIT 1", (lead_id,)).fetchone()
    row_id = _insert(db, lead, "appointment", user_id=user_id,
                     disposition="scheduled", note=(note or "").strip() or None,
                     appointment_at=appointment_at)
    if prior_open is not None:
        # T1 fix: close the superseded row with the TERMINAL outcome that
        # exists for exactly this. Without it the old row kept
        # disposition='scheduled' with no child, so it stayed in
        # `pending_confirmations` and the owner got a SECOND reminder
        # naming the OLD time — invisible on lead detail, which renders
        # only `latest_scheduled_appointment`. With the child it drops out
        # of pending_confirmations (terminal outcome), out of
        # awaiting_outcome (it has a child) and off the `appointment`
        # pipeline rung, while the NEW row holds the lead there.
        # `pay.py` counts PARENT scheduled/showed rows, so no VA bonus
        # moves. Written directly rather than through appointment_outcome
        # because we are inside the caller's transaction and the Google
        # side is handled post-commit by _gcal_after_reschedule.
        _insert(db, lead, "appointment", user_id=user_id,
                disposition="rescheduled", parent_id=prior_open["id"],
                note="superseded automatically: rebooked for %s"
                     % appointment_at)
    _halt(db, lead_id, "appointment scheduled")
    # R3: an appointment supersedes the admin's pending follow-up.
    clear_followup(db, lead_id, user_id=user_id, reason="appointment scheduled")
    # R4: an appointment on a recovery-flagged lead resolves the flag (the
    # booking notification covers alerting).
    _resolve_recovery_flag(db, lead, "appointment", user_id=user_id)
    return row_id, prior_open


def _schedule_appointment_after(db, lead, row_id, appointment_at, prior_open,
                                notify=True):
    """The POST-COMMIT half: the Google Calendar mirror (silent degrade —
    never blocks the appointment; the worker retries missing events) and the
    booking notification."""
    _gcal_after_reschedule(db, lead, prior_open)
    _gcal_after_schedule(db, lead, row_id, appointment_at)
    if not notify:
        return
    name = _lead_name(lead)
    try:
        from leadflow.notify import notify as owner_notify
        owner_notify(db, "booking",
                     "Appointment scheduled: %s (%s / %s) at %s. "
                     "Sequence halted." % (
                         name, lead["email"] or "-", lead["phone"] or "-",
                         appointment_at),
                     lead_id=lead["id"])
    except ImportError:
        logger.warning("leadflow.notify unavailable; booking alert skipped")


def schedule_appointment(db, lead_id, user_id, appointment_at, note=None,
                         notify=True):
    # type: (object, int, Optional[int], str, Optional[str], bool) -> int
    """Log an appointment/scheduled interaction (appointment_at = UTC ISO),
    halt the sequence, recompute, and (always) send the booking notification.
    Returns the interactions row id."""
    lead = _lead_or_raise(db, lead_id)
    own = not db.in_transaction
    row_id, prior_open = _schedule_appointment_write(
        db, lead, user_id, appointment_at, note=note)
    _recompute(db, lead_id)
    if own:
        db.commit()
    _schedule_appointment_after(db, lead, row_id, appointment_at, prior_open,
                                notify=notify)
    logger.info("appointment scheduled lead=%s at=%s user=%s",
                lead_id, appointment_at, user_id)
    return row_id


def appointment_outcome(db, appointment_id, user_id, disposition,
                        lead_id=None):
    # type: (object, int, Optional[int], str, Optional[int]) -> int
    """Mark a scheduled appointment's outcome (child row, parent_id).

    Four outcomes (T1 added the last two):

    - showed / no_show: the appointment reached its time. The lead STAYS
      on the `appointment` pipeline rung either way — a no-show is not a
      lost appointment, it is an appointment that happened badly. Google
      event title gets the check/cross prefix.
    - rescheduled / cancelled (TERMINAL): the appointment did not happen.
      The lead drops off the `appointment` rung, detection.is_claimed
      releases it, and the confirmation task ends. On `cancelled` the
      Google event is DELETED; on `rescheduled` its title is patched with
      the '[rescheduled] ' prefix (the same shape a second appointment on
      the lead already uses), so a superseded event never sits on the
      calendar looking current.

    Marking an outcome does NOT un-halt the sequence and does NOT reopen
    outreach — resuming outreach stays an explicit act (the Reopen
    precedent).

    **One appointment, ONE outcome.** A second outcome of any kind is
    refused. A stale tab or a back-button resubmit could otherwise mark
    `showed` on an appointment that was already CANCELLED — which put the
    lead back on the `appointment` rung, earned an `appt_showed` bonus
    (pay.py) and fired a doomed `gcal.patch_event` whose raw HTTP error
    landed on the lead's timeline (unlike `delete_event`, patch does not
    swallow a 404/410). Changing your mind means booking a NEW
    appointment, not stacking children on the old one. Note this does not
    obstruct the app's own auto-`rescheduled` child on a superseded
    booking: `_schedule_appointment_write` only ever writes it on a row
    that has no outcome yet.

    Raises ValueError on a bad disposition, an unknown/non-scheduled
    parent, or an appointment that already carries an outcome. lead_id
    (when given, S1) must match the parent's lead — a URL can never target
    another lead's (or tenant's) appointment. Returns the child
    interactions row id."""
    if disposition not in APPOINTMENT_OUTCOMES:
        raise ValueError("appointment outcome must be one of %s"
                         % ", ".join(APPOINTMENT_OUTCOMES))
    parent = db.execute(
        "SELECT * FROM interactions WHERE id = ? AND itype = 'appointment' "
        "AND disposition = 'scheduled'", (appointment_id,)).fetchone()
    if parent is None or (lead_id is not None
                          and parent["lead_id"] != lead_id):
        raise ValueError("unknown scheduled appointment %s" % appointment_id)
    settled = db.execute(
        "SELECT disposition FROM interactions WHERE parent_id = ? "
        "AND itype = 'appointment' ORDER BY id LIMIT 1",
        (appointment_id,)).fetchone()
    if settled is not None:
        raise ValueError(
            "That appointment already has an outcome (%s) — book a new "
            "appointment instead of changing this one."
            % settled["disposition"])
    lead = _lead_or_raise(db, parent["lead_id"])
    own = not db.in_transaction
    row_id = _insert(db, lead, "appointment", user_id=user_id,
                     disposition=disposition, parent_id=appointment_id)
    _recompute(db, lead["id"])
    if own:
        db.commit()
    # S8 + T1: reflect the outcome on the linked Google event (post-commit,
    # silent degrade in every branch).
    if disposition == "cancelled":
        _gcal_after_cancel(db, lead, parent)
    elif disposition == "rescheduled":
        _gcal_after_reschedule(db, lead, parent)
    else:
        _gcal_after_outcome(db, lead, parent, disposition)
    logger.info("appointment %s lead=%s parent=%s user=%s",
                disposition, lead["id"], appointment_id, user_id)
    return row_id


def latest_scheduled_appointment(db, lead_id):
    """The lead's most recent appointment/scheduled row (or None), with any
    child outcome rows attached as 'outcomes'."""
    row = db.execute(
        "SELECT * FROM interactions WHERE lead_id = ? "
        "AND itype = 'appointment' AND disposition = 'scheduled' "
        "ORDER BY id DESC LIMIT 1", (lead_id,)).fetchone()
    if row is None:
        return None
    out = dict(row)
    out["outcomes"] = [dict(r) for r in db.execute(
        "SELECT * FROM interactions WHERE parent_id = ? ORDER BY id",
        (row["id"],)).fetchall()]
    return out
