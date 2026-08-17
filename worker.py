"""Background worker: 30s tick loop driving dispatch, polling and expiry.

Started as a daemon thread from app.py (start_worker). MULTI-TENANT since
S1: every periodic job loops the ACTIVE accounts and runs under that
account's settings (auth.account_scope), each account inside its own
try/except so one tenant's failure never blocks another. Every sub-task
also runs inside its own try/except with a per-task error counter so one
failing subsystem never kills the loop, and config-gating keeps the worker
from crash-looping when settings are empty (heartbeat always runs and
stays GLOBAL — one worker process).

The OUTREACH switch (outreach_live off = paused) freezes EVERY per-account
job below it except the ones that are not outreach — the S8 calendar sync,
the T1 confirmation reminder and (since T2) the Gmail poll — an intentional
fail-closed freeze (SPEC S3 accepted decision). Only /today page hits still
build the VA queue.

AN ACCOUNT THAT IS NOT `active` gets no per-account job at all, and not
because of a gate in this file: `_active_accounts` selects
`status = 'active'`, so a pending or rejected tenant is simply never in
the loop — including the three jobs that are exempt from the outreach
switch. The Gmail poll in particular must not run, because it marks
messages seen permanently; mail that arrives while an account is waiting
for approval sits in the mailbox and is ingested as new once it is
approved. (BLOCK 1 STEP C removed the billing pause that used to sit
here; B3 removed suspension, so approval is the only thing this gate is
about now.)

There is no telephony job here at all. Ancora placed calls through Twilio
until the calling system was removed; dialing now happens in Ringy, outside
the app, and the VA records the outcome by hand.

LEAD INTAKE is a SEPARATE switch since T2 (`lead_intake_enabled`): the
mailbox poll runs when EITHER intake or outreach is on, because the same
poll carries new leads AND the replies/bounces outreach depends on. Which
of those it acts on is decided per message inside gmail.intake.

Cadence (per SPEC), per active account unless noted:
- every tick (30s): heartbeat (global), dispatch_due (outreach live only),
  approvals expire_stale (global sweep — expiry is by timestamp only)
- every 120s, ABOVE the outreach gate (T2), when gmail is configured AND
  (lead intake is on OR outreach is live): gmail poll_gmail (per-tenant
  credentials + imap cursor)
- every 300s (outreach live only): detection.scan (R3 recovery-flag pass)
- nightly, first tick after 00:30 in the account's my_timezone (live
  only): outreach mark_exhausted; va.expire_nocontact (S3 no-contact
  death pass)
- daily, first tick after 00:30 (live only): sales prompt_due_asks (R7
  referral asks -> approval drafts; never auto-sends)
- daily, first live tick after midnight: va.ensure_daily_queue (no-op
  while the VA plan is off; /today also triggers it on first hit)
- every tick (R5, NOT gated by the outreach switch — recovery lines are
  written for a human to read aloud, so the pass contacts nobody; no-ops
  while the VA plan is off): va.fill_missing_scripts — caches AI recovery
  lines for today's ghost/stale queue rows, a few per tick. This is the
  ONLY generator outside an explicit human action: the work console is a
  GET and never generates.
- every 300s, per CONNECTED account (S8, NOT gated by the outreach
  switch — appointments are human-made data, not outreach):
  gcal.sync_account (incremental Google->app overlay sync) +
  gcal.retry_unsynced (app->Google catch-up for appointments missing
  gcal_event_id)
- every tick (30s), per account with an unconfirmed upcoming appointment
  (T1, also NOT gated by the outreach switch — the reminder is a note to
  the AGENT about a human-made appointment and never contacts a lead):
  confirmations.notify_due (one "text them to confirm" owner alert per
  appointment, ever)

Per-account app_state keys (db.account_state_key; account 1 keeps the
legacy bare names): imap_since, email_bounce_window, email_paused,
consecutive_failures_email, va_queue_date, worker_exhausted_date,
referral_asks_date, nocontact_expire_date, agent_lead_expire_date,
overflow_expire_date, gcal_sync, gcal_events.
"""
import datetime
import logging
import threading
import time

try:
    from zoneinfo import ZoneInfo
except ImportError:  # pragma: no cover - py3.9+ always has zoneinfo
    ZoneInfo = None

logger = logging.getLogger("leadflow.worker")

TICK_SECONDS = 30
GMAIL_POLL_SECONDS = 120
DETECTION_SCAN_SECONDS = 300  # R3 detection pass every 5 minutes (live only)
GCAL_SYNC_SECONDS = 300  # S8 Google Calendar sync (connected accounts only)

# task name -> consecutive/total error count (visible for debugging/tests).
# Per-account tasks are keyed "<name>" for account 1 (legacy names the
# existing tests read) and "<name>_<account_id>" for other accounts.
error_counters = {}

_worker_thread = None
_stop_event = threading.Event()


# ---------------------------------------------------------------- helpers

def _state_get(db, key, default=None):
    row = db.execute("SELECT value FROM app_state WHERE key = ?", (key,)).fetchone()
    return row["value"] if row is not None else default


def _state_set(db, key, value):
    with db:
        db.execute(
            "INSERT INTO app_state (key, value) VALUES (?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            (key, str(value)),
        )


def _task_key(name, account_id):
    return name if account_id in (None, 1) else "%s_%d" % (name, account_id)


def _run_task(name, fn, *args, **kwargs):
    """Run one sub-task; never propagate. Returns True on success.

    Swallowing the exception is not enough on its own: a sub-task that
    raised after its first write leaves the worker's connection inside an
    open transaction, and the NEXT sub-task's commit would then persist
    those partial rows — for another TENANT, since accounts are walked in
    one loop — while the open write transaction blocks every web thread's
    writes with `database is locked`. Roll it back here so one failing
    sub-task really is contained to itself.
    """
    try:
        fn(*args, **kwargs)
        error_counters[name] = 0
        return True
    except Exception:
        error_counters[name] = error_counters.get(name, 0) + 1
        logger.exception("worker task %r failed (consecutive errors: %d)",
                         name, error_counters[name])
        from leadflow.db import rollback_dangling
        rollback_dangling("worker task %r" % name)
        return False


def _active_accounts(db):
    """The ACTIVE account ids (S1: pending accounts get no worker jobs).
    A pre-migration DB without accounts.status reads as [1]."""
    try:
        return [r["id"] for r in db.execute(
            "SELECT id FROM accounts WHERE status = 'active' ORDER BY id"
        ).fetchall()]
    except Exception:
        logger.exception("could not list active accounts; defaulting to [1]")
        return [1]


def _outreach_live(db, account_id):
    """Per-account OUTREACH switch. Any failure to read it means paused
    (fail closed)."""
    from leadflow.settings import get_setting
    try:
        return bool(get_setting("outreach_live", db=db,
                                account_id=account_id))
    except Exception:
        logger.exception("could not read outreach_live for account %s; "
                         "keeping outreach paused", account_id)
        return False


def _intake_enabled(db, account_id):
    """Per-account LEAD INTAKE switch (T2). Same fail-closed contract as
    _outreach_live: any failure to read it means intake stays off."""
    from leadflow.settings import get_setting
    try:
        return bool(get_setting("lead_intake_enabled", db=db,
                                account_id=account_id))
    except Exception:
        logger.exception("could not read lead_intake_enabled for account "
                         "%s; keeping intake off", account_id)
        return False


def _gmail_configured(db, account_id):
    from leadflow.settings import get_setting
    try:
        return (bool(get_setting("gmail_address", db=db,
                                 account_id=account_id))
                and bool(get_setting("gmail_app_password", db=db,
                                     account_id=account_id)))
    except Exception:
        logger.exception("could not read gmail settings for account %s",
                         account_id)
        return False


def _my_timezone(db, account_id):
    from leadflow.settings import get_setting
    try:
        name = get_setting("my_timezone", db=db,
                           account_id=account_id) or "America/New_York"
    except Exception:
        name = "America/New_York"
    try:
        return ZoneInfo(name)
    except Exception:
        return ZoneInfo("America/New_York")


def _daily_due(db, now_utc, key, account_id):
    """True when the account's local time is past 00:30 and the job keyed
    by `key` (already account-suffixed) has not run today."""
    local = now_utc.astimezone(_my_timezone(db, account_id))
    if (local.hour, local.minute) < (0, 30):
        return False
    today = local.date().isoformat()
    return _state_get(db, key) != today


def _record_daily_run(db, now_utc, key, account_id):
    local = now_utc.astimezone(_my_timezone(db, account_id))
    _state_set(db, key, local.date().isoformat())


# ---------------------------------------------------------------- tick

def tick(db, now=None, timers=None):
    """One worker tick. `timers` is a mutable dict carrying last-run
    monotonic stamps between ticks ({'gmail': t, 'detection': t})."""
    if now is None:
        now = datetime.datetime.now(datetime.timezone.utc)
    if timers is None:
        timers = {}
    mono = time.monotonic()

    # heartbeat always runs, even with zero configuration (global: one
    # worker process serves every tenant)
    _run_task("heartbeat", _state_set, db, "worker_heartbeat", now.isoformat())

    gmail_due = (mono - timers.get("gmail", -GMAIL_POLL_SECONDS)
                 >= GMAIL_POLL_SECONDS)
    detection_due = (mono - timers.get("detection", -DETECTION_SCAN_SECONDS)
                     >= DETECTION_SCAN_SECONDS)
    gcal_due = (mono - timers.get("gcal", -GCAL_SYNC_SECONDS)
                >= GCAL_SYNC_SECONDS)

    # Stale approvals expire across every tenant in one sweep (pure
    # timestamp comparison; no per-tenant settings involved).
    from leadflow.approvals import expire_stale
    _run_task("expire_stale", expire_stale, db)

    for account_id in _active_accounts(db):
        try:
            _tick_account(db, account_id, now, gmail_due, detection_due,
                          gcal_due)
        except Exception:
            # Belt: _tick_account shields each sub-task already. One
            # tenant's failure never blocks another (S1).
            logger.exception("worker tick failed for account %s", account_id)

    if gmail_due:
        timers["gmail"] = mono
    if detection_due:
        timers["detection"] = mono
    if gcal_due:
        timers["gcal"] = mono
    return timers


def _tick_account(db, account_id, now, gmail_due, detection_due,
                  gcal_due=False):
    """Every per-tenant job for one account, under its account scope."""
    from leadflow.auth import account_scope
    from leadflow.db import account_state_key

    def key(name):
        return account_state_key(name, account_id)

    def task(name):
        return _task_key(name, account_id)

    with account_scope(account_id):
        # BLOCK 1 STEP C: the BILLING PAUSE gate stood here, above every
        # other gate in this function, and is gone with billing. B3
        # removed suspension too, so what stops an unapproved account's
        # automation is `gmail.smtp_send.send_email`'s FIRST rung,
        # which refuses any account that is not `active` — the same rung
        # that already covered the background passes and the two send
        # paths that never reach the dispatcher.
        # S8: Google Calendar two-way sync, every 5 minutes for CONNECTED
        # accounts. Deliberately BEFORE the outreach gate — appointments
        # are human-made data, not outreach, so pausing outreach does not
        # pause calendar sync (accepted S8 decision).
        if gcal_due:
            from leadflow import gcal
            try:
                connected = gcal.is_connected(db, account_id)
            except Exception:
                logger.exception("gcal connection check failed for "
                                 "account %s", account_id)
                connected = False
            if connected:
                _run_task(task("gcal_sync"), gcal.sync_account, db,
                          account_id=account_id)
                _run_task(task("gcal_retry"), gcal.retry_unsynced, db,
                          account_id=account_id)

        # NOTE: there is no call-reconciliation pass any more. The app
        # placed calls through Twilio until the calling system was removed;
        # dialing now happens in Ringy, outside Ancora, and a VA records
        # the outcome by hand. Nothing to poll, and nothing here reaches a
        # lead.

        # T1: appointment confirmation reminders, every tick behind a
        # cheap EXISTS pre-check — one small LIMIT-1 query over this
        # tenant's own appointment rows. NOT an indexed lookup: EXPLAIN
        # QUERY PLAN reports SCAN on `interactions`, which carries only
        # (lead_id) and (user_id, created_at) indexes. At this scale the
        # scan is free, and an index added purely to make a comment true
        # would be worse than an honest comment. Deliberately BEFORE the outreach
        # gate, for the IDENTICAL reason the calendar sync and the call
        # poll are: this reminder is a note to the AGENT about a
        # human-made appointment and never contacts a lead — the app
        # sends no text here, ever — so it is not outreach.
        from leadflow import confirmations
        try:
            confirm_due = confirmations.has_pending_confirmations(
                db, account_id=account_id)
        except Exception:
            logger.exception("confirmation pre-check failed for account %s",
                             account_id)
            confirm_due = False
        if confirm_due:
            _run_task(task("appt_confirm"), confirmations.notify_due, db,
                      account_id)

        transport_ready = _gmail_configured(db, account_id)
        intake_enabled = _intake_enabled(db, account_id)
        outreach_live = _outreach_live(db, account_id)

        # T2: the mailbox poll runs ABOVE the outreach gate because it
        # serves TWO independent consumers — lead INTAKE and the reply /
        # bounce / booking paths that outreach depends on. Poll when
        # EITHER switch is on; skip it entirely when both are off (nothing
        # would consume the mail, and an unread inbox stays unread). The
        # per-message intake gate inside poll_gmail is what actually
        # decides whether a lead is created.
        if gmail_due and transport_ready and (intake_enabled
                                              or outreach_live):
            from leadflow.gmail.intake import poll_gmail
            _run_task(task("poll_gmail"), poll_gmail, db,
                      account_id=account_id)

        # R5 script fill — deliberately ABOVE the outreach guard, for the
        # same reason gcal sync, the Twilio poll and the confirmation
        # reminders are: it reaches nobody. It writes recovery lines onto
        # queue rows for a human to READ ALOUD; no lead is contacted.
        #
        # It has to run here or it does not run at all in the state that
        # matters: the work console is a GET and no longer generates
        # inline, /today builds the day's queue whether or not outreach is
        # live, so a paused tenant would show "preparing lines" forever.
        # It no-ops while the VA plan is off, so a tenant with no VAs makes
        # no API calls from this pass at all.
        from leadflow.va import fill_missing_scripts
        _run_task(task("va_scripts"), fill_missing_scripts, db,
                  account_id=account_id)

        if not outreach_live:
            # Outreach paused (per account): no dispatch, no detection, no
            # queue build, no nightly passes for THIS tenant — other
            # tenants unaffected.
            return

        # every tick: dispatch
        if transport_ready:
            from leadflow.outreach.dispatcher import dispatch_due
            _run_task(task("dispatch_due"), dispatch_due, db,
                      account_id=account_id)

        # R3 detection scan: recovery flags + hot expiry, every 5 minutes.
        if detection_due:
            from leadflow.detection import scan
            _run_task(task("detection_scan"), scan, db,
                      account_id=account_id)

        # VA queue: build once per account-local day (per-account cursor;
        # ensure_daily_queue no-ops after the first run and while
        # the VA plan is off).
        from leadflow.va import ensure_daily_queue, expire_nocontact
        _run_task(task("va_queue"), ensure_daily_queue, db,
                  account_id=account_id)

        # nightly exhausted pass (per-account cursor)
        try:
            if transport_ready and _daily_due(
                    db, now, key("worker_exhausted_date"), account_id):
                from leadflow.outreach.dispatcher import mark_exhausted
                if _run_task(task("mark_exhausted"), mark_exhausted, db,
                             account_id=account_id):
                    _record_daily_run(db, now, key("worker_exhausted_date"),
                                      account_id)
        except Exception:
            logger.exception("nightly check failed for account %s",
                             account_id)

        # S3: nightly no-contact expiry pass (per-account cursor; not
        # gated on transport — the pending-send guard inside the pass
        # already protects in-flight sequences).
        try:
            if _daily_due(db, now, key("nocontact_expire_date"), account_id):
                if _run_task(task("nocontact_expire"), expire_nocontact, db,
                             account_id=account_id):
                    _record_daily_run(db, now, key("nocontact_expire_date"),
                                      account_id)
        except Exception:
            logger.exception("nocontact expiry check failed for account %s",
                             account_id)

        # Agent leads: nightly unworked-residency pass (per-account
        # cursor). A SEPARATE pass from expire_nocontact above, not a
        # parameterisation of it: that one's predicate is stage-based and
        # would spare an agent lead that reached `quote` on a warm inbound
        # without anyone ever speaking to them. Not gated on transport or
        # on outreach — it sends nothing.
        try:
            if _daily_due(db, now, key("agent_lead_expire_date"), account_id):
                from leadflow.agent_leads import expire_agent_leads
                if _run_task(task("agent_lead_expire"), expire_agent_leads,
                             db, account_id=account_id):
                    _record_daily_run(db, now, key("agent_lead_expire_date"),
                                      account_id)
        except Exception:
            logger.exception("agent lead expiry check failed for account %s",
                             account_id)

        # Overflow pool: nightly 45-day residency sweep (per-account
        # cursor). Sends nothing, so it is not gated on transport or on
        # outreach. There is no positive-contact clock stop to honour —
        # positive contact PROMOTES the row out of the pool entirely.
        try:
            if _daily_due(db, now, key("overflow_expire_date"), account_id):
                from leadflow.overflow import expire_overflow
                if _run_task(task("overflow_expire"), expire_overflow,
                             db, account_id=account_id):
                    _record_daily_run(db, now, key("overflow_expire_date"),
                                      account_id)
        except Exception:
            logger.exception("overflow expiry check failed for account %s",
                             account_id)

        # R7: referral-ask daily pass (live only — the outreach gate
        # above already returned), alongside the nightly pass: due pending
        # asks become referral approval drafts + notifications. Never
        # auto-sends; not gated on transport (drafts wait in /approvals).
        try:
            if _daily_due(db, now, key("referral_asks_date"), account_id):
                from leadflow.sales import prompt_due_asks
                if _run_task(task("referral_asks"), prompt_due_asks, db,
                             account_id=account_id):
                    _record_daily_run(db, now, key("referral_asks_date"),
                                      account_id)
        except Exception:
            logger.exception("referral-ask daily check failed for "
                             "account %s", account_id)


# ---------------------------------------------------------------- loop

def _loop():
    from leadflow.db import get_db
    timers = {}
    logger.info("worker loop started (tick every %ds)", TICK_SECONDS)
    while not _stop_event.is_set():
        try:
            db = get_db()
            tick(db, timers=timers)
        except Exception:
            # tick() shields sub-tasks; this catches e.g. DB open failure
            logger.exception("worker tick crashed")
        _stop_event.wait(TICK_SECONDS)
    logger.info("worker loop stopped")


def start_worker(app=None):
    """Start the daemon worker thread (idempotent)."""
    global _worker_thread
    if _worker_thread is not None and _worker_thread.is_alive():
        return _worker_thread
    _stop_event.clear()
    _worker_thread = threading.Thread(target=_loop, name="leadflow-worker",
                                      daemon=True)
    _worker_thread.start()
    return _worker_thread


def stop_worker(timeout=5):
    """Signal the loop to stop (used by tests)."""
    _stop_event.set()
    if _worker_thread is not None:
        _worker_thread.join(timeout=timeout)
