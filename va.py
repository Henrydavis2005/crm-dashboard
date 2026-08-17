"""The VA assistant queue: what an assistant calls today.

B6 CHANGED WHERE THE ROWS COME FROM. An agent SENDS a lead
(leadflow/va_send.py), and the day's queue is rebuilt from the sends that
have not been worked or closed yet. A lead sent on Tuesday and not reached
is on Wednesday's queue without anybody re-sending it.

WHAT WAS REMOVED, and why it is not coming back: three automatic tiers
(callbacks due, recovery flags, the S3 no-contact volume pool) and
`insert_ghost`'s same-day line-jumping. They chose who a VA called by
arithmetic over everything in the database — which is how a lead nobody
had looked at, from a vendor nobody had approved, in a state nobody was
licensed for, could reach a dialler. The recovery FLAGS still open;
"ghosted two days with nothing booked" is now the first signal
`va_send.rank_suggestions` orders by, where an agent sees it and chooses.

THE EXCLUSIONS SURVIVED THE TIERS. They are not selection — they are the
list of leads that must not be in front of an assistant whatever anybody
sent — and each is applied to the send-derived candidate list:
  closed_state set (sold/dead/no_number, covering C1's not_qualified and
  C2a's "can't find a real number"); phone missing or phone_bad (C1 Wrong
  Number); suppressed or revoked; an OPEN callback_review task (C1
  Callback Requested — the agent is deciding, the VA must not re-serve
  it); `referred_by` set (the R7 referral firewall); CLAIMED
  (detection.is_claimed: a future appointment, follow-up or callback, or
  sold); and B4 LICENSURE, applied at `_add` so it holds for every row by
  construction. Legacy source values (callback/ghost/stale/volume/aged/
  fresh) remain readable on pre-B6 rows.

S2 CLAIMS are unchanged: placing the DIAL claims the row for that user
(assigned_to, first claim wins, status-guarded UPDATE; re-entering an own
claim is fine). Other VAs' lists and next-in-queue skip foreign-assigned
rows. A claim is released when the lead is worked, when that caller claims
another lead, when the dial that took it is refused or fails, and
implicitly at day end. The work console is a GET and takes no claim.

`expire_nocontact(db)` is the nightly per-tenant pass: no-contact leads
older than the window with no pending sequence sends left are marked DEAD
(closed_state='dead', event 'nocontact_expired') and evicted from today's
pending queue.

`evict_pending(db, lead_id, reason)` is the mid-day mirror: a lead that
stops being workable (tagged as a referral, suppressed, sold/dead) loses
its PENDING row for today immediately (worked rows untouched).

The 8am-8pm lead-local calling window (quiet_start/quiet_end settings +
the lead's stored timezone) hard-blocks queued leads: pending rows outside
the window render locked on /today and the call-log route rejects an
early/late log server-side. `slot_hour` is NULL on every new row — the S3
retry rotation was computed inside the volume tier's ordering pass, and a
slot invented for a send would be a lock with no reason behind it.

Idempotent: re-running build_queue only appends missing slots (top-up);
existing rows and their positions never change. Generation is skipped
entirely while the VA plan is off. Triggered from the first /today hit of
the day and by the worker after midnight my_timezone (ensure_daily_queue).
When it owns its transaction the whole build runs inside BEGIN IMMEDIATE,
so the worker's midnight tick racing the first /today hit cannot fill the
day twice.

R5 script cache: `fill_missing_scripts` (worker follow-up, a few rows per
tick) generates and caches the per-lead AI recovery lines for rows that
carry a recovery source, so page loads never wait on the API.
"""
import datetime
import logging
from zoneinfo import ZoneInfo

from leadflow import licensure
from leadflow import pipeline as pipeline_module
from leadflow.audit import log_event
from leadflow.auth import current_account_id
from leadflow.db import utcnow
from leadflow.tz import DEFAULT_TZ, is_quiet_ok

logger = logging.getLogger("leadflow.va")

# B11: the three stages this used to name — new, contacted, nurture — were
# the three ways of saying "we have never heard back", and they are now the
# one COLD lane. Imported from pipeline rather than re-spelt here, so a
# change to what Cold means cannot leave the dial queue behind.
NOT_CONTACTED_STAGES = tuple(pipeline_module.COLD_STAGES)
RECOVERY_SOURCES = ("ghost", "stale")
# Legacy aged/fresh rows count toward the volume side of the slot math.
VOLUME_SOURCES = ("volume", "aged", "fresh")
# Every value `va_queue.source` can hold. Callbacks are queued directly and
# belong to neither pool above, so the full vocabulary was previously only
# implicit. It is named here because three templates build a CSS class from
# it (`badge-src-{{ ... }}`) and a source with no matching rule loses its
# colour SILENTLY — tests/test_badge_coverage.py walks this tuple.
# B6: "sent" is the only source a queue row can now have — an agent
# pressed Send. The older labels stay in the tuple because rows
# written before B6 still carry them and every badge, filter and
# per-source card reads this list; dropping them would silently
# uncolour history.
QUEUE_SOURCES = ("sent", "callback") + RECOVERY_SOURCES + VOLUME_SOURCES
_KIND_SOURCE = {"fast_ghost": "ghost",
                "stale_quote": "stale",
                "stale_engaged": "stale"}
# Max ids per IN (...) probe — SQLite's variable limit is 999 on older
# builds, and the volume pool can be thousands of leads wide.
_ID_CHUNK = 400

# Shared exclusion clauses (all tiers). Params: day_start_utc, day_end_utc.
# The suppressions probe is account-scoped (S1): another tenant
# suppressing the same contact never excludes this tenant's lead.
# C1: an OPEN callback_review task (the callback_requested disposition)
# holds the lead out of BOTH blocks until the agent sets a follow-up or
# dismisses the task — the VA pool never re-serves a lead awaiting the
# agent's decision. closed_state IS NULL already covers not_qualified
# ('dead') and C2a's 'no_number'; phone_bad = 0 covers Wrong Number.
# C2 verified both: this ONE string is interpolated into the callback,
# recovery AND volume candidate queries, so every exclusion holds for
# every block by construction — a no_number lead, a not_qualified lead
# and a lead with an open callback_review task are absent from all three
# (tests/test_va_queue.py asserts it per block). C2 adds queue ORDERING
# (attempt tiers) on top, in _volume_candidates; the exclusions are C1's.
_EXCLUDE_SQL = (
    " AND l.referred_by IS NULL"
    " AND l.closed_state IS NULL"
    " AND l.phone IS NOT NULL AND l.phone != ''"
    " AND l.phone_bad = 0"
    " AND NOT EXISTS (SELECT 1 FROM tasks t WHERE t.lead_id = l.id"
    "   AND t.kind = 'callback_review' AND t.status = 'open')"
    " AND NOT EXISTS (SELECT 1 FROM suppressions s"
    "   WHERE s.account_id = l.account_id AND (s.lead_id = l.id"
    "   OR (s.email IS NOT NULL AND l.email IS NOT NULL"
    "       AND s.email = l.email)"
    "   OR (s.phone IS NOT NULL AND l.phone IS NOT NULL"
    "       AND s.phone = l.phone)))"
    " AND NOT EXISTS (SELECT 1 FROM messages m WHERE m.lead_id = l.id"
    "   AND m.direction = 'out' AND m.status = 'pending'"
    "   AND m.due_at >= ? AND m.due_at < ?)"
)


def _utcnow():
    # type: () -> datetime.datetime
    """Now, UTC aware. Module-level so tests can monkeypatch time."""
    return datetime.datetime.now(datetime.timezone.utc)


def _my_zone(db):
    from leadflow.settings import get_setting
    try:
        return ZoneInfo(get_setting("my_timezone", db=db))
    except Exception:
        return ZoneInfo("America/New_York")


def _int_setting(db, key, default):
    from leadflow.settings import get_setting
    try:
        return int(get_setting(key, db=db))
    except Exception:
        return default


def local_today(db):
    # type: (object) -> str
    """Today's date (YYYY-MM-DD) in my_timezone."""
    return _utcnow().astimezone(_my_zone(db)).date().isoformat()


def _day_bounds_utc(db, qdate):
    """(start_iso, end_iso): the UTC window covering qdate in my_timezone."""
    zone = _my_zone(db)
    day = datetime.date.fromisoformat(qdate)
    start = datetime.datetime(day.year, day.month, day.day, tzinfo=zone)
    end = start + datetime.timedelta(days=1)
    return (start.astimezone(datetime.timezone.utc).isoformat(
                timespec="seconds"),
            end.astimezone(datetime.timezone.utc).isoformat(
                timespec="seconds"))


# ------------------------------------------------------------ candidates

def _callback_candidates(db, qdate, account_id, day_start, day_end):
    """Lead ids whose LATEST answered_callback is due (callback_on <= qdate)
    and unworked (no later call of any disposition — the outcome works a
    callback), most overdue first. LEGACY since C1: answered_callback is no
    longer loggable, so this tier only ever serves pre-C1 rows."""
    return [r["id"] for r in db.execute(
        "SELECT l.id FROM leads l JOIN ("
        "  SELECT i1.id AS cb_id, i1.lead_id, i1.callback_on"
        "  FROM interactions i1"
        "  WHERE i1.itype = 'call' AND i1.disposition = 'answered_callback'"
        "  AND i1.id = (SELECT MAX(i2.id) FROM interactions i2"
        "               WHERE i2.lead_id = i1.lead_id AND i2.itype = 'call'"
        "               AND i2.disposition = 'answered_callback')"
        ") cb ON cb.lead_id = l.id "
        "WHERE l.account_id = ? AND cb.callback_on <= ? "
        "AND NOT EXISTS (SELECT 1 FROM interactions iw"
        "  WHERE iw.lead_id = l.id AND iw.itype = 'call'"
        "  AND iw.id > cb.cb_id)" + _EXCLUDE_SQL +
        " ORDER BY cb.callback_on, l.id",
        (account_id, qdate, day_start, day_end)).fetchall()]


def _recovery_candidates(db, account_id, day_start, day_end):
    """Active recovery flags (joined to eligible leads) in urgency order:
    fast_ghost (oldest flagged_at first) -> stale_quote -> stale_engaged.

    Includes status 'queued' flags too: a flag queued on a previous day but
    never worked re-queues today instead of starving."""
    return db.execute(
        "SELECT f.id AS flag_id, f.kind, f.status AS flag_status, "
        "f.lead_id AS lead_id FROM recovery_flags f "
        "JOIN leads l ON l.id = f.lead_id "
        "WHERE f.account_id = ? AND f.status IN ('open','queued')"
        + _EXCLUDE_SQL +
        " ORDER BY CASE f.kind WHEN 'fast_ghost' THEN 0"
        "   WHEN 'stale_quote' THEN 1 ELSE 2 END, f.flagged_at, f.id",
        (account_id, day_start, day_end)).fetchall()


def _volume_candidates(db, account_id, day_start, day_end, window_days,
                       min_age_hours, near_expiry_days, qdate=None, zone=None,
                       now=None, attempts=None):
    """The S3 no-contact volume pool, in queue order.

    Eligible: received within the window AND at least min_age_hours old
    AND the lead is COLD (B11: never responded — engaged/quote stay
    recovery's, and every Negative stage is out) AND the shared
    exclusions. The CLAIMED check
    (detection.is_claimed — future appointment / follow-up / callback,
    sold) is applied lazily by the build loop (it needs per-lead queries;
    the loop stops once the day is full).

    Ordering (C2), in three keys:
      1. NEAR-EXPIRY GUARD, unchanged: leads received_at within
         near_expiry_days of the window cutoff come first, closest to
         expiry first. C2 does NOT re-sort this block — a lead about to
         age out is worked before any tier consideration.
      2. ATTEMPT TIER ascending: 0 prior no-contact attempts, then 1,
         then 2+ (tier = min(attempts, 2)). Repeat voicemails/no-answers
         sink; fresh, never-tried numbers rise.
      3. NEWEST received_at first WITHIN the tier (S3's rule, preserved),
         id DESC as the final tiebreak.
    Keys 1 and 3 are the SQL ORDER BY (unchanged); the tier is applied as
    a STABLE sort on top, so within a tier the SQL order — newest first —
    survives untouched, and inside the near-expiry block the tier can only
    break an exact received_at tie.

    `attempts`, when a dict is passed in, is filled with the pool's
    {lead_id: attempt count} so the build loop can stamp each row's S3
    retry slot from the very same numbers the tiers were built from (one
    definition, no second pass)."""
    if now is None:
        now = _utcnow()
    if qdate is None:
        qdate = day_start[:10]
    if zone is None:
        zone = _my_zone(db)
    cutoff_dt = (datetime.datetime.fromisoformat(day_start)
                 - datetime.timedelta(days=window_days))
    cutoff = cutoff_dt.isoformat(timespec="seconds")
    near_cutoff = (cutoff_dt + datetime.timedelta(days=near_expiry_days)
                   ).isoformat(timespec="seconds")
    max_received = (now - datetime.timedelta(hours=min_age_hours)
                    ).isoformat(timespec="seconds")
    stage_in = ",".join("?" for _ in NOT_CONTACTED_STAGES)
    rows = db.execute(
        "SELECT l.id, l.received_at FROM leads l "
        "WHERE l.account_id = ? AND l.received_at >= ? "
        "AND l.received_at <= ? "
        "AND l.pipeline_stage IN (%s)" % stage_in
        + _EXCLUDE_SQL +
        " ORDER BY CASE WHEN l.received_at < ? THEN 0 ELSE 1 END,"
        " CASE WHEN l.received_at < ? THEN l.received_at ELSE '' END,"
        " l.received_at DESC, l.id DESC",
        (account_id, cutoff, max_received) + NOT_CONTACTED_STAGES
        + (day_start, day_end, near_cutoff, near_cutoff)).fetchall()

    counts = _attempt_counts(db, account_id, [r["id"] for r in rows],
                             qdate, zone)
    if attempts is not None:
        attempts.update(counts)

    def _order_key(row):
        near = row["received_at"] < near_cutoff
        return (0 if near else 1,
                row["received_at"] if near else "",
                attempt_tier(counts.get(row["id"], 0)))
    return [r["id"] for r in sorted(rows, key=_order_key)]


# ------------------------------------------------------------ S3 slots

DEFAULT_RETRY_SLOTS = [8, 9, 11, 13, 15, 17, 19]


def retry_slots(db, account_id=None):
    # type: (object, object) -> list
    """The parsed va_retry_slots hours (S3). Malformed values fall back to
    the defaults; hours are clamped to 0-23 order-preserved."""
    from leadflow.settings import get_setting
    try:
        raw = str(get_setting("va_retry_slots", db=db,
                              account_id=account_id) or "")
        slots = [int(p.strip()) for p in raw.split(",") if p.strip()]
        slots = [h for h in slots if 0 <= h <= 23]
    except Exception:
        slots = []
    return slots or list(DEFAULT_RETRY_SLOTS)


# C2: the volume block's attempt tiers. 0 and 1 stand alone; every lead
# with 2 or more prior no-contact attempts shares the bottom tier (a 5th
# voicemail is not meaningfully worse than a 3rd — the point is to stop
# burning the day on numbers that keep not answering, not to rank them).
MAX_ATTEMPT_TIER = 2

# The two dispositions that ARE a no-contact attempt (C1 kept the values;
# only the labels moved to "No Answer" / "Voicemail Left").
NOCONTACT_DISPOSITIONS = ("voicemail", "no_answer")


def attempt_tier(attempts):
    # type: (int) -> int
    """The C2 ordering tier for an attempt count: 0, 1, or 2 ("2+")."""
    return min(int(attempts), MAX_ATTEMPT_TIER)


def _local_day(created_at, zone):
    """A UTC ISO timestamp as a YYYY-MM-DD day in `zone` (None if unparseable)."""
    try:
        dt = datetime.datetime.fromisoformat(
            str(created_at).replace("Z", "+00:00"))
    except (ValueError, TypeError):
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=datetime.timezone.utc)
    return dt.astimezone(zone).date().isoformat()


def _attempt_counts(db, account_id, lead_ids, qdate, zone):
    # type: (object, int, object, str, object) -> dict
    """{lead_id: attempts} for a whole set of leads, in two queries.

    THE attempt definition (S3, unchanged by C2): the number of DISTINCT
    prior queue-days (qdate < today, this account) on which a
    voicemail/no_answer call was logged on the lead. It drives BOTH the S3
    retry-slot rotation and C2's volume-block tiers, so the two can never
    disagree.

    Set-based because C2 needs it for the entire volume pool at build
    time: one query for the prior queue-days, one (chunked) for the calls
    of the leads that actually have prior queue-days — a lead never queued
    before is 0 attempts by definition and is never probed. The
    UTC->my_timezone day conversion stays in Python: SQLite has no tz
    database, and a fixed offset would silently miscount across a DST
    boundary."""
    ids = [int(i) for i in lead_ids]
    counts = dict((i, 0) for i in ids)
    if not counts:
        return counts

    prior_qdates = {}
    for r in db.execute(
            "SELECT DISTINCT lead_id, qdate FROM va_queue "
            "WHERE account_id = ? AND qdate < ?",
            (account_id, qdate)).fetchall():
        if r["lead_id"] in counts:
            prior_qdates.setdefault(r["lead_id"], set()).add(r["qdate"])
    if not prior_qdates:
        return counts

    probe = sorted(prior_qdates)
    disp_in = ",".join("?" for _ in NOCONTACT_DISPOSITIONS)
    call_days = {}
    for start in range(0, len(probe), _ID_CHUNK):
        chunk = probe[start:start + _ID_CHUNK]
        id_in = ",".join("?" for _ in chunk)
        for r in db.execute(
                "SELECT lead_id, created_at FROM interactions "
                "WHERE itype = 'call' AND disposition IN (%s) "
                "AND lead_id IN (%s)" % (disp_in, id_in),
                NOCONTACT_DISPOSITIONS + tuple(chunk)).fetchall():
            day = _local_day(r["created_at"], zone)
            if day is not None:
                call_days.setdefault(r["lead_id"], set()).add(day)

    for lead_id, days in prior_qdates.items():
        counts[lead_id] = len(days & call_days.get(lead_id, set()))
    return counts


def _attempt_count(db, account_id, lead_id, qdate, zone):
    # type: (object, int, int, str, object) -> int
    """One lead's attempt count — the single-lead face of
    `_attempt_counts` (ONE definition; see it for the semantics)."""
    return _attempt_counts(db, account_id, [lead_id], qdate, zone).get(
        lead_id, 0)


def _is_claimed(db, lead_id):
    """S3 pool gate: detection.is_claimed (future appointment / follow-up /
    callback, sold), deferred import to avoid cycles. Errors read as NOT
    claimed (the lead stays workable)."""
    try:
        from leadflow.detection import is_claimed
        return bool(is_claimed(db, lead_id))
    except Exception:
        logger.exception("is_claimed failed for lead %s", lead_id)
        return False


# ------------------------------------------------------------ S2 quotas

def effective_quota(db, user_row, account_id=None):
    # type: (object, object, object) -> int
    """A VA's effective daily quota: users.daily_quota else the tenant
    va_daily_quota (S2)."""
    if user_row is not None and user_row["daily_quota"]:
        return int(user_row["daily_quota"])
    return _int_setting(db, "va_daily_quota", 125)


def day_target(db, account_id):
    # type: (object, int) -> int
    """S2: the day's queue target = SUM of enabled VAs' effective quotas;
    zero enabled VAs -> the tenant default (admin can still work it)."""
    vas = db.execute(
        "SELECT * FROM users WHERE account_id = ? AND role = 'va' "
        "AND enabled = 1", (account_id,)).fetchall()
    if not vas:
        return _int_setting(db, "va_daily_quota", 125)
    return sum(effective_quota(db, u) for u in vas)


# ------------------------------------------------------------ build

def build_queue(db, qdate, account_id=None):
    # type: (object, str, object) -> int
    """Fill qdate's va_queue up to the day target (S2: sum of enabled VAs'
    effective quotas; fill order per R4: callbacks, recovery up to
    va_recovery_slots, volume fills the rest — the S3 pool, near-expiry
    first, then C2's attempt tiers, then newest first inside each tier,
    each volume row stamped with its S3 retry slot_hour from the same
    attempt count). Idempotent top-up: existing rows keep their positions;
    only missing slots are appended and the per-class slot math counts
    what is already queued. Returns the number of rows added (0 while
    the VA plan is off)."""
    from leadflow.auth import account_scope
    if account_id is None:
        account_id = current_account_id()
    # Everything below (settings, timezone, is_claimed) resolves against
    # this account, whatever thread we run on (S1).
    with account_scope(account_id):
        return _build_queue(db, qdate, account_id)


def _build_queue(db, qdate, account_id):
    from leadflow import entitlements
    if not entitlements.va_access(db, account_id):
        return 0
    own = not db.in_transaction
    if own:
        # The build is a CLAIM/COUNTER path (CLAUDE.md): it reads how many
        # rows the day already holds and then fills the gap. The snapshot
        # and the inserts must be ONE write transaction, or two builders
        # racing at the day boundary (the worker's midnight tick against
        # the first /today hit — the pairing R4 names) each see an empty
        # day and each fill it to the full target. UNIQUE(qdate, lead_id)
        # only de-dupes the leads they have in common; the loser walks
        # further down the candidate list, so the day ends up at twice its
        # target with colliding positions. BEGIN IMMEDIATE makes the second
        # builder wait, take a snapshot that already includes the first
        # one's rows, and add nothing.
        db.execute("BEGIN IMMEDIATE")
    try:
        return _fill_queue(db, qdate, account_id, own)
    except Exception:
        if own:
            db.rollback()
        raise


def _fill_queue(db, qdate, account_id, own):
    """The build itself — snapshot the day, then close the gap. Runs inside
    the caller's transaction (`own` says whether _build_queue opened it and
    therefore owes the commit)."""
    quota = day_target(db, account_id)
    recovery_slots = _int_setting(db, "va_recovery_slots", 35)
    window_days = _int_setting(db, "va_nocontact_window_days", 90)
    min_age_hours = _int_setting(db, "va_nocontact_min_age_hours", 6)
    near_expiry_days = _int_setting(db, "va_near_expiry_days", 7)
    slots = retry_slots(db, account_id=account_id)
    zone = _my_zone(db)
    day_start, day_end = _day_bounds_utc(db, qdate)

    existing = db.execute(
        "SELECT lead_id, position, source FROM va_queue "
        "WHERE account_id = ? AND qdate = ?", (account_id, qdate)).fetchall()
    queued = set(r["lead_id"] for r in existing)
    # Overflow rows drawn EARLIER TODAY occupy day-target slots just like
    # real ones, so the idempotent top-up has to see them — otherwise the
    # second build of the day (worker tick after the first /today hit)
    # counts only the va_queue rows, believes the day is short by however
    # many overflow rows it already holds, and backfills that many again.
    of_existing = db.execute(
        "SELECT position, source FROM overflow_queue "
        "WHERE account_id = ? AND qdate = ?", (account_id, qdate)).fetchall()
    count = len(existing) + len(of_existing)
    recovery_used = (
        sum(1 for r in existing if r["source"] in RECOVERY_SOURCES)
        + sum(1 for r in of_existing if r["source"] == "overflow_recovery"))
    next_pos = max([r["position"] for r in existing]
                   + [r["position"] for r in of_existing] or [0]) + 1

    added = 0

    def _room():
        return quota - count - added

    # B4: the states this account may work today, read ONCE for the whole
    # build. Expired licences are already absent from the set, so an
    # account whose Georgia licence lapsed overnight stops queueing
    # Georgia leads on the next build with no row having changed — which
    # is what "checked at read, not only at write" means here.
    covered = licensure.covered_states(db, account_id)

    def _add(lead_id, source, slot_hour=None, allocated_to=None):
        # INSERT OR IGNORE: a concurrent build (worker tick racing the
        # first /today hit) may have queued the lead after our snapshot —
        # UNIQUE(qdate, lead_id) must never crash the build. An ignored
        # insert consumes no slot (rowcount 0).
        nonlocal next_pos, added
        # B4 LICENSURE, at the ONE function every tier's candidate passes
        # through — callbacks, recovery, volume and the overflow backfill
        # alike. Putting it in `_EXCLUDE_SQL` would have meant writing the
        # expiry rule a second time in SQL, where it could drift from
        # `licensure.covers`; putting it in each tier would have meant
        # writing it four times.
        #
        # A refused lead consumes NO SLOT and is not deleted, not
        # reassigned and not handed to another account. It stays in this
        # agent's pipeline, and /leads renders why.
        row = db.execute("SELECT state FROM leads WHERE id = ?",
                         (lead_id,)).fetchone()
        state = licensure.normalise_state(row["state"] if row else None)
        if state is None or state not in covered:
            queued.add(lead_id)   # do not reconsider it later in this build
            return False
        cur = db.execute(
            "INSERT OR IGNORE INTO va_queue (account_id, qdate, lead_id, "
            "position, source, status, slot_hour, allocated_to) "
            "VALUES (?,?,?,?,?,'pending',?,?)",
            (account_id, qdate, lead_id, next_pos, source, slot_hour,
             allocated_to))
        queued.add(lead_id)
        if cur.rowcount == 0:
            return False
        next_pos += 1
        added += 1
        return True

    # B6: THE ONLY SOURCE OF A QUEUE ROW IS AN AGENT'S EXPLICIT SEND.
    #
    # The three automatic tiers that stood here — callbacks, recovery
    # flags and the S3 volume pool — are GONE. They chose who a VA called
    # by arithmetic over everything in the database, which is how a lead
    # nobody had looked at, from a vendor nobody had approved, in a state
    # nobody was licensed for, reached a dialler. B6 replaced that
    # judgement with a person's: an agent looks at /send-to-va, sees what
    # passed six hard rules, and sends it.
    #
    # The day-based queue itself is unchanged — the VA console, the
    # positions, the scripts and the worked/locked machinery all still
    # want it — so each day this rebuilds from the sends that have not
    # been worked or closed yet. A lead sent on Tuesday and not reached is
    # on Wednesday's queue without anybody re-sending it.
    #
    # Sends are drawn for the whole TEAM (va_sends.team_account_id), which
    # is what makes it the team's queue rather than each agent's own.
    from leadflow.va_send import team_root
    root = team_root(db, account_id)

    # B12: OWN vs TEAM, and it is not a new concept or a second column.
    # `va_sends` has carried both since B6 — `team_account_id` is the
    # team root and `account_id` is the agent who pressed Send — so
    # "leads my own FTA sent me" and "leads the rest of the team sent"
    # are one WHERE clause apart. `origin` of None keeps the pre-B12
    # behaviour exactly: the whole team's sends, in one pass.
    def _sent_candidates(origin=None):
        where, params = "", [root]
        if origin == "own":
            where = "AND v.account_id = ? "
            params.append(account_id)
        elif origin == "team":
            where = "AND v.account_id != ? "
            params.append(account_id)
        return db.execute(
            "SELECT v.lead_id FROM va_sends v "
            "JOIN leads l ON l.id = v.lead_id "
            "WHERE v.team_account_id = ? " + where
            + "AND l.closed_state IS NULL "
            # R7 REFERRAL FIREWALL: a referred lead gets zero automated
            # outreach, and being handed to an assistant to cold-call is
            # exactly that. Kept from the exclusions the retired tiers
            # shared — it is an exclusion, not automatic selection.
            "AND l.referred_by IS NULL "
            "AND l.phone IS NOT NULL AND l.phone != '' "
            "AND l.phone_bad = 0 "
            # C1: a lead with an OPEN callback review is being handled by
            # an admin and must not be re-queued underneath them. Kept
            # from the exclusions the retired tiers shared — it is an
            # exclusion, not automatic selection, and dropping it would
            # put a lead back in front of a VA while somebody is deciding
            # what to do with it.
            "AND NOT EXISTS (SELECT 1 FROM tasks t WHERE t.lead_id = l.id "
            "  AND t.kind = 'callback_review' AND t.status = 'open') "
            "AND NOT EXISTS (SELECT 1 FROM suppressions s "
            "  WHERE s.account_id = l.account_id AND (s.lead_id = l.id "
            "  OR (s.email IS NOT NULL AND l.email IS NOT NULL "
            "      AND s.email = l.email) "
            "  OR (s.phone IS NOT NULL AND l.phone IS NOT NULL "
            "      AND s.phone = l.phone))) "
            "ORDER BY v.id", tuple(params)).fetchall()

    def _take(rows, cap, allocated_to=None):
        """Queue up to `cap` of these, skipping what is already queued or
        claimed. Returns how many actually landed — the CALLER needs the
        real number, because a seat that ran short is backfilled by
        exactly the shortfall and not by the target."""
        landed = 0
        for row in rows:
            if cap is not None and landed >= cap:
                break
            if _room() <= 0:
                break
            if row["lead_id"] in queued:
                continue
            # CLAIMED leads are held back, the one Python-side exclusion
            # the retired tiers had: a lead the admin has taken (a future
            # follow-up, an unresolved appointment, sold) must not
            # reappear in front of a VA underneath them. Kept for the same
            # reason as the callback-review exclusion above — it is an
            # exclusion, not automatic selection.
            if _is_claimed(db, row["lead_id"]):
                continue
            if _add(row["lead_id"], "sent", allocated_to=allocated_to):
                landed += 1
        return landed

    # 3a. B12 PER-SEAT ALLOCATION. Runs only for seats an FTA has actually
    # configured; every other seat, and every tenant that has configured
    # none, falls through to 3b and behaves exactly as it did before.
    #
    # Per seat, in order: OWN sends up to own_leads_target, TEAM sends up
    # to team_leads_target, then the SHORTFALL from overflow. The
    # shortfall is measured against what LANDED, not against the target,
    # so a seat short two own leads is backfilled by two.
    #
    # A SHORT DAY IS AN ACCEPTABLE OUTCOME. If own, team and overflow
    # together cannot fill the allocation, the seat gets fewer leads.
    # Nothing here relaxes a check to close the gap.
    from leadflow import allocation
    for seat in allocation.for_account(db, account_id):
        if not seat["configured"] or _room() <= 0:
            continue
        seat_id = seat["user_id"]
        own_target = seat["own_leads_target"] or 0
        team_target = seat["team_leads_target"] or 0
        landed = _take(_sent_candidates("own"), own_target, seat_id)
        landed += _take(_sent_candidates("team"), team_target, seat_id)
        gap = (own_target + team_target) - landed
        if gap > 0 and _room() > 0:
            added += _backfill_overflow(
                db, qdate, account_id, next_pos,
                recovery_slots - recovery_used, min(gap, _room()),
                allocated_to=seat_id)

    # 3b. Everything the allocation did not claim, for the whole team, in
    # one pass — unconfigured seats, the admin working the list, and any
    # room the configured seats left behind.
    _take(_sent_candidates(), None)

    # 4. OVERFLOW BACKFILL — the cold-start bridge, and it runs LAST for
    # exactly that reason. Every real lead the tenant has (callbacks,
    # recovery flags, the whole S3 volume pool) has already taken its slot
    # by the time we get here, so overflow can only ever occupy slots
    # nothing else wanted. It SUPPLEMENTS the day target; it never raises
    # it, never reorders a real lead, and never competes for a slot. On a
    # tenant with 125 real leads a day this loop draws nothing at all.
    #
    # It backfills BOTH tiers: whatever recovery slots the flags left
    # unused, then whatever the volume pool left unused. The tier only
    # decides the row's `source` label — an overflow row ALWAYS gets the
    # no-contact script, whichever tier it landed in, because nobody has
    # ever spoken to these people.
    added += _backfill_overflow(db, qdate, account_id, next_pos,
                                recovery_slots - recovery_used, _room())

    if own:
        db.commit()
    if added:
        logger.info("va_queue %s: added %d row(s) (total %d/%d)",
                    qdate, added, count + added, quota)
    return added


def _backfill_overflow(db, qdate, account_id, next_pos, recovery_room,
                       total_room, allocated_to=None):
    """Fill the day's LEFTOVER slots from the overflow pool.

    Called only at the very end of _fill_queue, with `total_room` already
    reduced by every real lead queued today — so this can never starve a
    bought or organic lead. `recovery_room` is what the recovery tier left
    unused; rows drawn against it are labelled `overflow_recovery` and the
    rest `overflow_volume`. Both work identically; the label exists so the
    admin's per-source day card still adds up.

    Draw order is the pool's own: NEWEST upload first, ties by row order
    within the file. Returns the number of rows added.
    """
    from leadflow import overflow
    if total_room <= 0:
        return 0
    # OVER-DRAW ON PURPOSE. Every candidate is judged by
    # `overflow.eligible` and a failure is SKIPPED, not force-filled, so
    # asking for exactly `total_room` rows would hand back fewer than
    # asked for whenever any of them is ineligible. The cap keeps a pool
    # full of unlicensed rows from turning one build into a full scan.
    candidates = overflow.draw_candidates(
        db, account_id, qdate, min(total_room * 4 + 20, 500))
    if not candidates:
        return 0
    # B12 DEFECT FIX: read once for the whole draw, exactly as _fill_queue
    # does for real leads. Before this, overflow rows reached a VA's dial
    # list without any licensure check at all — _backfill_overflow never
    # went through `_add`, which is where that check lives.
    covered = licensure.covered_states(db, account_id)
    recovery_room = max(0, recovery_room)
    added = 0
    skipped = {}
    for row in candidates:
        if added >= total_room:
            break
        ok, reason = overflow.eligible(db, account_id, row, covered=covered)
        if not ok:
            skipped[reason] = skipped.get(reason, 0) + 1
            continue
        source = ("overflow_recovery" if added < recovery_room
                  else "overflow_volume")
        cur = db.execute(
            "INSERT OR IGNORE INTO overflow_queue (account_id, qdate, "
            "overflow_id, position, source, status, allocated_to) "
            "VALUES (?,?,?,?,?,'pending',?)",
            (account_id, qdate, row["id"], next_pos + added, source,
             allocated_to))
        if cur.rowcount:
            added += 1
    if added:
        logger.info("va_queue %s: backfilled %d overflow row(s)%s",
                    qdate, added,
                    "" if allocated_to is None else " for seat %d"
                    % allocated_to)
    if skipped:
        # NEVER SILENT. A short day that looks like "the pool was empty"
        # when it was really "nine rows are in a state we are not
        # licensed for" is the difference between a supply problem and a
        # compliance problem, and the FTA can only fix one of them.
        logger.info("va_queue %s: overflow skipped %s", qdate,
                    ", ".join("%s=%d" % (k, v)
                              for k, v in sorted(skipped.items())))
    return added


def ensure_daily_queue(db, account_id=None):
    # type: (object, object) -> int
    """Build today's queue once per local day (per-account app_state
    cursor, S1). Called on every /today hit and every worker tick; cheap
    no-op after the first."""
    from leadflow.db import account_state_key
    from leadflow import entitlements
    if account_id is None:
        account_id = current_account_id()
    if not entitlements.va_access(db, account_id):
        return 0
    today = local_today(db)
    key = account_state_key("va_queue_date", account_id)
    row = db.execute(
        "SELECT value FROM app_state WHERE key = ?", (key,)).fetchone()
    if row is not None and row["value"] == today:
        return 0
    added = build_queue(db, today, account_id=account_id)
    with db:
        db.execute(
            "INSERT INTO app_state (key, value) VALUES (?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            (key, today))
    return added


# ------------------------------------------------------------ line-jumping

# B6 REMOVED `insert_ghost`. It inserted a freshly-flagged ghost into
# today's queue the moment detection noticed it — automatic queue fill by
# another name, and the same objection: it put somebody on a call list
# without a person deciding to. The FLAG still opens; "ghosted two days
# with nothing booked" is now the first signal `va_send.rank_suggestions`
# orders by, where an agent sees it and chooses.


def fill_missing_scripts(db, limit=3, account_id=None):
    # type: (object, int, object) -> int
    """R5 worker follow-up (per account since S1): cache AI recovery lines
    for today's ghost/stale queue rows whose script_json is still NULL, a
    few per tick (build_queue inserts rows with script_json NULL so page
    loads never block on N API calls). Failures cache the fallback lines
    (generate_for_queue_row's safety nets); an unexpected per-row crash is
    logged and skipped. Returns the number of rows filled. No-op while
    the VA plan is off."""
    from leadflow import entitlements
    if account_id is None:
        account_id = current_account_id()
    if not entitlements.va_access(db, account_id):
        return 0
    from leadflow import scripts
    rows = db.execute(
        "SELECT id, lead_id, source FROM va_queue "
        "WHERE account_id = ? AND qdate = ? AND source IN ('ghost','stale') "
        "AND script_json IS NULL ORDER BY position, id LIMIT ?",
        (account_id, local_today(db), limit)).fetchall()
    filled = 0
    for row in rows:
        try:
            scripts.generate_for_queue_row(db, row)
            filled += 1
        except Exception:
            logger.exception("script fill failed for queue row %s",
                             row["id"])
    return filled


# ------------------------------------------------------------ calling window

def call_window_ok(db, lead, at=None):
    # type: (object, object, object) -> bool
    """True when `at` (default now) is inside the lead-local calling window
    (quiet_start-quiet_end settings, default 8am-8pm, in the lead's stored
    timezone)."""
    from leadflow.settings import get_setting
    quiet_start = get_setting("quiet_start", db=db) or "08:00"
    quiet_end = get_setting("quiet_end", db=db) or "20:00"
    tz_name = lead["timezone"] or DEFAULT_TZ
    return is_quiet_ok(tz_name, quiet_start, quiet_end, at or _utcnow())


def window_note(db, lead, at=None):
    # type: (object, object, object) -> str
    """Locked-row note: 'opens 8:00 AM EDT' (lead-local zone abbrev)."""
    from leadflow.settings import get_setting
    quiet_start = str(get_setting("quiet_start", db=db) or "08:00")
    tz_name = lead["timezone"] or DEFAULT_TZ
    try:
        zone = ZoneInfo(tz_name)
    except Exception:
        zone = ZoneInfo(DEFAULT_TZ)
    parts = quiet_start.split(":")
    hour = int(parts[0])
    minute = int(parts[1]) if len(parts) > 1 else 0
    ampm = "AM" if hour < 12 else "PM"
    abbrev = (at or _utcnow()).astimezone(zone).tzname() or tz_name
    return "opens %d:%02d %s %s" % (hour % 12 or 12, minute, ampm, abbrev)


def queued_pending_today(db, lead_id):
    """The lead's PENDING va_queue row for today in the CURRENT account
    (or None). The calling-window hard block applies to these rows only —
    a worked row never blocks a later log, and non-queued leads are
    unaffected."""
    return db.execute(
        "SELECT * FROM va_queue WHERE account_id = ? AND qdate = ? "
        "AND lead_id = ? AND status = 'pending' LIMIT 1",
        (current_account_id(), local_today(db), lead_id)).fetchone()


def _clamped_slot_hour(db, slot_hour):
    # type: (object, int) -> int
    """Clamp a retry slot at READ time: a slot at/after the calling-window
    end (possible when quiet_end was shrunk AFTER slots were saved) would
    otherwise never coincide with an open window — window-ok AND
    hour>=slot could never both hold, locking the row forever, silently.
    Such a slot is treated as (window end - 1) so the lead stays workable
    in the last window hour. Shared by slot_ok, unlock_note and
    unlock_sort_key so the lock, the note and the sort always agree."""
    from leadflow.settings import get_setting
    try:
        end_hour = int(str(get_setting("quiet_end", db=db)
                           or "20:00").split(":")[0])
    except (ValueError, TypeError):
        end_hour = 20
    if slot_hour >= end_hour:
        return max(end_hour - 1, 0)
    return slot_hour


def slot_ok(db, row, lead, at=None):
    # type: (object, object, object, object) -> bool
    """S3 retry-slot lock: True when the queue row has no slot_hour or the
    lead-local clock has reached it (window-end clamp applied). The full
    unlock condition for a pending row is call_window_ok AND slot_ok."""
    slot_hour = row["slot_hour"] if row is not None else None
    if slot_hour is None:
        return True
    slot_hour = _clamped_slot_hour(db, int(slot_hour))
    tz_name = lead["timezone"] or DEFAULT_TZ
    try:
        zone = ZoneInfo(tz_name)
    except Exception:
        zone = ZoneInfo(DEFAULT_TZ)
    local = (at or _utcnow()).astimezone(zone)
    return local.hour >= slot_hour


def row_unlocked(db, row, lead, at=None):
    # type: (object, object, object, object) -> bool
    """A pending queue row is workable when the lead-local calling window
    is open AND its S3 retry slot (if any) has arrived."""
    return (call_window_ok(db, lead, at=at)
            and slot_ok(db, row, lead, at=at))


def unlock_note(db, row, lead, at=None):
    # type: (object, object, object, object) -> str
    """Locked-row note: the LATER of window open and slot hour,
    lead-local (e.g. 'opens 11:00 AM EDT'). The slot is clamped the same
    way slot_ok clamps it, so the displayed time matches when the row
    actually unlocks."""
    from leadflow.settings import get_setting
    quiet_start = str(get_setting("quiet_start", db=db) or "08:00")
    parts = quiet_start.split(":")
    window_hour = int(parts[0])
    window_minute = int(parts[1]) if len(parts) > 1 else 0
    slot_hour = row["slot_hour"] if row is not None else None
    if slot_hour is not None:
        slot_hour = _clamped_slot_hour(db, int(slot_hour))
    hour, minute = window_hour, window_minute
    if slot_hour is not None and (slot_hour, 0) > (hour, minute):
        hour, minute = slot_hour, 0
    tz_name = lead["timezone"] or DEFAULT_TZ
    try:
        zone = ZoneInfo(tz_name)
    except Exception:
        zone = ZoneInfo(DEFAULT_TZ)
    ampm = "AM" if hour < 12 else "PM"
    abbrev = (at or _utcnow()).astimezone(zone).tzname() or tz_name
    return "opens %d:%02d %s %s" % (hour % 12 or 12, minute, ampm, abbrev)


def unlock_sort_key(db, row, lead, at=None):
    # type: (object, object, object, object) -> tuple
    """(hour, minute) lead-local at which a row unlocks — display sorting
    for locked rows (S3: rows sort by unlock time within their block).
    Uses the same window-end clamp as slot_ok/unlock_note."""
    from leadflow.settings import get_setting
    quiet_start = str(get_setting("quiet_start", db=db) or "08:00")
    parts = quiet_start.split(":")
    hour = int(parts[0])
    minute = int(parts[1]) if len(parts) > 1 else 0
    slot_hour = row["slot_hour"] if row is not None else None
    if slot_hour is not None:
        slot_hour = _clamped_slot_hour(db, int(slot_hour))
        if (slot_hour, 0) > (hour, minute):
            return (slot_hour, 0)
    return (hour, minute)


# ------------------------------------------------------------ views/worked

def queue_for_date(db, qdate):
    """The day's queue rows joined to their leads, in position order.
    Carries the lead's timezone/phone (calling-window lock), the latest
    queued/done recovery flag's flagged_at (ghost badge age), the claiming
    user's name (S2 assigned_username) and the lead's last activity in the
    DETECTION engine's sense (detection.LAST_ACTIVITY_SQL) — the column
    sits beside a Ghost/Stale badge that means "this lead has gone quiet",
    so it must never count our own outbound as the lead doing something."""
    from leadflow.detection import LAST_ACTIVITY_SQL  # deferred: avoid cycles
    return db.execute(
        "SELECT q.*, l.first_name, l.last_name, l.state, l.pipeline_stage, "
        "l.phone_bad, l.phone, l.email, l.timezone, l.hot_since, "
        "l.consent_date, "
        "u.username AS assigned_username, "
        + LAST_ACTIVITY_SQL + " AS last_activity, "
        "(SELECT f.flagged_at FROM recovery_flags f WHERE f.lead_id = l.id "
        " AND f.status IN ('queued','done') "
        " ORDER BY f.id DESC LIMIT 1) AS flagged_at "
        "FROM va_queue q JOIN leads l ON l.id = q.lead_id "
        "LEFT JOIN users u ON u.id = q.assigned_to "
        "WHERE q.account_id = ? AND q.qdate = ? ORDER BY q.position, q.id",
        (current_account_id(), qdate)).fetchall()


def claim_holder(db, qdate, lead_id):
    # type: (object, str, int) -> object
    """The user_id currently holding this row's claim, or None (unclaimed,
    not pending, or no such row).

    A pure READ, so a GET may call it. `work()` uses this to render "with
    <username>" without writing claim state — see claim_row's note.
    """
    row = db.execute(
        "SELECT assigned_to FROM va_queue WHERE account_id = ? "
        "AND qdate = ? AND lead_id = ? AND status = 'pending'",
        (current_account_id(), qdate, lead_id)).fetchone()
    return row["assigned_to"] if row is not None else None


def claim_row(db, qdate, lead_id, user_id):
    # type: (object, str, int, int) -> str
    """S2 queue claim: reserve a pending row for the user about to WORK it.
    Status-guarded UPDATE — the first claim wins; re-entering an own claim
    is fine. Returns 'claimed' (won or already ours), 'taken' (another user
    holds it), or 'free' (no pending row — worked/absent rows need none).

    A claim is taken by ACTING on a lead (placing the dial), never by
    looking at one. It used to be written from the `GET /today/work/<lead>`
    handler, and nothing in the codebase ever set `assigned_to` back to
    NULL: merely opening a console — including on a row outside its
    calling window, which the opener physically could not dial — removed
    that lead from every other caller's list for the rest of the day. A
    GET must not mutate claim state.

    Claiming also RELEASES this user's other pending claims for the day, so
    one caller holds exactly one lead and an abandoned claim cannot outlive
    the call that created it. Together with mark_worked's release, that is
    the whole lifecycle: taken on dial, dropped on the next dial or when
    the outcome is logged, and gone at day end with the day's rows.
    """
    account_id = current_account_id()
    own = not db.in_transaction
    cur = db.execute(
        "UPDATE va_queue SET assigned_to = ? "
        "WHERE account_id = ? AND qdate = ? AND lead_id = ? "
        "AND status = 'pending' "
        "AND (assigned_to IS NULL OR assigned_to = ?)",
        (user_id, account_id, qdate, lead_id, user_id))
    if cur.rowcount:
        released = db.execute(
            "UPDATE va_queue SET assigned_to = NULL "
            "WHERE account_id = ? AND qdate = ? AND assigned_to = ? "
            "AND status = 'pending' AND lead_id != ?",
            (account_id, qdate, user_id, lead_id)).rowcount
        if own:
            db.commit()
        if released:
            logger.info("va_queue released %d stale claim(s) user=%s "
                        "on claiming lead=%s", released, user_id, lead_id)
        return "claimed"
    row = db.execute(
        "SELECT assigned_to FROM va_queue WHERE account_id = ? "
        "AND qdate = ? AND lead_id = ? AND status = 'pending'",
        (account_id, qdate, lead_id)).fetchone()
    if row is None:
        return "free"
    return "taken" if row["assigned_to"] not in (None, user_id) else "claimed"


def release_claim(db, qdate, lead_id, user_id):
    # type: (object, str, int, int) -> int
    """Drop THIS user's claim on a pending row. A claim another caller
    holds is left alone. Returns the number of rows released.

    Called when the action that took the claim does not happen — a refused
    or failed dial must not leave the lead reserved behind it.
    """
    own = not db.in_transaction
    cur = db.execute(
        "UPDATE va_queue SET assigned_to = NULL "
        "WHERE account_id = ? AND qdate = ? AND lead_id = ? "
        "AND status = 'pending' AND assigned_to = ?",
        (current_account_id(), qdate, lead_id, user_id))
    if own:
        db.commit()
    return cur.rowcount


def queue_status(db, qdate):
    """Read-only status for the admin card: totals, per-class breakdown
    (queued/worked per source, R4) and per-VA worked counts."""
    account_id = current_account_id()
    totals = db.execute(
        "SELECT COUNT(*) AS queued, "
        "SUM(CASE WHEN status = 'worked' THEN 1 ELSE 0 END) AS worked "
        "FROM va_queue WHERE account_id = ? AND qdate = ?",
        (account_id, qdate)).fetchone()
    per_source = db.execute(
        "SELECT source, COUNT(*) AS queued, "
        "SUM(CASE WHEN status = 'worked' THEN 1 ELSE 0 END) AS worked "
        "FROM va_queue WHERE account_id = ? AND qdate = ? GROUP BY source "
        "ORDER BY CASE source WHEN 'callback' THEN 0 WHEN 'ghost' THEN 1 "
        "WHEN 'stale' THEN 2 WHEN 'volume' THEN 3 ELSE 4 END, source",
        (account_id, qdate)).fetchall()
    per_va = db.execute(
        "SELECT u.username, COUNT(*) AS worked "
        "FROM va_queue q JOIN users u ON u.id = q.worked_by "
        "WHERE q.account_id = ? AND q.qdate = ? AND q.status = 'worked' "
        "GROUP BY u.username ORDER BY u.username COLLATE NOCASE",
        (account_id, qdate)).fetchall()
    # S2: live claims (pending rows assigned to a user) for the admin card.
    per_va_claimed = db.execute(
        "SELECT u.username, COUNT(*) AS claimed "
        "FROM va_queue q JOIN users u ON u.id = q.assigned_to "
        "WHERE q.account_id = ? AND q.qdate = ? AND q.status = 'pending' "
        "GROUP BY u.username ORDER BY u.username COLLATE NOCASE",
        (account_id, qdate)).fetchall()
    return {"queued": totals["queued"] or 0, "worked": totals["worked"] or 0,
            "per_source": per_source, "per_va": per_va,
            "per_va_claimed": per_va_claimed}


def mark_worked(db, lead_id, user_id):
    # type: (object, int, object) -> int
    """Mark today's pending queue row for lead_id worked (first worker
    sticks; current account only). Never commits (log_call owns the
    transaction). Returns the number of rows updated (0 or 1).

    Marking a row worked RELEASES its claim. `assigned_to` reserves a
    PENDING row against other callers, and this row is no longer pending;
    `worked_by` is the permanent record of who worked it. Leaving the
    claim behind is what let a finished row keep holding a name.
    """
    return db.execute(
        "UPDATE va_queue SET status = 'worked', worked_by = ?, worked_at = ?, "
        "assigned_to = NULL "
        "WHERE account_id = ? AND qdate = ? AND lead_id = ? "
        "AND status = 'pending'",
        (user_id, utcnow(), current_account_id(), local_today(db),
         lead_id)).rowcount


def evict_pending(db, lead_id, reason):
    # type: (object, int, str) -> int
    """Mid-day queue eviction: delete the lead's PENDING va_queue rows for
    today (worked rows untouched) + an event log.

    Build-time exclusions only protect the NEXT build; a lead already in
    today's queue that becomes unworkable mid-day — tagged as a referral
    (SPEC R7: referrals are NEVER in the queue), suppressed, or closed
    (sold/dead) — must leave the queue immediately. Called from referral
    tagging, every lead-linked suppression write, sales.mark_sold and the
    dead/closed-state setter. Never commits inside a caller's open
    transaction. Returns the number of rows deleted. (lead_id is globally
    unique, so the (qdate, lead_id) key is already tenant-safe.)"""
    own = not db.in_transaction
    cur = db.execute(
        "DELETE FROM va_queue WHERE qdate = ? AND lead_id = ? "
        "AND status = 'pending'", (local_today(db), lead_id))
    if cur.rowcount:
        log_event(db, lead_id, "va_queue_evicted",
                  "%d pending queue row(s) removed: %s"
                  % (cur.rowcount, reason))
        if own:
            db.commit()
        logger.info("va_queue eviction lead=%s reason=%s rows=%d",
                    lead_id, reason, cur.rowcount)
    return cur.rowcount


# ------------------------------------------------------------ S3 expiry

def expire_nocontact(db, account_id=None, now=None):
    # type: (object, object, object) -> list
    """S3 nightly per-tenant pass: no-contact leads received more than
    va_nocontact_window_days ago (default 90) are marked DEAD
    (closed_state='dead' + event 'nocontact_expired') and evicted from
    today's pending queue — but ONLY once no pending sequence sends remain
    (the day-90 email may still be in flight).

    "No-contact" mirrors the volume-pool gates: the lead is COLD (B11), no
    closed_state, not a referral, not claimed (detection.is_claimed).
    phone-bad / phone-less / suppressed-contact leads are NOT exempt — 90
    days unworked is dead either way (a suppressed lead already sits in a
    NEGATIVE stage and falls out via the stage filter).
    Returns the list of lead ids transitioned."""
    from leadflow.auth import account_scope
    if account_id is None:
        account_id = current_account_id()
    with account_scope(account_id):
        return _expire_nocontact(db, account_id, now)


def _expire_nocontact(db, account_id, now=None):
    if now is None:
        now = _utcnow()
    window_days = _int_setting(db, "va_nocontact_window_days", 90)
    today = now.astimezone(_my_zone(db)).date().isoformat()
    day_start, _day_end = _day_bounds_utc(db, today)
    cutoff = (datetime.datetime.fromisoformat(day_start)
              - datetime.timedelta(days=window_days)).isoformat(
                  timespec="seconds")
    stage_in = ",".join("?" for _ in NOT_CONTACTED_STAGES)
    rows = db.execute(
        "SELECT l.id FROM leads l "
        "WHERE l.account_id = ? AND l.received_at < ? "
        "AND l.pipeline_stage IN (%s) "
        "AND l.closed_state IS NULL AND l.referred_by IS NULL "
        "AND NOT EXISTS (SELECT 1 FROM messages m WHERE m.lead_id = l.id "
        "  AND m.direction = 'out' AND m.step_id IS NOT NULL "
        "  AND m.status = 'pending') "
        "ORDER BY l.received_at, l.id" % stage_in,
        (account_id, cutoff) + NOT_CONTACTED_STAGES).fetchall()

    from leadflow.pipeline import recompute  # deferred: avoid cycles
    expired = []
    for r in rows:
        lead_id = r["id"]
        if _is_claimed(db, lead_id):
            continue  # protected leads never auto-die
        own = not db.in_transaction
        db.execute("UPDATE leads SET closed_state = 'dead' WHERE id = ?",
                   (lead_id,))
        log_event(db, lead_id, "nocontact_expired",
                  "no contact within %d days; marked dead" % window_days)
        evict_pending(db, lead_id, "no-contact window expired")
        recompute(db, lead_id)
        if own:
            db.commit()
        expired.append(lead_id)
    if expired:
        logger.info("nocontact expiry account=%s: %d lead(s) marked dead",
                    account_id, len(expired))
    return expired
