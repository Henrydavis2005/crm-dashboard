"""The overflow pool: cold-start backfill for a new tenant's VA queue.

A new tenant's VA has an empty queue on day one because organic lead flow
has not started yet. Overflow leads fill the gap until it does.

THE INVARIANT: an overflow row is NOT a real lead until positive contact.
It lives in its own table, not in `leads` and not behind a flag on `leads`,
because a flag holds that invariant only for as long as every current AND
FUTURE query remembers to filter — and one that forgets leaks a non-lead
into the pipeline, the stats, the ROI and the sequence. Physical separation
makes the violation impossible rather than merely discouraged.

What that buys, concretely:

- No overflow row can be picked up by `_volume_candidates`, `stats`,
  `pipeline`, `dispatcher`, `intake` or any other `SELECT ... FROM leads`,
  present or future, because it is not in that table.
- `va_queue` is untouched: its `lead_id` stays NOT NULL REFERENCES
  leads(id), so no existing queue query becomes a union type. Overflow
  rows are drawn into `overflow_queue` and merged only for display.
- PROMOTION MOVES the row: one transaction inserts into `leads` and marks
  the overflow row promoted. There is never a moment where the person is
  in both places as a live record, and never an orphan if it fails.

Never enrolls in the email sequence — on promotion or ever. Call-only.
"""
import datetime
import logging

from leadflow.agent_leads import (
    POSITIVE_APPOINTMENT_DISPOSITIONS, POSITIVE_CALL_DISPOSITIONS,
)
from leadflow.audit import log_event
from leadflow.db import utcnow

logger = logging.getLogger("leadflow.overflow")

# 45 days from upload. Deliberately NOT the 30/90-day no-contact window:
# the pool is a temporary bridge, not a lead source, and its residency is
# fixed rather than configurable so a tenant cannot quietly turn the pool
# into permanent storage.
RESIDENCY_DAYS = 45

MAX_ROWS_PER_UPLOAD = 50
MIN_ROWS_PER_UPLOAD = 1

# The pool's dispositions. The non-positive ones are ordinary call
# outcomes; the positive ones PROMOTE and the hard no KILLS.
#
# POSITIVE = exactly what agent-lead expiry already means by positive
# contact (imported, never re-declared — see agent_leads for why that
# tuple is a named constant) PLUS the three text heat levels, because
# log_text records positive lead texts only by design, so all three of
# HEAT_LEVELS are positive contact wherever they appear.
HEAT_LEVELS = ("mild", "warm", "hot")
PROMOTING_DISPOSITIONS = tuple(POSITIVE_CALL_DISPOSITIONS) + HEAT_LEVELS

# A hard no. Kills the row AND suppresses the contact, through the same
# suppression path a real lead uses — a person who says no must not be
# called again just because the record they said it on was temporary.
KILLING_DISPOSITIONS = ("answered_not_interested", "not_qualified",
                        "answered_do_not_call")

# Of those, the ones that are a LEGAL instruction rather than a soft close.
# They suppress IRREVERSIBLY, exactly as they do on a real lead.
IRREVERSIBLE_KILLS = ("answered_do_not_call",)

NEUTRAL_DISPOSITIONS = ("no_answer", "voicemail", "bad_number")

# The promoting dispositions whose promotion writes a `call` row on the
# new lead (see _mirror_disposition). `pay` reads this to avoid crediting
# ONE conversation as TWO leads worked: for these, the work already shows
# up as an interactions row, so the pool-side attempt must not count too.
#
# It is NOT simply "the promoting ones". A heat level mirrors as a
# text_log and `appointment_set` mirrors as nothing at all — neither is a
# call row, so neither is counted on the lead side, and the VA would lose
# the floor credit for a call they genuinely made if this tuple were any
# wider. Getting that wrong docks someone's base pay, so it is derived
# here rather than re-listed at the call site.
def _mirrored_as_call():
    from leadflow.interactions import CALL_DISPOSITIONS
    return tuple(d for d in PROMOTING_DISPOSITIONS
                 if d in CALL_DISPOSITIONS and d != "appointment_set")

ALL_DISPOSITIONS = (NEUTRAL_DISPOSITIONS + KILLING_DISPOSITIONS
                    + PROMOTING_DISPOSITIONS)

DISPOSITION_LABELS = [
    ("no_answer", "No Answer"),
    ("voicemail", "Voicemail Left"),
    ("bad_number", "Wrong Number"),
    ("mild", "Interested — mild"),
    ("warm", "Interested — warm"),
    ("hot", "Interested — hot"),
    ("callback_requested", "Callback Requested"),
    ("appointment_set", "Appointment Set"),
    ("answered_send_options", "Send Options — agreed to emailed quotes"),
    ("answered_not_interested", "Not Interested"),
    ("not_qualified", "Not Qualified"),
    ("answered_do_not_call", "Do not call — verbal opt-out"),
]


def is_promoting(disposition):
    return disposition in PROMOTING_DISPOSITIONS


def is_killing(disposition):
    return disposition in KILLING_DISPOSITIONS


# ------------------------------------------------------- B12 eligibility

# OVERFLOW IS A SOURCE, NOT AN EXEMPTION.
#
# It was one. Two holes, both live before B12:
#
#   1. LICENSURE DID NOT APPLY. `va._fill_queue._add()` is the single
#      choke point that refuses a lead in an unlicensed state, and its
#      own comment claimed it covered "callbacks, recovery, volume and
#      the overflow backfill alike". It did not: `_backfill_overflow`
#      inserts straight into `overflow_queue` and never calls `_add`, so
#      a pool row in a state the account holds no licence for reached a
#      VA's dial list.
#
#   2. THE DRAW MISSED GLOBAL REVOCATIONS. `draw_candidates` filtered
#      suppressions with `s.account_id = o.account_id`. B8 made a
#      revocation GLOBAL — one person, one revocation — so somebody who
#      told another account to stop could still be drawn here.
#
# `eligible()` is now the one place a pool row is judged, and it is
# applied at BOTH ends: at IMPORT (write time, so an ineligible row never
# enters the pool) and at DRAW (read time, so a row that became
# ineligible while it sat there is never served). Neither alone is
# enough — a licence lapses, a revocation arrives, a residency expires,
# all of them after the upload.
#
# A row that fails is SKIPPED. There is no override, no bypass and no
# FTA-approved exception: a VA running short of their allocation is an
# acceptable outcome and a wrongly-dialled person is not.

REASON_SUPPRESSED = "suppressed_or_revoked"
REASON_LICENSURE = "not_licensed"
REASON_STALE = "past_45_day_residency"
REASON_HALTED = "matches_a_halted_lead"
REASON_DUPLICATE = "duplicate_phone"
REASON_NO_PHONE = "no_phone"

REASON_TEXT = {
    REASON_SUPPRESSED: "This person is suppressed or has revoked consent.",
    REASON_LICENSURE: "Not licensed in this person's state.",
    REASON_STALE: "Past the %d-day overflow residency." % RESIDENCY_DAYS,
    REASON_HALTED: "Matches a lead whose sequence is halted.",
    REASON_DUPLICATE: "Another lead already holds this phone number.",
    REASON_NO_PHONE: "No usable phone number.",
}

# Checked in this order, and the order is the message the FTA reads.
REASON_ORDER = (REASON_SUPPRESSED, REASON_LICENSURE, REASON_NO_PHONE,
                REASON_STALE, REASON_HALTED, REASON_DUPLICATE)


def _residency_cutoff(now=None):
    if now is None:
        now = datetime.datetime.now(datetime.timezone.utc)
    return (now - datetime.timedelta(days=RESIDENCY_DAYS)).isoformat(
        timespec="seconds")


def _stored_phone(raw):
    """A phone in THE storage format every column uses ('000-000-0000').

    Pool rows are written through the same importer real leads are, so in
    practice they already match — but `eligible` is also called with a
    freshly-parsed CSV row at import time, and comparing a raw '+1609...'
    against a stored '609-...' silently matches nothing. A duplicate rule
    that never fires is worse than no duplicate rule, because the pool
    count says the number was accepted.

    This is NOT the suppression path, which stays a digit comparison and
    is deliberately not normalised (CLAUDE.md)."""
    from leadflow.phone import normalize_phone
    return normalize_phone(raw) or raw


def _halted_match(db, account_id, phone, email):
    """A lead of this tenant with the same number or address whose
    sequence is HALTED. The halted set is manual-only and permanently so;
    a halted person must not come back through the pool instead."""
    clauses, params = [], [int(account_id)]
    phone = _stored_phone(phone) if phone else None
    if phone:
        clauses.append("(l.phone IS NOT NULL AND l.phone = ?)")
        params.append(phone)
    if email:
        clauses.append("(l.email IS NOT NULL AND lower(l.email) = lower(?))")
        params.append(email)
    if not clauses:
        return None
    return db.execute(
        "SELECT l.id FROM leads l WHERE l.account_id = ? "
        "AND l.sequence_halted = 1 AND (%s) LIMIT 1" % " OR ".join(clauses),
        tuple(params)).fetchone()


def _duplicate_holder(db, account_id, phone):
    """FIRST SEND WINS, and the pool is judged by the same rule a real
    lead is: `va_sends` is UNIQUE(team_account_id, phone), so a number
    already sent to this team cannot reach a second VA queue through the
    pool either."""
    if not phone:
        return None
    from leadflow.va_send import team_root
    root = team_root(db, account_id)
    return db.execute(
        "SELECT id FROM va_sends WHERE team_account_id = ? AND phone = ? "
        "LIMIT 1", (root, _stored_phone(phone))).fetchone()


def eligible(db, account_id, row, covered=None, now=None):
    # type: (object, int, object, object, object) -> tuple
    """(ok, reason) for ONE pool row. THE gate, used at write and read.

    `covered` is the account's licensed state set; passed in by the build
    so a whole draw reads it once, computed here when a caller has none.
    """
    from leadflow import licensure
    from leadflow.suppression import is_suppressed

    phone = row["phone"]
    email = row["email"]

    # ONE CALL, AND IT ALREADY ASKS BOTH QUESTIONS. B8 gave `is_suppressed`
    # a global arm — its scope clause is
    # `(account_id = ? OR reason IN (<revocation reasons>))` — so it
    # answers "this tenant suppressed them" OR "they revoked, anywhere".
    #
    # An explicit `is_revoked` call stood here first. Sabotaging it did
    # NOT turn any test red, because this line already covered it: a
    # guard no test can distinguish from its absence is dead weight that
    # LOOKS load-bearing, and the next reader would have maintained it.
    # The defect being fixed was never a missing revocation call anyway —
    # it was `draw_candidates` asking the per-tenant question in SQL and
    # nothing asking the global one at all.
    if is_suppressed(db, email=email, phone=phone, account_id=account_id):
        return (False, REASON_SUPPRESSED)

    # B4 LICENSURE, on the person's RESIDENT STATE. Never the area code:
    # a number's prefix says where it was issued, which for a mobile is
    # frequently not where its owner lives.
    if covered is None:
        covered = licensure.covered_states(db, account_id)
    state = licensure.normalise_state(row["state"])
    if state is None or state not in covered:
        return (False, REASON_LICENSURE)

    if not phone:
        return (False, REASON_NO_PHONE)
    if (row["uploaded_at"] or "") < _residency_cutoff(now):
        return (False, REASON_STALE)
    if _halted_match(db, account_id, phone, email) is not None:
        return (False, REASON_HALTED)
    if _duplicate_holder(db, account_id, phone) is not None:
        return (False, REASON_DUPLICATE)
    return (True, None)


# ------------------------------------------------------------------- pool

def get_row(db, account_id, overflow_id):
    """One pool row of THIS tenant, or None. Every route resolves through
    here, so a foreign id 404s exactly like a foreign lead id does."""
    return db.execute(
        "SELECT * FROM overflow_leads WHERE id = ? AND account_id = ?",
        (overflow_id, account_id)).fetchone()


def pool_size(db, account_id):
    return db.execute(
        "SELECT COUNT(*) AS c FROM overflow_leads "
        "WHERE account_id = ? AND status = 'pool'",
        (account_id,)).fetchone()["c"]


def pool_rows(db, account_id, limit=200):
    return db.execute(
        "SELECT o.*, ("
        "  SELECT COUNT(*) FROM overflow_attempts a "
        "   WHERE a.overflow_id = o.id) AS attempts "
        "FROM overflow_leads o "
        "WHERE o.account_id = ? AND o.status = 'pool' "
        "ORDER BY o.uploaded_at DESC, o.file_order, o.id LIMIT ?",
        (account_id, limit)).fetchall()


def recent_batches(db, account_id, limit=20):
    return db.execute(
        "SELECT batch_id, MIN(uploaded_at) AS uploaded_at, COUNT(*) AS n, "
        " SUM(CASE WHEN status = 'pool' THEN 1 ELSE 0 END) AS still_pool, "
        " SUM(CASE WHEN status = 'promoted' THEN 1 ELSE 0 END) AS promoted, "
        " SUM(CASE WHEN status = 'dead' THEN 1 ELSE 0 END) AS dead, "
        " SUM(CASE WHEN status = 'expired' THEN 1 ELSE 0 END) AS expired "
        "FROM overflow_leads WHERE account_id = ? AND batch_id IS NOT NULL "
        "GROUP BY batch_id ORDER BY MIN(uploaded_at) DESC LIMIT ?",
        (account_id, limit)).fetchall()


def expires_on(uploaded_at):
    """The date a row uploaded at `uploaded_at` ages out, YYYY-MM-DD."""
    try:
        base = datetime.datetime.fromisoformat(
            str(uploaded_at).replace("Z", "+00:00")).date()
    except (ValueError, TypeError):
        return None
    return (base + datetime.timedelta(days=RESIDENCY_DAYS)).isoformat()


# ----------------------------------------------------------------- dedupe

def duplicate_probe(db, account_id):
    """The injected dedupe probe for lead_import.build_preview.

    Checks BOTH tables — a person already in `leads` must not enter the
    pool, and a person already in the pool must not enter it twice — and
    BOTH are filtered on this tenant's account_id. Returns a row carrying
    `kind` so the preview can say which side matched, or None.

    lead_import stays pure: it takes this callable and never learns which
    tables exist. That is the same cut agent leads uses, unchanged — its
    signature is untouched, so agent leads is unaffected."""
    def probe(phone, email):
        for table, kind in (("leads", "lead"),
                            ("overflow_leads", "overflow")):
            if phone:
                row = db.execute(
                    "SELECT id, first_name, last_name FROM %s "
                    "WHERE account_id = ? AND phone = ? "
                    "ORDER BY id DESC LIMIT 1" % table,
                    (account_id, phone)).fetchone()
                if row is not None:
                    return {"id": row["id"], "kind": kind,
                            "first_name": row["first_name"],
                            "last_name": row["last_name"]}
            if email:
                row = db.execute(
                    "SELECT id, first_name, last_name FROM %s "
                    "WHERE account_id = ? AND email = ? "
                    "ORDER BY id DESC LIMIT 1" % table,
                    (account_id, email)).fetchone()
                if row is not None:
                    return {"id": row["id"], "kind": kind,
                            "first_name": row["first_name"],
                            "last_name": row["last_name"]}
        return None
    return probe


# ------------------------------------------------------------------ draw

def draw_candidates(db, account_id, qdate, limit):
    """Pool rows eligible for today's queue, in DRAW ORDER.

    NEWEST FIRST by upload date; ties fall back to row order within the
    file (`file_order`), then id. The pool is a bridge, so the freshest
    batch is the one worth calling.

    Excluded here, cheaply and in SQL: rows already drawn today and rows
    past their residency. THE REST OF THE GATE IS `eligible()`, applied
    per row by the caller — licensure, global revocation, halted match
    and duplicate phone all need helpers that do not belong in this
    query, and B12 found that writing half of it here was how the other
    half came to be missing.

    THE SUPPRESSION CLAUSE THAT USED TO LIVE HERE WAS WRONG, not merely
    duplicated: it read `s.account_id = o.account_id`, which after B8 is
    the per-tenant question. A REVOCATION is global, so a person who told
    another account to stop was still drawable here. `eligible()` asks
    the global question first.

    `limit` is a candidate limit, not a row count: the caller judges each
    row and skips the ones that fail, so it over-draws deliberately.

    The REFERRAL FIREWALL needs no clause — a pool row has no
    `referred_by` and cannot be a referral; the firewall applies to the
    LEAD it becomes, and promotion goes through the ordinary
    lead-creation path that honours it."""
    return db.execute(
        "SELECT o.* FROM overflow_leads o "
        "WHERE o.account_id = ? AND o.status = 'pool' "
        "AND o.uploaded_at >= ? "
        "AND NOT EXISTS (SELECT 1 FROM overflow_queue q "
        "                 WHERE q.qdate = ? AND q.overflow_id = o.id) "
        "ORDER BY o.uploaded_at DESC, o.file_order, o.id LIMIT ?",
        (account_id, _residency_cutoff(), qdate, limit)).fetchall()


def queue_for_date(db, account_id, qdate):
    """Today's drawn overflow rows joined to their pool rows."""
    return db.execute(
        "SELECT q.*, o.first_name, o.last_name, o.phone, o.email, o.state, "
        "o.city, o.timezone, o.uploaded_at, o.consent_date, "
        "u.username AS assigned_username, ("
        "  SELECT COUNT(*) FROM overflow_attempts a "
        "   WHERE a.overflow_id = o.id) AS attempts "
        "FROM overflow_queue q JOIN overflow_leads o ON o.id = q.overflow_id "
        "LEFT JOIN users u ON u.id = q.assigned_to "
        "WHERE q.account_id = ? AND q.qdate = ? ORDER BY q.position, q.id",
        (account_id, qdate)).fetchall()


def queue_row(db, account_id, qdate, overflow_id):
    return db.execute(
        "SELECT * FROM overflow_queue WHERE account_id = ? AND qdate = ? "
        "AND overflow_id = ?", (account_id, qdate, overflow_id)).fetchone()


def mark_worked(db, account_id, qdate, overflow_id, user_id):
    """Mark today's pending row worked; releases its claim, exactly as
    va.mark_worked does. Never commits (the caller owns the transaction)."""
    return db.execute(
        "UPDATE overflow_queue SET status = 'worked', worked_by = ?, "
        "worked_at = ?, assigned_to = NULL "
        "WHERE account_id = ? AND qdate = ? AND overflow_id = ? "
        "AND status = 'pending'",
        (user_id, utcnow(), account_id, qdate, overflow_id)).rowcount


def evict_pending(db, account_id, overflow_id, reason):
    """Remove the row from today's queue mid-day (promoted, killed,
    expired). Mirrors va.evict_pending."""
    cur = db.execute(
        "DELETE FROM overflow_queue WHERE account_id = ? AND overflow_id = ? "
        "AND status = 'pending'", (account_id, overflow_id))
    if cur.rowcount:
        logger.info("overflow queue eviction row=%s reason=%s",
                    overflow_id, reason)
    return cur.rowcount


# ----------------------------------------------------------- attempt log

def attempts_for(db, account_id, overflow_id):
    return db.execute(
        "SELECT a.*, u.username FROM overflow_attempts a "
        "LEFT JOIN users u ON u.id = a.user_id "
        "WHERE a.account_id = ? AND a.overflow_id = ? "
        "ORDER BY a.created_at, a.id", (account_id, overflow_id)).fetchall()


def log_attempt(db, account_id, overflow_id, user_id, disposition,
                note=None):
    """Record one call outcome against a pool row, and apply its effect.

    Returns (outcome, lead_id) where outcome is 'promoted', 'killed' or
    'logged' and lead_id is the new lead on promotion, else None.

    ONE transaction for the whole thing: the attempt row, the queue
    bookkeeping, and — on a promoting disposition — the lead INSERT and
    the pool row's status change. See `promote` for why that matters."""
    if disposition not in ALL_DISPOSITIONS:
        raise ValueError("unknown overflow disposition: %s" % disposition)
    row = get_row(db, account_id, overflow_id)
    if row is None:
        raise ValueError("no such overflow row for this account")
    if row["status"] != "pool":
        raise ValueError("overflow row is no longer in the pool")

    from leadflow.va import local_today
    qdate = local_today(db)

    own = not db.in_transaction
    if own:
        db.execute("BEGIN IMMEDIATE")
    try:
        db.execute(
            "INSERT INTO overflow_attempts (account_id, overflow_id, "
            "user_id, disposition, note, created_at) VALUES (?,?,?,?,?,?)",
            (account_id, overflow_id, user_id, disposition,
             (note or "").strip() or None, utcnow()))
        mark_worked(db, account_id, qdate, overflow_id, user_id)

        outcome, lead_id = "logged", None
        if is_promoting(disposition):
            lead_id = _promote(db, account_id, row, user_id, disposition,
                               note=note, disposition=disposition)
            outcome = "promoted"
        elif is_killing(disposition):
            _kill(db, account_id, row, user_id, disposition)
            outcome = "killed"
        if own:
            db.commit()
        return outcome, lead_id
    except Exception:
        if own:
            db.rollback()
        raise


# ------------------------------------------------------------- promotion

def promote(db, account_id, overflow_id, user_id=None, reason="positive contact"):
    """Public promotion entry point: pool row -> real lead, atomically.

    HOW A HALFWAY FAILURE IS HANDLED. The lead INSERT and the pool row's
    status change are ONE transaction, opened here with BEGIN IMMEDIATE
    when we own it. Three outcomes, and only three:

      1. Both succeed -> commit. The person is a lead; the pool row reads
         'promoted' and is out of every draw.
      2. Anything raises -> rollback. No lead row, pool row still 'pool',
         attempt log intact. The VA sees the error and can retry; the
         retry is safe because nothing was written.
      3. The process dies mid-transaction -> SQLite rolls back on the next
         open. Same end state as 2.

    There is no window in which a lead exists without the pool row being
    marked, or the pool row is marked without a lead — which is exactly
    the orphan/double-write pair the design has to exclude. The status
    change is an UPDATE guarded on `status = 'pool'`, so a concurrent
    second promotion (two VAs, one row, both clicking) finds rowcount 0
    and raises rather than inserting a second lead.
    """
    row = get_row(db, account_id, overflow_id)
    if row is None:
        raise ValueError("no such overflow row for this account")
    own = not db.in_transaction
    if own:
        db.execute("BEGIN IMMEDIATE")
    try:
        lead_id = _promote(db, account_id, row, user_id, reason)
        if own:
            db.commit()
        return lead_id
    except Exception:
        if own:
            db.rollback()
        raise


def _promote(db, account_id, row, user_id, reason, note=None,
             disposition=None):
    """The promotion itself. Runs inside the caller's transaction."""
    from leadflow.pipeline import recompute

    overflow_id = row["id"]
    # THE GUARD that makes a double-write impossible: this UPDATE is the
    # single claim on the row, and it only fires while the row is still in
    # the pool. Two callers racing means the loser sees rowcount 0 and
    # raises BEFORE any lead is inserted.
    claimed = db.execute(
        "UPDATE overflow_leads SET status = 'promoted' "
        "WHERE id = ? AND account_id = ? AND status = 'pool'",
        (overflow_id, account_id)).rowcount
    if not claimed:
        raise ValueError("overflow row was already promoted or closed")

    now = utcnow()
    cur = db.execute(
        # B11: pipeline_stage named explicitly — an upgraded database still
        # carries B4's DEFAULT 'new' on this column. A promoted overflow row
        # starts COLD like any other new lead; the promoting disposition is
        # mirrored onto it immediately afterwards and recompute lifts it.
        "INSERT INTO leads (account_id, source_id, first_name, last_name, "
        "email, phone, city, state, zip, timezone, metadata, stage, "
        "pipeline_stage, cost_cents, consent_date, received_at, created_at) "
        "VALUES (?,NULL,?,?,?,?,?,?,?,?,?,'active','cold',0,?,?,?)",
        (account_id, row["first_name"], row["last_name"], row["email"],
         row["phone"], row["city"], row["state"], row["zip"],
         row["timezone"], row["metadata"],
         # DIALER BLOCK 1: CARRIED, not re-derived. The pool row already
         # holds the date its upload established; promotion is a change
         # of table, not a new act of consent, and stamping the promotion
         # date here would silently refresh a lead that has been sitting
         # in the pool for 44 days.
         row["consent_date"],
         now, now))
    lead_id = cur.lastrowid

    log_event(db, lead_id, "lead_created",
              "promoted from the overflow pool (%s)" % reason,
              user_id=user_id)
    # NOTE what is NOT here: schedule_lead. An overflow lead is CALL-ONLY
    # and never enrols in the email sequence — not on promotion, not ever.
    _mirror_disposition(db, lead_id, user_id, disposition, note)
    recompute(db, lead_id)
    evict_pending(db, account_id, overflow_id, "promoted to a real lead")
    logger.info("overflow promoted row=%s -> lead=%s account=%s",
                overflow_id, lead_id, account_id)
    return lead_id


def _mirror_disposition(db, lead_id, user_id, disposition, note):
    """Replay the promoting outcome onto the NEW lead through the ordinary
    lead paths, so everything downstream fires "the same way it does
    everywhere else" with no overflow-shaped special case.

    That is what makes SEND-OPTIONS surface Run Quotes: `log_call` raises
    the `run_quotes` task exactly as it does for a bought lead, so the
    button appears on the lead page and the row appears on the dashboard
    and Today, with no second implementation to keep in sync. Callback
    Requested raises its `callback_review` task the same way, and the
    heat levels land as the positive text log they are.

    Two deliberate omissions:

    - `appointment_set` needs an actual appointment TIME, which the pool
      console does not collect (there is nowhere to put it on a row that
      is not a lead yet). The promotion still happens; the VA books the
      time on the real lead page a moment later.
    - The LEGACY dispositions are read-only by contract (CLAUDE.md):
      `log_call` refuses them for new rows, so they promote without a
      mirror rather than raising.
    """
    if not disposition:
        return
    from leadflow import interactions
    if disposition in HEAT_LEVELS:
        interactions.log_text(db, lead_id, user_id, disposition, note=note)
        return
    if disposition == "appointment_set":
        return
    if disposition not in interactions.CALL_DISPOSITIONS:
        return                       # legacy: read-only, never re-logged
    interactions.log_call(db, lead_id, user_id, disposition, note=note)


def _kill(db, account_id, row, user_id, disposition):
    """A hard no: close the row AND suppress the contact.

    The suppression goes through the SAME path a real lead's does
    (`suppression.suppress`), because a person who says no must not be
    called again just because the record they said it on was temporary.
    The suppression outlives the pool row — it is a compliance record and
    is keyed on the phone/email, not on a lead id."""
    from leadflow.suppression import suppress
    overflow_id = row["id"]
    db.execute(
        "UPDATE overflow_leads SET status = 'dead' "
        "WHERE id = ? AND account_id = ?", (overflow_id, account_id))
    dnc = disposition in IRREVERSIBLE_KILLS
    suppress(db, email=row["email"], phone=row["phone"],
             reason="do_not_call" if dnc else "not_interested",
             reversible=0 if dnc else 1,
             note="overflow pool: %s" % disposition)
    evict_pending(db, account_id, overflow_id, "hard no")
    logger.info("overflow killed row=%s account=%s disposition=%s",
                overflow_id, account_id, disposition)


# ---------------------------------------------------------------- expiry

def expire_overflow(db, account_id=None, now=None):
    """Nightly per-tenant pass: pool rows past their 45-day residency are
    closed out of the pool.

    `account_id` matters the same way it does for agent leads:
    current_account_id() silently returns 1 outside a request and this
    runs in the WORKER, so a fallback would expire TENANT 1's pool on
    every tenant's pass. Returns the ids closed.

    NO positive-contact clock stop, deliberately: positive contact
    PROMOTES the row out of the pool entirely, so there is never a worked
    row left in the pool for the clock to need to pause on."""
    from leadflow.auth import account_scope, current_account_id
    if account_id is None:
        account_id = current_account_id()
    with account_scope(account_id):
        return _expire_overflow(db, account_id, now)


def _expire_overflow(db, account_id, now=None):
    if now is None:
        now = datetime.datetime.now(datetime.timezone.utc)
    cutoff = (now - datetime.timedelta(days=RESIDENCY_DAYS)).isoformat(
        timespec="seconds")
    rows = db.execute(
        "SELECT id FROM overflow_leads WHERE account_id = ? "
        "AND status = 'pool' AND uploaded_at < ? ORDER BY uploaded_at, id",
        (account_id, cutoff)).fetchall()
    expired = []
    own = not db.in_transaction
    for r in rows:
        db.execute(
            "UPDATE overflow_leads SET status = 'expired' "
            "WHERE id = ? AND account_id = ? AND status = 'pool'",
            (r["id"], account_id))
        evict_pending(db, account_id, r["id"], "residency expired")
        expired.append(r["id"])
    if own and expired:
        db.commit()
    if expired:
        logger.info("overflow expiry account=%s: %d row(s) aged out",
                    account_id, len(expired))
    return expired
