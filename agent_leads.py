"""Agent leads: leads handed over by another licensed agent (a downline /
FTA arrangement), worked in the NORMAL pipeline and split on commission.

NOT a referral. `leads.referred_by` is the R7 referral firewall — zero
automation, never queued, routed to the owner personally — and it means the
OPPOSITE thing. The word "referral" does not appear in this feature: not the
column, not a function name, not UI copy. Several guards here sit literally
beside the referral firewall's guards and stay SEPARATE clauses, never a
shared "is this special" flag, because the two rules are allowed to change
independently.

What an agent lead is:

- tagged with `leads.source_agent` = the agent's NAME, snapshotted at import
- worked in the ordinary queue, with ordinary priority
- NEVER enrolled in the email sequence (leadflow.outreach.scheduler refuses)
- given a SHORT unworked residency (`agent_lead_expiry_days`, default 14),
  measured from the upload; the clock STOPS at the first positive contact
- half the commission, so the payout obligation surfaces at SOLD -> premium
  -> commission independently of the `fta_enabled` gate
- excluded from lead-ROI analytics (they cost nothing), but present on VA
  profitability unchanged
"""
import datetime
import json
import logging

from leadflow.audit import log_event
from leadflow.db import utcnow

logger = logging.getLogger("leadflow.agent_leads")


def is_agent_lead(lead):
    """True when this lead row carries a source_agent tag.

    Tolerates a row that predates the column (partial fixtures, a row built
    by an older SELECT): a missing key means "not an agent lead", which is
    the same answer NULL gives."""
    if lead is None:
        return False
    try:
        value = lead["source_agent"]
    except (IndexError, KeyError, TypeError):
        return False
    return bool(value)


# --------------------------------------------------------------- predicate

# WHAT COUNTS AS POSITIVE CONTACT. This tuple is the single definition in
# the app, and it is deliberately a NAMED CONSTANT rather than a literal
# inside the SQL below, because it has more than one reader:
#
#   - the agent-lead expiry sweep and delete (the SQL built from it here)
#   - leadflow.overflow, whose attempts live in their own table and so
#     cannot share the SQL, only the MEANING
#
# Adding a disposition here changes every caller at once, which is the
# whole point — "the clock stops on positive contact", "only leads with no
# positive contact may be deleted" and "any positive contact promotes an
# overflow row" must never drift into three different sentences.
#
# `answered_interested` / `answered_callback` are LEGACY_CALL_DISPOSITIONS.
# log_call rejects them for new rows but READ paths must keep handling them
# (CLAUDE.md), which is why they are here.
POSITIVE_CALL_DISPOSITIONS = (
    "answered_send_options",
    "callback_requested",
    "appointment_set",
    "answered_interested",   # legacy, read-only
    "answered_callback",     # legacy, read-only
)

# An appointment row counts on its `scheduled` PARENT, so a booking later
# cancelled or rescheduled still counts. Someone booked; the lead was
# worked.
POSITIVE_APPOINTMENT_DISPOSITIONS = ("scheduled", "showed")

# Contact that is NOT positive, listed so the omission reads as a decision
# rather than an oversight: no_answer, voicemail, bad_number,
# answered_not_interested, not_qualified. Someone picking up and saying no
# owes the source agent nothing.


def _sql_in(values):
    return ", ".join("'%s'" % v for v in values)


# THE predicate. Correlated on the alias `l` (leads), zero bind params.
# ONE definition, exactly two callers: the day-14 expiry sweep and the
# delete preview/action. They MUST agree — the delete promise ("only leads
# with no positive contact and no sale") and the expiry promise ("the clock
# stops on positive contact") are the same sentence.
#
# POSITIVE CONTACT is a HISTORICAL signal, never the current pipeline_stage:
# a NEGATIVE stage outranks the whole Working lane in pipeline.compute_stage,
# so a lead who booked an appointment and was later suppressed reads
# `revoked` (B11; `dead` before it) and a stage-based test would silently
# mark it deletable. B11 makes this worse, not better — the lane is decided
# by RECENCY now, so the same lead's stage can move back and forth over
# time while the historical fact that they were spoken to cannot. The
# signals below are exactly the ones compute_stage uses for its appointment
# / quote / engaged rungs, read directly.
#
# Contact that is NOT positive is deliberately absent: no_answer, voicemail,
# bad_number, answered_not_interested, not_qualified. Someone picking up and
# saying no owes the source agent nothing.
NO_POSITIVE_CONTACT_NO_SALE_SQL = ("""
 AND (l.closed_state IS NULL OR l.closed_state != 'sold')
 AND NOT EXISTS (SELECT 1 FROM sales s WHERE s.lead_id = l.id)
 AND NOT EXISTS (
       SELECT 1 FROM interactions i WHERE i.lead_id = l.id AND (
            (i.itype = 'call' AND i.disposition IN (%s))
         OR  i.itype = 'text_log'
         OR (i.itype = 'appointment'
             AND i.disposition IN (%s))))
 AND NOT EXISTS (
       SELECT 1 FROM messages m WHERE m.lead_id = l.id
        AND m.direction = 'in'
        AND (m.quote_request = 1
             OR m.classification IN ('INTERESTED', 'UNCLEAR')))
""" % (_sql_in(POSITIVE_CALL_DISPOSITIONS),
       _sql_in(POSITIVE_APPOINTMENT_DISPOSITIONS)))
# Notes an implementer must not lose:
#
# - `text_log` needs no disposition filter: log_text records POSITIVE lead
#   texts only by design, so all three HEAT_LEVELS are positive. That is
#   why overflow treats mild/warm/hot as promotion signals too.
# - `(l.closed_state IS NULL OR l.closed_state != 'sold')` rather than
#   `IS NOT 'sold'` — matches the house idiom in stats.py.
# - The `sales` EXISTS is the belt to closed_state's braces: a reopened
#   lead can lose closed_state='sold' while keeping its sales row.


def deletable_agent_leads(db, account_id):
    """Every agent lead of THIS tenant that may be deleted: tagged, no
    positive contact, no sale.

    The dry-run preview and the delete itself read the SAME function — the
    preview cannot under-report (AUDIT R-2's lesson, applied here)."""
    return db.execute(
        "SELECT l.id, l.first_name, l.last_name, l.phone, l.state, "
        "l.source_agent, l.received_at FROM leads l "
        "WHERE l.account_id = ? AND l.source_agent IS NOT NULL"
        + NO_POSITIVE_CONTACT_NO_SALE_SQL +
        " ORDER BY l.source_agent COLLATE NOCASE, l.id",
        (account_id,)).fetchall()


def expiring_agent_leads(db, account_id, cutoff_iso):
    """Agent leads whose UNWORKED residency has run out: same predicate,
    plus an age cutoff."""
    return db.execute(
        "SELECT l.id FROM leads l "
        "WHERE l.account_id = ? AND l.source_agent IS NOT NULL "
        "AND l.received_at < ?"
        + NO_POSITIVE_CONTACT_NO_SALE_SQL +
        " ORDER BY l.received_at, l.id",
        (account_id, cutoff_iso)).fetchall()


# ------------------------------------------------------------------ roster

def roster(db, account_id, enabled_only=False):
    """The tenant's source agents, with a live agent-lead count each."""
    where = " AND a.enabled = 1" if enabled_only else ""
    return db.execute(
        "SELECT a.*, ("
        "  SELECT COUNT(*) FROM leads l WHERE l.account_id = a.account_id "
        "   AND l.source_agent = a.name COLLATE NOCASE) AS lead_count "
        "FROM source_agents a WHERE a.account_id = ?" + where +
        " ORDER BY a.name COLLATE NOCASE", (account_id,)).fetchall()


def get_agent(db, account_id, agent_id):
    """One roster row of THIS tenant, or None."""
    return db.execute(
        "SELECT * FROM source_agents WHERE account_id = ? AND id = ?",
        (account_id, agent_id)).fetchone()


def find_agent_by_name(db, account_id, name):
    """This tenant's roster row for `name`, case-insensitively, or None."""
    return db.execute(
        "SELECT * FROM source_agents WHERE account_id = ? "
        "AND name = ? COLLATE NOCASE", (account_id, (name or "").strip())
    ).fetchone()


def ensure_agent(db, account_id, name):
    """The roster row for `name`, creating it if missing. Returns the id.

    Never commits — the caller owns the transaction, which is the whole
    point of the deferred-commit inline create: an abandoned preview must
    leave no orphan roster row. UNIQUE(account_id, name COLLATE NOCASE)
    means an exact case-insensitive re-entry REUSES the row rather than
    forking a second spelling."""
    name = (name or "").strip()
    if not name:
        raise ValueError("agent name is required")
    row = find_agent_by_name(db, account_id, name)
    if row is not None:
        return row["id"]
    cur = db.execute(
        "INSERT INTO source_agents (account_id, name, enabled, created_at) "
        "VALUES (?,?,1,?)", (account_id, name, utcnow()))
    logger.info("source agent created account=%s name=%r", account_id, name)
    return cur.lastrowid


def similar_agent_names(db, account_id, name, cutoff=0.82):
    """Roster names close enough to `name` to be a probable typo, excluding
    an exact case-insensitive match (that one REUSES the row, so it is not
    a fork). Feeds the preview's "Did you mean ...?" warning — local
    difflib only, no network, no model."""
    import difflib
    name = (name or "").strip()
    if not name:
        return []
    existing = [r["name"] for r in db.execute(
        "SELECT name FROM source_agents WHERE account_id = ?",
        (account_id,)).fetchall()]
    lowered = name.lower()
    out = []
    for other in existing:
        if other.lower() == lowered:
            return []  # exact match: reuse, never a typo warning
        ratio = difflib.SequenceMatcher(None, lowered, other.lower()).ratio()
        if ratio >= cutoff:
            out.append(other)
    return out


# ------------------------------------------------------------- saved maps

def saved_mapping(db, account_id, agent_id):
    """This tenant's saved header->field map for this agent, or None."""
    row = db.execute(
        "SELECT field_map FROM source_agent_maps "
        "WHERE account_id = ? AND agent_id = ?",
        (account_id, agent_id)).fetchone()
    if row is None:
        return None
    try:
        value = json.loads(row["field_map"])
    except (ValueError, TypeError):
        return None
    return value if isinstance(value, dict) else None


def save_mapping(db, account_id, agent_id, field_map):
    """Upsert the saved map. Never commits (import owns the transaction)."""
    now = utcnow()
    db.execute(
        "INSERT INTO source_agent_maps (account_id, agent_id, field_map, "
        "created_at, updated_at) VALUES (?,?,?,?,?) "
        "ON CONFLICT(account_id, agent_id) DO UPDATE SET "
        "field_map = excluded.field_map, updated_at = excluded.updated_at",
        (account_id, agent_id, json.dumps(field_map, sort_keys=True),
         now, now))


# ------------------------------------------------------------------ expiry

def expiry_days(db, account_id):
    from leadflow.settings import get_setting
    try:
        return max(1, int(get_setting("agent_lead_expiry_days", db=db,
                                      account_id=account_id) or 14))
    except (TypeError, ValueError):
        return 14


def expire_agent_leads(db, account_id=None, now=None):
    """Nightly per-tenant pass: agent leads that have sat `agent_lead_expiry_days`
    (default 14) from UPLOAD without positive contact are marked DEAD.

    A SEPARATE function from va.expire_nocontact, deliberately. That pass's
    predicate is STAGE-based (B11: the lead is COLD), which would wrongly
    spare an agent lead that reached `quote` on a warm inbound but was
    never actually spoken to. This
    predicate is SIGNAL-based and stricter, and the two expiries stay
    distinguishable in `events` via their own event type
    (`agent_lead_expired`, not `nocontact_expired`).

    `account_id` is a REQUIRED argument in practice: current_account_id()
    silently returns 1 outside a request, and this runs in the worker, so a
    helper that fell back to the ambient account would expire TENANT 1's
    leads on every tenant's pass. Returns the list of lead ids closed."""
    from leadflow.auth import account_scope, current_account_id
    if account_id is None:
        account_id = current_account_id()
    with account_scope(account_id):
        return _expire_agent_leads(db, account_id, now)


def _expire_agent_leads(db, account_id, now=None):
    from leadflow.pipeline import recompute       # deferred: avoid cycles
    from leadflow.va import _day_bounds_utc, _my_zone, _utcnow, evict_pending

    if now is None:
        now = _utcnow()
    days = expiry_days(db, account_id)
    today = now.astimezone(_my_zone(db)).date().isoformat()
    day_start, _day_end = _day_bounds_utc(db, today)
    cutoff = (datetime.datetime.fromisoformat(day_start)
              - datetime.timedelta(days=days)).isoformat(timespec="seconds")

    rows = expiring_agent_leads(db, account_id, cutoff)
    expired = []
    for r in rows:
        lead_id = r["id"]
        own = not db.in_transaction
        db.execute("UPDATE leads SET closed_state = 'dead' WHERE id = ?",
                   (lead_id,))
        log_event(db, lead_id, "agent_lead_expired",
                  "agent lead unworked for %d days; marked dead" % days)
        evict_pending(db, lead_id, "agent lead residency expired")
        recompute(db, lead_id)
        if own:
            db.commit()
        expired.append(lead_id)
    if expired:
        logger.info("agent lead expiry account=%s: %d lead(s) marked dead",
                    account_id, len(expired))
    return expired


# ------------------------------------------------------------------ delete

def delete_agent_leads(db, account_id, lead_ids=None):
    """Delete this tenant's deletable agent leads (§ the shared predicate).

    Reads `deletable_agent_leads` — the SAME function the preview renders —
    so what the preview promised is exactly what goes. `lead_ids`, when
    given, INTERSECTS that set: a caller can never widen it, only narrow.

    Child rows go first (foreign_keys is ON). `suppressions` and
    `processed_emails` survive with `lead_id` nulled, for the same reason
    reset.py keeps them: a suppression is a compliance record and the
    dedupe ledger is what keeps old mail from being reimported."""
    rows = deletable_agent_leads(db, account_id)
    ids = [r["id"] for r in rows]
    if lead_ids is not None:
        wanted = set(int(i) for i in lead_ids)
        ids = [i for i in ids if i in wanted]
    if not ids:
        return []
    marks = ",".join("?" for _ in ids)
    own = not db.in_transaction
    for table in ("suppressions", "processed_emails"):
        db.execute("UPDATE %s SET lead_id = NULL WHERE lead_id IN (%s)"
                   % (table, marks), ids)
    for table in ("approvals", "messages", "interactions", "calls",
                  "va_queue", "recovery_flags", "referral_asks", "tasks",
                  "notifications", "events"):
        db.execute("DELETE FROM %s WHERE lead_id IN (%s)" % (table, marks),
                   ids)
    db.execute("DELETE FROM leads WHERE account_id = ? AND id IN (%s)"
               % marks, [account_id] + ids)
    if own:
        db.commit()
    logger.info("agent leads deleted account=%s count=%d", account_id,
                len(ids))
    return ids
