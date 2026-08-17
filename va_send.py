"""B6: which leads may be sent to the team's call queue, and the record
that one was.

SIX HARD REFUSALS, IN CODE. Not settings, not a filter somebody can widen
from a form, not a suggestion the AI is free to overrule — six predicates
that each return a named reason, evaluated for every lead before anything
reaches a VA:

  source          the lead came from NextGen or USHA Marketplace, proven
                  by the PARSED EMAIL (the `lead_sources` row that matched
                  the sender), never by a string somebody typed
  freshness       received within SEND_MAX_AGE_DAYS of the email's own
                  Date header
  phone           a phone number is present
  compliance      not suppressed, not revoked
  licensure       the account holds an unexpired licence for the lead's
                  resident state (B4)
  duplicate       no other lead with this phone number has already been
                  sent to this team's queue

THE AI RANKS; IT DOES NOT ADMIT. `rank_suggestions` is handed the list
that already passed all six and reorders it. There is no path by which a
model's opinion adds a lead the code refused, and a test walks the call to
prove the ordering.

## 45 DAYS IS NOT 180 DAYS, AND THE TWO MUST NEVER BE UNIFIED

`SEND_MAX_AGE_DAYS = 45` here.
`consent.DEFAULT_MAX_AGE_DAYS = 180` there (`dialer_consent_max_age_days`).

They look like the same number and they are not the same question.

  180 is a COMPLIANCE ceiling. It is the outer limit past which a prior
  express written consent is too old to rely on for a telephone call at
  all. Crossing it is a legal problem. It is a SETTING because different
  carriers and different counsel land in different places, and it applies
  to the dialer.

  45 is an OPERATIONAL floor for handing work to an assistant. A
  seven-week-old inquiry is legally callable and commercially cold: the
  person has already bought, already forgotten, or already been called by
  four other agents. Sending it costs a VA's hour for almost nothing. It
  is a CONSTANT because it is a judgement about how to spend somebody's
  day, not about what the law permits.

A lead 60 days old is refused HERE and permitted THERE, and that is
correct. Anybody tempted to "fix the inconsistency" by making one read the
other would either start calling four-month-old leads or stop the dialer
from returning callbacks. Two names, two homes, two reasons — and this
paragraph, so the next person finds it before the edit.
"""
import datetime
import json
import logging

from leadflow.db import utcnow
from leadflow.phone import normalize_phone

logger = logging.getLogger("leadflow.va_send")

# See the module docstring. NOT consent.DEFAULT_MAX_AGE_DAYS.
SEND_MAX_AGE_DAYS = 45

# The vendors whose inquiries may be worked by an assistant, matched
# against the `lead_sources` row the intake parser used. A lead with no
# source row never matched a vendor email and cannot be proven to have
# come from one.
ELIGIBLE_SOURCES = ("NextGen Leads", "USHA Marketplace")

REASON_SOURCE = "source_not_eligible"
REASON_STALE = "older_than_45_days"
REASON_NO_PHONE = "no_phone"
REASON_SUPPRESSED = "suppressed_or_revoked"
REASON_LICENSURE = "not_licensed"
REASON_DUPLICATE = "duplicate_phone"
REASON_ALREADY_SENT = "already_sent"

REASON_TEXT = {
    REASON_SOURCE: "Not a NextGen or USHA Marketplace lead.",
    REASON_STALE: "Older than %d days." % SEND_MAX_AGE_DAYS,
    REASON_NO_PHONE: "No phone number.",
    REASON_SUPPRESSED: "Do not contact.",
    REASON_LICENSURE: "Not licensed in this lead's state.",
    REASON_DUPLICATE: ("Another agent already sent this phone number to "
                       "the team queue — keep working it by email."),
    REASON_ALREADY_SENT: "Already sent to the team queue.",
}

# Ordered, so a lead failing several rules always reports the same one and
# an agent chasing a fix is not sent round in circles. Compliance first
# because it is the one that must never be reported as something milder.
REASON_ORDER = (REASON_SUPPRESSED, REASON_LICENSURE, REASON_NO_PHONE,
                REASON_SOURCE, REASON_STALE, REASON_ALREADY_SENT,
                REASON_DUPLICATE)


def reason_text(reason):
    return REASON_TEXT.get(reason, "Not eligible.")


# ------------------------------------------------------------- the team

def team_root(db, account_id):
    # type: (object, int) -> int
    """Whose queue does this account send into.

    The manager's account for an agent on a team, the account itself
    otherwise. This is what "the TEAM VA queue" means, and it is what the
    duplicate rule is scoped to: two agents on one team may not both send
    the same telephone number, two agents on different teams may.
    """
    from leadflow import team
    upline = team.upline_id(db, account_id)
    return int(upline) if upline else int(account_id)


# --------------------------------------------------------- the six rules

def _parse_iso(value):
    try:
        parsed = datetime.datetime.fromisoformat(str(value))
    except (TypeError, ValueError):
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=datetime.timezone.utc)
    return parsed


def _now():
    return _parse_iso(utcnow()) or datetime.datetime.now(
        datetime.timezone.utc)


def source_ok(db, lead):
    """Proven by the PARSED EMAIL: the lead carries the `lead_sources` row
    whose sender addresses matched the vendor's mail. A lead with no
    source (a manual add, a CSV upload) never matched one."""
    source_id = lead["source_id"]
    if not source_id:
        return False
    row = db.execute("SELECT name FROM lead_sources WHERE id = ?",
                     (source_id,)).fetchone()
    return bool(row) and row["name"] in ELIGIBLE_SOURCES


def fresh_enough(lead, now=None):
    """Within SEND_MAX_AGE_DAYS of the lead email's own Date header.

    `leads.received_at` IS that header — intake writes it from the message
    and refuses a message whose date it cannot read. An unreadable value
    here reads as TOO OLD, never as fresh: a lead whose age cannot be
    established has not answered the question this rule asks.
    """
    received = _parse_iso(lead["received_at"])
    if received is None:
        return False
    age = (now or _now()) - received
    return age <= datetime.timedelta(days=SEND_MAX_AGE_DAYS)


def _already_sent(db, lead_id):
    return db.execute(
        "SELECT 1 FROM va_sends WHERE lead_id = ? LIMIT 1",
        (lead_id,)).fetchone() is not None


def _duplicate_holder(db, root, phone, lead_id):
    """The va_sends row that already holds this phone for this team, if
    any other lead holds it. FIRST SEND WINS."""
    if not phone:
        return None
    return db.execute(
        "SELECT * FROM va_sends WHERE team_account_id = ? AND phone = ? "
        "AND lead_id != ? LIMIT 1", (root, phone, lead_id)).fetchone()


def check(db, lead, now=None, root=None):
    # type: (object, object, object, object) -> tuple
    """(eligible, reason). THE gate. Every rule, in REASON_ORDER."""
    from leadflow import licensure
    from leadflow.suppression import is_suppressed

    account_id = lead["account_id"]
    root = root if root is not None else team_root(db, account_id)
    phone = normalize_phone(lead["phone"])

    if is_suppressed(db, email=lead["email"], phone=lead["phone"],
                     account_id=account_id):
        return (False, REASON_SUPPRESSED)
    allowed, _why = licensure.lead_is_workable(db, lead)
    if not allowed:
        return (False, REASON_LICENSURE)
    if not phone:
        return (False, REASON_NO_PHONE)
    if not source_ok(db, lead):
        return (False, REASON_SOURCE)
    if not fresh_enough(lead, now):
        return (False, REASON_STALE)
    if _already_sent(db, lead["id"]):
        return (False, REASON_ALREADY_SENT)
    if _duplicate_holder(db, root, phone, lead["id"]) is not None:
        return (False, REASON_DUPLICATE)
    return (True, None)


# ----------------------------------------------------------- the listing

def candidates(db, account_id, now=None, limit=500):
    # type: (object, int, object, int) -> dict
    """Every lead this account could send, judged one at a time.

    Returns {"eligible": [...], "ineligible": [(lead, reason), ...]} —
    BOTH, because B6 requires the refused ones to be visible with the
    reason. A lead nobody may send is not a lead nobody may see.
    """
    root = team_root(db, account_id)
    now = now or _now()
    rows = db.execute(
        "SELECT l.*, s.name AS source_name FROM leads l "
        "LEFT JOIN lead_sources s ON s.id = l.source_id "
        "WHERE l.account_id = ? AND l.closed_state IS NULL "
        "ORDER BY l.received_at DESC, l.id DESC LIMIT ?",
        (int(account_id), int(limit))).fetchall()
    eligible, ineligible = [], []
    for lead in rows:
        ok, reason = check(db, lead, now=now, root=root)
        if ok:
            eligible.append(lead)
        else:
            ineligible.append((lead, reason))
    return {"eligible": eligible, "ineligible": ineligible}


# -------------------------------------------------------------- the send

class SendRefused(RuntimeError):
    def __init__(self, reason):
        RuntimeError.__init__(self, reason_text(reason))
        self.reason = reason


def send(db, lead, user_id=None, now=None):
    # type: (object, object, object, object) -> int
    """Put ONE lead on the team's queue. Re-checks every rule.

    THE GATE IS HERE, not only in the listing. A page can be stale, a form
    can be replayed, and a bulk send iterates leads that were judged
    before the first of them was written — so the answer is taken again at
    the moment of the write, inside the transaction that does it.
    """
    account_id = lead["account_id"]
    root = team_root(db, account_id)
    ok, reason = check(db, lead, now=now, root=root)
    if not ok:
        raise SendRefused(reason)
    phone = normalize_phone(lead["phone"])
    own = not db.in_transaction
    try:
        cur = db.execute(
            "INSERT INTO va_sends (team_account_id, account_id, lead_id, "
            "phone, sent_by, created_at) VALUES (?,?,?,?,?,?)",
            (root, account_id, lead["id"], phone, user_id, utcnow()))
    except Exception:
        # UNIQUE(team_account_id, phone) is the real enforcement — two
        # agents pressing Send in the same second both pass `check` and
        # only one row can exist. The loser is refused with the SAME
        # reason the check would have given, so a race and a stale page
        # are indistinguishable to the person reading the message.
        if own:
            db.rollback()
        raise SendRefused(REASON_DUPLICATE)
    from leadflow.audit import log_event
    log_event(db, lead["id"], "sent_to_va",
              "sent to the team call queue", user_id=user_id)
    if own:
        db.commit()
    return cur.lastrowid


def send_many(db, leads, user_id=None, now=None):
    # type: (object, list, object, object) -> dict
    """Bulk send. Each lead is judged and written on its own.

    ONE REFUSAL DOES NOT ABORT THE REST — a bulk send of forty leads that
    stopped at the third would leave the agent guessing which ones landed.
    Returns {"sent": [ids], "refused": [(lead_id, reason)]}.
    """
    sent, refused = [], []
    for lead in leads:
        try:
            send(db, lead, user_id=user_id, now=now)
            sent.append(lead["id"])
        except SendRefused as exc:
            refused.append((lead["id"], exc.reason))
    return {"sent": sent, "refused": refused}


def sent_rows(db, root, limit=500):
    """What is on this team's queue, newest first."""
    return db.execute(
        "SELECT v.*, l.first_name, l.last_name, l.state, a.name AS agent "
        "FROM va_sends v JOIN leads l ON l.id = v.lead_id "
        "LEFT JOIN accounts a ON a.id = v.account_id "
        "WHERE v.team_account_id = ? ORDER BY v.id DESC LIMIT ?",
        (int(root), int(limit))).fetchall()


# ----------------------------------------------------------- the ranking

# What the model is asked to weigh, in the order B6 gave them. Named as
# DATA so the prompt and the fallback ordering cannot describe different
# things.
RANK_SIGNALS = (
    ("ghosted_two_days",
     "went quiet two days ago or longer with no follow-up and no "
     "appointment activity since"),
    ("recency", "how recently the inquiry arrived"),
    ("last_click", "how recently they clicked a link in an email"),
    ("engagement", "how much they have replied, opened and clicked"),
)


def signal_snapshot(db, lead, now=None):
    """The four signals for ONE lead, as plain numbers. No client details:
    this is what goes into the model's prompt, and a name or an email
    address in it would be leaving the application for no purpose the
    ranking has."""
    now = now or _now()
    lead_id = lead["id"]

    def scalar(sql, params):
        row = db.execute(sql, params).fetchone()
        return row["v"] if row and row["v"] is not None else None

    last_in = scalar(
        "SELECT MAX(created_at) AS v FROM messages WHERE lead_id = ? "
        "AND direction = 'in'", (lead_id,))
    last_appt = scalar(
        "SELECT MAX(created_at) AS v FROM interactions WHERE lead_id = ? "
        "AND itype = 'appointment'", (lead_id,))
    last_out = scalar(
        "SELECT MAX(sent_at) AS v FROM messages WHERE lead_id = ? "
        "AND direction = 'out' AND status = 'sent'", (lead_id,))
    replies = scalar(
        "SELECT COUNT(*) AS v FROM messages WHERE lead_id = ? "
        "AND direction = 'in'", (lead_id,)) or 0

    def age_days(stamp):
        parsed = _parse_iso(stamp)
        if parsed is None:
            return None
        return max(0, int((now - parsed).total_seconds() // 86400))

    quiet = age_days(last_in)
    return {
        "lead_id": lead_id,
        # "Ghosted two days" — they engaged, then stopped, and nothing has
        # been booked since. A lead that never replied at all is not
        # ghosting; it is cold, and `recency` is the signal for that.
        "ghosted_two_days": bool(
            quiet is not None and quiet >= 2 and last_appt is None),
        "days_since_reply": quiet,
        "days_since_inquiry": age_days(lead["received_at"]),
        "days_since_last_email": age_days(last_out),
        "reply_count": int(replies),
    }


def _fallback_order(snapshots):
    """The order used when no model is configured or the call fails.

    Deliberately the same PRIORITIES, arithmetically: ghosting first,
    then more replies, then a more recent inquiry. A fallback that ordered
    by lead id would quietly turn "AI suggests these" into "the oldest
    ones", and nobody would notice until they wondered why the
    suggestions never changed.
    """
    def key(snap):
        return (0 if snap["ghosted_two_days"] else 1,
                -int(snap["reply_count"] or 0),
                snap["days_since_inquiry"]
                if snap["days_since_inquiry"] is not None else 9999)
    return [s["lead_id"] for s in sorted(snapshots, key=key)]


def rank_suggestions(db, leads, account_id=None, now=None, limit=25):
    # type: (object, list, object, object, int) -> list
    """Reorder leads that ALREADY PASSED the code gate. Returns lead rows.

    The model never widens the set: it is given ids and signal numbers and
    asked for an order, the returned ids are intersected with what went
    in, and anything it omits is appended in fallback order. There is no
    branch here that can produce a lead the caller did not supply.
    """
    if not leads:
        return []
    snapshots = [signal_snapshot(db, lead, now=now) for lead in leads]
    by_id = dict((lead["id"], lead) for lead in leads)
    order = None
    try:
        order = _model_order(db, snapshots, account_id)
    except Exception:
        logger.exception("AI ranking failed for account %s; falling back "
                         "to the arithmetic order", account_id)
    if not order:
        order = _fallback_order(snapshots)
    # INTERSECT, never trust: ids the model invented are dropped, ids it
    # forgot are appended.
    seen, ordered = set(), []
    for lead_id in order:
        if lead_id in by_id and lead_id not in seen:
            seen.add(lead_id)
            ordered.append(by_id[lead_id])
    for lead_id in _fallback_order(snapshots):
        if lead_id not in seen:
            seen.add(lead_id)
            ordered.append(by_id[lead_id])
    return ordered[:limit]


def _model_order(db, snapshots, account_id):
    """Ask Claude for an order. Returns a list of lead ids, or None."""
    from leadflow.ai.core import (
        AiError, _api_settings, _create_message, _first_text,
    )
    try:
        api_key, model = _api_settings(db, account_id)
    except AiError:
        # No key configured is not an error here — the arithmetic fallback
        # is a perfectly good order and every lead in it already passed
        # the code gate.
        return None
    prompt = (
        "You are ordering leads for a call queue. Every lead below has "
        "ALREADY passed eligibility; your job is ONLY to order them.\n\n"
        "Weigh, in this order of importance:\n"
        + "\n".join("- %s" % text for _key, text in RANK_SIGNALS)
        + "\n\nReturn JSON only: {\"order\": [lead_id, ...]} containing "
          "every lead_id you were given, best first.\n\n"
        + json.dumps(snapshots, sort_keys=True))
    response = _create_message(
        api_key, model=model, max_tokens=1024,
        messages=[{"role": "user", "content": prompt}])
    text = _first_text(response)
    start, end = text.find("{"), text.rfind("}")
    if start < 0 or end < 0:
        return None
    payload = json.loads(text[start:end + 1])
    order = payload.get("order")
    if not isinstance(order, list):
        return None
    return [int(v) for v in order if isinstance(v, (int, float))]
