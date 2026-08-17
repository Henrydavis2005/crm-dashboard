"""Computed pipeline stage and lane (SPEC B11; was B4's flat stage list).

THREE LANES. A lead is in exactly ONE, and the lane is a pure function of
the stage — never a second stored column that can disagree with the first:

  COLD      bought, never reached. ONE stage, `cold`, and NO sub-stages.
            Cold leads are told apart by AGE, not by state — see
            `age_bucket()`. Contact with no response LEAVES a lead here,
            ageing: dialling someone is not a pipeline event, hearing back
            from them is.

  WORKING   they responded. Stages, in rung order:
            engaged -> quote -> appointment -> client.

  NEGATIVE  contacted and went nowhere: not_interested, wrong_person,
            ghosted, bad_number, do_not_call, revoked.

WORKING AND NEGATIVE SWAP FREELY, BOTH DIRECTIONS — people come back. That
is why the lane is decided by RECENCY (the most recent positive signal vs
the most recent negative one) rather than by the flat existence-precedence
B4 used. Under existence-precedence a lead who once replied would read
`engaged` forever, however many times they later said no; and a lead who
once said no could never climb back. Both are wrong, and only recency
fixes both at once.

WITHIN Working the rung is still HIGHEST-signal, not latest: a lead who
was quoted and then merely chatted is still at `quote`. Recency picks the
LANE; precedence picks the rung inside it.

TERMINAL — `do_not_call`, `revoked`, `bad_number` — is checked first and
short-circuits everything below, so no later signal of any kind can move a
lead out. This extends D2/B8 irreversibility: a revocation is a legal
instruction, not a stage, and B8 made it global to every account.

Full precedence:

  1. revoked      — an IRREVERSIBLE suppression with reason unsubscribe or
                    stop (B8: global, matched across every account).
  2. do_not_call  — an irreversible suppression with reason do_not_call
                    (the verbal opt-out; C1's answered_do_not_call).
  3. bad_number   — closed_state='no_number' (C2a: the agent's decision
                    that no real number exists). NOT the `bad_number` call
                    disposition, which is labelled "Wrong Number" and
                    means the wrong PERSON answered — see below.
  4. client       — closed_state='sold' (manual, admin only).
  5. not_interested — closed_state='dead' (manual, incl. C1's
                    not_qualified). Reopen clears closed_state and the
                    lead recomputes straight back out; that IS the
                    Negative->Working direction for a manual close.
  6. the recency contest, negative wins ties:
       NEGATIVE signals -> not_interested | wrong_person | ghosted
       POSITIVE signals -> engaged | quote | appointment (highest rung)
  7. cold         — no response either way, however long we have dialled.

`nurture` IS GONE. It meant "sequence exhausted with nothing higher",
which is precisely a Cold lead that has aged — a state, in the old model,
that a lead could only reach by NOT responding. Every nurture row lands in
`cold` (migration 37), where the age bucket now says the same thing more
honestly and without going stale the next day.

pipeline_stage_at updates only on change. Legacy leads.stage remains
engine-internal state; ALL UI displays pipeline_stage. Never commits
inside a caller's open transaction (helpers don't commit; entry points do).
"""
import datetime
import logging
from typing import Optional

from leadflow.db import utcnow

logger = logging.getLogger("leadflow.pipeline")

# ------------------------------------------------------------------ lanes

LANE_COLD = "cold"
LANE_WORKING = "working"
LANE_NEGATIVE = "negative"

LANES = (LANE_COLD, LANE_WORKING, LANE_NEGATIVE)

LANE_LABELS = {LANE_COLD: "Cold", LANE_WORKING: "Working",
               LANE_NEGATIVE: "Negative"}

# Cold has no stages. The single value exists so pipeline_stage stays one
# non-null column with one vocabulary; Cold is told apart by age_bucket().
COLD_STAGES = ("cold",)

# Rung order, lowest first. Position in this tuple IS the precedence.
WORKING_STAGES = ("engaged", "quote", "appointment", "client")

NEGATIVE_STAGES = ("not_interested", "wrong_person", "ghosted",
                   "bad_number", "do_not_call", "revoked")

# Display order for /pipeline lanes, the /leads filter, dashboard chips and
# Jarvis's per-stage counts: Cold, then Working by rung, then Negative.
PIPELINE_STAGES = (list(COLD_STAGES) + list(WORKING_STAGES)
                   + list(NEGATIVE_STAGES))

STAGE_LANE = {}
for _s in COLD_STAGES:
    STAGE_LANE[_s] = LANE_COLD
for _s in WORKING_STAGES:
    STAGE_LANE[_s] = LANE_WORKING
for _s in NEGATIVE_STAGES:
    STAGE_LANE[_s] = LANE_NEGATIVE
del _s

# The stages a lead can never leave. `bad_number` is here because C2a's
# "no real number exists" is a closure decision, not an observation — the
# same class of act as a revocation. Everything else in NEGATIVE_STAGES is
# reversible by a later signal, which is what "people come back" requires.
TERMINAL_STAGES = ("do_not_call", "revoked", "bad_number")

# The stages that mean the lead is out of play for queue-building and
# "active lead" counting: every Negative stage. Cold and Working are live.
LIVE_STAGES = tuple(COLD_STAGES) + tuple(WORKING_STAGES)

STAGE_LABELS = {
    "cold": "Cold",
    "engaged": "Engaged",
    "quote": "Quote",
    "appointment": "Appointment",
    "client": "Client",
    "not_interested": "Not interested",
    "wrong_person": "Wrong person",
    "ghosted": "Ghosted",
    "bad_number": "Bad number",
    "do_not_call": "Do not call",
    "revoked": "Revoked",
}


def lane_of(stage):
    # type: (Optional[str]) -> str
    """The lane a stage belongs to. Unknown values read as Cold — a lead
    is never lost off the board by a value we do not recognise."""
    return STAGE_LANE.get(stage or "", LANE_COLD)


def is_terminal(stage):
    # type: (Optional[str]) -> bool
    return (stage or "") in TERMINAL_STAGES


def stage_label(stage):
    # type: (Optional[str]) -> str
    return STAGE_LABELS.get(stage or "", stage or "cold")


# ------------------------------------------------------------ age buckets

# COLD age buckets, off received_at. DERIVED AT READ, NEVER STORED: a
# stored bucket is correct for one day and wrong every day after, and
# nothing in the app would tell you it had gone stale.
#
# (label, low_day, high_day) inclusive; high None = open-ended. 45 belongs
# to "31-45" and "45+" starts at 46 — the block writes the boundary twice,
# and a lead must land in exactly one bucket, so the earlier one keeps it.
AGE_BUCKETS = (
    ("today", 0, 0),
    ("1-3", 1, 3),
    ("4-7", 4, 7),
    ("8-14", 8, 14),
    ("15-30", 15, 30),
    ("31-45", 31, 45),
    ("45+", 46, None),
)

COLD_BUCKETS = tuple(label for label, _lo, _hi in AGE_BUCKETS)


def _parse_iso(value):
    if not value:
        return None
    try:
        dt = datetime.datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except (ValueError, TypeError):
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=datetime.timezone.utc)
    return dt


def age_days(received_at, now_dt=None):
    # type: (Optional[str], Optional[datetime.datetime]) -> Optional[int]
    """Whole days since received_at, floored at 0. None if unparseable."""
    dt = _parse_iso(received_at)
    if dt is None:
        return None
    if now_dt is None:
        now_dt = datetime.datetime.now(datetime.timezone.utc)
    return max(0, int((now_dt - dt).total_seconds() // 86400))


def age_bucket(received_at, now_dt=None):
    # type: (Optional[str], Optional[datetime.datetime]) -> Optional[str]
    """The COLD age bucket a lead falls in right now. None when received_at
    is missing or unparseable — an unknown age is not bucket 'today'."""
    days = age_days(received_at, now_dt=now_dt)
    if days is None:
        return None
    for label, low, high in AGE_BUCKETS:
        if days >= low and (high is None or days <= high):
            return label
    return AGE_BUCKETS[-1][0]


def bucket_counts(db, account_id, now_dt=None):
    # type: (object, int, Optional[datetime.datetime]) -> dict
    """{bucket: count} over the tenant's COLD leads, every bucket present.

    Bucketed in Python off received_at rather than in SQL so there is ONE
    definition of a boundary (AGE_BUCKETS) instead of a second one written
    in CASE WHENs that can drift from it."""
    counts = dict((label, 0) for label in COLD_BUCKETS)
    rows = db.execute(
        "SELECT received_at FROM leads "
        "WHERE account_id = ? AND pipeline_stage = 'cold'",
        (account_id,)).fetchall()
    for r in rows:
        bucket = age_bucket(r["received_at"], now_dt=now_dt)
        if bucket is not None:
            counts[bucket] += 1
    return counts


# --------------------------------------------------------- closed states

# closed_state values that CLOSE a lead without selling it. 'no_number'
# (C2a) is a distinct LOSS REASON — countable apart in /stats — and B11
# gives it its own terminal stage, so unlike B4 the two no longer share a
# rung. They still travel together everywhere closed_state gates a queue.
DEAD_CLOSED_STATES = ("dead", "no_number")

# Plain-English closed_state, as it reads after "This lead is ..." —
# 'no_number' must never reach a user as a raw slug.
CLOSED_STATE_LABELS = {"sold": "sold", "dead": "dead",
                       "no_number": "closed with no working phone number"}


def closed_state_label(closed_state):
    # type: (Optional[str]) -> str
    """'sold' / 'dead' / 'closed with no working phone number' (unknown
    values render as-is)."""
    return CLOSED_STATE_LABELS.get(closed_state, closed_state or "closed")


# ------------------------------------------------------------- the signals

def _latest(db, sql, params):
    """MAX(timestamp) for a signal, or None when the signal is absent."""
    row = db.execute(sql, params).fetchone()
    if row is None:
        return None
    return row[0] or None


def _revocation_stage(db, lead):
    """`revoked` / `do_not_call` for an IRREVERSIBLE suppression, else None.

    Two lookups, because a suppression row can be keyed EITHER way. A row
    written against this lead directly (`lead_id`) may carry no address at
    all, so an address-only match would miss it — that is the shape the
    B4 code got right and it is preserved here. B8 made revocations
    global, so the address match is deliberately unscoped: one person's
    opt-out holds across every account, while a reversible suppression
    stays the tenant's own."""
    from leadflow.suppression import (  # deferred: avoid cycles
        REVOCATION_REASONS, revocation_for,
    )
    marks = ",".join("?" for _ in REVOCATION_REASONS)
    row = db.execute(
        "SELECT reason FROM suppressions WHERE lead_id = ? "
        "AND reason IN (%s) ORDER BY created_at, id LIMIT 1" % marks,
        (lead["id"],) + tuple(REVOCATION_REASONS)).fetchone()
    if row is None:
        row = revocation_for(db, email=lead["email"], phone=lead["phone"])
    if row is None:
        return None
    return "do_not_call" if row["reason"] == "do_not_call" else "revoked"


def _soft_suppression_at(db, lead):
    """When this lead was last SOFT-suppressed (reversible: not_interested,
    hard_bounce, manual), or None.

    Deliberately NOT terminal. `not_interested` is "not right now" — a soft
    close the tenant may legitimately revisit (suppression.py) — and B11
    requires exactly that lead to be able to come back to Working."""
    from leadflow.suppression import REVOCATION_REASONS  # deferred: cycles
    marks = ",".join("?" for _ in REVOCATION_REASONS)
    params = [lead["account_id"], lead["id"]]
    clauses = ["(lead_id = ?)"]
    if lead["email"]:
        clauses.append("(email IS NOT NULL AND lower(email) = lower(?))")
        params.append(lead["email"])
    if lead["phone"]:
        clauses.append("(phone IS NOT NULL AND phone = ?)")
        params.append(lead["phone"])
    params.extend(REVOCATION_REASONS)
    return _latest(
        db,
        "SELECT MAX(created_at) FROM suppressions "
        "WHERE account_id = ? AND (%s) AND reason NOT IN (%s)"
        % (" OR ".join(clauses), marks),
        tuple(params))


def _latest_negative(db, lead, now_dt):
    """(when, stage) for the most recent NEGATIVE signal, or None.

    Ties inside this function go to the more specific stage by the order
    the candidates are listed, which is stable and does not depend on how
    SQLite happens to order equal timestamps."""
    lead_id = lead["id"]
    candidates = []

    # Someone picked up and said no, or did not qualify.
    when = _latest(
        db,
        "SELECT MAX(created_at) FROM interactions WHERE lead_id = ? "
        "AND itype = 'call' "
        "AND disposition IN ('answered_not_interested','not_qualified')",
        (lead_id,))
    if when:
        candidates.append((when, "not_interested"))

    # An inbound reply classified as a no. (This also writes a REVERSIBLE
    # suppression — replies_common — so the two agree rather than one
    # quietly outranking the other.)
    when = _latest(
        db,
        "SELECT MAX(created_at) FROM messages WHERE lead_id = ? "
        "AND direction = 'in' AND classification = 'NOT_INTERESTED'",
        (lead_id,))
    if when:
        candidates.append((when, "not_interested"))

    when = _soft_suppression_at(db, lead)
    if when:
        candidates.append((when, "not_interested"))

    # C1's `bad_number` disposition is LABELLED "Wrong Number": the wrong
    # PERSON answered. That is contact WITH a response, so it belongs in
    # Negative — but it is not the terminal `bad_number` stage, which only
    # closed_state='no_number' reaches. The lead can still come back on
    # another channel, and B11 requires that it can.
    #
    # GATED ON leads.phone_bad, not on the interaction row alone. The
    # disposition SETS phone_bad and C2a's "correct the number" action
    # CLEARS it, so the flag is the live answer to "is the number we hold
    # still the wrong one?" while the call row is only a permanent record
    # that it once was. Reading the row alone would leave a lead parked on
    # `wrong_person` forever after somebody fixed the number — the exact
    # thing Needs Review exists to undo.
    if lead["phone_bad"]:
        when = _latest(
            db,
            "SELECT MAX(created_at) FROM interactions WHERE lead_id = ? "
            "AND itype = 'call' AND disposition = 'bad_number'",
            (lead_id,))
        if when:
            candidates.append((when, "wrong_person"))

    # They engaged, went quiet, and the recovery attempt reached nobody.
    # R4 resolves a fast_ghost / stale_quote / stale_engaged flag with the
    # outcome 'no_contact' (interactions.RECOVERY_OUTCOMES) — an existing,
    # already-written signal, not a new one invented for this lane.
    when = _latest(
        db,
        "SELECT MAX(resolved_at) FROM recovery_flags WHERE lead_id = ? "
        "AND status IN ('done','cleared') AND outcome = 'no_contact'",
        (lead_id,))
    if when:
        candidates.append((when, "ghosted"))

    if not candidates:
        return None
    best = candidates[0]
    for cand in candidates[1:]:
        if cand[0] > best[0]:
            best = cand
    return best


def _latest_positive(db, lead, now_dt):
    """(when, stage) — the LATEST positive-signal time paired with the
    HIGHEST rung any positive signal reaches. The two are deliberately
    taken from different signals: recency decides the LANE, precedence
    decides the rung inside Working."""
    lead_id = lead["id"]
    rungs = []   # (rung_index, when)

    # appointment — a `showed` appointment, or a `scheduled` one with no
    # TERMINAL outcome child (T1: cancelled / rescheduled mean it is not
    # happening; no_show does NOT — a no-showed appointment still holds
    # the lead here, unchanged).
    when = _latest(
        db,
        "SELECT MAX(i.created_at) FROM interactions i WHERE i.lead_id = ? "
        "AND i.itype = 'appointment' AND ("
        " i.disposition = 'showed'"
        " OR (i.disposition = 'scheduled' AND NOT EXISTS ("
        "      SELECT 1 FROM interactions o WHERE o.parent_id = i.id"
        "      AND o.disposition IN ('cancelled','rescheduled'))))",
        (lead_id,))
    if when:
        rungs.append((2, when))

    # quote — quote_request inbound OR answered_send_options call OR
    # text_log warm/hot (R2) OR legacy stage 'quote'.
    when = _latest(
        db,
        "SELECT MAX(created_at) FROM messages WHERE lead_id = ? "
        "AND direction = 'in' AND quote_request = 1", (lead_id,))
    if when:
        rungs.append((1, when))
    when = _latest(
        db,
        "SELECT MAX(created_at) FROM interactions WHERE lead_id = ? "
        "AND ((itype = 'call' AND disposition = 'answered_send_options') "
        "  OR (itype = 'text_log' AND disposition IN ('warm','hot')))",
        (lead_id,))
    if when:
        rungs.append((1, when))
    if lead["stage"] == "quote":
        # A legacy engine stage with no timestamp of its own. Dated at the
        # lead's own arrival — the earliest defensible moment — so ANY
        # later negative signal outranks it rather than being outranked by
        # a rung whose age we do not actually know.
        rungs.append((1, lead["received_at"] or ""))

    # engaged — inbound classified INTERESTED/UNCLEAR OR a
    # callback_requested call (C1) OR a legacy answered_interested /
    # answered_callback call OR text_log mild (R2).
    when = _latest(
        db,
        "SELECT MAX(created_at) FROM messages WHERE lead_id = ? "
        "AND direction = 'in' AND classification IN ('INTERESTED','UNCLEAR')",
        (lead_id,))
    if when:
        rungs.append((0, when))
    when = _latest(
        db,
        "SELECT MAX(created_at) FROM interactions WHERE lead_id = ? "
        "AND ((itype = 'call' AND disposition IN "
        "      ('callback_requested','answered_interested',"
        "       'answered_callback')) "
        "  OR (itype = 'text_log' AND disposition = 'mild'))",
        (lead_id,))
    if when:
        rungs.append((0, when))

    if not rungs:
        return None
    top = max(r for r, _w in rungs)
    latest = max(w for _r, w in rungs)
    return (latest, WORKING_STAGES[top])


# ------------------------------------------------------------- the stage

def compute_stage(db, lead, now_dt=None):
    # type: (object, object, Optional[datetime.datetime]) -> str
    """The pipeline stage a lead row should be in right now."""
    if now_dt is None:
        now_dt = datetime.datetime.now(datetime.timezone.utc)

    # 1-3. TERMINAL. Checked first and returned immediately, so nothing
    # below — no reply, no appointment, no sale — can move a lead out.
    revocation = _revocation_stage(db, lead)
    if revocation is not None:
        return revocation
    if lead["closed_state"] == "no_number":
        return "bad_number"

    # 4-5. Manual closures. Reopen clears closed_state, and the lead
    # recomputes out of `not_interested` on the next signal it has.
    if lead["closed_state"] == "sold":
        return "client"
    if lead["closed_state"] == "dead":
        return "not_interested"

    # 6. The recency contest. A tie goes to the negative side: if the same
    # second holds both a reply and a refusal, the refusal is the one we
    # must not act against.
    negative = _latest_negative(db, lead, now_dt)
    positive = _latest_positive(db, lead, now_dt)
    if negative is not None and (positive is None
                                 or negative[0] >= positive[0]):
        return negative[1]
    if positive is not None:
        return positive[1]

    # 7. Dialled, emailed, dialled again — and never heard back. Cold,
    # ageing, exactly where they were.
    return "cold"


def recompute(db, lead_id, now_dt=None):
    # type: (object, int, Optional[datetime.datetime]) -> Optional[str]
    """Recompute and persist a lead's pipeline stage. Returns the stage
    (None for an unknown lead). pipeline_stage_at updates only on change.

    TERMINAL STAGES ARE NEVER OVERWRITTEN. compute_stage already returns
    them from the top of its precedence, but this is the second,
    unconditional guard: whatever a future signal or a future caller
    computes, a lead that is already do_not_call / revoked / bad_number
    keeps that stage. One of the two would do; both is what makes it a
    guarantee rather than an ordering detail."""
    lead = db.execute("SELECT * FROM leads WHERE id = ?", (lead_id,)).fetchone()
    if lead is None:
        return None
    if is_terminal(lead["pipeline_stage"]):
        return lead["pipeline_stage"]
    stage = compute_stage(db, lead, now_dt=now_dt)
    if stage != lead["pipeline_stage"] or lead["pipeline_stage_at"] is None:
        own = not db.in_transaction
        db.execute(
            "UPDATE leads SET pipeline_stage = ?, pipeline_stage_at = ? "
            "WHERE id = ?",
            (stage, utcnow(), lead_id),
        )
        if own:
            db.commit()
        logger.info("lead=%s pipeline_stage -> %s (%s)", lead_id, stage,
                    lane_of(stage))
    return stage
