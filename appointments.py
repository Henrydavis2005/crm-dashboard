"""B9 — the appointment tracker, and the split that pays for it.

WHAT THIS IS FOR. A team VA sets an appointment on an agent's lead. The
agent (or whoever runs it) closes the business. Both sides need to see
the same row and neither should have to ask the other what it was worth.
`interactions` already records that an appointment happened; it records
nothing about money, and it is scoped to the agent's tenant, so the VA
who set the appointment cannot read it at all.

TWO RULES SHAPE EVERY DECISION IN THIS MODULE.

1. THE LEAD IS A REFERENCE, NEVER A NAME.
   `appointment_tracker` stores `lead_id` and a snapshot of `state`, and
   nothing else that identifies the client. Both sides of a split read
   these rows, and the setting side is frequently a seat on the team
   account rather than on the agent's tenant — so a denormalised name
   would be this table quietly handing one tenant's client identity to
   another. `state` is snapshotted because the other side legitimately
   needs to know which state was worked and cannot read the lead row to
   find out. `describe` below is the ONLY thing that renders a row, and
   it is what makes that structural rather than a habit.

2. THE SPLIT AMOUNT IS DERIVED, NEVER STORED.
   "Split rate is CONFIGURABLE, not hardcoded — changing it later must
   not require re-entering anything." A stored `split_cents` fails that
   twice over: change the rate and either every historical row is wrong,
   or somebody re-enters them all. So the row stores the FACTS the closer
   typed — premium and commission — and the split is computed at read
   from the rate effective on the row's own date.

   `split_rates` is effective-dated exactly like `pay_rates`. A rate
   change is an INSERT with a new `effective_date`; rows already recorded
   keep resolving to the rate that was in force on their date, so
   changing the rate today re-prices nothing that already happened and
   re-enters nothing. Those two properties are the whole requirement, and
   only an effective-dated table gives both at once.

WHICH DATE GOVERNS. `date_run` when the appointment has been run,
`date_set` until then. The split pays for work, the work is the
appointment being run, and a row that has not been run yet has no
commission to split anyway — so the fallback only ever affects a preview.

WHO MAY DO WHAT.
  * whoever CLOSES enters the commission (`record_close`);
  * the app derives the other side's share from it;
  * whoever closed marks it paid (`mark_paid`);
  * BOTH sides see the row, through `for_team` / `for_person`.
"""
import datetime
import logging
from typing import Optional

from leadflow.db import utcnow

logger = logging.getLogger("leadflow.appointments")

# The outcomes a tracked appointment can carry. `scheduled` is the state
# it is born in; the rest are terminal for the appointment itself, though
# `showed` may later gain a close.
OUTCOMES = ("scheduled", "showed", "no_show", "cancelled")

# What happened to the BUSINESS, which is a different question from what
# happened to the appointment. Kept apart on purpose: an appointment can
# be showed-and-not-sold, and collapsing the two would make "showed" mean
# "sold" the first time somebody read the column quickly.
CLOSE_OUTCOMES = ("sold", "not_sold")

ALL_OUTCOMES = OUTCOMES + CLOSE_OUTCOMES

OUTCOME_LABELS = {
    "scheduled": "Scheduled",
    "showed": "Showed",
    "no_show": "No-show",
    "cancelled": "Cancelled",
    "sold": "Sold",
    "not_sold": "Ran, not sold",
}

# The split used when a team has never set one. NOT a hardcoded business
# rule — it is the value `ensure_default_rate` writes as a real, editable,
# effective-dated row the first time a team needs one, so it shows up in
# the UI as a number somebody can change rather than as a constant buried
# in a module. 5000bps = an even split.
DEFAULT_SPLIT_BPS = 5000

BPS = 10000


class AppointmentError(ValueError):
    """A tracker write that would be wrong."""


def _today():
    return datetime.date.today().isoformat()


# ------------------------------------------------------------ split rates

def ensure_default_rate(db, team_account_id):
    # type: (object, int) -> None
    """Give a team a real rate row the first time anything asks.

    Written rather than defaulted in code so the number is visible and
    editable where every other rate is. Idempotent: the unique index on
    (account_id, effective_date) and the existence check both hold.
    """
    row = db.execute(
        "SELECT 1 FROM split_rates WHERE account_id = ? LIMIT 1",
        (int(team_account_id),)).fetchone()
    if row is not None:
        return
    db.execute(
        "INSERT OR IGNORE INTO split_rates (account_id, effective_date, "
        "va_split_bps, note, created_at) VALUES (?,?,?,?,?)",
        (int(team_account_id), "1970-01-01", DEFAULT_SPLIT_BPS,
         "created automatically; edit to change the split", utcnow()))


def set_split_rate(db, team_account_id, va_split_bps, effective_date=None,
                   note=None):
    # type: (object, int, int, Optional[str], Optional[str]) -> int
    """Record a new split rate for a team, effective from a date.

    THIS IS AN INSERT, NEVER AN UPDATE of the number in use. That is what
    makes "changing it later must not require re-entering anything" true:
    every appointment already recorded keeps deriving from the rate in
    force on its own date, and only rows dated on or after
    `effective_date` see the new one.
    """
    bps = int(va_split_bps)
    if not 0 <= bps <= BPS:
        raise AppointmentError(
            "a split must be between 0 and 100%%; got %s bps" % bps)
    effective_date = effective_date or _today()
    own = not db.in_transaction
    db.execute(
        "INSERT INTO split_rates (account_id, effective_date, va_split_bps, "
        "note, created_at) VALUES (?,?,?,?,?) "
        "ON CONFLICT(account_id, effective_date) DO UPDATE SET "
        "va_split_bps = excluded.va_split_bps, note = excluded.note",
        (int(team_account_id), effective_date, bps, note, utcnow()))
    if own:
        db.commit()
    logger.info("split rate for team %s -> %s bps from %s",
                team_account_id, bps, effective_date)
    return bps


def split_bps_on(db, team_account_id, on_date=None):
    # type: (object, int, Optional[str]) -> int
    """The split in force for this team on this date.

    Max `effective_date <= on_date`, the same resolution `pay_rates` uses.
    A team with no row at all gets `DEFAULT_SPLIT_BPS` rather than zero —
    failing to nothing here would silently pay the setting side nothing,
    which is the wrong direction to fail in a money calculation.
    """
    on_date = on_date or _today()
    row = db.execute(
        "SELECT va_split_bps FROM split_rates WHERE account_id = ? "
        "AND effective_date <= ? ORDER BY effective_date DESC, id DESC "
        "LIMIT 1", (int(team_account_id), on_date)).fetchone()
    if row is None:
        return DEFAULT_SPLIT_BPS
    return int(row["va_split_bps"])


def rate_history(db, team_account_id):
    # type: (object, int) -> list
    """Every rate this team has set, newest first — so the page that
    changes it shows what it is changing FROM and when each one started
    biting."""
    return db.execute(
        "SELECT * FROM split_rates WHERE account_id = ? "
        "ORDER BY effective_date DESC, id DESC",
        (int(team_account_id),)).fetchall()


# ------------------------------------------------------------ the row

def _effective_date(row):
    """`date_run` once it has been run, `date_set` until then."""
    return row["date_run"] or row["date_set"]


def split_cents(db, row):
    # type: (object, object) -> Optional[int]
    """The setting side's share of this row's commission.

    None when there is no commission yet — NOT zero. "Nobody has closed
    this" and "this closed for nothing" are different facts and a report
    that renders both as $0.00 is lying about one of them.

    Rounded DOWN to the cent, and the agent side takes the remainder in
    `agent_cents`, so the two halves always add back to exactly the
    commission and no rounding penny is invented or lost.
    """
    if row["commission_cents"] is None:
        return None
    bps = split_bps_on(db, row["team_account_id"], _effective_date(row))
    return int(row["commission_cents"]) * bps // BPS


def agent_cents(db, row):
    # type: (object, object) -> Optional[int]
    """The closing side's share: the commission minus the split, so the
    rounding remainder lands here rather than vanishing."""
    if row["commission_cents"] is None:
        return None
    return int(row["commission_cents"]) - split_cents(db, row)


def record(db, lead_id, set_by_user_id, date_set=None, interaction_id=None,
           agent_user_id=None):
    # type: (object, int, Optional[int], Optional[str], Optional[int], Optional[int]) -> int
    """Track an appointment a VA has set.

    `state` and the two account ids are snapshotted FROM THE LEAD, because
    the setting side may not be able to read the lead row at all.
    """
    lead = db.execute("SELECT * FROM leads WHERE id = ?",
                      (int(lead_id),)).fetchone()
    if lead is None:
        raise AppointmentError("no such lead: %s" % lead_id)
    from leadflow.va_send import team_root
    team = team_root(db, lead["account_id"])
    ensure_default_rate(db, team)
    own = not db.in_transaction
    now = utcnow()
    cur = db.execute(
        "INSERT INTO appointment_tracker (account_id, team_account_id, "
        "lead_id, state, set_by_user_id, agent_user_id, date_set, outcome, "
        "interaction_id, created_at, updated_at) "
        "VALUES (?,?,?,?,?,?,?,'scheduled',?,?,?)",
        (lead["account_id"], team, int(lead_id), lead["state"],
         set_by_user_id, agent_user_id, date_set or _today(),
         interaction_id, now, now))
    if own:
        db.commit()
    logger.info("tracked appointment lead=%s team=%s", lead_id, team)
    return cur.lastrowid


def record_run(db, tracker_id, ran_by_user_id, outcome, date_run=None):
    # type: (object, int, Optional[int], str, Optional[str]) -> None
    """Who ran it, when, and what the appointment did."""
    if outcome not in OUTCOMES:
        raise AppointmentError("unknown appointment outcome %r" % (outcome,))
    own = not db.in_transaction
    db.execute(
        "UPDATE appointment_tracker SET ran_by_user_id = ?, date_run = ?, "
        "outcome = ?, updated_at = ? WHERE id = ?",
        (ran_by_user_id, date_run or _today(), outcome, utcnow(),
         int(tracker_id)))
    if own:
        db.commit()


def record_close(db, tracker_id, closed_by_user_id, outcome,
                 premium_cents=None, commission_cents=None):
    # type: (object, int, Optional[int], str, Optional[int], Optional[int]) -> None
    """WHOEVER CLOSES ENTERS THE COMMISSION. The app derives the rest.

    Only the commission is taken, never the split: the split is a
    function of the commission and the rate in force, and letting a
    closer type it directly would be a second, editable copy of a derived
    number — which is how the two sides end up disagreeing about what
    they are owed.
    """
    if outcome not in CLOSE_OUTCOMES:
        raise AppointmentError("unknown close outcome %r" % (outcome,))
    if outcome == "sold" and commission_cents is None:
        raise AppointmentError(
            "a sold appointment needs the commission — it is what the "
            "other side's share is derived from")
    if outcome == "not_sold":
        premium_cents = commission_cents = None
    own = not db.in_transaction
    db.execute(
        "UPDATE appointment_tracker SET outcome = ?, premium_cents = ?, "
        "commission_cents = ?, closed_by_user_id = ?, updated_at = ? "
        "WHERE id = ?",
        (outcome, premium_cents, commission_cents, closed_by_user_id,
         utcnow(), int(tracker_id)))
    if own:
        db.commit()


def mark_paid(db, tracker_id, by_user_id):
    # type: (object, int, Optional[int]) -> bool
    """Whoever closed marks it paid. Both sides then see it as paid.

    Refuses a row with no commission: "paid" on a row nobody has closed
    is a claim about money that does not exist yet.
    """
    row = db.execute("SELECT * FROM appointment_tracker WHERE id = ?",
                     (int(tracker_id),)).fetchone()
    if row is None:
        return False
    if row["commission_cents"] is None:
        raise AppointmentError(
            "nothing to pay: this appointment has no commission recorded")
    if row["paid_at"]:
        return False
    own = not db.in_transaction
    db.execute(
        "UPDATE appointment_tracker SET paid_at = ?, paid_by_user_id = ?, "
        "updated_at = ? WHERE id = ?",
        (utcnow(), by_user_id, utcnow(), int(tracker_id)))
    if own:
        db.commit()
    return True


# ------------------------------------------------------------ reading

def describe(db, row, usernames=None):
    # type: (object, object, Optional[dict]) -> dict
    """THE ONLY RENDERING OF A TRACKER ROW, and the reason rule 1 holds.

    Every surface — both calendars, the tracker list, anything B10 adds —
    goes through here. Nothing in the returned dict identifies the client:
    the lead is `lead_id` and a display reference, never a name, and the
    caller cannot accidentally add one because the caller never sees the
    lead row.
    """
    usernames = usernames or {}
    return {
        "id": row["id"],
        "lead_id": row["lead_id"],
        # A REFERENCE. Deliberately not a name, and deliberately the same
        # shape wherever it is shown.
        "lead_ref": "Lead #%s" % row["lead_id"],
        "state": row["state"] or "—",
        "agent": usernames.get(row["agent_user_id"], "—"),
        "va": usernames.get(row["set_by_user_id"], "—"),
        "ran_by": usernames.get(row["ran_by_user_id"], "—"),
        "date_set": row["date_set"],
        "date_run": row["date_run"],
        "outcome": row["outcome"],
        "outcome_label": OUTCOME_LABELS.get(row["outcome"], row["outcome"]),
        "premium_cents": row["premium_cents"],
        "commission_cents": row["commission_cents"],
        "split_cents": split_cents(db, row),
        "agent_cents": agent_cents(db, row),
        "split_bps": split_bps_on(db, row["team_account_id"],
                                  _effective_date(row)),
        "paid": bool(row["paid_at"]),
        "paid_at": row["paid_at"],
        "account_id": row["account_id"],
        "team_account_id": row["team_account_id"],
    }


def usernames_for(db, rows):
    # type: (object, list) -> dict
    """{user_id: username} for every person named across these rows, in
    ONE query. A per-row lookup is a query per person per row."""
    ids = set()
    for row in rows:
        for key in ("agent_user_id", "set_by_user_id", "ran_by_user_id",
                    "closed_by_user_id", "paid_by_user_id"):
            if row[key]:
                ids.add(row[key])
    if not ids:
        return {}
    marks = ",".join("?" * len(ids))
    return {r["id"]: r["username"] for r in db.execute(
        "SELECT id, username FROM users WHERE id IN (%s)" % marks,
        list(ids))}


def for_team(db, team_account_id, start=None, end=None):
    # type: (object, int, Optional[str], Optional[str]) -> list
    """THE TEAM CALENDAR — everything the team's VAs set.

    Scoped by `team_account_id`, which is the same edge `va_send` routes
    the queue by, so an FTA manager's team sees its own and only its own.
    Ordered by the date it was SET, because that is what this calendar is
    a calendar of.
    """
    sql = ("SELECT * FROM appointment_tracker WHERE team_account_id = ?")
    params = [int(team_account_id)]
    if start:
        sql += " AND date_set >= ?"
        params.append(start)
    if end:
        sql += " AND date_set <= ?"
        params.append(end)
    return db.execute(sql + " ORDER BY date_set DESC, id DESC",
                      params).fetchall()


def for_person(db, user_id, start=None, end=None):
    # type: (object, int, Optional[str], Optional[str]) -> list
    """THE PERSONAL CALENDAR — what this person RUNS.

    `ran_by_user_id`, not `set_by`: the two calendars answer different
    questions on purpose. "What did my team book" and "what am I sitting
    in" are different days.

    Rows not yet run are included when they were set by this person and
    nobody has run them, so a personal calendar is not empty until the
    first appointment is marked run.
    """
    sql = ("SELECT * FROM appointment_tracker WHERE (ran_by_user_id = ? "
           "OR (ran_by_user_id IS NULL AND agent_user_id = ?))")
    params = [int(user_id), int(user_id)]
    if start:
        sql += " AND COALESCE(date_run, date_set) >= ?"
        params.append(start)
    if end:
        sql += " AND COALESCE(date_run, date_set) <= ?"
        params.append(end)
    return db.execute(
        sql + " ORDER BY COALESCE(date_run, date_set) DESC, id DESC",
        params).fetchall()


def totals(db, rows):
    # type: (object, list) -> dict
    """Money across a set of rows, in cents. `split` and `agent` are
    derived per row and then summed — never the sum of the commissions
    times the current rate, which would silently re-price history."""
    out = {"appointments": len(rows), "sold": 0, "premium": 0,
           "commission": 0, "split": 0, "agent": 0, "paid": 0, "unpaid": 0}
    for row in rows:
        if row["outcome"] == "sold":
            out["sold"] += 1
        out["premium"] += row["premium_cents"] or 0
        out["commission"] += row["commission_cents"] or 0
        share = split_cents(db, row)
        if share is not None:
            out["split"] += share
            out["agent"] += agent_cents(db, row)
            if row["paid_at"]:
                out["paid"] += share
            else:
                out["unpaid"] += share
    return out
