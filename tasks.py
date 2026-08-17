"""Owner task list (SPEC R7; R4's recovery outcomes also write these).

Thin helpers over the `tasks` table (kind needs_email|new_referral|
run_quotes|callback_review, status open|done). Open tasks render in the
dashboard "Needs attention" panel and on the admin /today view, each with a
"Mark done" button. run_quotes tasks (S4) additionally link to the Run
Quotes form and are closed automatically when the quote email sends — or by
close_run_quotes when a stop condition (suppression/sold/reply) ends the
lead's sequence. callback_review tasks (C1) are opened by the
callback_requested call disposition, keep the lead out of the VA queues
while open (va._EXCLUDE_SQL), and close either when the agent sets a
follow-up (close_callback_review) or by hand from the task row.

DISMISSING a callback_review task by hand — closing it WITHOUT setting a
follow-up — is the agent saying "nothing scheduled, work it": it opens a
`stale_engaged` recovery flag so the lead comes back on the next queue
build (SPEC C1/C2: "closing/dismissing the task without a follow-up
returns the lead to the queues"). Setting a follow-up instead claims and
protects the lead, and closes the task through close_callback_review,
which opens nothing.

Helpers never commit inside a caller's open transaction.
"""
import logging
from typing import Optional

from leadflow.audit import log_event
from leadflow.db import utcnow

logger = logging.getLogger("leadflow.tasks")

TASK_KINDS = ("needs_email", "new_referral", "run_quotes", "callback_review")


def create_task(db, kind, lead_id=None, body=None):
    # type: (object, str, Optional[int], Optional[str]) -> int
    """Insert an open tasks row. Returns the task id."""
    if kind not in TASK_KINDS:
        raise ValueError("unknown task kind: %s" % kind)
    from leadflow.auth import current_account_id  # deferred: avoid cycles
    account_id = None
    if lead_id is not None:
        lead = db.execute("SELECT account_id FROM leads WHERE id = ?",
                          (lead_id,)).fetchone()
        if lead is not None:
            account_id = lead["account_id"]
    if account_id is None:
        account_id = current_account_id()
    own = not db.in_transaction
    cur = db.execute(
        "INSERT INTO tasks (account_id, kind, lead_id, body, status, "
        "created_at) VALUES (?,?,?,?,'open',?)",
        (account_id, kind, lead_id, (body or "").strip() or None, utcnow()))
    if own:
        db.commit()
    logger.info("task created kind=%s lead=%s id=%s", kind, lead_id,
                cur.lastrowid)
    return cur.lastrowid


def complete_task(db, task_id, user_id=None):
    # type: (object, int, Optional[int]) -> bool
    """Mark an open task done (current account only, S1). Returns True
    when it was open.

    C1/C2: dismissing a `callback_review` task here means the agent decided
    NOT to schedule anything (setting a follow-up would have closed the task
    through close_callback_review instead), so the lead goes back to the VA
    side immediately — see `release_callback_lead`.

    A callback_review is a per-LEAD state, not a per-click one: the queue
    exclusion is a live `NOT EXISTS (open callback_review)` on the lead, so
    a duplicate row (a resubmitted disposition — back button, double-click,
    retry) would survive the dismissal and keep the lead out of every block
    while `release_callback_lead` had already spent its one recovery flag.
    Dismissing one therefore closes the lead's others, exactly as the
    follow-up path already does through `close_callback_review`."""
    from leadflow.auth import current_account_id  # deferred: avoid cycles
    own = not db.in_transaction
    cur = db.execute(
        "UPDATE tasks SET status = 'done', done_at = ? "
        "WHERE id = ? AND account_id = ? AND status = 'open'",
        (utcnow(), task_id, current_account_id()))
    done = cur.rowcount == 1
    if done:
        row = db.execute("SELECT lead_id, kind FROM tasks WHERE id = ?",
                         (task_id,)).fetchone()
        log_event(db, row["lead_id"] if row else None, "task_done",
                  "task %s marked done" % task_id, user_id=user_id)
        if row is not None and row["kind"] == "callback_review":
            close_callback_review(
                db, row["lead_id"],
                "duplicate review closed with task %s" % task_id)
            release_callback_lead(db, row["lead_id"],
                                  "callback review dismissed with no "
                                  "follow-up set")
    if own:
        db.commit()
    return done


def release_callback_lead(db, lead_id, reason):
    # type: (object, Optional[int], str) -> Optional[int]
    """C1/C2: hand a dismissed Callback Requested lead back to the queues.

    Closing the task alone is not enough in practice. `log_call` HALTS the
    sequence on `callback_requested` and recomputes the lead to stage
    `engaged` — which is recovery's territory, not the volume pool's — and
    it clears hot_since and resolves whatever recovery flag was open. So a
    lead whose task is simply closed matches no queue block at all until
    the stale_engaged clock fires ~5 days later. Opening the flag NOW is
    what actually makes SPEC C1/C2's "returns the lead to the queues" true
    on the next build.

    `stale_engaged` is the honest kind: the lead engaged (they asked for a
    callback) and then nothing was scheduled. It carries recovery's lowest
    urgency, so a dismissed callback never jumps ahead of a real ghost.
    Gated by `detection.open_recovery_flag`, so a lead that is claimed,
    closed, suppressed or already flagged is left exactly as it is.
    Returns the new flag id, or None when nothing was opened."""
    if lead_id is None:
        return None
    from leadflow.detection import open_recovery_flag  # deferred: cycles
    return open_recovery_flag(db, lead_id, "stale_engaged", reason)


def close_run_quotes(db, lead_id, reason):
    # type: (object, int, str) -> int
    """Close the lead's open run_quotes task(s) and cancel any 'surfaced'
    quote step rows (S4 stop conditions + completion).

    Called when the quote email actually sends, and when suppression /
    sold / a real inbound reply ends the sequence. A follow-up does NOT
    call this (spec: the admin decides). Idempotent no-op when there is
    nothing open. Returns the number of tasks closed."""
    own = not db.in_transaction
    cur = db.execute(
        "UPDATE tasks SET status = 'done', done_at = ? "
        "WHERE lead_id = ? AND kind = 'run_quotes' AND status = 'open'",
        (utcnow(), lead_id))
    closed = cur.rowcount
    cur = db.execute(
        "UPDATE messages SET status = 'canceled' "
        "WHERE lead_id = ? AND direction = 'out' AND status = 'surfaced'",
        (lead_id,))
    canceled = cur.rowcount
    if closed or canceled:
        log_event(db, lead_id, "run_quotes_closed",
                  "%s (tasks closed=%d, surfaced rows canceled=%d)"
                  % (reason, closed, canceled))
        logger.info("run_quotes closed lead=%s reason=%s tasks=%d rows=%d",
                    lead_id, reason, closed, canceled)
    if own:
        db.commit()
    return closed


def close_callback_review(db, lead_id, reason):
    # type: (object, int, str) -> int
    """C1: close the lead's open `callback_review` task(s).

    Called when the agent sets a follow-up — the decision the task was
    asking for. Closing the task (here or by hand from the task row)
    returns the lead to the VA queues naturally, because the exclusion is
    a live query for an OPEN task. Idempotent no-op when nothing is open.
    Never commits inside a caller's open transaction. Returns the number of
    tasks closed."""
    own = not db.in_transaction
    cur = db.execute(
        "UPDATE tasks SET status = 'done', done_at = ? "
        "WHERE lead_id = ? AND kind = 'callback_review' AND status = 'open'",
        (utcnow(), lead_id))
    closed = cur.rowcount
    if closed:
        log_event(db, lead_id, "callback_review_closed",
                  "%s (tasks closed=%d)" % (reason, closed))
        logger.info("callback_review closed lead=%s reason=%s tasks=%d",
                    lead_id, reason, closed)
    if own:
        db.commit()
    return closed


def open_tasks(db, limit=50):
    # type: (object, int) -> list
    """The current account's open tasks (newest first) joined to their
    lead names for rendering."""
    from leadflow.auth import current_account_id  # deferred: avoid cycles
    return db.execute(
        "SELECT t.*, l.first_name, l.last_name FROM tasks t "
        "LEFT JOIN leads l ON l.id = t.lead_id "
        "WHERE t.account_id = ? AND t.status = 'open' "
        "ORDER BY t.id DESC LIMIT ?",
        (current_account_id(), limit)).fetchall()
