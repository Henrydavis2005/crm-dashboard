"""Post-sale engine (SPEC R7): sale records + the referral-ask track.

- `mark_sold` creates (or edits — lead_id is UNIQUE, never duplicates) the
  lead's sales row (status 'pending', premium required), sets
  closed_state='sold', HALTS the automated sequence (shared halt helper,
  reason 'sold' — a client never keeps receiving sequence emails; Dead
  stays no-halt by locked decision), evicts today's pending VA-queue row,
  recomputes (stage -> client), clears the pending follow-up, runs the VA
  sold-credit and schedules the 3 referral asks.
- Sale status moves pending <-> approved <-> denied after the fact;
  commission is required to approve and is kept only while the sale is
  approved (NULL otherwise — "NULL until approved"). A denied sale keeps
  closed_state='sold' (stats count the denial; Reopen is manual and keeps
  the sales row).
- Referral asks: 3 per sale at sold_at + referral_ask_days offsets,
  idempotent (re-sold / reopen+resold keeps existing asks). The worker's
  daily pass (`prompt_due_asks`, live mode only) turns due pending asks
  into referral-kind approval drafts + a 'referral' notification — the
  admin sends from /approvals, NEVER auto-sent. Ask lifecycle: pending ->
  prompted -> sent (when the approval sends) | dismissed (Dismiss button /
  suppressed client auto-dismiss).

Helpers never commit inside a caller's open transaction (entry points do).
Cross-package imports are deferred inside the functions that use them.
"""
import datetime
import logging
from typing import Optional

from leadflow.audit import log_event
from leadflow.db import utcnow

logger = logging.getLogger("leadflow.sales")

SALE_STATUSES = ("pending", "approved", "denied")
DEFAULT_ASK_DAYS = [0, 14, 365]

_UNSET = object()


def parse_dollars(raw):
    # type: (object) -> int
    """Dollars from a form field -> cents (int). Raises ValueError on junk.

    Accepts '45.50', '$45.50', '1,200'. The caller enforces positivity
    rules (premium must be > 0; commission may be 0).
    """
    s = str(raw or "").strip().lstrip("$").replace(",", "")
    if not s:
        raise ValueError("enter a dollar amount")
    try:
        value = float(s)
    except ValueError:
        raise ValueError("not a dollar amount: %s" % raw)
    if value < 0:
        raise ValueError("dollar amount cannot be negative")
    return int(round(value * 100))


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


def _lead_or_raise(db, lead_id):
    lead = db.execute("SELECT * FROM leads WHERE id = ?",
                      (lead_id,)).fetchone()
    if lead is None:
        raise ValueError("unknown lead %s" % lead_id)
    return lead


def _halt(db, lead_id, reason):
    """Halt via outreach.scheduler (deferred import), inline fallback."""
    try:
        from leadflow.outreach.scheduler import halt_lead
    except ImportError:
        halt_lead = None
    if halt_lead is not None:
        halt_lead(db, lead_id, reason)
        return
    db.execute("UPDATE leads SET sequence_halted = 1 WHERE id = ?",
               (lead_id,))
    db.execute(
        "UPDATE messages SET status = 'canceled' "
        "WHERE lead_id = ? AND direction = 'out' AND status = 'pending'",
        (lead_id,))
    log_event(db, lead_id, "halted", "reason=%s" % reason)


def get_sale(db, lead_id):
    """The lead's sales row (lead_id is UNIQUE) or None."""
    return db.execute("SELECT * FROM sales WHERE lead_id = ?",
                      (lead_id,)).fetchone()


def _ask_days(db, account_id=None):
    """referral_ask_days setting as exactly 3 ints (defensive fallback)."""
    from leadflow.settings import get_setting
    try:
        days = [int(d) for d in (get_setting("referral_ask_days", db=db,
                                             account_id=account_id)
                                 or DEFAULT_ASK_DAYS)]
    except Exception:
        days = list(DEFAULT_ASK_DAYS)
    if len(days) != 3 or any(d < 0 for d in days):
        days = list(DEFAULT_ASK_DAYS)
    return days


# ---------------------------------------------------------------------------
# Sale record
# ---------------------------------------------------------------------------

def mark_sold(db, lead_id, premium_cents, user_id=None):
    # type: (object, int, int, Optional[int]) -> int
    """Mark a lead sold with its monthly premium (cents, required, > 0).

    First call creates the sales row (status 'pending', sold_at = now);
    a lead that already has a sales row takes the EDIT path (premium
    updated, status/sold_at kept — lead_id UNIQUE, never a duplicate).
    Also: closed_state='sold', pipeline recompute (-> client), follow-up
    cleared, VA sold-credit (idempotent) and the 3 referral asks
    (idempotent — existing asks are kept). Returns the sales row id.
    """
    if not premium_cents or premium_cents <= 0:
        raise ValueError("monthly premium must be a positive dollar amount")
    lead = _lead_or_raise(db, lead_id)
    now = utcnow()

    own = not db.in_transaction
    sale = get_sale(db, lead_id)
    if sale is None:
        cur = db.execute(
            "INSERT INTO sales (account_id, lead_id, premium_cents, status, "
            "sold_at, created_at, updated_at) VALUES (?,?,?,'pending',?,?,?)",
            (lead["account_id"], lead_id, premium_cents, now, now, now))
        sale_id = cur.lastrowid
        sold_at = now
        log_event(db, lead_id, "sold",
                  "marked sold; monthly premium $%.2f (pending approval)"
                  % (premium_cents / 100.0), user_id=user_id)
    else:
        sale_id = sale["id"]
        sold_at = sale["sold_at"] or now
        db.execute(
            "UPDATE sales SET premium_cents = ?, updated_at = ? WHERE id = ?",
            (premium_cents, now, sale_id))
        log_event(db, lead_id, "sale_edited",
                  "re-marked sold; monthly premium now $%.2f"
                  % (premium_cents / 100.0), user_id=user_id)

    db.execute("UPDATE leads SET closed_state = 'sold' WHERE id = ?",
               (lead_id,))

    # A sold lead is a client: stop the automated sequence NOW (cancel
    # pending sends + sequence_halted) via the shared halt helper — a
    # phone-in sale with no prior halt must not keep emailing the client.
    # Only SOLD halts: Dead's no-halt semantics are a locked decision, so
    # the dispatcher carries no closed_state filter.
    _halt(db, lead_id, "sold")

    # S4 stop condition: SOLD closes an open Run Quotes task (and cancels
    # the surfaced quote step row) — the client no longer needs quotes.
    from leadflow.tasks import close_run_quotes
    close_run_quotes(db, lead_id, "marked sold")

    # Mid-day queue eviction: a sold lead leaves today's pending VA queue.
    from leadflow.va import evict_pending
    evict_pending(db, lead_id, "marked sold")

    from leadflow.pipeline import recompute
    recompute(db, lead_id)

    from leadflow import interactions
    # R3: a sale supersedes the admin's pending follow-up.
    interactions.clear_followup(db, lead_id, user_id=user_id,
                                reason="marked sold")
    # B6: VA sold-bonus credit (idempotent; earliest qualifying logger).
    interactions.on_lead_sold(db, _lead_or_raise(db, lead_id))

    ensure_referral_asks(db, lead, sold_at)

    if own:
        db.commit()
    logger.info("lead=%s sold premium_cents=%s sale=%s",
                lead_id, premium_cents, sale_id)
    return sale_id


def set_sale_status(db, lead_id, status, commission_cents=None, user_id=None):
    # type: (object, int, str, Optional[int], Optional[int]) -> None
    """Move a sale pending <-> approved <-> denied (back and forth is fine).

    approved requires commission_cents (>= 0). Commission is kept only
    while the sale is approved: moving to pending/denied NULLs it (schema
    semantics — 'NULL until approved'); re-approving prompts it again.
    """
    if status not in SALE_STATUSES:
        raise ValueError("unknown sale status: %s" % status)
    sale = get_sale(db, lead_id)
    if sale is None:
        raise ValueError("no sale recorded for lead %s" % lead_id)
    now = utcnow()
    if status == "approved":
        if commission_cents is None or commission_cents < 0:
            raise ValueError("a commission amount is required to approve")
        resolved_at = now
    else:
        commission_cents = None
        resolved_at = now if status == "denied" else None

    own = not db.in_transaction
    db.execute(
        "UPDATE sales SET status = ?, commission_cents = ?, resolved_at = ?, "
        "updated_at = ? WHERE id = ?",
        (status, commission_cents, resolved_at, now, sale["id"]))
    detail = "sale %s" % status
    if status == "approved":
        detail += "; commission $%.2f" % (commission_cents / 100.0)
    log_event(db, lead_id, "sale_" + status, detail, user_id=user_id)
    if own:
        db.commit()


def update_sale(db, lead_id, premium_cents=_UNSET, commission_cents=_UNSET,
                note=_UNSET, user_id=None):
    """Edit sale fields after the fact. Commission edits apply only to an
    approved sale (ValueError otherwise). Unpassed fields are untouched."""
    sale = get_sale(db, lead_id)
    if sale is None:
        raise ValueError("no sale recorded for lead %s" % lead_id)
    sets, params, changes = [], [], []
    if premium_cents is not _UNSET:
        if not premium_cents or premium_cents <= 0:
            raise ValueError("monthly premium must be a positive dollar amount")
        sets.append("premium_cents = ?")
        params.append(premium_cents)
        changes.append("premium $%.2f" % (premium_cents / 100.0))
    if commission_cents is not _UNSET:
        if sale["status"] != "approved":
            raise ValueError("commission applies only to an approved sale")
        if commission_cents is None or commission_cents < 0:
            raise ValueError("commission cannot be negative")
        sets.append("commission_cents = ?")
        params.append(commission_cents)
        changes.append("commission $%.2f" % (commission_cents / 100.0))
    if note is not _UNSET:
        note = (note or "").strip() or None
        sets.append("note = ?")
        params.append(note)
        changes.append("note")
    if not sets:
        return
    sets.append("updated_at = ?")
    params.append(utcnow())
    params.append(sale["id"])
    own = not db.in_transaction
    db.execute("UPDATE sales SET %s WHERE id = ?" % ", ".join(sets), params)
    log_event(db, lead_id, "sale_edited", "edited: %s" % ", ".join(changes),
              user_id=user_id)
    if own:
        db.commit()


# ---------------------------------------------------------------------------
# Referral asks
# ---------------------------------------------------------------------------

def ensure_referral_asks(db, lead, sold_at):
    # type: (object, object, str) -> int
    """Schedule the 3 referral asks at sold_at + referral_ask_days offsets.

    Idempotent: a lead with ANY existing asks (whatever their status) keeps
    them — re-sold / reopen+resold never duplicates. Returns asks created.
    """
    lead_id = lead["id"]
    if db.execute("SELECT 1 FROM referral_asks WHERE lead_id = ? LIMIT 1",
                  (lead_id,)).fetchone() is not None:
        return 0
    sold_dt = _parse_iso(sold_at) or datetime.datetime.now(
        datetime.timezone.utc)
    now = utcnow()
    days = _ask_days(db, account_id=lead["account_id"])
    own = not db.in_transaction
    for ask_no, offset in enumerate(days, start=1):
        due = sold_dt + datetime.timedelta(days=offset)
        db.execute(
            "INSERT INTO referral_asks (account_id, lead_id, ask_no, due_at, "
            "status, created_at) VALUES (?,?,?,?,'pending',?)",
            (lead["account_id"], lead_id, ask_no,
             due.astimezone(datetime.timezone.utc).isoformat(
                 timespec="seconds"), now))
    log_event(db, lead_id, "referral_asks_scheduled",
              "3 referral asks at +%s days" % ",".join(str(d) for d in days))
    if own:
        db.commit()
    return len(days)


def asks_for_lead(db, lead_id):
    return db.execute(
        "SELECT * FROM referral_asks WHERE lead_id = ? ORDER BY ask_no, id",
        (lead_id,)).fetchall()


def _dismiss_ask_row(db, ask, reason):
    db.execute(
        "UPDATE referral_asks SET status = 'dismissed' "
        "WHERE id = ? AND status IN ('pending','prompted')", (ask["id"],))
    log_event(db, ask["lead_id"], "referral_ask_dismissed",
              "ask %d dismissed: %s" % (ask["ask_no"], reason))


def dismiss_ask(db, ask_id, reason="dismissed", user_id=None):
    # type: (object, int, str, Optional[int]) -> bool
    """Dismiss a pending/prompted ask (Dismiss button; current account
    only, S1). Revokes the linked pending approval when one exists.
    Returns True when dismissed."""
    from leadflow.auth import current_account_id  # deferred: avoid cycles
    ask = db.execute(
        "SELECT * FROM referral_asks WHERE id = ? AND account_id = ?",
        (ask_id, current_account_id())).fetchone()
    if ask is None or ask["status"] not in ("pending", "prompted"):
        return False
    own = not db.in_transaction
    if ask["approval_id"] is not None:
        from leadflow.approvals import revoke
        # revoke() also flips prompted asks tied to the approval; the direct
        # update below keeps pending (never-prompted) asks covered too.
        revoke(db, ask["approval_id"])
    _dismiss_ask_row(db, ask, reason)
    if own:
        db.commit()
    return True


def prompt_due_asks(db, now=None, account_id=None):
    # type: (object, object, Optional[int]) -> dict
    """The worker's daily referral pass (live mode only, PER TENANT since
    S1): each due pending ask becomes a referral-kind approval draft +
    notification (ntype 'referral', in-app + email per notify()) and moves
    to 'prompted' with its approval_id stored. A suppressed (or email-less)
    client is auto-dismissed instead. NEVER sends anything itself.

    Returns counters {'prompted': n, 'dismissed': n}.
    """
    from leadflow.auth import current_account_id  # deferred: avoid cycles
    if account_id is None:
        account_id = current_account_id()
    if now is None:
        now_iso = utcnow()
    else:
        now_iso = str(now)
    counters = {"prompted": 0, "dismissed": 0}
    rows = db.execute(
        "SELECT * FROM referral_asks WHERE account_id = ? "
        "AND status = 'pending' AND due_at <= ? ORDER BY due_at, id",
        (account_id, now_iso)).fetchall()
    if not rows:
        return counters

    tpl = db.execute(
        "SELECT * FROM templates WHERE account_id = ? "
        "AND slug = 'referral_ask'", (account_id,)).fetchone()
    from leadflow.suppression import is_suppressed

    for ask in rows:
        lead = db.execute("SELECT * FROM leads WHERE id = ?",
                          (ask["lead_id"],)).fetchone()
        own = not db.in_transaction
        if lead is None:
            _dismiss_ask_row(db, ask, "lead missing")
            counters["dismissed"] += 1
            if own:
                db.commit()
            continue
        if is_suppressed(db, email=lead["email"], phone=lead["phone"],
                         account_id=account_id):
            _dismiss_ask_row(db, ask, "client suppressed")
            counters["dismissed"] += 1
            if own:
                db.commit()
            continue
        if not lead["email"]:
            _dismiss_ask_row(db, ask, "client has no email")
            counters["dismissed"] += 1
            if own:
                db.commit()
            continue

        from leadflow.gmail.smtp_send import render_tpl
        body = render_tpl(
            tpl["body"] if tpl is not None else
            "Hi {{first_name}}, would you pass my info along to anyone "
            "shopping for coverage? {{agent_name}}", lead)
        subject = render_tpl(tpl["subject"], lead) if (
            tpl is not None and tpl["subject"]) else None

        try:
            from leadflow.approvals import create_draft_and_notify
            approval_id = create_draft_and_notify(
                db, lead, "email", body, kind="referral", subject=subject)
        except Exception:
            logger.exception("referral ask %s: draft creation failed; "
                             "left pending for the next pass", ask["id"])
            continue
        db.execute(
            "UPDATE referral_asks SET status = 'prompted', approval_id = ? "
            "WHERE id = ? AND status = 'pending'", (approval_id, ask["id"]))
        log_event(db, lead["id"], "referral_ask_prompted",
                  "ask %d -> approval %s" % (ask["ask_no"], approval_id))
        db.commit()
        counters["prompted"] += 1

    if counters["prompted"] or counters["dismissed"]:
        logger.info("referral asks: %s", counters)
    return counters
