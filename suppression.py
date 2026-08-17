"""Suppression list: never contact these emails/phones again.

DIALER BLOCK 2 — REVOCATION UNIFICATION. A suppression row covers a
person, not a channel: `suppress` fills BOTH `email` and `phone` from the
lead and `is_suppressed` checks both, so one row has always stopped email
and calls together. What was NOT unified is which suppressions are
PERMANENT.

`reversible` was a parameter every call site set by hand. Three of them
set 0 for a revocation and got it right; nothing made that a rule, so a
path added later could record `reason='do_not_call', reversible=1` and
the person who said "stop calling me" would sit behind an Undo button.
That is the gap a dialer makes live, and it is closed in three places at
once so no single one of them is the whole guarantee:

  1. HERE. `suppress` FORCES `reversible = 0` for any reason in
     REVOCATION_REASONS, whatever the caller passed. Irreversibility is a
     property of the reason now, not of the call site.
  2. `unsuppress` already refuses a row with `reversible = 0`, which is
     what makes both removal routes decline it. Unchanged — this is the
     path that made an email unsubscribe permanent, and a verbal
     do-not-call now reaches the same path rather than a parallel one.
  3. THE DATABASE. Migration 26 installs triggers that refuse to DELETE a
     revocation row and refuse to UPDATE one back to reversible, the same
     shape that protects `legal_documents` and `document_acceptances`.
     A compliance record that a bug can erase is not a record.

A revocation is not a soft close. `not_interested` — "not right now" —
stays REVERSIBLE on purpose, in both the call and the email path: it is
the tenant's own commercial judgement, not an instruction from the
person, and merging the two would quietly make every polite brush-off
permanent.

B8 — GLOBAL REVOCATION. A revocation now covers the person on EVERY
account on this install, not just the one they happened to say it to.
The reasoning is the same one that made a suppression cover both channels
rather than the channel it arrived on: the unit is the PERSON. Somebody
who says "stop calling me" has not made a statement about one agency's
lead list; they have told the thing that is calling them to stop, and one
application placing the calls is what this is.

Three consequences, each deliberate:

  1. `is_suppressed` answers two scopes at once — global for revocations,
     per tenant for everything else. Its docstring says why the second
     half was NOT globalised.
  2. `revocation_for`, `is_revoked` and `revocation_index` LOST their
     `account_id` parameter rather than ignoring it. A scope argument on
     a global question can only mislead its caller.
  3. `revocation_note` is now read by agents who were not the ones told,
     so it carries the reason and the date and nothing else — never the
     free-text note, never which account holds the record.

D2's irreversibility extends with it: migration 34 adds `account_id` to
the columns its UPDATE trigger freezes on a revocation row. Under global
scope the account no longer decides who the row bites, but it is still
the record of who was told, and a compliance record a bug can rewrite is
not a record.

WHAT IS NOT DONE, ON PURPOSE: a revocation performs no cross-tenant
WRITES. It does not reach into another account to halt their lead, cancel
their pending sends or evict their queue rows. Every one of those paths
asks `is_suppressed` at the moment it acts — the dispatcher before a
send, `dialer.check` before a call, `va_send.check` before a queue row —
so the guarantee holds by refusal at the boundary rather than by one
tenant mutating another's data. Refusing is enforceable; a cascade of
cross-tenant writes is a second copy of the truth.
"""
import logging
from typing import Optional

from leadflow.audit import log_event
from leadflow.db import utcnow
from leadflow.phone import (
    digits as phone_digits, digits_sql as phone_digits_sql,
    normalize_phone,
)

logger = logging.getLogger("leadflow.suppression")

# The reasons that are an INSTRUCTION FROM THE PERSON to stop contacting
# them, in any channel. Each is permanent, and permanence is enforced from
# this tuple rather than from whatever each call site remembered to pass.
#
# `stop` is the SMS STOP keyword. Texting was removed in R1 and nothing
# writes it any more, but historical rows carry it and it means exactly
# what the other two mean, so it is listed rather than special-cased.
#
# NOT here, deliberately:
#   not_interested — a soft close the tenant may legitimately revisit.
#   hard_bounce    — a fact about a mailbox, not a request from a person.
#                    It is already written irreversibly by its own call
#                    sites (a dead address does not come back), but it is
#                    not a revocation and must not be reported as one:
#                    "they asked us to stop" and "their mail server said
#                    no" are different things to show a VA.
#   manual         — an operator's own housekeeping.
REVOCATION_REASONS = ("unsubscribe", "do_not_call", "stop")

# What a revoked person is shown as, per reason. The queue and the lead
# page print these, so a VA reads why rather than a database token.
REVOCATION_LABELS = {
    "unsubscribe": "Unsubscribed by email",
    "do_not_call": "Verbal do-not-call",
    "stop": "Replied STOP",
}


def is_revocation(reason):
    # type: (Optional[str]) -> bool
    """Is this reason an instruction from the person to stop?"""
    return (reason or "") in REVOCATION_REASONS


def _norm_email(email):
    # type: (Optional[str]) -> Optional[str]
    if not email:
        return None
    return str(email).strip().lower() or None


def _norm_phone(phone):
    # type: (Optional[str]) -> Optional[str]
    if not phone:
        return None
    return normalize_phone(phone)


def _revocation_marks():
    return ",".join("?" * len(REVOCATION_REASONS))


def is_suppressed(db, email=None, phone=None, account_id=None):
    # type: (object, Optional[str], Optional[str], Optional[int]) -> bool
    """True when THIS account may not contact this person.

    B8 — TWO SCOPES IN ONE ANSWER, and the distinction is the whole block.

      A REVOCATION IS GLOBAL. One person, one revocation, across every
      account on the install. Somebody who told one agent to stop did not
      tell that agent — they said stop, and this application is what does
      the contacting. `account_id` does not narrow this half.

      EVERYTHING ELSE STAYS PER TENANT. `not_interested` is the tenant's
      own commercial judgement ("not right now"), `manual` is their
      housekeeping, and `hard_bounce` is a fact one tenant's mail server
      observed. Making those global would mean agent A's polite brush-off
      silently stopping agent B from ever emailing a lead B paid for,
      with no record B can see and no way to ask why. That is a different
      product decision from the one this block asked for, so it is not
      taken here.

    `account_id=None` resolves to the current request/worker account, and
    still governs the per-tenant half only.
    """
    from leadflow.auth import current_account_id  # deferred: avoid cycles
    if account_id is None:
        account_id = current_account_id()
    email = _norm_email(email)
    phone = _norm_phone(phone)
    marks = _revocation_marks()
    # "mine, for any reason" OR "anybody's, if it is a revocation".
    scope = "(account_id = ? OR reason IN (%s))" % marks
    scope_params = [account_id] + list(REVOCATION_REASONS)
    if email:
        row = db.execute(
            "SELECT 1 FROM suppressions WHERE email = ? AND %s LIMIT 1"
            % scope, [email] + scope_params).fetchone()
        if row:
            return True
    if phone:
        # B6: matched on DIGITS. Revocation rows are append-only by
        # trigger (D2), so migration 32 could not rewrite them into the
        # new stored format — and a revocation that stopped matching
        # because the lead's column was reformatted would be this
        # application quietly emailing somebody who said no.
        row = db.execute(
            "SELECT 1 FROM suppressions WHERE %s = ? AND %s LIMIT 1"
            % (phone_digits_sql("phone"), scope),
            [phone_digits(phone)] + scope_params).fetchone()
        if row:
            return True
    return False


def revocation_for(db, email=None, phone=None):
    # type: (object, Optional[str], Optional[str]) -> object
    """The REVOCATION row covering this email or phone, anywhere. Or None.

    Distinct from `is_suppressed`, which answers a different and broader
    question. A lead can be suppressed because they said "not right now",
    because their mailbox bounced, or because an operator added them by
    hand — none of which is a revocation, and none of which should be
    shown to a VA as "this person asked us to stop". The dial path and
    the queue want THIS one.

    B8 REMOVED THE `account_id` PARAMETER RATHER THAN IGNORING IT. A
    revocation is global, so a scope argument here could only ever be a
    lie: the caller would pass it, read the signature, and believe the
    answer had been narrowed. Callers that used to pass the lead's
    account now pass nothing, which is the honest shape.

    Returns the OLDEST matching row, so the record shown is the moment
    they actually asked rather than whichever duplicate was written last —
    and, across accounts, the FIRST agent they said it to.
    """
    email = _norm_email(email)
    phone = _norm_phone(phone)
    if not email and not phone:
        return None
    params = []
    clauses = []
    if email:
        clauses.append("email = ?")
        params.append(email)
    if phone:
        # Same reason as `is_suppressed`: a revocation row is append-only,
        # so it keeps whatever spelling it was written with.
        clauses.append("%s = ?" % phone_digits_sql("phone"))
        params.append(phone_digits(phone))
    params.extend(REVOCATION_REASONS)
    return db.execute(
        "SELECT * FROM suppressions WHERE (%s) AND reason IN (%s) "
        "ORDER BY created_at, id LIMIT 1"
        % (" OR ".join(clauses), _revocation_marks()), params).fetchone()


def is_revoked(db, email=None, phone=None):
    # type: (object, Optional[str], Optional[str]) -> bool
    """Has this person told us to stop, in any channel, to anybody?

    THE predicate the dial path asks, and the one the dispatcher's
    suppression check already covers by being broader.
    """
    return revocation_for(db, email=email, phone=phone) is not None


def revocation_index(db):
    # type: (object) -> dict
    """{email-or-phone: revocation row} for the WHOLE INSTALL, in ONE query.

    A queue render asks this question once per row. Asking the database
    once per row instead is 125 queries to paint one page, so the whole
    list comes back together and the rows are matched in memory. Ordered
    oldest-first and inserted with `setdefault`, so a duplicate leaves the
    earliest record — the moment they actually asked — in place.

    B8: no longer per account, for the same reason `revocation_for` lost
    its parameter. The index a VA's queue is painted from must carry every
    revocation on the install or the queue would show a person as callable
    who is not.
    """
    index = {}
    for row in db.execute(
            "SELECT * FROM suppressions WHERE reason IN (%s) "
            "ORDER BY created_at, id" % _revocation_marks(),
            list(REVOCATION_REASONS)):
        for key in (_norm_email(row["email"]), _norm_phone(row["phone"])):
            if key:
                index.setdefault(key, row)
    return index


def revocation_in(index, email=None, phone=None):
    # type: (dict, Optional[str], Optional[str]) -> object
    """Look one person up in a `revocation_index`. Either identifier hits:
    a revocation covers the PERSON, not the channel it arrived on."""
    for key in (_norm_email(email), _norm_phone(phone)):
        if key and key in index:
            return index[key]
    return None


def revocation_note(row):
    # type: (object) -> Optional[str]
    """Why this person cannot be contacted, in words a VA can act on.

    B8 — REASON AND DATE, AND NOTHING ELSE. Under global revocation this
    string is routinely rendered to an agent who is NOT the one the person
    spoke to, so what it may carry is now a tenancy question and not a
    wording question:

      * the REASON, from the fixed three-value vocabulary above — never
        `row["note"]`, which is free text one tenant typed and could name
        a person, a competitor or a complaint;
      * the DATE they asked, which is the compliance fact;
      * NOT `row["account_id"]`, and nothing derived from it. That another
        agency on this install holds this person's record is not something
        this agent is entitled to learn from a lead page.
    """
    if row is None:
        return None
    label = REVOCATION_LABELS.get(row["reason"], "Revoked")
    return ("%s on %s — this person asked us to stop, so they cannot be "
            "called or emailed." % (label, str(row["created_at"])[:10]))


def suppress(db, lead_id=None, email=None, phone=None, reason="manual",
             reversible=0, note=None):
    # type: (object, Optional[int], Optional[str], Optional[str], str, int, Optional[str]) -> int
    """Add a suppression covering both channels; halt the lead if one matches.

    Fills email/phone from the lead when a lead_id is given; conversely finds
    the matching lead when only contact info is given. Sets the lead's stage to
    'suppressed', halts its sequence, and cancels its pending outbound sends.
    Returns the suppression row id.

    A REVOCATION REASON IS ALWAYS IRREVERSIBLE, whatever `reversible` the
    caller passed. Three call sites already passed 0 and were correct; the
    point of overriding rather than trusting them is the fourth one,
    written later by somebody who did not read this docstring.
    """
    from leadflow.auth import current_account_id  # deferred: avoid cycles
    email = _norm_email(email)
    phone = _norm_phone(phone)

    if is_revocation(reason) and reversible:
        logger.warning(
            "%s is a revocation and cannot be reversible; the caller asked "
            "for reversible=%r and is being overridden", reason, reversible)
        reversible = 0

    lead = None
    account_id = None
    if lead_id is not None:
        lead = db.execute("SELECT * FROM leads WHERE id = ?", (lead_id,)).fetchone()
        if lead is not None:
            account_id = lead["account_id"]
            email = email or _norm_email(lead["email"])
            phone = phone or _norm_phone(lead["phone"])
    else:
        # Contact-only suppression: match within the CURRENT account only
        # (S1 — never attach to or halt another tenant's lead).
        account_id = current_account_id()
        if email:
            lead = db.execute(
                "SELECT * FROM leads WHERE account_id = ? AND email = ? "
                "ORDER BY id DESC LIMIT 1", (account_id, email)).fetchone()
        if lead is None and phone:
            lead = db.execute(
                "SELECT * FROM leads WHERE account_id = ? AND phone = ? "
                "ORDER BY id DESC LIMIT 1", (account_id, phone)).fetchone()
        if lead is not None:
            lead_id = lead["id"]
            email = email or _norm_email(lead["email"])
            phone = phone or _norm_phone(lead["phone"])
    if account_id is None:
        account_id = current_account_id()

    own = not db.in_transaction
    cur = db.execute(
        "INSERT INTO suppressions (account_id, email, phone, lead_id, reason, "
        "reversible, note, created_at) VALUES (?,?,?,?,?,?,?,?)",
        (account_id, email, phone, lead_id, reason, 1 if reversible else 0,
         note, utcnow()),
    )
    suppression_id = cur.lastrowid

    if lead_id is not None:
        db.execute(
            "UPDATE leads SET stage = 'suppressed', sequence_halted = 1 WHERE id = ?",
            (lead_id,),
        )
        db.execute(
            "UPDATE messages SET status = 'canceled' "
            "WHERE lead_id = ? AND direction = 'out' AND status = 'pending'",
            (lead_id,),
        )
        # Mid-day queue eviction: a suppressed lead leaves today's pending
        # VA queue immediately (build-time exclusions only cover the next
        # build). Worked rows are untouched.
        from leadflow.va import evict_pending  # deferred: avoid cycles
        evict_pending(db, lead_id, "lead suppressed")
        # S4 stop condition: suppression closes an open Run Quotes task
        # (and cancels the surfaced quote step row).
        from leadflow.tasks import close_run_quotes  # deferred: avoid cycles
        close_run_quotes(db, lead_id, "lead suppressed")
    log_event(db, lead_id, "suppressed",
              "reason=%s email=%s phone=%s" % (reason, email or "-", phone or "-"))
    if lead_id is not None:
        from leadflow.pipeline import recompute  # deferred: avoid cycles
        recompute(db, lead_id)
    if own:
        db.commit()
    # The lead's email and phone used to go out at INFO, which put contact
    # details of real people into every log file, log shipper and terminal
    # scrollback this process ever writes to — for a record that already
    # exists, in full, in the suppressions table. What an operator reading
    # logs actually needs is that a suppression happened and which lead it
    # was; the identifiers are one query away for anyone entitled to them.
    logger.info("suppressed lead=%s reason=%s (contact details redacted)",
                lead_id, reason)
    logger.debug("suppressed lead=%s email=%s phone=%s reason=%s",
                 lead_id, email, phone, reason)
    return suppression_id


def unsuppress(db, suppression_id):
    # type: (object, int) -> bool
    """Delete a reversible suppression row (current account only, S1).
    Restores nothing else."""
    from leadflow.auth import current_account_id  # deferred: avoid cycles
    row = db.execute(
        "SELECT * FROM suppressions WHERE id = ? AND account_id = ?",
        (suppression_id, current_account_id())).fetchone()
    if row is None or not row["reversible"]:
        return False
    own = not db.in_transaction
    db.execute("DELETE FROM suppressions WHERE id = ?", (suppression_id,))
    log_event(db, row["lead_id"], "unsuppressed",
              "suppression_id=%s email=%s phone=%s"
              % (suppression_id, row["email"] or "-", row["phone"] or "-"))
    if row["lead_id"] is not None:
        from leadflow.pipeline import recompute  # deferred: avoid cycles
        recompute(db, row["lead_id"])
    if own:
        db.commit()
    return True
