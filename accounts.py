"""Account lifecycle: the approval gate (PART 12 Step 5).

`accounts.status` means ONE thing now: where an account sits between
signing up and being allowed to operate. It used to mean "has the
attestation been signed", which is a different question and now lives with
the other documents in leadflow/acceptance.py — signed at signup, before
the account row is even usable.

    signup ──> pending ──approve(level)──> active
                  │
                  └──reject──> rejected

REJECTED IS TERMINAL FROM THE OUTSIDE. Logging in again does not put an
account back in the queue — `reject` is the only writer that produces it
and nothing in the login path ever moves a status. A superadmin can still
reactivate deliberately (Step 7); a rejected applicant cannot re-apply
their way past a decision.

B3 REMOVED SUSPENSION. There is no `suspended` status and no freeze: an
account is waiting, working, refused, or deleted. It was removed rather
than kept because nothing ever read the VALUE — every gate in the app
asks `status in USABLE`, an allowlist of one — so the state cost a
console control, a status page branch, an audit category and a test file
to express something `rejected` already expressed. Migration 30 moves any
row still carrying it to `pending`. `reset.delete_account` is what ends
an account now, and it takes a backup and an export first.

ONE WRITER. `_set_status` is the only function in the codebase that writes
`accounts.status`, and every transition goes through it: it validates the
target, stamps the decision, and writes the audit event. A test enforces
that no other module writes the column, because SQLite cannot express a
CHECK constraint added to an existing table without rebuilding it, and
rebuilding `accounts` — referenced by every tenant-scoped table — is a far
bigger risk than a guarded single writer.

THE ENTITLEMENT IS NOT A THIRD STATE. Approving picks one of two levels
and the level sets `accounts.va_eligible` — the ELIGIBILITY half of the
VA plan, and approval is one of exactly two callers allowed to write it
(the other is the superadmin console). It does NOT set `va_active`: what
the operator permits and what the tenant switches on are separate
questions, so a freshly approved multi-user account is eligible with VA
off until its owner turns it on. Both halves are still checked in the
SAME one place (the request guard, against auth.VA_GATED), through the
single `entitlements.va_access` predicate. See leadflow/entitlements.py.

  LEVEL_STANDARD    one user: the account holder, working their own leads
  LEVEL_MULTI_USER  unlimited users

Neither name says "VA" — that is an internal word for a product surface,
not something an applicant is told about their plan.

THE BILLING SEAM is the boundary between `approve` and `activate`.
`approve` records the decision and then calls `activate`. When tier
selection and payment land, `approve` stops calling `activate` and the
payment callback calls it instead; nothing else moves, and no caller of
either function has to change. No billing is built here.
"""
import logging
from typing import Optional

from leadflow.db import utcnow

logger = logging.getLogger("leadflow.accounts")

PENDING = "pending"
ACTIVE = "active"
REJECTED = "rejected"

STATUSES = (PENDING, ACTIVE, REJECTED)

# The ONLY status that may use the application. Everything else —
# pending, rejected, and any value a future migration adds — is refused at
# the routing layer and at the send boundary. Written as an allowlist on
# purpose: a new status must be deliberately let in, not accidentally
# inherit access by not being named in a blocklist. This allowlist is
# also why removing `suspended` removed no enforcement: no gate ever
# named the value, they all ask this question.
USABLE = (ACTIVE,)

LEVEL_STANDARD = "standard"
LEVEL_MULTI_USER = "multi_user"
LEVELS = (LEVEL_STANDARD, LEVEL_MULTI_USER)

# What each level grants. The value IS accounts.va_eligible.
LEVEL_ENTITLES = {LEVEL_STANDARD: 0, LEVEL_MULTI_USER: 1}

# Shown to the applicant. Deliberately free of the word "VA".
LEVEL_LABELS = {
    LEVEL_STANDARD: "Standard (single user)",
    LEVEL_MULTI_USER: "Multi-user (unlimited users)",
}

# Where a new-signup alert goes: the OPERATOR's notification inbox, not
# the new tenant's. Notifications are addressed to an ACCOUNT, and account
# 1 is the account /setup bootstraps — the one whose first user carries
# `users.is_superadmin`. It moved here from entitlements.py in PART 13:
# that module is now purely about the two VA plan flags, and routing an
# alert is not an entitlement question.
OWNER_ACCOUNT_ID = 1


class AccountStateError(RuntimeError):
    """An invalid status or entitlement level."""


def get(db, account_id):
    return db.execute("SELECT * FROM accounts WHERE id = ?",
                      (account_id,)).fetchone()


def status(db, account_id):
    # type: (object, int) -> str
    """The account's status, FAILING CLOSED.

    A missing row, an unreadable column or any other surprise reads as
    PENDING — i.e. cannot act. The old helper did the opposite (missing
    rows read as active, to protect the grandfathered first boot) and that
    is the wrong default now that this gate stands in front of sending.
    Account 1 is grandfathered by the MIGRATION stamping it active, which
    is a fact in the database rather than a hole in a guard.
    """
    try:
        row = get(db, account_id)
    except Exception:
        logger.exception("could not read status for account %s; treating "
                         "it as pending", account_id)
        return PENDING
    if row is None:
        return PENDING
    try:
        value = row["status"]
    except (IndexError, KeyError):
        return PENDING
    return value if value in STATUSES else PENDING


def is_active(db, account_id):
    # type: (object, int) -> bool
    """True when this account may use the app at all. THE question the
    routing layer and the send boundary both ask."""
    return status(db, account_id) in USABLE


def is_pending(db, account_id):
    return status(db, account_id) == PENDING


def _set_status(db, account_id, new_status, by_user_id=None, note=None,
                event=None):
    """THE only writer of accounts.status. Returns the previous status."""
    if new_status not in STATUSES:
        raise AccountStateError("unknown account status %r" % (new_status,))
    previous = status(db, account_id)
    own = not db.in_transaction
    db.execute(
        "UPDATE accounts SET status = ?, status_changed_at = ?, "
        "status_changed_by = ?, status_note = ? WHERE id = ?",
        (new_status, utcnow(), by_user_id, (note or "").strip() or None,
         account_id))
    from leadflow.audit import log_event
    from leadflow.auth import account_scope
    # Stamped with the account it is ABOUT, not whoever is logged in —
    # a superadmin approving from their own session would otherwise file
    # the decision on their own audit trail.
    with account_scope(account_id):
        log_event(db, None, event or "account_status",
                  "%s -> %s%s" % (previous, new_status,
                                  (": " + note) if note else ""),
                  user_id=by_user_id)
    if own:
        db.commit()
    logger.info("account %s status %s -> %s", account_id, previous,
                new_status)
    return previous


def activate(db, account_id, by_user_id=None, note=None):
    """Open the account for business.

    Kept separate from `approve` on purpose. `approve` is a decision about
    a NEW account and picks an entitlement level; this is the transition
    that makes an account usable, and the superadmin console calls it on
    its own to reverse a rejection it decides was wrong.
    """
    return _set_status(db, account_id, ACTIVE, by_user_id=by_user_id,
                       note=note, event="account_activated")


def approve(db, account_id, level, by_user_id=None, note=None):
    # type: (object, int, str, Optional[int], Optional[str]) -> str
    """Approve a pending account at one of the two entitlement levels.

    The level sets `accounts.va_eligible` and nothing else. It leaves
    `va_active` alone deliberately: approval says the account MAY have VA,
    not that it wants it on, and writing both here would take the switch
    out of the tenant's hands on day one.
    """
    if level not in LEVELS:
        raise AccountStateError("unknown entitlement level %r" % (level,))
    own = not db.in_transaction
    db.execute("UPDATE accounts SET va_eligible = ?, approved_at = ?, "
               "approved_by = ? WHERE id = ?",
               (LEVEL_ENTITLES[level], utcnow(), by_user_id, account_id))
    result = activate(db, account_id, by_user_id=by_user_id,
                      note=note or ("approved: %s" % LEVEL_LABELS[level]))
    if own and db.in_transaction:
        db.commit()
    return result


def reject(db, account_id, by_user_id=None, note=None):
    """Refuse an application. Terminal from the applicant's side."""
    return _set_status(db, account_id, REJECTED, by_user_id=by_user_id,
                       note=note, event="account_rejected")


def pending(db):
    """Accounts awaiting a decision, oldest first."""
    return db.execute(
        "SELECT * FROM accounts WHERE status = ? ORDER BY created_at, id",
        (PENDING,)).fetchall()


def notify_owner_of_signup(db, account_id, account_name, username):
    """Tell the owner a new account is waiting.

    Uses the app's EXISTING owner-alert mechanism — `leadflow.notify`, the
    in-app notifications inbox, reached through `gmail.replies.notify_safe`
    so a notification failure can never take down a signup. Scoped to the
    OWNER account: an alert about a stranger's application belongs in the
    owner's inbox, not in the applicant's.
    """
    from leadflow.auth import account_scope
    from leadflow.gmail import replies
    with account_scope(OWNER_ACCOUNT_ID):
        replies.notify_safe(
            db, "system",
            "New account awaiting approval: %s (admin %s). Approve or "
            "reject it from the accounts console."
            % (account_name, username),
            subtype="account_pending_approval")
