"""B12: per-VA daily allocation — how many OWN and how many TEAM leads.

Config only. **Nothing here changes VA ownership**: a VA still belongs to
exactly one owning FTA (`users.account_id`), and nothing in B10's pay
model, `split_rates` scoping or statement recipients is touched. This
module answers one question — how many of each kind of lead this seat's
day should be built from — and `va.build_queue` reads the answer.

OWN vs TEAM is not a new concept and is not stored twice. It falls out of
`va_sends`, which has carried both columns since B6:

    own   — va_sends.account_id  = the VA's own account (their FTA sent it)
    team  — va_sends.team_account_id = the team root, account_id != theirs
             (another agent on the same team sent it)

NULL MEANS UNCONFIGURED, NEVER ZERO. Every seat is NULL after migration
38, and an unconfigured seat keeps precisely the behaviour it had: its
effective quota, filled own -> team -> overflow with no per-source cap.
Defaulting to a number would silently re-shape every existing tenant's
day on upgrade, and defaulting to zero would empty it.

WHO MAY EDIT. The VA's **upline FTA only**, plus superadmin. "Upline" is
an ACCOUNT relationship (`team.upline_id` / `team.downline_ids`), so the
predicate is: the actor's account is the VA's account, or the VA's
account is somewhere in the actor's downline. An FTA cannot set an
allocation for a VA outside their downline, and that is enforced here
rather than in the route — a second entry point would otherwise have to
remember the rule.
"""
import logging
from typing import Optional

from leadflow.audit import log_event
from leadflow.db import utcnow

logger = logging.getLogger("leadflow.allocation")

# A sanity ceiling, not a business rule. It exists so a typo cannot ask
# the build for a hundred thousand leads and spin; the real bound on a
# day is the supply and the seat's effective quota.
MAX_TARGET = 1000


class AllocationRefused(Exception):
    """The actor may not set this seat's allocation."""


def _field(row, name):
    try:
        return row[name]
    except (KeyError, IndexError, TypeError):
        return None


def targets(db, user_row):
    # type: (object, object) -> tuple
    """(own_target, team_target, configured).

    `configured` is False when BOTH are NULL, which is the state every
    seat is in until an FTA sets one. A seat with only one of the two set
    IS configured: the unset side reads as 0, because an FTA who set
    "20 own" and left team blank asked for twenty own leads and no team
    leads. That is the narrower reading and it is reversible by clearing
    both."""
    own = _field(user_row, "own_leads_target")
    team = _field(user_row, "team_leads_target")
    if own is None and team is None:
        return (None, None, False)
    return (int(own or 0), int(team or 0), True)


def _va_account_id(db, user_id):
    row = db.execute("SELECT account_id, role FROM users WHERE id = ?",
                     (int(user_id),)).fetchone()
    return row


def may_edit(db, actor, target_user_id):
    # type: (object, object, int) -> bool
    """May `actor` set this VA's allocation?

    Superadmin: any seat. Otherwise the actor's account must BE the VA's
    account or be above it — `team.downline_ids` walks the account tree,
    so a two-level agency works without this function knowing the depth.
    """
    if actor is None:
        return False
    target = _va_account_id(db, target_user_id)
    if target is None:
        return False
    if _field(actor, "is_superadmin"):
        return True
    actor_account = _field(actor, "account_id")
    if actor_account is None:
        return False
    actor_account = int(actor_account)
    target_account = int(target["account_id"])
    if actor_account == target_account:
        return True
    from leadflow import team
    return target_account in set(int(a) for a in
                                 team.downline_ids(db, actor_account))


def _clean(value, label):
    if value is None or value == "":
        return None
    try:
        n = int(value)
    except (TypeError, ValueError):
        raise ValueError("%s must be a whole number" % label)
    if n < 0:
        raise ValueError("%s cannot be negative" % label)
    if n > MAX_TARGET:
        raise ValueError("%s cannot be more than %d" % (label, MAX_TARGET))
    return n


def set_targets(db, user_id, own, team, actor=None, by_user_id=None):
    # type: (object, int, object, object, object, Optional[int]) -> tuple
    """Set a seat's allocation. Raises AllocationRefused / ValueError.

    Passing None for either clears it. Clearing BOTH returns the seat to
    unconfigured, which is a real state and not the same as (0, 0):
    unconfigured means "build this seat's day the way you did before",
    (0, 0) means "build it from overflow only"."""
    user_id = int(user_id)
    if actor is not None and not may_edit(db, actor, user_id):
        raise AllocationRefused(
            "that assistant is not in your downline")
    own_n = _clean(own, "Own leads")
    team_n = _clean(team, "Team leads")
    own_write = not db.in_transaction
    db.execute(
        "UPDATE users SET own_leads_target = ?, team_leads_target = ? "
        "WHERE id = ?", (own_n, team_n, user_id))
    log_event(db, None, "va_allocation_set",
              "seat %d allocation own=%s team=%s"
              % (user_id, "unset" if own_n is None else own_n,
                 "unset" if team_n is None else team_n),
              user_id=by_user_id)
    if own_write:
        db.commit()
    logger.info("allocation user=%s own=%s team=%s at %s",
                user_id, own_n, team_n, utcnow())
    return (own_n, team_n)


def for_account(db, account_id):
    # type: (object, int) -> list
    """Every enabled VA seat of an account with its allocation, in a
    stable order. The build and the settings screen read the SAME list, so
    what an FTA sees is what the queue was built from."""
    rows = db.execute(
        "SELECT * FROM users WHERE account_id = ? AND role = 'va' "
        "AND enabled = 1 ORDER BY id", (int(account_id),)).fetchall()
    out = []
    for r in rows:
        own, team, configured = targets(db, r)
        out.append({
            "user_id": r["id"],
            "username": r["username"],
            "own_leads_target": own,
            "team_leads_target": team,
            "configured": configured,
        })
    return out
