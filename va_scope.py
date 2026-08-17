"""B7: what an assistant seat is allowed to be, and who may dial.

TWO KINDS OF ASSISTANT SEAT (`users.va_scope`):

  team      works the shared call queue for the team under account 1, and
            is the ONLY kind that may ever place a telephone call.
  personal  works only their own account's leads. Never dials.

A team manager (B3) can hire their own assistant, and that assistant is
a `personal` seat: they help their agent, they do not join Henry's calling
operation. **FTA personal VAs do not dial** — that is the whole reason the
distinction exists, and it is why `personal` is the DEFAULT. A seat that
appears without anybody choosing gets the fewer capabilities.

## THE DIAL GATE, in full

A call is permitted only when ALL of these hold:

  1. `users.role = 'va'`        — an assistant seat, never an admin, never
                                  the owner, never a superadmin
  2. `users.can_dial = 1`       — granted by the operator alone
                                  (`/superadmin/users/<id>/dial`)
  3. `users.va_scope = 'team'`  — a team seat, not a personal one
  4. the seat's ACCOUNT is on Henry's team — account 1 itself, or an
     account whose `upline_id` is 1

Rung 4 is B3's structure, not a new concept: `accounts.upline_id` already
names who manages whom, so "belongs to the team under account 1" is a
question the hierarchy can already answer and no second flag is invented
to answer it again. `team_account_id(db, account_id)` is the same walk
`va_send.team_root` does, and both are one edge deep on purpose.

EVERY RUNG FAILS CLOSED. A user row that predates the column, an
unreadable account, a `va_scope` value nothing recognises — all read as
"may not dial". The cost of failing closed is a call that does not happen;
the cost of failing open is a call that should not have.
"""
import logging

logger = logging.getLogger("leadflow.va_scope")

TEAM = "team"
PERSONAL = "personal"
VA_SCOPES = (TEAM, PERSONAL)

SCOPE_LABELS = {
    TEAM: "Team assistant (shared call queue)",
    PERSONAL: "Personal assistant (this account only)",
}

# The account whose team may dial. The install's own account — the one
# `/setup` bootstraps and the one B3 stamps `manager`. Named here rather
# than spelled `1` at each rung so there is one place to read it.
DIALING_TEAM_ACCOUNT_ID = 1


class ScopeError(ValueError):
    """A seat scope that would be invalid."""


def _field(row, name):
    """Read a column that may predate its migration. Missing reads as
    None, which every caller here treats as the closed answer."""
    try:
        return row[name]
    except (IndexError, KeyError, TypeError):
        return None


def scope(user):
    # type: (object) -> str
    """This seat's scope, FAILING CLOSED to `personal`.

    A row written before migration 33, or carrying a value nothing
    recognises, is a personal seat — the one that cannot dial.
    """
    if not user:
        return PERSONAL
    value = _field(user, "va_scope")
    return value if value in VA_SCOPES else PERSONAL


def is_team_seat(user):
    # type: (object) -> bool
    return scope(user) == TEAM


def team_account_id(db, account_id):
    # type: (object, int) -> int
    """The account at the top of this account's team. B3's edge, one deep.

    The same walk `va_send.team_root` does. Kept as its own name here
    because this module answers a permission question and that one answers
    a queue-routing question; sharing the sentence is fine, sharing the
    function would make one of them the other's caller for no reason.
    """
    try:
        from leadflow import team
        upline = team.upline_id(db, account_id)
    except Exception:
        logger.exception("could not resolve the team for account %s; "
                         "treating it as its own team", account_id)
        return int(account_id)
    return int(upline) if upline else int(account_id)


def on_dialing_team(db, account_id):
    # type: (object, int) -> bool
    """Is this account inside the team that is allowed to make calls.

    Account 1 itself, or an account B3 attached to it. Fails CLOSED on any
    read failure.
    """
    try:
        account_id = int(account_id)
    except (TypeError, ValueError):
        return False
    if account_id == DIALING_TEAM_ACCOUNT_ID:
        return True
    return team_account_id(db, account_id) == DIALING_TEAM_ACCOUNT_ID


def may_dial(db, user):
    # type: (object, object) -> bool
    """THE predicate. All four rungs, all failing closed.

    Every dial path asks this and nothing else, so there is one answer to
    "may this seat place a call" and no second copy to drift.
    """
    if not user:
        return False
    if _field(user, "role") != "va":
        return False
    if not _field(user, "can_dial"):
        return False
    if not is_team_seat(user):
        return False
    return on_dialing_team(db, _field(user, "account_id"))


def refusal_reason(db, user):
    # type: (object, object) -> str
    """WHY a seat may not dial — for the log, never for the caller.

    Ordered like `may_dial`, so the reason names the first rung that
    failed rather than the most interesting one.
    """
    if not user:
        return "no user"
    if _field(user, "role") != "va":
        return "not an assistant seat (role=%s)" % _field(user, "role")
    if not _field(user, "can_dial"):
        return "calling has not been granted to this seat"
    if not is_team_seat(user):
        return "a personal assistant seat never dials"
    return "this account is not on the calling team"


def set_scope(db, user_id, new_scope, by_user_id=None):
    # type: (object, int, str, object) -> str
    """Change a seat's scope. SUPERADMIN ONLY (routes_superadmin).

    Returns the previous scope. Refuses anything that is not an assistant
    seat: an admin with `va_scope = 'team'` would be a row whose value is
    read by nothing and believed by the next person to look.
    """
    if new_scope not in VA_SCOPES:
        raise ScopeError("unknown assistant scope %r" % (new_scope,))
    row = db.execute("SELECT * FROM users WHERE id = ?",
                     (int(user_id),)).fetchone()
    if row is None:
        raise ScopeError("no such user: %s" % user_id)
    if row["role"] != "va":
        raise ScopeError(
            "%s is a %s, not an assistant seat" % (row["username"],
                                                   row["role"]))
    previous = scope(row)
    if previous == new_scope:
        return previous
    own = not db.in_transaction
    db.execute("UPDATE users SET va_scope = ? WHERE id = ?",
               (new_scope, int(user_id)))
    # DEMOTING A SEAT TAKES ITS CALLING WITH IT. A personal seat that kept
    # `can_dial = 1` would be one `va_scope` edit away from dialling
    # again, and the operator who demoted them would reasonably believe
    # they had stopped.
    if new_scope == PERSONAL:
        db.execute("UPDATE users SET can_dial = 0 WHERE id = ?",
                   (int(user_id),))
    from leadflow.audit import log_event
    from leadflow.auth import account_scope
    with account_scope(row["account_id"]):
        log_event(db, None, "va_scope",
                  "%s: %s -> %s" % (row["username"], previous, new_scope),
                  user_id=by_user_id)
    if own:
        db.commit()
    logger.info("user %s va_scope %s -> %s", user_id, previous, new_scope)
    return previous
