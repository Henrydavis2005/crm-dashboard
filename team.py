"""B3: the team hierarchy — who manages whom, and what that lets them see.

AN EDGE, NOT A CONTAINER. `accounts.upline_id` names the account that
manages this one. Every agent keeps their own account, their own leads and
their own tenant scope; the edge grants their manager COUNTS and nothing
else. The alternative — a shared team account — would have merged two
agents' lead data into one tenant, and no later filter could unmerge it.

WHAT A MANAGER MAY SEE, exhaustively: for each agent directly under them,
that agent's account name and a set of integers. `breakdown` is the ONLY
function that answers the question and it returns no lead row, no email,
no phone, no client name and no pipeline detail — there is nothing in its
result to leak, which is a stronger guarantee than a caller remembering to
filter. `tests/test_team.py` walks the returned structure and fails on any
string that is not an account name.

A superadmin sees the same breakdown for every account. Reading one
individual record is a SEPARATE, audit-logged action
(`/superadmin/accounts/<id>/records/<lead_id>`), filed against the account
that was read, so the tenant's own audit trail shows the operator looked.

THREE SHAPES THAT MUST NOT EXIST, all refused by `set_upline`:
  - self-reference (an account managing itself)
  - a cycle (A → B → A, and any longer ring)
  - an upline that is not a manager
An account with no upline is NOT one of them — it is the normal state of
account 1 and of every account between signup and assignment.

WHY `manager` AND NOT THE CARRIER'S WORD. The role is an Ancora role: it
says which surfaces of THIS app an account can reach. It is not a rank in
anyone's upline, promoting somebody here promotes them nowhere else, and
demoting them here takes nothing away from them anywhere else. The two
concepts move independently and naming them alike would invite an operator
to keep them in sync.
"""
import datetime
import logging

from leadflow import pipeline
from leadflow.db import utcnow

logger = logging.getLogger("leadflow.team")

# The rolling window the activity counts use.
ACTIVITY_DAYS = 30

AGENT = "agent"
MANAGER = "manager"
TEAM_ROLES = (AGENT, MANAGER)

# What a manager is CALLED in front of a person. Never "FTA", never
# "upline" — those are the carrier's words for a different relationship.
ROLE_LABELS = {
    AGENT: "Agent",
    MANAGER: "Team manager",
}

# Depth beyond which `_walk_up` gives up and calls the chain circular. A
# real tree is two or three deep; anything past this is corrupt data, and
# looping forever on it would hang a request rather than refuse it.
MAX_DEPTH = 64


class TeamError(RuntimeError):
    """A hierarchy change that would make the tree invalid."""


def _row(db, account_id):
    return db.execute(
        "SELECT id, name, status, upline_id, team_role FROM accounts "
        "WHERE id = ?", (int(account_id),)).fetchone()


def role(db, account_id):
    # type: (object, int) -> str
    """This account's team role, FAILING CLOSED to `agent`.

    A missing row, a column that predates migration 30 or a value no
    longer in TEAM_ROLES all read as `agent` — the role that can see
    nobody else's numbers. Fail-closed here means an unreadable row grants
    no visibility, never accidental visibility.
    """
    try:
        row = _row(db, account_id)
    except Exception:
        logger.exception("could not read team_role for account %s; "
                         "treating it as an agent", account_id)
        return AGENT
    if row is None:
        return AGENT
    try:
        value = row["team_role"]
    except (IndexError, KeyError):
        return AGENT
    return value if value in TEAM_ROLES else AGENT


def is_manager(db, account_id):
    # type: (object, int) -> bool
    return role(db, account_id) == MANAGER


def upline_id(db, account_id):
    # type: (object, int) -> object
    """The account that manages this one, or None."""
    row = _row(db, account_id)
    if row is None:
        return None
    try:
        value = row["upline_id"]
    except (IndexError, KeyError):
        return None
    return int(value) if value else None


def downline_ids(db, account_id):
    # type: (object, int) -> list
    """Accounts DIRECTLY under this one, lowest id first.

    Direct reports only, deliberately. Every rule that uses this one —
    what a manager may see, whether an account may be deleted — is about
    the accounts attached to this node, and a transitive walk would let a
    manager two levels up read numbers for agents they were never given.
    """
    return [int(r["id"]) for r in db.execute(
        "SELECT id FROM accounts WHERE upline_id = ? ORDER BY id",
        (int(account_id),)).fetchall()]


def _walk_up(db, account_id):
    """Every ancestor of `account_id`, nearest first. Stops at MAX_DEPTH."""
    seen = []
    current = upline_id(db, account_id)
    while current is not None and len(seen) < MAX_DEPTH:
        if current in seen:
            break
        seen.append(current)
        current = upline_id(db, current)
    return seen


def set_team_role(db, account_id, new_role, by_user_id=None):
    # type: (object, int, str, object) -> str
    """Make an account a manager, or put it back to agent. SUPERADMIN ONLY.

    MOVES NOBODY. Promoting an account attaches no agents to it and
    demoting one detaches none — reassignment is its own action, because
    an operator fixing a role should never discover they have also
    rehomed somebody's book of business.

    Demotion is REFUSED while agents are still attached, for the same
    reason deletion is: an agent whose manager is no longer a manager is
    pointing at an upline that `set_upline` would not accept today, and
    the tree would be in a state the rules forbid.
    """
    if new_role not in TEAM_ROLES:
        raise TeamError("unknown team role %r" % (new_role,))
    row = _row(db, account_id)
    if row is None:
        raise TeamError("no such account: %s" % account_id)
    previous = role(db, account_id)
    if previous == new_role:
        return previous
    if new_role == AGENT:
        attached = downline_ids(db, account_id)
        if attached:
            raise TeamError(
                "account %d still manages %d account(s) (%s) — reassign "
                "them before changing the role"
                % (int(account_id), len(attached),
                   ", ".join(str(a) for a in attached)))
    own = not db.in_transaction
    db.execute("UPDATE accounts SET team_role = ? WHERE id = ?",
               (new_role, int(account_id)))
    _log(db, account_id, "team_role",
         "%s -> %s" % (previous, new_role), by_user_id)
    if own:
        db.commit()
    logger.info("account %s team_role %s -> %s", account_id, previous,
                new_role)
    return previous


def set_upline(db, account_id, new_upline_id, by_user_id=None):
    # type: (object, int, object, object) -> object
    """Attach an account to a manager, or detach it. SUPERADMIN ONLY.

    Returns the previous upline id (or None). Every refusal below is a
    shape the tree must not take; each one is its own message because
    "invalid" tells an operator nothing about which rule they hit.
    """
    account_id = int(account_id)
    row = _row(db, account_id)
    if row is None:
        raise TeamError("no such account: %s" % account_id)
    previous = upline_id(db, account_id)

    if new_upline_id in (None, "", 0, "0"):
        new_upline_id = None
    else:
        new_upline_id = int(new_upline_id)
        if new_upline_id == account_id:
            raise TeamError(
                "an account cannot manage itself (account %d)" % account_id)
        target = _row(db, new_upline_id)
        if target is None:
            raise TeamError("no such account: %s" % new_upline_id)
        if role(db, new_upline_id) != MANAGER:
            raise TeamError(
                "account %d is not a team manager, so it cannot be an "
                "upline" % new_upline_id)
        # The cycle test asks the question in the only direction that can
        # be wrong: is the account being attached ALREADY somewhere above
        # the proposed manager? If so, closing this edge would make a ring.
        if account_id in _walk_up(db, new_upline_id):
            raise TeamError(
                "account %d is already above account %d — that would make "
                "a circular team" % (account_id, new_upline_id))

    if previous == new_upline_id:
        return previous
    own = not db.in_transaction
    db.execute("UPDATE accounts SET upline_id = ? WHERE id = ?",
               (new_upline_id, account_id))
    _log(db, account_id, "team_upline",
         "%s -> %s" % (previous if previous else "none",
                       new_upline_id if new_upline_id else "none"),
         by_user_id)
    if own:
        db.commit()
    logger.info("account %s upline %s -> %s", account_id, previous,
                new_upline_id)
    return previous


def _log(db, account_id, etype, detail, by_user_id):
    """Audit the change against the account it is ABOUT, so a tenant's own
    trail shows who moved them — not only the operator's."""
    from leadflow.audit import log_event
    from leadflow.auth import account_scope
    with account_scope(int(account_id)):
        log_event(db, None, etype, detail, user_id=by_user_id)


# --- what a manager may see -------------------------------------------------

# Every key `_counts` produces. Named as data so the test that proves the
# breakdown carries no PII can assert on the SHAPE rather than on whatever
# a query happened to return that day.
COUNT_KEYS = ("leads", "active_leads", "sold", "appointments",
              "calls_30d", "emails_sent_30d", "suppressed")


def _window_start():
    """The ISO stamp ACTIVITY_DAYS ago, from the app's OWN clock.

    Not SQLite's `datetime('now', '-30 days')`, for two reasons: that
    function is blind to the test-clock harness, so a shifted-clock run
    would silently count against the real wall clock; and it formats a
    stamp with a space where `db.utcnow()` writes a 'T', which is a string
    comparison waiting to be subtly wrong on the boundary day.
    """
    try:
        now = datetime.datetime.fromisoformat(utcnow())
    except (TypeError, ValueError):  # pragma: no cover - utcnow is ISO
        now = datetime.datetime.now(datetime.timezone.utc)
    return (now - datetime.timedelta(days=ACTIVITY_DAYS)).isoformat(
        timespec="seconds")


def _counts(db, account_id):
    # type: (object, int) -> dict
    """Integers only. Every value here is a COUNT(*) — there is no branch
    of this function that can return a client's name, address, email,
    phone or lead id, which is what makes the manager view safe by
    construction rather than by review.

    A lead is 'sold' by `closed_state`, never by `pipeline_stage`: a sold
    lead sits on the `client` rung of the WORKING lane and 'sold' is not
    one of `pipeline.PIPELINE_STAGES` at all. Counting the stage would
    have reported zero sales forever.
    """
    account_id = int(account_id)
    since = _window_start()

    def scalar(sql, params=()):
        try:
            row = db.execute(sql, params).fetchone()
        except Exception:
            logger.exception("team count failed for account %s", account_id)
            return 0
        return int(row["c"] or 0) if row is not None else 0

    return {
        "leads": scalar(
            "SELECT COUNT(*) AS c FROM leads WHERE account_id = ?",
            (account_id,)),
        # B11: `dead` was the one closed rung, so excluding it was enough.
        # There are now six NEGATIVE stages, and naming any single one of
        # them here would have quietly counted the other five as active.
        # The predicate is the LIVE lanes — Cold and Working — read from
        # pipeline so a new stage lands on the right side by construction.
        "active_leads": scalar(
            "SELECT COUNT(*) AS c FROM leads WHERE account_id = ? "
            "AND COALESCE(closed_state,'') = '' "
            "AND COALESCE(pipeline_stage,'') IN (%s)"
            % ",".join("?" for _ in pipeline.LIVE_STAGES),
            (account_id,) + tuple(pipeline.LIVE_STAGES)),
        "sold": scalar(
            "SELECT COUNT(*) AS c FROM leads WHERE account_id = ? "
            "AND closed_state = 'sold'", (account_id,)),
        "appointments": scalar(
            "SELECT COUNT(*) AS c FROM interactions WHERE account_id = ? "
            "AND itype = 'appointment'", (account_id,)),
        "calls_30d": scalar(
            "SELECT COUNT(*) AS c FROM interactions WHERE account_id = ? "
            "AND itype = 'call' AND created_at >= ?", (account_id, since)),
        "emails_sent_30d": scalar(
            "SELECT COUNT(*) AS c FROM messages WHERE account_id = ? "
            "AND status = 'sent' AND sent_at >= ?", (account_id, since)),
        "suppressed": scalar(
            "SELECT COUNT(*) AS c FROM suppressions WHERE account_id = ?",
            (account_id,)),
    }


def breakdown(db, account_id):
    # type: (object, int) -> list
    """Per-agent named counts for one manager. THE only answer to "what
    does a manager see", and the ONE function both the /team page and
    Jarvis call — two callers of one query cannot drift apart, which is
    the whole reason Jarvis does not assemble its own.

    Returns [] for an account that manages nobody, including an agent: a
    caller that forgets to check `is_manager` gets an empty list, never
    somebody else's numbers.
    """
    if not is_manager(db, account_id):
        return []
    rows = []
    for agent_id in downline_ids(db, account_id):
        row = _row(db, agent_id)
        if row is None:
            continue
        entry = {"account_id": agent_id, "name": row["name"],
                 "status": row["status"], "team_role": role(db, agent_id)}
        entry.update(_counts(db, agent_id))
        rows.append(entry)
    return rows


def team_totals(rows):
    # type: (list) -> dict
    """Column totals for a breakdown. Pure arithmetic on integers."""
    return dict((key, sum(int(r.get(key) or 0) for r in rows))
                for key in COUNT_KEYS)


def all_accounts_breakdown(db):
    # type: (object) -> list
    """Every account, with its counts and its place in the tree. SUPERADMIN
    ONLY — the console's own view, which is the manager view plus the
    accounts nobody manages."""
    rows = []
    for row in db.execute(
            "SELECT id, name, status, upline_id, team_role FROM accounts "
            "ORDER BY id").fetchall():
        entry = {"account_id": int(row["id"]), "name": row["name"],
                 "status": row["status"],
                 "team_role": row["team_role"] if row["team_role"]
                 in TEAM_ROLES else AGENT,
                 "upline_id": int(row["upline_id"])
                 if row["upline_id"] else None}
        entry.update(_counts(db, int(row["id"])))
        rows.append(entry)
    return rows


def blocking_downline(db, account_id):
    # type: (object, int) -> list
    """Accounts that must be reassigned before this one may be deleted.

    Deleting a manager with agents still attached would leave every one of
    them pointing at an account that no longer exists — an upline the
    rules would refuse to create, arrived at by deletion instead. The
    agents are not touched and not cascaded: whose team they join is a
    decision, and `reset.delete_account` is not the place it gets made.
    """
    blocking = []
    for agent_id in downline_ids(db, account_id):
        row = _row(db, agent_id)
        blocking.append({"account_id": agent_id,
                         "name": row["name"] if row is not None else "?"})
    return blocking
