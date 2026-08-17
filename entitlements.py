"""The VA plan: two flags, and the AND of them.

TWO QUESTIONS, TWO FLAGS, ONE PREDICATE.

  accounts.va_eligible — MAY this account have VA at all? SUPERADMIN
      ONLY. There is no tenant form, no tenant route and no tenant-visible
      control that sets it. `set_eligible` is called from the superadmin
      console and from account approval, and from nowhere else.

  accounts.va_active — does the tenant WANT VA on right now? The tenant
      owns this one, and may only set it while eligible. Turning it off
      HIDES surfaces; it deletes nothing, so turning it back on returns
      the same queue rows, dispositions and pay records.

`va_access` is the ONLY predicate anything else calls. It reads one row
and ANDs both columns, so no caller can accidentally answer half the
question — which is what a second read path would eventually do.

WHERE IT IS ENFORCED: the request guard in leadflow/auth.py, against the
VA_GATED table there. That is the routing layer and it is the only place
a whole surface is refused. Background work (the worker, va.py's queue
build and script fill) has no routing layer, so it calls the same
predicate directly; that is one predicate in several callers, not several
checks.

FAIL CLOSED. A read error is "no access" for both flags. A tenant wrongly
shown a surface they have not bought is a worse failure than one briefly
missing a surface they have, and the missing one is visible and instantly
reversible.

ACCESS CODES ARE GONE (PART 13). Redemption was a TENANT route that set
the eligibility flag — exactly what "superadmin only" forbids — so
`redeem`, `grant`, code minting and code revocation were removed with it.
The `access_codes` and `access_code_redemptions` tables SURVIVE as
history, and `document_acceptances.access_code_id` keeps its column so
the shape of an acceptance record already written does not change. Both
are read-only now; nothing writes either again.
"""
import logging
from typing import Optional

from leadflow.db import utcnow

logger = logging.getLogger("leadflow.entitlements")


def _flags(db, account_id):
    # type: (object, int) -> dict
    """Both flags in one read. Any failure is (False, False)."""
    try:
        row = db.execute(
            "SELECT va_eligible, va_active FROM accounts WHERE id = ?",
            (account_id,)).fetchone()
    except Exception:
        logger.exception("could not read the VA plan flags for account %s; "
                         "treating as off", account_id)
        return {"eligible": False, "active": False}
    if row is None:
        return {"eligible": False, "active": False}
    return {"eligible": bool(row["va_eligible"]),
            "active": bool(row["va_active"])}


def is_eligible(db, account_id):
    # type: (object, int) -> bool
    """May this account have VA at all? Superadmin's answer."""
    return _flags(db, account_id)["eligible"]


def is_active(db, account_id):
    # type: (object, int) -> bool
    """Has the tenant switched VA on? Meaningless without eligibility —
    read `va_access` unless you specifically need to render the toggle."""
    return _flags(db, account_id)["active"]


def va_access(db, account_id):
    # type: (object, int) -> bool
    """THE VA predicate: eligible AND active. Everything else calls this."""
    flags = _flags(db, account_id)
    return flags["eligible"] and flags["active"]


def set_eligible(db, account_id, on, actor_user_id=None,
                 reason="superadmin"):
    # type: (object, int, bool, Optional[int], str) -> bool
    """Grant or revoke eligibility. SUPERADMIN ONLY — the caller enforces
    that; this function does not know who is asking.

    Returns True when the value CHANGED, so callers can tell "just
    granted" from "already had it" without a second read. Never commits;
    the caller owns the transaction.

    Revoking does NOT touch va_active. The tenant's own choice is theirs
    and survives, so restoring eligibility restores exactly the state they
    left — and while eligibility is off, `va_access` is False regardless,
    which is the whole point of the AND.
    """
    value = 1 if on else 0
    changed = db.execute(
        "UPDATE accounts SET va_eligible = ? WHERE id = ? AND "
        "va_eligible != ?", (value, account_id, value)).rowcount > 0
    if changed:
        logger.info("VA eligibility %s for account %s (%s) by user %s",
                    "granted" if on else "revoked", account_id, reason,
                    actor_user_id)
    return changed


def set_active(db, account_id, on):
    # type: (object, int, bool) -> bool
    """The TENANT's switch. Refuses to turn on while not eligible, so a
    forged POST cannot light up a surface the account was never granted —
    the routing layer would refuse the surface anyway, but a flag that
    reads True while access is denied is a flag that will be believed by
    the next person to read it.

    Returns True when the value CHANGED. Never commits.
    """
    if on and not is_eligible(db, account_id):
        logger.warning("refused to activate VA on account %s: not eligible",
                       account_id)
        return False
    value = 1 if on else 0
    return db.execute(
        "UPDATE accounts SET va_active = ? WHERE id = ? AND va_active != ?",
        (value, account_id, value)).rowcount > 0
