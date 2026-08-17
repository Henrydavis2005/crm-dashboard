"""Event audit log.

`log_event` has always been the one writer. PART 12 Step 8 added the
CATEGORIES below and the /audit surface that reads them.

CATEGORIES group the free-form `etype` strings into the buckets somebody
reviewing this log actually thinks in. It is a VIEW over what is already
recorded, not a schema: an etype missing from every bucket still appears
in the log and is reachable through the etype filter, it just has no
grouping. A test fails if a category names an etype nothing ever writes,
so these cannot rot into a list of aspirations.
"""
import logging
from typing import Optional

from leadflow.db import utcnow

logger = logging.getLogger("leadflow.audit")

# The buckets the audit surface offers, and the etypes in each. Ordered
# for the filter dropdown, security-relevant first.
CATEGORIES = {
    "Sign-in": (
        "login", "login_failed", "logout", "login_locked",
        "mfa_verified", "mfa_failed",
    ),
    "Two-factor": (
        "mfa_enrolled", "mfa_disabled", "mfa_recovery_regenerated",
        # Spending a recovery code BYPASSES TOTP, so it is audited
        # separately from a normal mfa_verified. The row carries the
        # actor, their IP and how many codes remain — never the code
        # itself and never its hash.
        "mfa_recovery_used",
    ),
    # B3: the operator reading one of THIS tenant's records. Filed against
    # the account that was read, not the operator's, so it appears here —
    # in the tenant's own trail — which is the entire point of the route
    # being separate and audited rather than a loosened filter.
    "Operator access": (
        "superadmin_record_view",
    ),
    "Account status": (
        "account_signup", "account_status", "account_activated",
        "account_rejected",
        # B3 removed `account_suspended` with suspension itself. Nothing
        # writes it, and a category naming an etype nothing writes is what
        # tests/test_audit_surface.py exists to catch.
    ),
    "Team": (
        "team_role", "team_upline",
        # B7: an assistant seat's scope (team vs personal), and the SOFT
        # signals an assistant leaves on a lead. `va_update` is what the
        # "VA updates" feed on the lead page reads.
        "va_scope", "va_update",
    ),
    "Documents": (
        "documents_accepted",
    ),
    "Settings": (
        "settings_changed", "outreach_live", "outreach_paused",
        "lead_intake_enabled", "lead_intake_disabled", "password_changed",
        "va_toggled", "fta_toggled", "user_added", "user_toggled",
        # PART 13 dropped four access-code etypes from this bucket
        # (access_code_created / _revoked, va_access_granted,
        # va_access_code). The routes that wrote them are gone, and a
        # category naming an etype nothing writes is exactly what
        # tests/test_audit_surface.py exists to catch. Nothing was
        # orphaned: production had never written one.
        "user_fields", "gcal_connected",
        "gcal_disconnected", "cost_updated", "email_paused",
        "email_resumed",
    ),
    "Lead holds": (
        "halted", "unhalted", "suppressed", "unsuppressed",
        "suppressed_intake", "do_not_call", "compliance_override",
        "attempt_cap_blocked",
        # BLOCK 1 STEP C: `paused_manual_only` had exactly one writer,
        # the billing pause, and billing is gone. `manual_only_no_sequence`
        # stays because `outreach.scheduler` still refuses a lead carrying
        # the permanent mark, and any lead that carries one predates this
        # block.
        "manual_only_no_sequence",
    ),
}


def category_of(etype):
    # type: (str) -> Optional[str]
    """Which bucket an etype belongs to, or None when it belongs to none."""
    for name, kinds in CATEGORIES.items():
        if etype in kinds:
            return name
    return None


def _request_user_id():
    # type: () -> Optional[int]
    """The acting user's id inside a request context; None for the worker."""
    try:
        from flask import g, has_request_context
        if has_request_context():
            user = getattr(g, "user", None)
            if user:
                return user["id"]
    except Exception:  # pragma: no cover - flask always importable in app
        pass
    return None


def log_event(db, lead_id, etype, detail=None, user_id=None):
    # type: (object, Optional[int], str, Optional[str], Optional[int]) -> int
    """Insert an events row. Commits unless the caller already holds a
    transaction. user_id auto-fills from g.user inside a request context;
    worker actions record NULL. account_id (S1) comes from the lead when
    one is given, else the current request/worker account."""
    if user_id is None:
        user_id = _request_user_id()
    account_id = None
    if lead_id is not None:
        row = db.execute("SELECT account_id FROM leads WHERE id = ?",
                         (lead_id,)).fetchone()
        if row is not None:
            account_id = row["account_id"]
    if account_id is None:
        from leadflow.auth import current_account_id  # deferred: avoid cycle
        account_id = current_account_id()
    own = not db.in_transaction
    cur = db.execute(
        "INSERT INTO events (account_id, lead_id, user_id, etype, detail, "
        "created_at) VALUES (?,?,?,?,?,?)",
        (account_id, lead_id, user_id, etype, detail, utcnow()),
    )
    if own:
        db.commit()
    return cur.lastrowid
