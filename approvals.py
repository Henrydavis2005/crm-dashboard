"""Approval flow: human-approved reply drafts, sent from the web UI only.

Since R1 there is no SMS code redemption: a draft becomes an approvals row
(code written NULL — the column is legacy), the owner is notified in-app +
by email, and the draft is approved/edited/revoked at /approvals.

Cross-package imports (leadflow.gmail, leadflow.outreach) are deferred
inside functions so this module loads independently and tests can
monkeypatch.
"""
import datetime
import importlib
import logging

from leadflow.audit import log_event
from leadflow.db import utcnow
from leadflow.settings import get_setting
from leadflow.suppression import is_suppressed

logger = logging.getLogger("leadflow.approvals")

EXPIRY_HOURS = 24


def _lead_row(db, lead):
    if isinstance(lead, int):
        return db.execute("SELECT * FROM leads WHERE id = ?", (lead,)).fetchone()
    return lead


def _compliance_matches(db, text, account_id=None):
    # type: (object, str, object) -> list
    """Blocklist pre-check via outreach.compliance; empty list if unavailable."""
    try:
        compliance = importlib.import_module("leadflow.outreach.compliance")
        return list(compliance.check_text(db, text, account_id=account_id)
                    or [])
    except Exception as exc:
        logger.debug("compliance pre-check unavailable (%s); skipping", exc)
        return []


def _warning_text(matches):
    if not matches:
        return None
    return "Blocked phrases: " + ", ".join(str(m) for m in matches)


def _insert_approval(db, lead_id, message_id, warning, account_id):
    """Insert an approvals row (code stays NULL — legacy column)."""
    now = datetime.datetime.now(datetime.timezone.utc)
    expires_at = (now + datetime.timedelta(hours=EXPIRY_HOURS)).isoformat(
        timespec="seconds")
    created_at = now.isoformat(timespec="seconds")
    cur = db.execute(
        "INSERT INTO approvals (account_id, lead_id, message_id, code, "
        "status, compliance_warning, created_at, expires_at) "
        "VALUES (?,?,?,NULL,'pending',?,?,?)",
        (account_id, lead_id, message_id, warning, created_at, expires_at),
    )
    return cur.lastrowid


def _lead_display_name(lead):
    name = ((lead["first_name"] or "") + " " + (lead["last_name"] or "")).strip()
    return name or lead["email"] or lead["phone"] or ("lead #%s" % lead["id"])


def _source_name(db, lead):
    if lead["source_id"] is None:
        return "unknown source"
    row = db.execute(
        "SELECT name FROM lead_sources WHERE id = ? AND account_id = ?",
        (lead["source_id"], lead["account_id"])).fetchone()
    return row["name"] if row is not None else "unknown source"


def _last_inbound_body(db, lead_id):
    row = db.execute(
        "SELECT body FROM messages WHERE lead_id = ? AND direction = 'in' "
        "ORDER BY id DESC LIMIT 1",
        (lead_id,),
    ).fetchone()
    return (row["body"] or "") if row is not None else ""


def create_draft_and_notify(db, lead, channel, body, quote=False, kind=None,
                            subject=None):
    # type: (object, object, str, str, bool, object, object) -> int
    """Store a draft + approval row, then alert the owner (in-app + email).

    kind='referral' (R7 referral asks) stores the messages row with kind
    'referral', sets an optional subject on the draft, and notifies with
    ntype 'referral' instead of approval/quote. Returns the approval id.
    """
    lead = _lead_row(db, lead)
    if lead is None:
        raise ValueError("create_draft_and_notify: unknown lead")

    matches = _compliance_matches(db, body, account_id=lead["account_id"])
    warning = _warning_text(matches)
    is_referral = kind == "referral"
    msg_kind = kind or ("holding" if quote else "reply")

    own = not db.in_transaction
    cur = db.execute(
        "INSERT INTO messages (account_id, lead_id, direction, channel, "
        "kind, subject, body, status, created_at) "
        "VALUES (?,?,?,?,?,?,?,'draft',?)",
        (lead["account_id"], lead["id"], "out", channel, msg_kind, subject,
         body, utcnow()),
    )
    message_id = cur.lastrowid
    approval_id = _insert_approval(db, lead["id"], message_id, warning,
                                   lead["account_id"])
    if own:
        db.commit()

    lines = []
    if is_referral:
        lines.append("REFERRAL ASK ready for %s (%s)"
                     % (_lead_display_name(lead), _source_name(db, lead)))
    elif quote:
        lines.append("QUOTE REQUEST - %s (%s, %s)"
                     % (_lead_display_name(lead), _source_name(db, lead), channel))
    else:
        lines.append("Reply from %s (%s, %s)"
                     % (_lead_display_name(lead), _source_name(db, lead), channel))
    if not is_referral:
        their_message = _last_inbound_body(db, lead["id"])[:300]
        if their_message:
            lines.append("They said: \"%s\"" % their_message)
    lines.append("Draft: %s" % body)
    if warning:
        lines.append("COMPLIANCE WARNING: %s. Review in the app before sending."
                     % warning)
    notify_body = "\n".join(lines)

    ntype = "referral" if is_referral else ("quote" if quote else "approval")
    notify_mod = importlib.import_module("leadflow.notify")
    notify_mod.notify(db, ntype, notify_body, lead_id=lead["id"])

    log_event(db, lead["id"], "approval_created",
              "approval=%s channel=%s kind=%s" % (approval_id, channel,
                                                  msg_kind))
    return approval_id


def _mark_message(db, message_id, status, external_id=None, error=None):
    own = not db.in_transaction
    if status == "sent":
        db.execute(
            "UPDATE messages SET status='sent', sent_at=?, external_id=?, "
            "error=NULL WHERE id=?",
            (utcnow(), external_id, message_id),
        )
    else:
        db.execute(
            "UPDATE messages SET status=?, error=? WHERE id=?",
            (status, error, message_id),
        )
    if own:
        db.commit()


def _resolve_approval(db, approval_id, status, via=None):
    own = not db.in_transaction
    db.execute(
        "UPDATE approvals SET status=?, approved_via=?, resolved_at=? WHERE id=?",
        (status, via, utcnow(), approval_id),
    )
    if own:
        db.commit()


def _claim_pending(db, approval_id):
    # type: (object, int) -> bool
    """Atomically flip a pending approval to approved (status-guarded UPDATE).

    Guards against the same approval being approved twice (double-clicked
    Approve buttons, two browser tabs): only one caller wins the
    pending->approved transition; the loser sees rowcount 0.
    """
    own = not db.in_transaction
    cur = db.execute(
        "UPDATE approvals SET status='approved', approved_via='web', "
        "resolved_at=? WHERE id=? AND status='pending'",
        (utcnow(), approval_id),
    )
    if own:
        db.commit()
    return cur.rowcount == 1


def _unclaim(db, approval_id):
    """Put a claimed-but-unsent approval back to pending (send failed)."""
    own = not db.in_transaction
    db.execute(
        "UPDATE approvals SET status='pending', approved_via=NULL, "
        "resolved_at=NULL WHERE id=? AND status='approved'",
        (approval_id,),
    )
    if own:
        db.commit()


def _send_draft(db, approval_row):
    # type: (object, object) -> tuple
    """Send an approved draft email. Replies bypass caps; email still
    requires identity + unsubscribe (enforced by smtp_send.send_email);
    suppression is always checked. Returns (ok, detail)."""
    if not get_setting("outreach_live", db=db,
                       account_id=approval_row["account_id"]):
        # OUTREACH switch: refuse to send. Callers _unclaim on failure, so
        # the approval stays pending and the draft stays a draft.
        log_event(db, approval_row["lead_id"], "send_blocked",
                  "approved draft: outreach paused (outreach_live off)")
        return (False, "outreach is paused — set Outreach to Live in "
                       "Settings → Mode to send.")

    message = db.execute(
        "SELECT * FROM messages WHERE id = ?", (approval_row["message_id"],)
    ).fetchone()
    lead = db.execute(
        "SELECT * FROM leads WHERE id = ?", (approval_row["lead_id"],)
    ).fetchone()
    if message is None or lead is None:
        return (False, "missing draft or lead row")

    if message["channel"] != "email":
        # Historical pre-R1 text drafts have no transport anymore.
        _mark_message(db, message["id"], "failed",
                      error="text drafts can no longer be sent (texting removed)")
        return (False, "text drafts can no longer be sent (texting removed)")

    if is_suppressed(db, email=lead["email"], phone=lead["phone"]):
        _mark_message(db, message["id"], "blocked", error="suppressed")
        log_event(db, lead["id"], "send_blocked", "approved draft: suppressed")
        return (False, "suppressed")

    try:
        smtp_send = importlib.import_module("leadflow.gmail.smtp_send")
    except Exception as exc:
        _mark_message(db, message["id"], "failed",
                      error="email module unavailable: %s" % exc)
        return (False, "email module unavailable")
    subject = message["subject"] or "Re: your health coverage inquiry"
    # send_email resolves the lead's pinned mailbox (else primary) and
    # records channel_id on the messages row itself.
    # PART 11: is_reply=True. An approved draft is a reply TO the lead —
    # an AI-drafted answer to something they wrote, or a referral ask to a
    # client already in conversation — so it does not carry the signature.
    # It sets no threading headers today (in_reply_to stays None), so
    # without this flag the header check alone would read it as a fresh
    # thread and sign it. This changes the SIGNATURE only; threading
    # behaviour is untouched.
    ok, detail = smtp_send.send_email(
        db, lead, subject, message["body"], kind=message["kind"],
        message_row_id=message["id"], is_reply=True,
    )

    if ok:
        log_event(db, lead["id"], "sent",
                  "approved email reply message_id=%s" % message["id"])
        # Mirror row + pipeline recompute (SPEC B4 choke point: approvals
        # send; idempotent — smtp_send already mirrored on success).
        # user_id auto-fills with the approving admin's id from g.user.
        interactions = importlib.import_module("leadflow.interactions")
        interactions.mirror_message(db, message["id"])
    else:
        log_event(db, lead["id"], "send_failed",
                  "approved email reply: %s" % detail)
    return (ok, detail)


def approve_web(db, approval_id, edited_body=None, override_compliance=False):
    # type: (object, int, object, bool) -> tuple
    """Approve (and send) from the web UI. Edit revokes + recreates the row.

    Returns (ok, detail).
    """
    from leadflow.auth import current_account_id  # deferred: avoid cycles
    row = db.execute(
        "SELECT * FROM approvals WHERE id = ? AND account_id = ?",
        (approval_id, current_account_id())).fetchone()
    if row is None:
        return (False, "approval not found")
    if row["status"] != "pending":
        return (False, "approval is %s" % row["status"])
    if row["expires_at"] <= utcnow():
        _resolve_approval(db, row["id"], "expired")
        return (False, "approval expired")

    if edited_body is not None and edited_body.strip():
        message = db.execute(
            "SELECT * FROM messages WHERE id = ?", (row["message_id"],)
        ).fetchone()
        if message is not None and edited_body != message["body"]:
            own = not db.in_transaction
            db.execute(
                "UPDATE messages SET body = ? WHERE id = ?",
                (edited_body, row["message_id"]),
            )
            if own:
                db.commit()
            _resolve_approval(db, row["id"], "revoked")
            warning = _warning_text(_compliance_matches(
                db, edited_body, account_id=row["account_id"]))
            new_id = _insert_approval(
                db, row["lead_id"], row["message_id"], warning,
                row["account_id"])
            # R7: a prompted referral ask follows its approval through the
            # revoke+recreate edit path (the ask tracks the live approval).
            db.execute(
                "UPDATE referral_asks SET approval_id = ? "
                "WHERE approval_id = ? AND status = 'prompted'",
                (new_id, row["id"]))
            if own:
                db.commit()
            log_event(db, row["lead_id"], "approval_edited",
                      "approval %s revoked; recreated as %s" % (row["id"], new_id))
            row = db.execute(
                "SELECT * FROM approvals WHERE id = ?", (new_id,)
            ).fetchone()

    if row["compliance_warning"] and not override_compliance:
        return (False, "compliance: %s" % row["compliance_warning"])

    if not _claim_pending(db, row["id"]):
        # Raced: another web click already took it.
        return (False, "approval already resolved")
    ok, detail = _send_draft(db, row)
    if ok:
        if override_compliance and row["compliance_warning"]:
            log_event(db, row["lead_id"], "compliance_override",
                      "approval %s sent with override" % row["id"])
        # R7: a sent referral-ask approval flips its ask prompted -> sent.
        own = not db.in_transaction
        cur = db.execute(
            "UPDATE referral_asks SET status = 'sent' "
            "WHERE approval_id = ? AND status = 'prompted'", (row["id"],))
        if cur.rowcount:
            log_event(db, row["lead_id"], "referral_ask_sent",
                      "referral ask sent (approval %s)" % row["id"])
        if own:
            db.commit()
    else:
        _unclaim(db, row["id"])
    return (ok, detail)


def revoke(db, approval_id):
    # type: (object, int) -> bool
    """Revoke a pending approval. Returns True if it was pending.

    R7: revoking a referral-ask approval dismisses its prompted ask —
    dismiss/revoke are the same outcome for the referral track."""
    from leadflow.auth import current_account_id  # deferred: avoid cycles
    row = db.execute(
        "SELECT * FROM approvals WHERE id = ? AND account_id = ? "
        "AND status = 'pending'",
        (approval_id, current_account_id()),
    ).fetchone()
    if row is None:
        return False
    _resolve_approval(db, approval_id, "revoked")
    own = not db.in_transaction
    cur = db.execute(
        "UPDATE referral_asks SET status = 'dismissed' "
        "WHERE approval_id = ? AND status = 'prompted'", (approval_id,))
    if cur.rowcount:
        log_event(db, row["lead_id"], "referral_ask_dismissed",
                  "referral ask dismissed (approval %s revoked)" % approval_id)
    if own:
        db.commit()
    return True


def expire_stale(db):
    # type: (object) -> int
    """Expire pending approvals past their expiry. Returns count expired."""
    own = not db.in_transaction
    cur = db.execute(
        "UPDATE approvals SET status = 'expired', resolved_at = ? "
        "WHERE status = 'pending' AND expires_at <= ?",
        (utcnow(), utcnow()),
    )
    if own:
        db.commit()
    if cur.rowcount:
        logger.info("expired %d stale approvals", cur.rowcount)
    return cur.rowcount


def pending_list(db):
    # type: (object) -> list
    """The current account's pending approvals joined with lead + draft."""
    from leadflow.auth import current_account_id  # deferred: avoid cycles
    rows = db.execute(
        "SELECT a.id, a.lead_id, a.message_id, a.status, "
        "a.compliance_warning, a.created_at, a.expires_at, "
        "l.first_name, l.last_name, l.email, l.phone, l.stage, "
        "m.channel, m.kind, m.subject, m.body AS draft_body "
        "FROM approvals a "
        "JOIN leads l ON l.id = a.lead_id "
        "JOIN messages m ON m.id = a.message_id "
        "WHERE a.account_id = ? AND a.status = 'pending' "
        "ORDER BY a.created_at", (current_account_id(),)
    ).fetchall()
    out = []
    for row in rows:
        item = dict(row)
        item["lead_name"] = ((row["first_name"] or "") + " "
                             + (row["last_name"] or "")).strip()
        item["their_message"] = _last_inbound_body(db, row["lead_id"])[:300]
        out.append(item)
    return out
