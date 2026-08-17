"""Shared inbound decision matrix for classified lead replies.

`handle_classified_inbound(db, lead, message_row)` is called by the email
reply pipeline (leadflow.gmail.replies) after the inbound message row has
been stored. It is the single place that decides whether the sequence
halts: it classifies the message via the AI package first, and only a
non-AUTO_REPLY classification halts the sequence and changes the stage
(SPEC: AUTO_REPLY is logged only).

Cross-package imports (leadflow.ai, leadflow.approvals) are deferred so this
module loads independently and tests can monkeypatch.
"""
import importlib
import logging

from leadflow import notify as notify_mod
from leadflow.audit import log_event
from leadflow.db import utcnow
from leadflow.settings import get_setting
from leadflow.suppression import suppress
from leadflow.branding import PRODUCT_NAME

logger = logging.getLogger("leadflow.replies_common")

FALLBACK_REPLY_BODY = "Thanks for reaching out - I'll get back to you shortly."
HOLDING_LINE_BODY = (
    "Perfect - I'll pull your options together today and get back to you shortly."
)


def _render_tpl(text, lead):
    # type: (str, object) -> str
    """Minimal placeholder substitution (mirrors smtp_send.render_tpl).
    Settings resolve against the LEAD's account (S1)."""
    account_id = lead["account_id"]
    first = (lead["first_name"] or "").strip()
    last = (lead["last_name"] or "").strip()
    full = (first + " " + last).strip()
    subs = {
        "{{first_name}}": first,
        "{{last_name}}": last,
        "{{name}}": full,
        "{{state}}": lead["state"] or "",
        "{{booking_link}}": get_setting("booking_link",
                                        account_id=account_id) or "",
        "{{agent_name}}": get_setting("identity_name",
                                      account_id=account_id) or "",
    }
    out = str(text)
    for placeholder, value in subs.items():
        out = out.replace(placeholder, value)
    return out


def _template_body(db, slug, fallback, account_id):
    # type: (object, str, str, int) -> str
    row = db.execute(
        "SELECT body FROM templates WHERE account_id = ? AND slug = ?",
        (account_id, slug)).fetchone()
    return row["body"] if row is not None else fallback


def _set_stage(db, lead_id, stage):
    own = not db.in_transaction
    db.execute(
        "UPDATE leads SET stage = ? WHERE id = ? "
        "AND stage NOT IN ('booked','suppressed')",
        (stage, lead_id),
    )
    if own:
        db.commit()


def _halt_lead(db, lead_id, reason):
    """Halt via the shared outreach helper, with an inline fallback."""
    halt = None
    try:
        scheduler = importlib.import_module("leadflow.outreach.scheduler")
        halt = getattr(scheduler, "halt_lead", None)
    except ImportError:
        logger.debug("outreach.scheduler unavailable; using inline halt")
    if halt is not None:
        halt(db, lead_id, reason)
        return
    own = not db.in_transaction
    db.execute(
        "UPDATE leads SET sequence_halted = 1 WHERE id = ?", (lead_id,)
    )
    db.execute(
        "UPDATE messages SET status = 'canceled' "
        "WHERE lead_id = ? AND direction = 'out' AND status = 'pending'",
        (lead_id,),
    )
    log_event(db, lead_id, "halted", reason)
    if own:
        db.commit()


def _store_classification(db, message_id, classification, evidence, quote):
    own = not db.in_transaction
    db.execute(
        "UPDATE messages SET classification = ?, classification_evidence = ?, "
        "quote_request = ? WHERE id = ?",
        (classification, evidence, 1 if quote else 0, message_id),
    )
    if own:
        db.commit()


def handle_classified_inbound(db, lead, message_row):
    # type: (object, object, object) -> str
    """Classify an inbound lead message and act on it. Returns classification."""
    if isinstance(message_row, int):
        message_row = db.execute(
            "SELECT * FROM messages WHERE id = ?", (message_row,)
        ).fetchone()
    if isinstance(lead, int):
        lead = db.execute("SELECT * FROM leads WHERE id = ?", (lead,)).fetchone()
    if message_row is None or lead is None:
        logger.error("handle_classified_inbound: missing lead or message row")
        return "UNCLEAR"

    message_id = message_row["id"]
    body = message_row["body"] or ""
    channel = message_row["channel"]
    lead_id = lead["id"]

    # -- classify (deferred AI import; failure -> UNCLEAR + system alert) ---
    try:
        ai = importlib.import_module("leadflow.ai")
        result = ai.classify_message(db, lead, body, channel) or {}
        classification = result.get("classification") or "UNCLEAR"
        evidence = result.get("evidence") or ""
        quote = bool(result.get("quote_request"))
    except Exception as exc:
        logger.warning("AI classification failed for lead %s: %s", lead_id, exc)
        classification, evidence, quote = "UNCLEAR", "", False
        notify_mod.notify(
            db, "system",
            "%s: AI classification failed (%s). Treating the reply as "
            "UNCLEAR and drafting for approval." % (PRODUCT_NAME, exc),
            subtype="ai_classify_failed", lead_id=lead_id,
        )

    _store_classification(db, message_id, classification, evidence, quote)
    log_event(db, lead_id, "reply_classified",
              "%s quote_request=%s channel=%s" % (classification, quote, channel))
    # R3: INTERESTED classification and quote_request inbound are hot signals
    # — stamp/refresh leads.hot_since (drives ghost detection). AUTO_REPLY is
    # machine traffic and negatives suppress; neither stamps.
    if classification == "INTERESTED" or (
            quote and classification in ("INTERESTED", "UNCLEAR")):
        own = not db.in_transaction
        db.execute("UPDATE leads SET hot_since = ? WHERE id = ?",
                   (utcnow(), lead_id))
        if own:
            db.commit()
    # Pipeline recompute now that classification/quote_request are stored
    # (SPEC B4 trigger: inbound classification). Suppress branches below
    # recompute again via suppression.
    pipeline = importlib.import_module("leadflow.pipeline")
    pipeline.recompute(db, lead_id)

    if classification == "AUTO_REPLY":
        # SPEC: AUTO_REPLY does NOT halt the sequence — logged only.
        # No halt, no stage change, no draft; pending sends stay pending.
        log_event(db, lead_id, "auto_reply",
                  "auto-reply detected on %s; sequence not halted" % channel)
        return classification

    # A real (non-auto) inbound message: halt the sequence now and stage the
    # lead as replied (unless already booked/suppressed). The suppress/quote
    # branches below override the stage where the matrix says so.
    _halt_lead(db, lead_id, "inbound %s reply" % channel)
    _set_stage(db, lead_id, "replied")
    # S4 stop condition: a real reply also closes an open Run Quotes task
    # (the admin now answers the reply instead of running the sequence).
    from leadflow.tasks import close_run_quotes
    close_run_quotes(db, lead_id, "inbound %s reply" % channel)

    approvals = importlib.import_module("leadflow.approvals")

    # New inbound while an approval is pending -> revoke; we regenerate
    # below. Referral-ask drafts (message kind 'referral', R7) are NOT
    # conversation drafts: a new inbound never supersedes them — revoking
    # would terminally dismiss the linked ask (approvals.revoke flips a
    # prompted ask to 'dismissed'), so a client replying "thanks!" would
    # silently kill their referral ask.
    pending = db.execute(
        "SELECT a.id FROM approvals a "
        "JOIN messages m ON m.id = a.message_id "
        "WHERE a.lead_id = ? AND a.status = 'pending' "
        "AND m.kind != 'referral'",
        (lead_id,),
    ).fetchall()
    for row in pending:
        approvals.revoke(db, row["id"])
        log_event(db, lead_id, "approval_revoked",
                  "superseded by new inbound message")

    if classification == "NOT_INTERESTED":
        suppress(db, lead_id=lead_id, reason="not_interested", reversible=1,
                 note="classified NOT_INTERESTED: %s" % evidence[:200])
        return classification

    if classification == "UNSUBSCRIBE":
        suppress(db, lead_id=lead_id, reason="unsubscribe", reversible=0,
                 note="classified UNSUBSCRIBE: %s" % evidence[:200])
        return classification

    # INTERESTED / UNCLEAR from here on.
    if quote:
        holding = _render_tpl(
            _template_body(db, "holding_line", HOLDING_LINE_BODY,
                           lead["account_id"]), lead)
        _set_stage(db, lead_id, "quote")
        approvals.create_draft_and_notify(db, lead, channel, holding, quote=True)
        return classification

    try:
        ai = importlib.import_module("leadflow.ai")
        draft = ai.draft_reply(db, lead, channel)
        if not draft:
            raise ValueError("empty draft")
    except Exception as exc:
        logger.warning("AI draft failed for lead %s: %s", lead_id, exc)
        draft = _render_tpl(
            _template_body(db, "fallback_reply", FALLBACK_REPLY_BODY,
                           lead["account_id"]), lead)
        notify_mod.notify(
            db, "system",
            "%s: AI drafting failed (%s). Using the fallback reply "
            "template for the approval draft." % (PRODUCT_NAME, exc),
            subtype="ai_draft_failed", lead_id=lead_id,
        )
    approvals.create_draft_and_notify(db, lead, channel, draft)
    return classification
