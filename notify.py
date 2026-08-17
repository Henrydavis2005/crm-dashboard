"""Owner notifications: an in-app notifications row plus a plain email.

Every alert ALWAYS writes a notifications row (the in-app notification
center). It is then emailed to the `owner_email` setting (empty -> falls
back to gmail_address) from the primary sending mailbox. Owner mail is not
lead mail: no identity block, no unsubscribe footer, no compliance check,
no caps, no mirror interaction, and NOT gated by the outreach switch.

OWNER MAIL IS NOT PLATFORM MAIL EITHER. These alerts are the tenant's own
system telling them about their own leads, so they are sent from the
tenant's own mailbox to the tenant's own inbox and that is correct.
Vendor-to-customer mail — none today, see BLOCK 1 STEP C — comes
from the platform's mailbox instead, through
`leadflow/platform_email.py`; the two share `owner_address` below and
nothing else.

ntype 'system' honors system_alerts_enabled and a 6h-per-subtype rate
limit — both apply to the EMAIL only; the in-app row is always written.
The notifications.status column records the email outcome
(sent | failed | skipped). Never raises.
"""
import datetime
import logging
import smtplib
from email.message import EmailMessage
from email.utils import formatdate, make_msgid

from leadflow.db import utcnow
from leadflow.settings import get_setting
from leadflow.branding import PRODUCT_NAME

logger = logging.getLogger("leadflow.notify")

NTYPES = ("approval", "quote", "booking", "bounce_pause", "recovery",
          "referral", "task", "system")
SYSTEM_RATE_LIMIT_HOURS = 6

SMTP_HOST = "smtp.gmail.com"
SMTP_PORT = 587
SMTP_TIMEOUT = 30


def _rate_limited(db, subtype, account_id):
    # type: (object, object, int) -> bool
    """True if this ACCOUNT's system alert email with this subtype went out
    in the last 6h (S1: the rate limit is per tenant)."""
    cutoff = (
        datetime.datetime.now(datetime.timezone.utc)
        - datetime.timedelta(hours=SYSTEM_RATE_LIMIT_HOURS)
    ).isoformat(timespec="seconds")
    row = db.execute(
        "SELECT 1 FROM notifications WHERE account_id = ? AND "
        "ntype = 'system' AND subtype IS ? "
        "AND status = 'sent' AND created_at >= ? LIMIT 1",
        (account_id, subtype, cutoff),
    ).fetchone()
    return row is not None


def owner_address(db, account_id=None):
    # type: (object, object) -> str
    """Where mail to a tenant goes: owner_email, defaulting to
    gmail_address.

    PUBLIC because `leadflow/platform_email.py` reads it too. The sender
    moved out to the platform mailbox; the ADDRESSEE did not move, and one
    definition is what keeps that true.
    """
    owner = (get_setting("owner_email", db=db,
                         account_id=account_id) or "").strip()
    if owner:
        return owner
    return (get_setting("gmail_address", db=db,
                        account_id=account_id) or "").strip()


def _sender_mailbox(db, account_id=None):
    """The primary sending mailbox (send_channels), else the Gmail settings
    mailbox. Returns dict(address, app_password) or None."""
    try:
        from leadflow.outreach.caps import mailbox_dict, primary_channel
        ch = primary_channel(db, "email", account_id=account_id)
        if ch is not None:
            mb = mailbox_dict(db, ch, account_id=account_id)
            if mb and mb.get("address") and mb.get("app_password"):
                return mb
    except Exception:
        logger.exception("could not resolve the primary mailbox for notify")
    address = (get_setting("gmail_address", db=db,
                           account_id=account_id) or "").strip()
    password = get_setting("gmail_app_password", db=db,
                           account_id=account_id)
    if address and password:
        return {"address": address, "app_password": password}
    return None


def _lead_name(db, lead_id):
    if not lead_id:
        return None
    row = db.execute(
        "SELECT first_name, last_name FROM leads WHERE id = ?", (lead_id,)
    ).fetchone()
    if row is None:
        return None
    name = ((row["first_name"] or "") + " " + (row["last_name"] or "")).strip()
    return name or None


def _send_owner_email(db, subject, body, account_id=None):
    # type: (object, str, str, object) -> tuple
    """Plain owner email from the primary mailbox. Returns (status, detail)."""
    owner = owner_address(db, account_id=account_id)
    mailbox = _sender_mailbox(db, account_id=account_id)
    if not owner or not mailbox:
        return ("failed", "owner email or sending mailbox not configured")
    msg = EmailMessage()
    msg["From"] = mailbox["address"]
    msg["To"] = owner
    msg["Subject"] = subject
    msg["Message-ID"] = make_msgid()
    msg["Date"] = formatdate(usegmt=True)
    msg.set_content(body)
    try:
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=SMTP_TIMEOUT) as smtp:
            smtp.ehlo()
            smtp.starttls()
            smtp.ehlo()
            smtp.login(mailbox["address"], mailbox["app_password"])
            smtp.send_message(msg)
    except Exception as exc:
        return ("failed", str(exc))
    return ("sent", owner)


def notify(db, ntype, body, subtype=None, lead_id=None):
    # type: (object, str, str, object, object) -> bool
    """Record an in-app notification and email it to the owner.

    - ALWAYS inserts a notifications row (in-app center), whatever happens
      to the email.
    - ntype 'system' honors system_alerts_enabled + the 6h/subtype rate
      limit for the EMAIL only.
    - Approval/quote/referral alert emails append the /approvals review
      link (referral asks are approved from /approvals too, R7).
    - Never raises; returns True only when the email was sent.
    """
    # S1: the notification belongs to the lead's account when a lead is
    # given, else the current request/worker account. Settings reads below
    # resolve through the same account context (the worker wraps each
    # tenant's jobs in account_scope).
    from leadflow.auth import current_account_id
    account_id = None
    if lead_id is not None:
        lead_row = db.execute("SELECT account_id FROM leads WHERE id = ?",
                              (lead_id,)).fetchone()
        if lead_row is not None:
            account_id = lead_row["account_id"]
    if account_id is None:
        account_id = current_account_id()

    email_status = "skipped"
    try:
        send_email_alert = True
        if ntype == "system":
            if not get_setting("system_alerts_enabled", db=db,
                               account_id=account_id):
                logger.info("system alert emails disabled; in-app only (%s)",
                            subtype)
                send_email_alert = False
            elif _rate_limited(db, subtype, account_id):
                logger.info("system alert email rate-limited: subtype=%s",
                            subtype)
                send_email_alert = False

        if send_email_alert:
            subject = "%s: %s" % (PRODUCT_NAME, ntype)
            name = _lead_name(db, lead_id)
            if name:
                subject += " — %s" % name
            email_body = body
            # referral asks are approved/sent from /approvals too (R7).
            # No public_base_url configured -> omit the link line entirely
            # (a bare "/approvals" is not a usable link in an email).
            if ntype in ("approval", "quote", "referral"):
                base = (get_setting("public_base_url", db=db,
                                    account_id=account_id) or "").rstrip("/")
                if base:
                    email_body += "\n\nReview and send: %s/approvals" % base
            email_status, detail = _send_owner_email(db, subject, email_body,
                                                     account_id=account_id)
            if email_status != "sent":
                logger.warning("notify email not sent (%s/%s): %s",
                               ntype, subtype, detail)
    except Exception:
        logger.exception("notify email failed (ntype=%s subtype=%s)",
                         ntype, subtype)
        email_status = "failed"

    try:
        own = not db.in_transaction
        db.execute(
            "INSERT INTO notifications (account_id, ntype, subtype, body, "
            "lead_id, status, created_at) VALUES (?,?,?,?,?,?,?)",
            (account_id, ntype, subtype, body, lead_id, email_status,
             utcnow()),
        )
        if own:
            db.commit()
    except Exception:
        logger.exception("notify row insert failed (ntype=%s subtype=%s)",
                         ntype, subtype)
        return False
    return email_status == "sent"
