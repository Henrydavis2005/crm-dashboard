"""Email the PLATFORM sends to a tenant, from the PLATFORM's own mailbox.

THE DEFECT THIS EXISTS TO FIX. Trial warnings went out through
`notify._send_owner_email`, which sends from the TENANT's connected Gmail
and falls back to their `gmail_address` setting. That is the right sender
for an alert about their own leads — their system talking to them about
their own mailbox — and the wrong sender for everything in this file. A
tenant on day 7 of a trial usually has not connected Gmail yet, so the one
message telling them the account is about to pause was posted from a
mailbox that does not exist and failed. On the days it did work it was
worse: a billing notice appearing to come from the customer's own address.

ONE CONSTANT. `PLATFORM_SENDER` below is the address all of it comes from.
Moving to a real system sender — billing@ on a company domain, a
transactional provider — is a change to that line or to
LEADFLOW_PLATFORM_EMAIL in the environment. It is never a change to a
call site.

WHAT IS PLATFORM MAIL. Mail from the vendor to the customer about the
commercial relationship: the trial warnings that used it are gone with
billing (BLOCK 1 STEP C) and NOTHING CALLS `send` today, but whatever
vendor-to-customer mail follows
(pause confirmations, receipts, plan changes). What is NOT platform mail,
and deliberately still goes out from the tenant's own mailbox through
`leadflow/notify.py`: alerts about their own leads — a reply to approve, a
quote to send, a booking. Those are the tenant's system mailing the tenant
about the tenant's business, they are a self-send from an address they
control, and routing them through a vendor mailbox would make them look
like marketing and would put every one of them behind the credentials
below.

THERE IS NO FALLBACK TO THE TENANT'S MAILBOX, and that is the point. A
fallback means the sender depends on state nobody can see from the
outside, and a bill that arrives from the customer's own address is worse
than one that does not arrive: they cannot act on it and cannot reply to
it. When the platform mailbox cannot send, `send` returns a NAMED refusal
and the caller records it beside the warning. Nothing is rerouted.

CREDENTIALS THIS APP DOES NOT HAVE, stated rather than worked around.
Gmail SMTP authenticates the SENDING account; there is no way to post as
PLATFORM_SENDER without an app password for that mailbox, and none ships
with this code. Until LEADFLOW_PLATFORM_EMAIL_PASSWORD is set in the
environment, `send` refuses BEFORE it opens a socket and the refusal names
the missing variable. It does not attempt a login it knows will fail,
because "authentication failed" in a log is a different and much more
confusing problem than "nobody has set this up yet".
"""
import logging
import os
import smtplib
from email.message import EmailMessage
from email.utils import formataddr, formatdate, make_msgid

from leadflow.branding import PRODUCT_NAME

logger = logging.getLogger("leadflow.platform_email")

# THE CONSTANT. Every platform-generated email to a tenant comes from
# here. It is a personal Gmail address today because that is what exists;
# the seam is what makes replacing it a config change.
PLATFORM_SENDER = "henrydavisadvisor@gmail.com"

# Environment overrides. The LEADFLOW_ prefix is the same deliberate
# holdover as the rest of them (see leadflow/branding.py): a rebrand does
# not get to break a running deployment's environment.
SENDER_ENV = "LEADFLOW_PLATFORM_EMAIL"
PASSWORD_ENV = "LEADFLOW_PLATFORM_EMAIL_PASSWORD"

SMTP_HOST = "smtp.gmail.com"
SMTP_PORT = 587
SMTP_TIMEOUT = 30

# Outcomes. Four of them rather than ok/not-ok, because the whole reason
# this module exists is that a send failed for a reason nobody could read
# off the record afterwards. Each one names a different party's problem:
# UNCONFIGURED is the operator's, NO_RECIPIENT is the tenant's, FAILED is
# the network's.
SENT = "sent"
UNCONFIGURED = "unconfigured"
NO_RECIPIENT = "no_recipient"
FAILED = "failed"


def sender():
    # type: () -> str
    """The address platform mail comes from."""
    return (os.environ.get(SENDER_ENV) or PLATFORM_SENDER).strip()


def credential():
    # type: () -> str
    """The platform mailbox's app password, or "" when none is set.

    Read at call time, never at import: an operator who sets the variable
    and restarts the service gets a working mailbox without a deploy, and
    the test suite can prove both states in one process.
    """
    return (os.environ.get(PASSWORD_ENV) or "").strip()


def is_configured():
    # type: () -> bool
    return bool(sender() and credential())


def recipient(db, account_id):
    # type: (object, int) -> str
    """Where platform mail goes: `owner_email`, falling back to
    `gmail_address`. Unchanged from the owner-alert path — the sender is
    what moved, not the addressee."""
    from leadflow.notify import owner_address
    return owner_address(db, account_id=account_id)


def send(db, account_id, subject, body):
    # type: (object, int, str, str) -> tuple
    """Send one platform email to a tenant. Returns (status, detail).

    NEVER RAISES and never falls back to another mailbox. `status` is one
    of SENT / UNCONFIGURED / NO_RECIPIENT / FAILED and `detail` is written
    to be read months later by somebody asking why a tenant says they were
    never told.
    """
    from_addr = sender()
    password = credential()
    if not from_addr:
        return (UNCONFIGURED,
                "%s is set but empty, so there is no platform sender"
                % SENDER_ENV)
    if not password:
        # THE STATE THIS SHIPS IN. No socket is opened; see the module
        # docstring.
        return (UNCONFIGURED,
                "%s is not set, so the platform mailbox (%s) cannot "
                "authenticate and no platform email can be sent"
                % (PASSWORD_ENV, from_addr))

    to_addr = recipient(db, account_id)
    if not to_addr:
        return (NO_RECIPIENT,
                "account %s has no owner_email and no gmail_address"
                % account_id)

    msg = EmailMessage()
    msg["From"] = formataddr((PRODUCT_NAME, from_addr))
    msg["To"] = to_addr
    msg["Subject"] = subject or ""
    msg["Message-ID"] = make_msgid()
    msg["Date"] = formatdate(usegmt=True)
    msg.set_content(body or "")
    try:
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=SMTP_TIMEOUT) as smtp:
            smtp.ehlo()
            smtp.starttls()
            smtp.ehlo()
            smtp.login(from_addr, password)
            smtp.send_message(msg)
    except Exception as exc:
        logger.warning("platform email to account %s failed: %s",
                       account_id, exc)
        return (FAILED, str(exc))
    logger.info("platform email sent to account %s (%s)", account_id, to_addr)
    return (SENT, to_addr)
