"""The email signature: one definition, one validator, one attachment rule.

PART 11. This module replaced the old four-field identity block
(identity_name / identity_title / identity_npn / identity_address), whose
`_footer_plain` / `_footer_html` pair hard-coded the layout of the agent's
own sign-off. It is now free text the agent writes, stored in the
`email_signature` setting.

TWO FIELDS SURVIVED the identity block and are deliberately NOT folded in:

  identity_name — because it is not only an email field. It is the
      {{agent_name}} merge token in email templates and AI reply drafts,
      and the {agent_name} token in VA call scripts and appointment
      confirmation texts. Deleting it would have blanked four surfaces
      that have nothing to do with email.
  identity_npn  — because the signature is VALIDATED against it. A
      signature that does not contain the agent's own NPN is refused on
      save (`validate`), which is what makes the NPN requirement
      enforceable rather than advisory.

THE ATTACHMENT RULE (`attach_to`): an email that STARTS a thread carries
the signature; an email sent as a REPLY inside an existing thread does
not. See SPEC Part 11 for the per-path table.

THE UNSUBSCRIBE LINE IS NOT PART OF THIS. It renders on every outbound
email regardless, along with the List-Unsubscribe headers — stripping the
visible opt-out from replies would be a CAN-SPAM regression. `footer_*`
below take the signature and the unsubscribe URL separately for exactly
that reason: the signature is optional, the unsubscribe is not.
"""
import logging
from html import escape as html_escape

logger = logging.getLogger("leadflow.signature")

# Generous enough for a real sign-off with a disclaimer paragraph, small
# enough that a paste accident cannot put a document in an email footer.
MAX_LENGTH = 2000


def get(db=None, account_id=None):
    """The account's signature text, stripped of trailing whitespace."""
    from leadflow.settings import get_setting
    return str(get_setting("email_signature", db=db,
                           account_id=account_id) or "").strip()


def npn(db=None, account_id=None):
    """The account's stored NPN, stripped."""
    from leadflow.settings import get_setting
    return str(get_setting("identity_npn", db=db,
                           account_id=account_id) or "").strip()


def is_configured(db=None, account_id=None):
    """True when a non-blank signature exists.

    THE SEND GATE. Both the dispatcher's rung 5 and the transport's own
    backstop call this; an email is undeliverable while it is False. It is
    deliberately a whitespace-sensitive check — a signature of spaces and
    newlines is not a signature.
    """
    try:
        return bool(get(db=db, account_id=account_id))
    except Exception:
        # FAIL CLOSED, like every other switch in this app: a settings
        # read that raises must not become "no signature needed".
        logger.exception("could not read the email signature; treating the "
                         "account as unconfigured")
        return False


def validate(text, stored_npn):
    """Validate a signature about to be saved.

    Returns None when it is acceptable, else a human-readable refusal.
    The NPN rule is the point of this function: a health-insurance agent's
    sign-off has to carry their National Producer Number, and the only way
    to guarantee that is to refuse a signature that does not contain the
    NPN the account has on file.
    """
    text = str(text or "").strip()
    stored_npn = str(stored_npn or "").strip()
    if not text:
        return ("The email signature cannot be empty — outbound email is "
                "blocked until one is set.")
    if len(text) > MAX_LENGTH:
        return ("The email signature is %d characters; the limit is %d."
                % (len(text), MAX_LENGTH))
    if not stored_npn:
        return ("Set your NPN first — the signature is checked against it, "
                "so it cannot be validated while the NPN is blank.")
    if stored_npn not in text:
        return ("The signature must contain your NPN (%s). Every outbound "
                "email carries this signature, and a health-insurance "
                "agent's sign-off has to show their National Producer "
                "Number. Add it and save again." % stored_npn)
    return None


def attach_to(in_reply_to, is_reply=False):
    """THE RULE, in one place: does this email get the signature?

    in_reply_to — the parent Message-ID when the email threads onto an
        earlier send (the dispatcher's S4 threading), else None.
    is_reply    — an explicit override for paths that ARE replies to the
        lead but do not set threading headers today. Approved AI reply
        drafts and referral asks go out through `approvals.send_approved`
        with in_reply_to=None, so by headers alone they would look like
        fresh threads and would wrongly collect a signature. They pass
        is_reply=True. This does NOT change threading behaviour; it only
        decides the signature.
    """
    if is_reply:
        return False
    return not in_reply_to


def footer_plain(signature, unsub):
    """text/plain footer. `signature` may be empty (a reply) — the
    unsubscribe line renders either way."""
    signature = str(signature or "").strip()
    if signature:
        return "\n\n--\n%s\n\nUnsubscribe: %s" % (signature, unsub)
    return "\n\nUnsubscribe: %s" % unsub


def footer_html(signature, unsub):
    """text/html footer. Same contract as `footer_plain`. The signature is
    escaped and its newlines become <br> so what the agent typed in the
    textarea is what the lead sees."""
    signature = str(signature or "").strip()
    unsub_html = ('<p style="color:#666;font-size:12px;line-height:1.5">'
                  '<a href="%s">Unsubscribe</a></p>'
                  % html_escape(unsub, quote=True))
    if not signature:
        return unsub_html
    return (
        '<hr style="border:none;border-top:1px solid #ddd;margin:16px 0">'
        '<p style="color:#666;font-size:12px;line-height:1.5">%s</p>%s'
        % (html_escape(signature).replace("\n", "<br>"), unsub_html)
    )
