"""Autosaved partial forms.

A DRAFT IS NOT AN ACCEPTANCE, and the separation is structural rather
than a matter of care: drafts live in their own table with no
`document_type`, no signature column, no hash and no foreign key to
`document_acceptances`. Nothing joins the two. A half-filled form cannot
be read as a signed agreement by any query, including one written later
by somebody who has not read this file.

Drafts are DELETED the moment the real acceptance is written, inside the
same transaction, so a signed agreement never coexists with a scratch
copy of itself.

Scope is (account, user, form_key): the acceptance form is per account,
but two people on the same account typing into it should not overwrite
each other mid-sentence.
"""
import json
import logging

from leadflow.db import utcnow

logger = logging.getLogger("leadflow.drafts")

# Longest payload accepted. The forms this serves are a page of text
# fields; anything larger is a mistake or an attempt to use the table as
# storage, and either way it should not silently succeed.
MAX_BYTES = 64 * 1024

# Field names never written to a draft, whatever the form sends.
#
# A draft is a convenience; it is not worth keeping a password, a CSRF
# token or a signature in a second, mutable, deletable place. The typed
# SIGNATURE in particular is excluded on purpose — the only copy of it
# that should exist is the one inside the append-only acceptance row.
NEVER_SAVED = ("_csrf", "password", "confirm", "current_password",
               "new_password", "signature", "code", "access_code")


def _clean(payload):
    out = {}
    for key, value in (payload or {}).items():
        key = str(key)
        if key in NEVER_SAVED or not isinstance(value, (str, int, float)):
            continue
        out[key] = str(value)[:4000]
    return out


def save(db, account_id, user_id, form_key, payload):
    """Upsert the draft. Returns the number of fields kept."""
    fields = _clean(payload)
    blob = json.dumps(fields, sort_keys=True)
    if len(blob.encode("utf-8")) > MAX_BYTES:
        raise ValueError("draft too large")
    own = not db.in_transaction
    db.execute(
        "INSERT INTO form_drafts (account_id, user_id, form_key, payload, "
        "updated_at) VALUES (?,?,?,?,?) "
        "ON CONFLICT (account_id, user_id, form_key) DO UPDATE SET "
        "payload = excluded.payload, updated_at = excluded.updated_at",
        (account_id, user_id, form_key, blob, utcnow()))
    if own:
        db.commit()
    return len(fields)


def load(db, account_id, user_id, form_key):
    """The saved fields, or {}. Never raises on bad JSON — a corrupt
    draft should lose the convenience, not the page."""
    row = db.execute(
        "SELECT payload FROM form_drafts WHERE account_id = ? AND "
        "user_id = ? AND form_key = ?",
        (account_id, user_id, form_key)).fetchone()
    if row is None:
        return {}
    try:
        data = json.loads(row["payload"])
    except Exception:
        logger.exception("unreadable draft for account=%s form=%s",
                         account_id, form_key)
        return {}
    return data if isinstance(data, dict) else {}


def discard(db, account_id, user_id, form_key):
    """Delete the draft. Called inside the transaction that writes the
    real record, so the scratch copy cannot outlive it."""
    db.execute(
        "DELETE FROM form_drafts WHERE account_id = ? AND user_id = ? "
        "AND form_key = ?", (account_id, user_id, form_key))


def discard_all_for_form(db, account_id, form_key):
    """Every user's draft of one form on one account. The acceptance form
    is per ACCOUNT, so once anybody signs it nobody else's draft of it
    means anything."""
    db.execute(
        "DELETE FROM form_drafts WHERE account_id = ? AND form_key = ?",
        (account_id, form_key))
