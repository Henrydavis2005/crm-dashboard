"""The legal document registry and its acceptance gate.

A PERMANENT LEGAL RECORD. Everything here is built so that what a tenant
saw, and what they signed, can be reconstructed years later from the
database alone.

THE TEXT IS STORED, NOT REFERENCED. `legal_documents.text` holds the full
rendered document, not a path. A file on disk can be edited, moved, or
lost with the repository; a row cannot. The sha256 of that text is stored
beside it and is what the acceptance record points at, so "which words
did they agree to" has one answer and it is a byte comparison.

IMMUTABILITY IS ENFORCED BY THE DATABASE. Migration 22 installs triggers
that refuse any UPDATE to slug, version, text, sha256 or published_at,
and refuse DELETE outright. `active` is deliberately left updatable —
publishing v2 has to be able to stand v1 down — and that is the ONLY
column that can move after publication. A CHECK constraint makes
active = 1 impossible while the text is empty, so an inactive placeholder
slot cannot be switched on by accident and start gating on nothing.

SUPERSEDING NEVER DESTROYS. Publishing a new version flips the old row's
`active` to 0 and nothing else. The old row keeps its text, its hash and
its published_at forever, because acceptance rows point at it and an
acceptance whose document has vanished is not a record of anything.

ACCEPTANCE IS PER ACCOUNT, one row per version accepted. Prior rows are
never rewritten, never migrated forward and never flagged superseded;
"has this account accepted what is published today" is answered by
looking for a row with today's version, which leaves every earlier row
exactly as it was written.
"""
import hashlib
import logging
from typing import Optional

from leadflow.db import utcnow

logger = logging.getLogger("leadflow.agreements")

# The slugs the registry knows. `csa` is the Cloud Service Agreement (the
# Cover Page followed by the Standard Terms, as one document). `dpa` is a
# SLOT: a row with no text and active = 0, so the shape exists without
# gating on an empty document.
SLUGS = ("csa", "dpa")

# The plans a tenant can be on. Recorded on the acceptance so the record
# says what was being bought, not just what was agreed. No enforcement
# lives here — this block records the plan, it does not police it.
PLANS = ("core", "va")


class NotPublished(LookupError):
    """No active version of that document."""


def sha256(text):
    # type: (str) -> str
    return hashlib.sha256((text or "").encode("utf-8")).hexdigest()


# ------------------------------------------------------------- publishing

def publish(db, slug, version, text, active=True):
    # type: (object, str, str, str, bool) -> int
    """Publish a version and stand down whatever it supersedes.

    The supersede is an UPDATE of `active` ALONE, which is the one column
    the immutability triggers allow to move. Both statements share one
    transaction, so there is never an instant with two active versions of
    a slug or none.
    """
    if slug not in SLUGS:
        raise ValueError("unknown document slug: %r" % (slug,))
    version = (version or "").strip()
    if not version:
        raise ValueError("a version string is required")
    text = text or ""
    if active and not text.strip():
        raise ValueError(
            "refusing to publish %s %s active with empty text — an active "
            "document with nothing in it would gate every account on a "
            "blank page" % (slug, version))
    own = not db.in_transaction
    if own:
        db.execute("BEGIN IMMEDIATE")
    try:
        if active:
            db.execute("UPDATE legal_documents SET active = 0 "
                       "WHERE slug = ? AND active = 1", (slug,))
        cur = db.execute(
            "INSERT INTO legal_documents (slug, version, text, sha256, "
            "active, published_at) VALUES (?,?,?,?,?,?)",
            (slug, version, text, sha256(text), 1 if active else 0,
             utcnow()))
        if own:
            db.commit()
    except Exception:
        if own:
            db.rollback()
        raise
    logger.info("published %s %s (active=%s, sha256=%s)", slug, version,
                bool(active), sha256(text)[:12])
    return cur.lastrowid


# --------------------------------------------------------------- reading

def active_version(db, slug):
    """The published version of `slug`, or None."""
    return db.execute(
        "SELECT * FROM legal_documents WHERE slug = ? AND active = 1 "
        "ORDER BY id DESC LIMIT 1", (slug,)).fetchone()


def by_version(db, slug, version):
    """A specific version, active or not. This is what a permalink reads,
    and it is why superseding must never delete."""
    return db.execute(
        "SELECT * FROM legal_documents WHERE slug = ? AND version = ?",
        (slug, version)).fetchone()


def versions(db, slug):
    """Every version of a slug, newest first."""
    return db.execute(
        "SELECT * FROM legal_documents WHERE slug = ? ORDER BY id DESC",
        (slug,)).fetchall()


def active_documents(db):
    """Every document currently gating, in a stable order.

    An INACTIVE document is not gated on — that is the whole point of the
    dpa slot — so this is the list the gate iterates and nothing else
    decides what blocks.
    """
    return db.execute(
        "SELECT * FROM legal_documents WHERE active = 1 "
        "ORDER BY slug").fetchall()


# ------------------------------------------------------------- the gate

def accepted_versions(db, account_id, slug):
    """Every version of `slug` this account has accepted."""
    return {r["version"] for r in db.execute(
        "SELECT version FROM document_acceptances "
        "WHERE account_id = ? AND document_type = ?",
        (account_id, slug)).fetchall()}


def outstanding_for(db, account_id):
    """Active documents this account has not accepted at their CURRENT
    version, oldest slug first.

    FAILS CLOSED. A read that raises reports everything as outstanding
    rather than letting an account past a gate whose state is unknown.
    """
    if not account_id:
        return []
    try:
        docs = active_documents(db)
    except Exception:
        logger.exception("could not read the document registry; treating "
                         "every document as outstanding")
        return [None]
    out = []
    for doc in docs:
        if doc["version"] not in accepted_versions(db, account_id,
                                                   doc["slug"]):
            out.append(doc)
    return out


# ----------------------------------------------------------- acceptance

def record_acceptance(db, doc, account_id, user_id, fields, ip, user_agent):
    # type: (object, object, int, int, dict, str, str) -> int
    """Write the acceptance row.

    Snapshots BOTH the text and its hash as served. The hash is what makes
    the record checkable without re-reading the whole document, and the
    text is what makes it readable if the registry row is ever in doubt.

    Does NOT commit — the caller owns the transaction, so the acceptance,
    its audit event and the deletion of the draft land together or not at
    all.
    """
    cur = db.execute(
        "INSERT INTO document_acceptances ("
        "  account_id, user_id, document_type, version, text, sha256,"
        "  signed_name, legal_entity, signer_title, signer_email,"
        "  notice_address, npn, plan, access_code_id,"
        "  accepted_at, ip, user_agent"
        ") VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (account_id, user_id, doc["slug"], doc["version"], doc["text"],
         doc["sha256"],
         fields.get("signature"), fields.get("legal_entity"),
         fields.get("signer_title"), fields.get("signer_email"),
         fields.get("notice_address"), fields.get("npn"),
         fields.get("plan"), fields.get("access_code_id"),
         utcnow(), ip, user_agent))
    logger.info("accepted %s %s account=%s user=%s", doc["slug"],
                doc["version"], account_id, user_id)
    return cur.lastrowid


def acceptances_for(db, account_id, slug=None):
    """Every acceptance on an account, oldest first. Read-only."""
    if slug:
        return db.execute(
            "SELECT * FROM document_acceptances WHERE account_id = ? "
            "AND document_type = ? ORDER BY id", (account_id, slug)
        ).fetchall()
    return db.execute(
        "SELECT * FROM document_acceptances WHERE account_id = ? ORDER BY id",
        (account_id,)).fetchall()
