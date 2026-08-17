"""Versioned acceptance of the three legal documents (PART 12 Step 4).

ONE table, ONE recording function, three documents. `document_acceptances`
replaces the old `attestations` table, which migration 20 copies in and
drops — a second table would mean a second answer to "has this tenant
agreed", and the two would eventually disagree.

APPEND-ONLY IS ENFORCED BY THE DATABASE, not by convention. Migration 20
installs BEFORE UPDATE and BEFORE DELETE triggers that RAISE(ABORT), so
there is no code path — including one written later by somebody who has
never read this file — that can alter or remove an acceptance. Rolling back
a transaction is not a DELETE and does not fire the trigger, so a signup
that fails after recording still unwinds cleanly.

WHAT IS RECORDED. Everything needed to prove who agreed to what, when,
from where: account, user, document type, the version STRING, the full
document text as it read at that moment, the timestamp, the caller's IP and
their user agent. The text is snapshotted because a document on disk can be
edited; a snapshot cannot. Nothing here is ever back-filled — the rows
migrated from `attestations` predate IP capture and say so in the column
rather than carrying a plausible-looking guess.

TWO SCOPES, because the documents differ in who they bind:

  tos, dpa        PER USER, version-pinned. Every user accepts for
                  themselves at signup, and a version bump blocks every
                  existing user at their next request until they accept
                  the new one. This is the gate in `outstanding_for`.

  account_holder  PER ACCOUNT, signed once by the admin with a typed
                  name, AT SIGNUP alongside the other two (PART 12 Step
                  5). It no longer flips any status — `accounts.status`
                  means approval state now and leadflow/accounts.py owns
                  it. Bumping this document's version does not re-prompt
                  an already-signed account; /attest shows what was
                  signed and lets an account that has none sign one.

The documents themselves are files in `leadflow/legal/` — see the README
there. Text and version are data, so publishing a new version is a file
edit and a restart, with no code change.
"""
import logging
import os
import threading
from collections import namedtuple
from typing import Optional

from flask import request

from leadflow.db import utcnow

logger = logging.getLogger("leadflow.acceptance")

LEGAL_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "legal")

# Every document type the table accepts. Kept in sync with the CHECK
# constraint in migration 20 by a test — the constraint is the real
# enforcement, this tuple is what the app iterates.
DOCUMENT_TYPES = ("tos", "dpa", "account_holder")

# The documents every user accepts for themselves, in the order they are
# shown. A version bump on either of these blocks existing users until
# they accept; see `outstanding_for`.
#
# EMPTY SINCE PART 12 STEP 9. The Cloud Service Agreement in the
# `legal_documents` registry supersedes both of these: the CSA *is* the
# terms of service, and the two files this tuple used to name declare
# themselves placeholders in their own first line. Leaving them here
# would gate every user TWICE — once on a placeholder, once on the real
# agreement.
#
# The files stay in leadflow/legal/ and stay readable, and every
# acceptance row ever written against them stays exactly where it is.
# Nothing was deleted, migrated forward or marked superseded: an
# acceptance is a record of what somebody agreed to on a day, and that
# does not stop being true when the document is replaced.
#
# `account_holder` is UNAFFECTED and still gates — it is the signup
# attestation the approval flow depends on, not a terms document.
PER_USER_DOCUMENTS = ()

# The document the ACCOUNT signs once, with a typed name.
ACCOUNT_DOCUMENT = "account_holder"

# Recorded in place of an IP or user agent that was never captured. The
# rows migrated out of `attestations` predate those columns. Written out
# in words on purpose: an empty string or a 0.0.0.0 reads like a captured
# value, and an audit trail that quietly invents its own evidence is worse
# than one with an honest hole in it.
NOT_RECORDED = "(not recorded)"

Document = namedtuple("Document", "kind version title text")

_cache = {}
_cache_lock = threading.Lock()


class UnknownDocument(KeyError):
    """No such document type."""


def _parse(raw):
    # type: (str) -> tuple
    """Split a `Key: value` header block from the body. Returns
    (headers, body). A file with no blank line is all header and no body,
    which `document` rejects."""
    headers = {}
    lines = raw.splitlines(True)
    index = 0
    for index, line in enumerate(lines):
        if not line.strip():
            index += 1
            break
        key, sep, value = line.partition(":")
        if not sep:
            break
        headers[key.strip().lower()] = value.strip()
    else:
        index = len(lines)
    return headers, "".join(lines[index:])


def document(kind):
    # type: (str) -> Document
    """The document as it reads on disk RIGHT NOW.

    Cached on (mtime, size) so publishing a new version takes effect
    without a code change, and without re-reading the file on every
    request. Raises UnknownDocument for an unknown type and ValueError for
    a file missing its Version header or its body — both are operator
    errors at deploy time, and failing loudly beats recording an
    acceptance against version ''.
    """
    if kind not in DOCUMENT_TYPES:
        raise UnknownDocument(kind)
    path = os.path.join(LEGAL_DIR, "%s.md" % kind)
    stat = os.stat(path)
    stamp = (stat.st_mtime_ns, stat.st_size)
    with _cache_lock:
        hit = _cache.get(kind)
        if hit is not None and hit[0] == stamp:
            return hit[1]
    with open(path, "r", encoding="utf-8") as handle:
        headers, body = _parse(handle.read())
    version = headers.get("version", "")
    if not version:
        raise ValueError("%s.md has no Version: header" % kind)
    if not body.strip():
        raise ValueError("%s.md has no body" % kind)
    doc = Document(kind=kind, version=version,
                   title=headers.get("title") or kind, text=body)
    with _cache_lock:
        _cache[kind] = (stamp, doc)
    return doc


def clear_cache():
    """Drop the parsed-document cache. For tests that write a document."""
    with _cache_lock:
        _cache.clear()


def current_version(kind):
    # type: (str) -> str
    return document(kind).version


# ------------------------------------------------------------- recording

def request_ip():
    # type: () -> str
    """The caller's IP, or NOT_RECORDED outside a request context."""
    try:
        return (request.remote_addr or "").strip() or NOT_RECORDED
    except RuntimeError:      # no request context (worker, CLI, tests)
        return NOT_RECORDED


def request_user_agent():
    # type: () -> str
    """The caller's user agent, truncated. Stored as sent — it is evidence
    about the acceptance, not something to normalise."""
    try:
        value = (request.headers.get("User-Agent") or "").strip()
    except RuntimeError:
        return NOT_RECORDED
    return value[:500] or NOT_RECORDED


def record(db, account_id, user_id, kind, signed_name=None, ip=None,
           user_agent=None):
    # type: (object, int, int, str, Optional[str], Optional[str], Optional[str]) -> int
    """Append one acceptance row and return its id.

    Snapshots the document text and version as they read at this instant.
    Does NOT commit: the caller owns the transaction, so an acceptance and
    whatever it gates (an account row, an active status) land together or
    not at all. There is deliberately no counterpart that edits or removes
    a row — the database triggers refuse both.
    """
    doc = document(kind)
    cur = db.execute(
        "INSERT INTO document_acceptances (account_id, user_id, "
        "document_type, version, text, signed_name, accepted_at, ip, "
        "user_agent) VALUES (?,?,?,?,?,?,?,?,?)",
        (account_id, user_id, kind, doc.version, doc.text,
         (signed_name or "").strip() or None, utcnow(),
         ip if ip is not None else request_ip(),
         user_agent if user_agent is not None else request_user_agent()))
    logger.info("accepted %s v%s account=%s user=%s", kind, doc.version,
                account_id, user_id)
    return cur.lastrowid


def sign_account_document(db, account_id, user_id, signed_name):
    # type: (object, int, int, str) -> int
    """Record the account-holder attestation and activate the account.

    PART 12 Step 5 REMOVED THE STATUS FLIP. Signing used to set
    accounts.status = 'active', because status meant "has the attestation
    been signed". It now means where the account sits in the APPROVAL
    ladder, and leadflow/accounts.py is its only writer — so signing
    records a signature and nothing else. Signup collects this document
    alongside the other two, before the account row is usable.

    Raises ValueError on a blank name — the typed name IS the signature.
    """
    signed_name = (signed_name or "").strip()
    if not signed_name:
        raise ValueError("type your full name to sign")
    own = not db.in_transaction
    row_id = record(db, account_id, user_id, ACCOUNT_DOCUMENT,
                    signed_name=signed_name)
    if own:
        db.commit()
    return row_id


def record_signup_documents(db, account_id, user_id):
    # type: (object, int, int) -> list
    """Record the per-user documents at signup. Called INSIDE the signup
    transaction, so no account exists without them."""
    return [record(db, account_id, user_id, kind)
            for kind in PER_USER_DOCUMENTS]


# --------------------------------------------------------------- reading

def latest_for_user(db, user_id, kind):
    """This user's most recent acceptance of `kind`, or None."""
    return db.execute(
        "SELECT * FROM document_acceptances WHERE user_id = ? "
        "AND document_type = ? ORDER BY id DESC LIMIT 1",
        (user_id, kind)).fetchone()


def latest_for_account(db, account_id, kind=ACCOUNT_DOCUMENT):
    """The account's most recent acceptance of `kind`, or None. Used for
    the account-scoped attestation."""
    return db.execute(
        "SELECT * FROM document_acceptances WHERE account_id = ? "
        "AND document_type = ? ORDER BY id DESC LIMIT 1",
        (account_id, kind)).fetchone()


def for_account(db, account_id):
    """Every acceptance on an account, oldest first. Read-only; the
    superadmin console (Step 7) renders this."""
    return db.execute(
        "SELECT * FROM document_acceptances WHERE account_id = ? "
        "ORDER BY id", (account_id,)).fetchall()


def outstanding_for(db, user):
    # type: (object, object) -> tuple
    """The per-user documents this user must accept BEFORE doing anything
    else, in display order. Empty tuple means they are current.

    A user is current on a document when their most recent acceptance
    carries the version the file has RIGHT NOW. Anything else — never
    accepted, accepted at an older version, accepted at a version that was
    later withdrawn — reads as outstanding, because the only question
    worth asking is "is there a row for what we are publishing today".

    FAILS CLOSED. A document that cannot be read (missing file, no Version
    header) is reported as outstanding rather than skipped: refusing to
    let anyone in is recoverable, and letting everyone past an unreadable
    consent gate is not.
    """
    if not user:
        return ()
    pending = []
    for kind in PER_USER_DOCUMENTS:
        try:
            wanted = current_version(kind)
        except Exception:
            logger.exception("could not read the %s document; treating it "
                             "as outstanding", kind)
            pending.append(kind)
            continue
        row = latest_for_user(db, user["id"], kind)
        if row is None or row["version"] != wanted:
            pending.append(kind)
    return tuple(pending)
