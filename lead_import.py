"""Shared CSV lead importer: parse / map / normalise / dedupe / preview.

NO WRITES. This module never INSERTs, never opens a transaction and never
imports leadflow.agent_leads. The CALLER owns the write, because the write
is where two importers genuinely differ: agent leads go into `leads` with a
`source_agent` tag and a 14-day clock that STOPS on positive contact; the
parked overflow pool goes into its own `overflow_leads` table with 45-day
residency and no stop. One shared parse, two separate writes.

THE LINE TO HOLD: the moment this module gains an INSERT, a `table=`
argument, or an `if kind == "overflow"`, the boundary has been crossed and
both features are coupled to one write path. If a future caller needs a
field the parser does not produce, add it to CANONICAL — never a mode flag.

NO AI, NO API CALL, NO NETWORK. Lead data never passes through a language
model. The header matching is difflib + normalised tokens, entirely local;
this module imports nothing from leadflow.ai and opens no socket.
"""
import csv
import difflib
import io
import re

from leadflow import consent
from leadflow.phone import normalize_phone

# Lead fields this parser can produce, each with the CSV headers seen in the
# wild, normalised (lowercase, punctuation stripped). Matching is by header
# NAME, never by position — see read_rows' docstring for why that matters.
CANONICAL = {
    "first_name": ("first name", "firstname", "first", "fname"),
    "last_name": ("last name", "lastname", "last", "lname", "surname"),
    "email": ("email", "email address", "e-mail"),
    "phone": ("phone number", "phone", "mobile", "cell", "telephone"),
    "state": ("state", "st"),
    "city": ("city",),
    "zip": ("zip code", "zip", "postal code", "zipcode"),
    "address": ("street address", "address", "address 1"),
    # DIALER BLOCK 1. Aliases are deliberately SPECIFIC — no bare "date".
    # A Ringy export carries "Date created", which is when the row was
    # made in the CRM, and auto-mapping that to consent would silently
    # turn an export timestamp into a compliance record. If a file names
    # its column something else the uploader picks it from the dropdown,
    # which is a human confirming rather than difflib guessing.
    "consent_date": ("consent date", "consent", "date of consent",
                     "consent timestamp", "opt in date", "optin date",
                     "opt in", "optin", "tcpa consent date",
                     "tcpa date", "lead date", "inquiry date"),
}

# A row without one of these cannot be worked, so it is rejected.
#
# `consent_date` is NOT here on purpose: it is required on the ROW but
# may arrive from either the file or the date the uploader types on the
# confirm screen, and REQUIRED drives the "your file is missing a
# column" warning. A file with no consent column is fine as long as the
# uploader supplies the date. `normalise_row` is what enforces that one
# of the two is present.
REQUIRED = ("phone", "first_name", "state")

# Ignored on purpose: a concatenated full-name column. The real Ringy row
# ends with a bare `Name` that is "First Last" — mapping it would fight the
# two real columns. Use first + last.
IGNORE_HEADERS = ("name", "full name")

FIELD_ORDER = ("first_name", "last_name", "email", "phone", "city", "state",
               "zip", "address", "consent_date")

_PUNCT = re.compile(r"[^a-z0-9]+")


def _norm(header):
    return _PUNCT.sub(" ", (header or "").strip().lower()).strip()


def read_rows(raw_bytes):
    """Decode + parse an uploaded CSV into (headers, list-of-dicts).

    utf-8-sig, ALWAYS. Ringy exports carry a UTF-8 BOM: opened as plain
    utf-8 the first header becomes '﻿First name', which matches no
    mapping, so EVERY row silently imports with a blank first name. This is
    the single most likely way the first upload fails, and it fails
    quietly. utf-8-sig strips the BOM; on a file that has none it is a
    no-op, so there is no downside.

    Mapping is by header NAME, never by column index, for a reason visible
    in the real Ringy header row:

        First name, Email, Last name, Phone number, Street address,
        City, State, ZIP code, Name

    `Email` sits BETWEEN First name and Last name. Positional mapping would
    put every email address into last_name.
    """
    if isinstance(raw_bytes, str):
        text = raw_bytes
        if text[:1] == "﻿":
            text = text[1:]
    else:
        text = (raw_bytes or b"").decode("utf-8-sig", errors="replace")
    reader = csv.DictReader(io.StringIO(text))
    headers = [(h or "").strip() for h in (reader.fieldnames or [])]
    rows = []
    for row in reader:
        # DictReader keys on the RAW fieldnames; re-key on the stripped
        # ones so a header with stray whitespace still lines up with the
        # mapping the user confirmed.
        clean = {}
        for raw_key, value in row.items():
            if raw_key is None:
                continue          # csv puts extra columns under None
            clean[(raw_key or "").strip()] = value
        rows.append(clean)
    return headers, rows


def guess_mapping(headers):
    """Best-effort {lead_field: csv_header} for this file's headers.

    Exact normalised alias first, then a difflib near-match. Purely local.
    Headers that match nothing are simply absent from the result — the
    caller renders dropdowns so a human confirms before anything is
    written."""
    normalised = {}
    for header in headers:
        key = _norm(header)
        if key and key not in normalised:
            normalised[key] = header
    used = set()
    out = {}
    for field in FIELD_ORDER:
        for alias in CANONICAL.get(field, ()):
            header = normalised.get(_norm(alias))
            if header is not None and header not in used:
                out[field] = header
                used.add(header)
                break
    # Second pass: fuzzy, only for fields still unmapped.
    remaining = [h for h in headers
                 if h not in used and _norm(h) not in
                 [_norm(i) for i in IGNORE_HEADERS]]
    for field in FIELD_ORDER:
        if field in out or not remaining:
            continue
        aliases = [_norm(a) for a in CANONICAL.get(field, ())]
        best, best_ratio = None, 0.0
        for header in remaining:
            key = _norm(header)
            for alias in aliases:
                ratio = difflib.SequenceMatcher(None, key, alias).ratio()
                if ratio > best_ratio:
                    best, best_ratio = header, ratio
        if best is not None and best_ratio >= 0.82:
            out[field] = best
            used.add(best)
            remaining.remove(best)
    return out


def apply_mapping(row, field_map):
    """Pull the mapped lead fields out of one raw CSV row."""
    out = {}
    for field, header in (field_map or {}).items():
        if field in CANONICAL:
            out[field] = (row.get(header) or "").strip()
    return out


def extra_columns(row, field_map):
    """The PERMITTED unclaimed columns, under their canonical labels.

    Unrecognised columns are ignored, never errored. What survives is
    `parser.allowed_extras` — date of birth, age, address, household size
    — the SAME allowlist Gmail intake applies, deliberately reached
    through the same function rather than re-stated here.

    BLOCK 1 STEP B closed the Gmail path and left this one open, which is
    the gap BLOCK 2 closes: this returned every unclaimed column
    "verbatim, so nothing the agent sent is thrown away", and an agent's
    purchased list routinely carries Conditions / Tobacco / Height /
    Weight columns. All three CSV importers — the overflow pool, agent
    leads and the shared normaliser — go through this one function, so
    one allowlist covers all three.

    Something the agent sent IS now thrown away, on purpose. The columns
    dropped are the ones the app has no business holding.
    """
    from leadflow.parser import allowed_extras  # deferred: avoid a cycle
    claimed = set((field_map or {}).values())
    unclaimed = {k: v for k, v in (row or {}).items()
                 if k and k not in claimed and (v or "").strip()}
    return allowed_extras(unclaimed)


def normalise_row(mapped, fallback_consent_date=None):
    """Boundary treatment + validation for one mapped row.

    Returns (clean_dict, reject_reason_or_None). The same boundary rules
    the manual Add-lead form applies: phone to E.164, state upper-cased,
    email lower-cased.

    `fallback_consent_date` is the date the uploader typed on the confirm
    screen, used only for rows whose own consent cell is empty or
    unreadable. It is NOT a default and never becomes today by omission:
    the caller passes None when the uploader left it blank, and then a
    row with no usable date of its own is REJECTED. That refusal is the
    feature — the alternative is stamping a date nobody obtained onto a
    lead somebody is then allowed to dial.
    """
    clean = dict(mapped)
    clean["first_name"] = (mapped.get("first_name") or "").strip()
    clean["last_name"] = (mapped.get("last_name") or "").strip()
    clean["email"] = (mapped.get("email") or "").strip().lower() or None
    clean["state"] = (mapped.get("state") or "").strip().upper()
    clean["city"] = (mapped.get("city") or "").strip()
    clean["zip"] = (mapped.get("zip") or "").strip()
    clean["address"] = (mapped.get("address") or "").strip()
    raw_phone = (mapped.get("phone") or "").strip()
    clean["phone"] = normalize_phone(raw_phone)

    raw_consent = (mapped.get("consent_date") or "").strip()
    clean["consent_date"] = consent.parse_date(raw_consent) or (
        consent.parse_date(fallback_consent_date))

    # A row is rejected ONLY for a missing/unusable phone, a blank first
    # name, a blank state, or no usable consent date. A missing email or
    # last name is ACCEPTED with blanks — expect both at volume;
    # leads.email is nullable and last_name defaults ''.
    if not raw_phone:
        return clean, "no phone number"
    if clean["phone"] is None:
        return clean, "phone is not a valid US number"
    if not clean["first_name"]:
        return clean, "no first name"
    if not clean["state"]:
        return clean, "no state"
    if clean["consent_date"] is None:
        # Two different reasons, because they have two different fixes:
        # a bad cell means the file needs looking at, an empty one means
        # the uploader needs to supply the date.
        if raw_consent:
            return clean, ("consent date %r is not a usable past date"
                           % raw_consent[:32])
        return clean, "no consent date"
    return clean, None


class ImportPreview(object):
    """What the confirm screen renders. Holds no DB handle and no table
    name — `label` and `expiry_date` are plain strings, so the template
    renders them without knowing which importer produced them."""

    def __init__(self, accepted, rejected, duplicates, total, label,
                 expiry_date, field_map, headers,
                 fallback_consent_date=None):
        self.accepted = accepted
        self.rejected = rejected
        self.duplicates = duplicates
        self.total = total
        self.label = label
        self.expiry_date = expiry_date
        self.field_map = field_map
        self.headers = headers
        # What the confirm screen echoes back so the uploader can see the
        # date they typed is the one that will be written.
        self.fallback_consent_date = fallback_consent_date

    @property
    def consent_from_file(self):
        """How many accepted rows carried their own consent date, as
        opposed to taking the uploader's fallback."""
        if not self.fallback_consent_date:
            return len(self.accepted)
        return sum(1 for row in self.accepted
                   if row.get("consent_date") != self.fallback_consent_date)

    @property
    def first_five(self):
        """The first five rows EXACTLY as they would land — phones already
        normalised to E.164, state upper-cased, blanks shown as blanks."""
        return self.accepted[:5]

    @property
    def reject_reasons(self):
        """Rejected counts broken out by reason, commonest first."""
        counts = {}
        for item in self.rejected:
            counts[item["reason"]] = counts.get(item["reason"], 0) + 1
        return sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))


def build_preview(headers, rows, field_map, dupe_check, expiry_date, label,
                  fallback_consent_date=None):
    """Parse + validate + dedupe into an ImportPreview. Writes NOTHING.

    `dupe_check(phone, email) -> existing_row_or_None` is INJECTED by the
    caller, so this module never decides which table or which tenant is
    authoritative. The agent-lead route passes a tenant-scoped probe
    against `leads`; a future overflow route passes its own.

    A duplicate is SKIPPED, never tagged: a lead already the owner's stays
    the owner's, with its original tag untouched. Within-file duplicates
    (two rows, one phone) are caught before the DB probe.
    """
    accepted, rejected, duplicates = [], [], []
    seen_phones, seen_emails = set(), set()
    for index, raw in enumerate(rows):
        mapped = apply_mapping(raw, field_map)
        clean, reason = normalise_row(mapped, fallback_consent_date)
        if reason is not None:
            rejected.append({"row": index + 2,  # +2: 1-based, past the header
                             "reason": reason, "data": clean})
            continue
        phone, email = clean.get("phone"), clean.get("email")
        if phone and phone in seen_phones:
            duplicates.append({"row": index + 2, "data": clean,
                               "existing": None, "within_file": True})
            continue
        if email and email in seen_emails:
            duplicates.append({"row": index + 2, "data": clean,
                               "existing": None, "within_file": True})
            continue
        existing = dupe_check(phone, email) if dupe_check else None
        if existing is not None:
            duplicates.append({"row": index + 2, "data": clean,
                               "existing": existing, "within_file": False})
            continue
        if phone:
            seen_phones.add(phone)
        if email:
            seen_emails.add(email)
        clean["extra"] = extra_columns(raw, field_map)
        accepted.append(clean)
    return ImportPreview(accepted, rejected, duplicates, len(rows), label,
                         expiry_date, field_map, headers,
                         consent.parse_date(fallback_consent_date))
