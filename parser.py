"""Generic label/value HTML lead-email parser.

Handles the two seeded vendors (NextGen Leads, USHA Marketplace) and any
similar notification email whose body is a run of label/value pairs, either
as two-cell table rows (``<td>Label:</td><td>Value</td>``) or as text runs
inside ``<div>``/``<p>`` blocks (``<b>Label:</b> Value``).
"""
import json
import logging
import re

from bs4 import BeautifulSoup

logger = logging.getLogger("leadflow.parser")

_WS = re.compile(r"\s+")
# "Label: value" inline in a single text node / plain-text line.
_INLINE = re.compile(r"^([A-Za-z][A-Za-z0-9 .#()'/&-]{0,39}?)\s*:\s*(.*)$")
# A bare label string (used for table cells, sans trailing colon).
_LABELISH = re.compile(r"^[A-Za-z][A-Za-z0-9 .#()'/&-]{0,39}$")
_MAX_LABEL = 40


# ------------------------------------------------ what a lead may carry
#
# BLOCK 1 STEP B. This parser is GENERIC: it reads every "Label: value"
# pair a vendor sends, and every one of them used to land in
# `leads.metadata`. The health-insurance vendors send medical conditions,
# tobacco use, height and weight, so the app was storing all four — and
# `metadata` has exactly ONE reader, `leadflow/ai/core.py`, which puts
# every key and value into the reply-draft prompt it sends to Anthropic.
# Health data was leaving the app.
#
# THIS IS AN ALLOWLIST AND MUST STAY ONE. A blocklist naming those four
# fields would be correct today and wrong the first time a vendor adds a
# fifth; nobody would notice, because nothing renders `metadata` in the
# UI. Anything not named here is dropped at the parse boundary and never
# reaches a column, a prompt or a log line.
#
# Name, email, phone, city, state, zip and received-on are real columns
# and are handled above — they are not extras. What is left of the
# permitted set is these four.
KEEP_EXTRAS = (
    ("Date of Birth", ("dob", "d.o.b.", "date of birth", "birth date",
                       "birthdate", "born")),
    ("Age", ("age",)),
    ("Address", ("address", "street address", "street", "address 1",
                 "address line 1", "mailing address")),
    ("Household Size", ("household size", "household", "family size",
                        "number in household", "# in household",
                        "people in household", "household members")),
)


def allowed_extras(pairs):
    # type: (dict) -> dict
    """The permitted label/value pairs, under their canonical labels.

    Matching is case-insensitive and synonym-aware, so one vendor's "DOB"
    and another's "Date of Birth" both arrive as "Date of Birth" and the
    downstream vocabulary is fixed rather than whatever the vendor typed.
    Empty values are skipped, so a blank field never displaces a filled
    synonym.
    """
    lower = {}
    for key, value in pairs.items():
        lower.setdefault(str(key).strip().lower(), value)
    kept = {}
    for canonical, synonyms in KEEP_EXTRAS:
        for synonym in synonyms:
            value = _clean(lower.get(synonym) or "")
            if value:
                kept[canonical] = value
                break
    return kept


def recognised_labels(pairs):
    # type: (dict) -> list
    """The canonical labels from `pairs` this app would keep, sorted.

    The reporting counterpart of `allowed_extras`: same allowlist, names
    only, no values. Everything a parse failure says about a message is
    built from this and a COUNT, never from the labels themselves.
    """
    return sorted(allowed_extras(pairs).keys())


def label_summary(pairs):
    # type: (dict) -> str
    """How a parse failure describes what it saw, WITHOUT recording it.

    It used to be "found labels: <every label the vendor sent>", which on
    a health-insurance lead form is "Medical Conditions, Tobacco Use,
    Height, Weight" — a durable record that the vendor asked, written into
    `dead_letters.error` and shown on screen. Nothing else in the app
    holds that any more, so neither does this.

    What is left is what a field_map is actually diagnosed against: how
    MANY labels the message carried, and which of them this app knows.
    "12 labels present; none recognised" says the field map matched
    nothing, which is the whole finding. The message itself is still in
    the mailbox for anybody who needs to read the vendor's wording.
    """
    total = len(pairs or {})
    known = recognised_labels(pairs or {})
    if not total:
        return "no labels found"
    return "%d label(s) present; %s" % (
        total, ("recognised: " + ", ".join(known)) if known
        else "none recognised")


class ParseError(Exception):
    """Raised when a lead email cannot be parsed into required fields."""

    def __init__(self, detail):
        super(ParseError, self).__init__(detail)
        self.detail = detail


def _clean(s):
    # type: (str) -> str
    return _WS.sub(" ", s.replace("\xa0", " ")).strip()


def _looks_like_label(s):
    # type: (str) -> bool
    """True if a cleaned text chunk looks like a 'Label:' marker."""
    if not s or not s.endswith(":"):
        return False
    core = s[:-1].strip()
    return bool(core) and len(core) <= _MAX_LABEL and bool(_LABELISH.match(core))


def _pairs_from_html(html_body):
    # type: (str) -> dict
    soup = BeautifulSoup(html_body, "html.parser")
    pairs = {}

    # Pass 1: two-cell table rows -- the most reliable structure. The value
    # cell is authoritative even when empty (avoids swallowing the next label).
    for tr in soup.find_all("tr"):
        cells = tr.find_all(["td", "th"], recursive=False)
        if len(cells) < 2:
            cells = tr.find_all(["td", "th"])
        if len(cells) < 2:
            continue
        label = _clean(cells[0].get_text(" ")).rstrip(":").strip()
        if not label or len(label) > _MAX_LABEL or not _LABELISH.match(label):
            continue
        value = _clean(cells[1].get_text(" "))
        if _looks_like_label(value):
            value = ""
        if label not in pairs or (not pairs[label] and value):
            pairs[label] = value

    # Pass 2: sequential text runs (<div>/<p> layouts, or tables where the
    # label and value live in separate inline nodes).
    strings = [t for t in (_clean(s) for s in soup.stripped_strings) if t]
    i = 0
    while i < len(strings):
        s = strings[i]
        if _looks_like_label(s):
            label = s[:-1].strip()
            value = ""
            if i + 1 < len(strings) and not _looks_like_label(strings[i + 1]):
                nxt = strings[i + 1]
                m = _INLINE.match(nxt)
                if not m:
                    value = nxt
                    i += 1
            if label not in pairs:
                pairs[label] = value
        else:
            m = _INLINE.match(s)
            if m:
                label = _clean(m.group(1))
                value = _clean(m.group(2))
                if _looks_like_label(value):
                    value = ""
                if label and label not in pairs:
                    pairs[label] = value
        i += 1
    return pairs


def _pairs_from_text(text_body):
    # type: (str) -> dict
    pairs = {}
    lines = text_body.splitlines()
    i = 0
    while i < len(lines):
        line = _clean(lines[i])
        if not line:
            i += 1
            continue
        m = _INLINE.match(line)
        if m:
            label = _clean(m.group(1))
            value = _clean(m.group(2))
            if not value and i + 1 < len(lines):
                nxt = _clean(lines[i + 1])
                if nxt and not _INLINE.match(nxt):
                    value = nxt
                    i += 1
            if _looks_like_label(value):
                value = ""
            if label and label not in pairs:
                pairs[label] = value
        i += 1
    return pairs


def parse_lead(html_body, text_body, field_map):
    # type: (str, str, dict) -> dict
    """Parse a lead email body into contact fields.

    Returns dict(first_name, last_name, email, phone, city, state, zip,
    extras) where extras holds ONLY the labels named in KEEP_EXTRAS —
    date of birth, age, address, household size. Everything else the
    vendor sent is read and discarded; see KEEP_EXTRAS for why that is an
    allowlist. Raises ParseError (with .detail) when required fields are
    missing: at least one of email/phone, plus a name (full or
    first+last).
    """
    if isinstance(field_map, str):
        field_map = json.loads(field_map)
    field_map = field_map or {}

    pairs = {}
    if html_body:
        pairs = _pairs_from_html(html_body)
    if not pairs and text_body:
        pairs = _pairs_from_text(text_body)

    lower = {}
    for k, v in pairs.items():
        lower.setdefault(k.lower(), v)

    labels = field_map.get("labels", {})

    def pick(field):
        # type: (str) -> str
        for lab in labels.get(field, []):
            v = lower.get(str(lab).lower())
            if v:
                return _clean(v)
        return ""

    name_mode = field_map.get("name_mode", "full")
    if name_mode == "split":
        first_name = pick("first_name")
        last_name = pick("last_name")
    else:
        full = pick("name")
        parts = full.split()
        first_name = parts[0] if parts else ""
        last_name = " ".join(parts[1:]) if len(parts) > 1 else ""

    email = pick("email") or None
    phone = pick("phone") or None
    city = pick("city")
    state = pick("state")
    zip_code = pick("zip")

    missing = []
    if not email and not phone:
        missing.append("email or phone")
    if not first_name and not last_name:
        missing.append("name")
    if missing:
        detail = "missing required fields: %s (%s)" % (
            ", ".join(missing), label_summary(pairs),
        )
        raise ParseError(detail)

    return {
        "first_name": first_name,
        "last_name": last_name,
        "email": email,
        "phone": phone,
        "city": city,
        "state": state,
        "zip": zip_code,
        "extras": allowed_extras(pairs),
    }
