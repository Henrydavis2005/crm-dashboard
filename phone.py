"""US phone numbers. ONE stored format: 000-000-0000.

B6 made the format a rule rather than a habit. Before it, `leads.phone`
held E.164 (`+1XXXXXXXXXX`), a lead typed in by hand could arrive with
parentheses, and every comparison — duplicate detection, the per-number
daily attempt cap, suppression matching — was one unnormalised caller away
from deciding two spellings of one telephone number were two people.

So: **ten digits, dashed, nothing else, everywhere.** Intake, display,
duplicate detection, the attempt cap and the dialer all read the same
string. `normalize_phone` is the only thing that produces it and it is
called at every boundary where a number enters the application.

E.164 SURVIVES IN EXACTLY ONE PLACE: the carrier. `to_e164` converts at
the moment of the REST call and nowhere else, because Twilio requires it
and nothing else does. A stored `+1` is now a bug; a `+1` on the wire is
correct.

`digits` is the comparison form for the one table that CANNOT be migrated
— `dial_attempts` is append-only by trigger, so historical rows keep
whatever format they were written in, and the attempt cap compares the ten
digits rather than the spelling.
"""
import re
from typing import Optional

_DIGITS = re.compile(r"\D+")

# NXX-NXX-XXXX exactly: ten digits, two dashes, no country code, no
# parentheses, no spaces. What every column holds.
STORED_RE = re.compile(r"^[2-9]\d{2}-[2-9]\d{2}-\d{4}$")


def digits(raw):
    # type: (Optional[str]) -> Optional[str]
    """The ten NANP digits, or None. THE comparison form.

    Accepts anything a person or a vendor might write, including the
    E.164 this application used to store, so a comparison across the
    format change still lands on the same number.
    """
    if raw is None:
        return None
    value = _DIGITS.sub("", str(raw))
    if len(value) == 11 and value.startswith("1"):
        value = value[1:]
    if len(value) != 10:
        return None
    if value[0] in "01" or value[3] in "01":
        return None
    return value


def normalize_phone(raw):
    # type: (Optional[str]) -> Optional[str]
    """Normalize any US phone format to '000-000-0000'; None if invalid.

    Strips non-digits, drops a leading country code 1, and requires a
    valid 10-digit NANP number (area code and exchange must start with
    2-9). THE storage format — every column that holds a telephone number
    holds this.
    """
    value = digits(raw)
    if value is None:
        return None
    return "%s-%s-%s" % (value[:3], value[3:6], value[6:])


def to_e164(raw):
    # type: (Optional[str]) -> Optional[str]
    """'+1XXXXXXXXXX', for the CARRIER and nothing else.

    Called at the Twilio boundary. A `+1` anywhere else in this
    application — in a column, in a comparison, on a page — is a bug.
    """
    value = digits(raw)
    if value is None:
        return None
    return "+1" + value


def digits_sql(column):
    # type: (str) -> str
    """A SQL expression reducing `column` to its ten digits.

    For the two tables a migration may NOT rewrite:
      * `dial_attempts` is append-only by trigger.
      * `suppressions` revocation rows are append-only by trigger — D2
        made a revocation permanent on purpose, and "permanent" has to
        include the contact details it names or the record stops
        identifying anybody.

    Rows in those tables keep whatever spelling they were written with, so
    every comparison against them reduces both sides to digits. ONE
    definition, here, because two hand-rolled REPLACE chains would
    eventually disagree about a parenthesis.
    """
    return ("REPLACE(REPLACE(REPLACE(REPLACE(REPLACE(%s, '+1', ''), "
            "'-', ''), '(', ''), ')', ''), ' ', '')" % column)


def is_stored_format(raw):
    # type: (Optional[str]) -> bool
    """Does this string already look like what the columns hold."""
    return bool(STORED_RE.match(str(raw or "")))
