"""VA call scripts (SPEC R5): merge-field rendering, section assembly, side
panel parsing, and the per-lead AI recovery-line cache.

Two scripts, all copy editable in Settings -> VA scripts (script_* keys):

- No-contact (queue source volume/callback): the four script_nc_* sections
  rendered in order (Opening / Qualify / Disclaimer / Close).
- Recovery (queue source ghost/stale): script_rec_* sections (Opening /
  Reconnect / Deflect-pivot / Ask / Close). Opening and Reconnect carry
  [AI: ...] markers replaced with per-lead lines from ai.recovery_lines,
  generated at QUEUE time and cached on va_queue.script_json (JSON dict:
  opening_line, reconnect_lines, kind, generated_at, fallback). The Close
  section is the booking-response flow (script_panel_booking).

Merge fields filled server-side: {name} {first_name} {state} {va_name}
{agent_name}. Fallbacks: name -> first name -> "there"; state ->
"your state"; agent_name -> identity_name setting -> "the adviser";
va_name -> the logged-in user's username, first letter capitalized.

Output safety: every AI line is checked with compliance.check_text; a
violation, AiError (including a missing anthropic key) or ANY other failure
falls back to the neutral generic FALLBACK_* lines - generation can never
break queue building or the console.
"""
import json
import logging
import re

from leadflow.db import utcnow

logger = logging.getLogger("leadflow.scripts")

# Queue sources that get the recovery script (everything else, including
# legacy aged/fresh rows, gets the no-contact script).
RECOVERY_SOURCES = ("ghost", "stale")

_AI_MARKER_RE = re.compile(r"\[AI:[^\]]*\]")

# Neutral generic fallback lines: reference nothing specific, trip no
# compliance rule. Used whenever generation fails for any reason.
FALLBACK_OPENING = (
    "I'm just following up on the request you put in for help with health "
    "coverage - I wanted to make sure it didn't slip through the cracks."
)
FALLBACK_RECONNECT = [
    "I know things get busy, so I'll keep this quick.",
    "The easiest next step is to set up a quick call or get everything "
    "sent over to you in writing.",
]


def _get(db, key):
    from leadflow.settings import get_setting
    return str(get_setting(key, db=db) or "")


# ------------------------------------------------------------- merge fields

def merge_fields(db, lead, va_username):
    # type: (object, object, object) -> dict
    """The five R5 merge-field values for a lead + logged-in VA."""
    first = (lead["first_name"] or "").strip() if lead is not None else ""
    last = (lead["last_name"] or "").strip() if lead is not None else ""
    state = (lead["state"] or "").strip() if lead is not None else ""
    full = (first + " " + last).strip()
    va_name = (va_username or "").strip()
    return {
        "name": full or first or "there",
        "first_name": first or "there",
        "state": state or "your state",
        "va_name": (va_name[:1].upper() + va_name[1:]) if va_name
                   else "the assistant",
        # B7: the agent who OWNS the lead, resolved by the lead's own
        # account. Reading the signed-in user's setting put the
        # assistant's agency name in a script about somebody else's
        # client the moment a team VA worked more than one agent's leads.
        "agent_name": owning_agent_name(db, lead),
    }


def render_merge(text, fields):
    # type: (str, dict) -> str
    """Fill {name} {first_name} {state} {va_name} {agent_name} in text.
    Only the known fields are touched (stray braces stay literal)."""
    out = text or ""
    for key, value in fields.items():
        out = out.replace("{%s}" % key, value)
    return out


# ----------------------------------------------------------------- sections

def no_contact_script(db, lead, va_username):
    """The four no-contact sections as (label, text) pairs, merge-rendered."""
    fields = merge_fields(db, lead, va_username)
    return [
        ("Opening", render_merge(_get(db, "script_nc_opening"), fields)),
        ("Qualify", render_merge(_get(db, "script_nc_qualify"), fields)),
        ("Disclaimer", render_merge(_get(db, "script_nc_disclaimer"), fields)),
        ("Close", render_merge(_get(db, "script_nc_close"), fields)),
    ]


def recovery_script(db, lead, va_username, payload):
    """The five recovery sections as (label, text) pairs. `payload` is the
    cached script_json dict; its lines replace the [AI: ...] markers in
    Opening/Reconnect. Deflect-pivot and Ask are fixed copy; Close is the
    booking-response flow (same lines as the side panel)."""
    fields = merge_fields(db, lead, va_username)
    payload = payload if isinstance(payload, dict) else {}
    opening_line = str(payload.get("opening_line") or FALLBACK_OPENING)
    raw = payload.get("reconnect_lines")
    if isinstance(raw, list) and raw:
        reconnect_line = " ".join(str(l) for l in raw if str(l).strip())
    else:
        reconnect_line = " ".join(FALLBACK_RECONNECT)
    opening = _AI_MARKER_RE.sub(
        lambda m: opening_line,
        render_merge(_get(db, "script_rec_opening"), fields))
    reconnect = _AI_MARKER_RE.sub(
        lambda m: reconnect_line,
        render_merge(_get(db, "script_rec_reconnect"), fields))
    booking = booking_lines(db, lead, va_username)
    return [
        ("Opening", opening),
        ("Reconnect", reconnect),
        ("Deflect-pivot", render_merge(_get(db, "script_rec_deflect"),
                                       fields)),
        ("Ask", render_merge(_get(db, "script_rec_ask"), fields)),
        ("Close", "\n".join(booking)),
    ]


def script_for_source(db, lead, va_username, source, payload=None):
    """(kind, sections): the script for a queue row's source. volume/
    callback (and legacy aged/fresh) -> no-contact; ghost/stale ->
    recovery."""
    if source in RECOVERY_SOURCES:
        return "recovery", recovery_script(db, lead, va_username, payload)
    return "no_contact", no_contact_script(db, lead, va_username)


def context_for_source(db, lead, source):
    """The B7 context block, for the sources that get one.

    Every row a send produces is `sent`, and a sent lead may have a whole
    email history behind it that the VA can no longer see. A legacy
    recovery row already carries its context in the AI lines.
    """
    if source in RECOVERY_SOURCES:
        return []
    return context_lines(db, lead)


# --------------------------------------------------------------- side panel

def booking_lines(db, lead, va_username):
    """script_panel_booking, one response per line, merge-rendered."""
    fields = merge_fields(db, lead, va_username)
    return [render_merge(line.strip(), fields)
            for line in _get(db, "script_panel_booking").splitlines()
            if line.strip()]


def rebuttals(db, lead, va_username):
    """script_panel_rebuttals parsed as "Trigger :: Response" per line,
    merge-rendered, as (trigger, response) pairs. Malformed lines (no
    "::" or an empty half) are skipped, never fatal."""
    fields = merge_fields(db, lead, va_username)
    out = []
    for line in _get(db, "script_panel_rebuttals").splitlines():
        if "::" not in line:
            continue
        trigger, response = line.split("::", 1)
        trigger = trigger.strip()
        response = response.strip()
        if not trigger or not response:
            continue
        out.append((render_merge(trigger, fields),
                    render_merge(response, fields)))
    return out


# ------------------------------------------------- B7: the context block

# What a VA is told about a lead, and the ONLY thing they are told. B7
# took the email history off the lead page for an assistant seat — a VA
# reading a customer's inbound replies is a customer's correspondence in
# front of somebody who is not their agent — so the context the VA
# legitimately needs to make the call has to arrive HERE instead, in the
# script, summarised.
#
# SUMMARISED, never quoted. Every value below is a count, a date, a stage
# name or a yes/no. There is no branch of `context_block` that returns the
# text of a message.
CONTEXT_KEYS = ("stage", "sequence_position", "last_activity",
                "replies", "last_reply_days", "asked_about_pricing",
                "last_click_days", "engagement")


def owning_agent_name(db, lead):
    """The agent whose lead this is, BY ACCOUNT.

    Not `current_account_id()`. Since B6 a team assistant works leads that
    belong to several different agents, so reading the signed-in user's
    own account would put the assistant's agency name in a script about
    somebody else's client — and the VA would introduce themselves on
    behalf of the wrong person.
    """
    from leadflow.settings import get_setting
    try:
        account_id = lead["account_id"]
    except (IndexError, KeyError, TypeError):
        return "the adviser"
    try:
        name = get_setting("identity_name", db=db, account_id=account_id)
    except Exception:
        logger.exception("could not resolve the owning agent for a lead")
        return "the adviser"
    return (name or "").strip() or "the adviser"


def _days_since(stamp, now=None):
    import datetime
    if not stamp:
        return None
    try:
        parsed = datetime.datetime.fromisoformat(str(stamp))
    except (TypeError, ValueError):
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=datetime.timezone.utc)
    now = now or datetime.datetime.now(datetime.timezone.utc)
    return max(0, int((now - parsed).total_seconds() // 86400))


def context_block(db, lead):
    """What has happened with this lead, as numbers and dates.

    B7: the VA no longer sees the email history, so this is how the
    context reaches them — recent activity, replies, where the sequence
    got to, and engagement. Counts and dates only; see CONTEXT_KEYS.
    """
    lead_id = lead["id"]

    def scalar(sql, params=()):
        try:
            row = db.execute(sql, params).fetchone()
        except Exception:
            logger.exception("context lookup failed for lead %s", lead_id)
            return None
        return row["v"] if row is not None else None

    sent = scalar("SELECT COUNT(*) AS v FROM messages WHERE lead_id = ? "
                  "AND direction = 'out' AND status = 'sent'", (lead_id,)) or 0
    remaining = scalar(
        "SELECT COUNT(*) AS v FROM messages WHERE lead_id = ? "
        "AND direction = 'out' AND status = 'pending'", (lead_id,)) or 0
    replies = scalar("SELECT COUNT(*) AS v FROM messages WHERE lead_id = ? "
                     "AND direction = 'in'", (lead_id,)) or 0
    last_reply = scalar("SELECT MAX(created_at) AS v FROM messages "
                        "WHERE lead_id = ? AND direction = 'in'", (lead_id,))
    last_sent = scalar("SELECT MAX(sent_at) AS v FROM messages "
                       "WHERE lead_id = ? AND direction = 'out' "
                       "AND status = 'sent'", (lead_id,))
    last_touch = scalar("SELECT MAX(created_at) AS v FROM interactions "
                        "WHERE lead_id = ?", (lead_id,))
    priced = scalar("SELECT 1 AS v FROM messages WHERE lead_id = ? "
                    "AND direction = 'in' AND quote_request = 1 LIMIT 1",
                    (lead_id,))
    calls = scalar("SELECT COUNT(*) AS v FROM interactions "
                   "WHERE lead_id = ? AND itype = 'call'", (lead_id,)) or 0

    try:
        stage = lead["pipeline_stage"] or "new"
    except (IndexError, KeyError, TypeError):
        stage = "new"

    if replies:
        engagement = "replied"
    elif sent:
        engagement = "emailed, no reply yet"
    else:
        engagement = "not contacted yet"

    return {
        "stage": stage,
        "sequence_position": ("%d sent, %d still to go" % (sent, remaining)
                              if (sent or remaining) else "not started"),
        "last_activity": _days_since(last_touch or last_sent),
        "replies": int(replies),
        "last_reply_days": _days_since(last_reply),
        "asked_about_pricing": bool(priced) or stage == "quote",
        "last_click_days": _days_since(last_sent),
        "engagement": engagement,
        "calls_logged": int(calls),
    }


def context_lines(db, lead):
    """`context_block` as the (label, value) pairs the console renders."""
    ctx = context_block(db, lead)

    def days(value, never="never"):
        if value is None:
            return never
        return "today" if value == 0 else (
            "yesterday" if value == 1 else "%d days ago" % value)

    return [
        ("Where they are", ctx["stage"]),
        ("Email sequence", ctx["sequence_position"]),
        ("Last activity", days(ctx["last_activity"], "nothing yet")),
        ("Replies", ("none" if not ctx["replies"]
                     else "%d — last %s" % (ctx["replies"],
                                            days(ctx["last_reply_days"])))),
        ("Asked about pricing", "yes" if ctx["asked_about_pricing"] else "no"),
        ("Last email to them", days(ctx["last_click_days"], "none sent")),
        ("Calls logged", str(ctx["calls_logged"])),
    ]


# ------------------------------------------------------ AI lines + caching

def fallback_lines():
    # type: () -> dict
    return {"opening_line": FALLBACK_OPENING,
            "reconnect_lines": list(FALLBACK_RECONNECT)}


def generate_lines(db, lead, kind):
    # type: (object, object, str) -> tuple
    """(lines_dict, used_fallback, reason): ai.recovery_lines with every
    safety net. Compliance violation in ANY returned line, AiError
    (missing key included) or any unexpected failure -> the neutral
    generic fallback lines. Never raises.

    PART 12 Step 3 added `reason`: the console used to say only "AI lines
    weren't available", which is true but not actionable. When the cause
    is a missing API key the tenant now sees the sentence that tells them
    what to do about it. The reason is shown to VAs as well as admins, so
    it must never carry anything sensitive — it is a fixed message, never
    an exception string from the SDK."""
    try:
        from leadflow.ai import AiError, recovery_lines
        from leadflow.ai.core import KEY_MISSING
        from leadflow.outreach.compliance import check_text
        try:
            data = recovery_lines(db, lead, kind)
        except AiError as exc:
            logger.warning("recovery lines unavailable for lead %s: %s",
                           lead["id"], exc)
            reason = KEY_MISSING if KEY_MISSING in str(exc) else ""
            return fallback_lines(), True, reason
        for line in [data["opening_line"]] + list(data["reconnect_lines"]):
            hits = check_text(db, line)
            if hits:
                logger.warning(
                    "recovery line for lead %s tripped compliance (%s); "
                    "using fallback lines", lead["id"], ", ".join(hits))
                return fallback_lines(), True, ""
        return data, False, ""
    except Exception:
        logger.exception("unexpected recovery-line failure for lead %s",
                         lead["id"] if lead is not None else None)
        return fallback_lines(), True, ""


def flag_kind_for(db, lead_id, source):
    """The lead's latest recovery-flag kind (any status), for prompt
    context. No flag row -> inferred from the queue source."""
    row = db.execute(
        "SELECT kind FROM recovery_flags WHERE lead_id = ? "
        "ORDER BY id DESC LIMIT 1", (lead_id,)).fetchone()
    if row is not None:
        return row["kind"]
    return "fast_ghost" if source == "ghost" else "stale_engaged"


def generate_for_queue_row(db, row):
    """Generate + cache AI lines for one ghost/stale va_queue row (any
    mapping with id, lead_id, source). Never raises on AI failure - the
    fallback lines are cached instead. Commits only when it owns the
    transaction. Returns the cached payload dict."""
    kind = flag_kind_for(db, row["lead_id"], row["source"])
    lead = db.execute("SELECT * FROM leads WHERE id = ?",
                      (row["lead_id"],)).fetchone()
    if lead is None:
        lines, fell_back, reason = fallback_lines(), True, ""
    else:
        lines, fell_back, reason = generate_lines(db, lead, kind)
    payload = {
        "opening_line": lines["opening_line"],
        "reconnect_lines": list(lines["reconnect_lines"]),
        "kind": kind,
        "generated_at": utcnow(),
        "fallback": bool(fell_back),
        "fallback_reason": reason,
    }
    own = not db.in_transaction
    db.execute("UPDATE va_queue SET script_json = ? WHERE id = ?",
               (json.dumps(payload), row["id"]))
    if own:
        db.commit()
    return payload


def cached_payload(row):
    """Parse a va_queue row's script_json; None when missing/unusable."""
    raw = row["script_json"]
    if not raw:
        return None
    try:
        payload = json.loads(raw)
    except (TypeError, ValueError):
        return None
    if not isinstance(payload, dict) or not payload.get("opening_line"):
        return None
    return payload
