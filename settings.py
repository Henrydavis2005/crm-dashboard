"""Settings registry + typed get/set with encrypted-at-rest secrets."""
import copy
import json
import logging
import secrets as _secrets

from leadflow import consent, crypto
from leadflow.db import get_db, utcnow

logger = logging.getLogger("leadflow.settings")

DEFAULT_AI_TONE_PROMPT = (
    "Write like a real person, not a marketer. Warm, brief, plain language - "
    "2 to 4 sentences. Use the lead's first name once. Answer their question "
    "directly when you can, and end with one clear next step (usually a quick "
    "call, or the booking link when it fits naturally). Never state prices, "
    "carrier names, or coverage promises. Never say guaranteed, approved, "
    "free, or that anyone qualifies. If they ask for specific numbers, say "
    "you'll pull their options together today and get right back to them."
)

# VA script defaults (R5 copy, seeded via the registry; editable in
# Settings → VA scripts). Merge fields: {name} {first_name} {state}
# {va_name} {agent_name}; recovery sections may contain [AI: ...] markers.
DEFAULT_SCRIPT_NC_OPENING = (
    "Hey, is this {name}? ... Hey {name}, this is {va_name} — I was just "
    "calling about the request that was put in there in {state} for help "
    "with the health coverage. Did I catch you at a good time to go over "
    "that real quick?"
)
DEFAULT_SCRIPT_NC_QUALIFY = (
    "So I'm just getting everything pulled up here... what's got you "
    "shopping for coverage right now — switching jobs, losing coverage, or "
    "just trying to find something more affordable?"
)
DEFAULT_SCRIPT_NC_DISCLAIMER = (
    "And I just want to be clear — I'm not a licensed adviser myself. My "
    "one job is just to connect you with {agent_name}, our licensed "
    "adviser, who'll be calling from his personal cell phone to go over "
    "all your options with you."
)
DEFAULT_SCRIPT_NC_CLOSE = (
    "So are you available for a quick call now from {agent_name}'s cell "
    "phone, or would it be better to set up a time for later today?"
)
DEFAULT_SCRIPT_REC_OPENING = (
    "Hey {name}, this is {va_name} calling for {agent_name}, the licensed "
    "adviser working on your health coverage request. [AI: one line "
    "referencing their last touchpoint. For fast ghosts, explicitly "
    "acknowledge the live thread — e.g. '{agent_name} was just texting "
    "with you about your options and wanted me to reach out to get a time "
    "locked in.']"
)
DEFAULT_SCRIPT_REC_RECONNECT = (
    "[AI: 1-2 lines on where things left off and a natural reason to pick "
    "it back up.]"
)
DEFAULT_SCRIPT_REC_DEFLECT = (
    "{agent_name}'s got all that on his end — easiest thing is either he "
    "sends you an email with everything available in {state} so you have "
    "it in writing, or we lock in a quick time for him to call. Which "
    "works better?"
)
DEFAULT_SCRIPT_REC_ASK = (
    "So {agent_name} wanted me to reach out — would it be easier to set "
    "up a quick call with him, or would you rather he just email you the "
    "options he put together?"
)
DEFAULT_SCRIPT_PANEL_BOOKING = (
    "Works now → 'Perfect — he'll call you in just a few minutes from his "
    "personal cell, keep an eye out.'\n"
    "Later today → 'Easy — what time works? I'll lock that in and he'll "
    "call you then. You'll get it from his personal cell.'"
)
# T1: the confirmation text the AGENT sends by hand from their own phone
# (the app never sends SMS — it only reminds and tracks). Merge fields:
# {first_name} {name} {appointment_time} {agent_name} {phone} {state};
# {agent_name} comes from identity_name and {appointment_time} renders in
# the LEAD's local timezone with its zone abbreviation.
DEFAULT_APPT_CONFIRM_TEMPLATE = (
    "Hi {first_name}, this is {agent_name} — just confirming our "
    "appointment today at {appointment_time}. Looking forward to it! "
    "Reply YES to confirm, or let me know if another time works better."
)

DEFAULT_SCRIPT_PANEL_REBUTTALS = (
    "Won't set a time :: 'No problem — easiest thing then is {agent_name} "
    "sends you an email with everything available in {state} so you have "
    "it in writing. Sound good?'\n"
    "Asked about price :: '{agent_name} has all the pricing on his end — "
    "he'll go over exact numbers with you on the call or put them in the "
    "email.'\n"
    "Not interested :: 'Totally understand — before I let you go, want him "
    "to just email you the options so you have them on hand if anything "
    "changes?'\n"
    "Stop calling / DNC :: 'Understood — I'll take you off the list right "
    "away. Sorry to bother you.'"
)

# key -> dict(default=..., secret=bool)
SETTINGS_REGISTRY = {
    # NOTE: app_password_hash is retired (B3). Credentials live in the users
    # table; migration 2 moved the old password to user 'admin'.
    "gmail_address": {"default": "", "secret": False},
    "gmail_app_password": {"default": "", "secret": True},
    # B5: the agent's OWN Google Cloud OAuth client. There is no shared
    # application — one project holding every tenant's mailbox grant is
    # one credential whose compromise reaches every inbox at once. The
    # refresh token IS the credential; the short-lived access token is
    # never stored. See leadflow/gmail/oauth.py and docs/GMAIL-SETUP.md.
    "gmail_client_id": {"default": "", "secret": False},
    "gmail_client_secret": {"default": "", "secret": True},
    "gmail_refresh_token": {"default": "", "secret": True},
    # NOTE: quo_outreach_numbers is retired (B2) and the whole Quo/texting
    # key family — quo_api_key, quo_notification_number, owner_cell,
    # text_daily_cap_per_number, text_daily_global_cap — is retired (R1);
    # migration 5 deleted the rows.
    # Where owner alerts are emailed; empty falls back to gmail_address (R1).
    "owner_email": {"default": "", "secret": False},
    # PART 12: require TOTP MFA for this account's VA users too. Admins and
    # superadmins are ALWAYS required (mfa.ALWAYS_REQUIRED_ROLES) and no
    # setting can turn that off — this key only reaches the other roles.
    "mfa_required_va": {"default": False, "secret": False},
    "anthropic_api_key": {"default": "", "secret": True},
    "anthropic_model": {"default": "claude-opus-5", "secret": False},
    "booking_link": {"default": "", "secret": False},
    "booking_sender_domains": {"default": ["calendly.com", "cal.com"], "secret": False},
    # The agent's name. NOT only an email field: it is also the
    # {{agent_name}} / {agent_name} merge token in email templates, AI
    # reply drafts, VA call scripts and appointment confirmation texts, so
    # it stays its own setting rather than being folded into the signature.
    "identity_name": {"default": "", "secret": False},
    # The NPN stays a separate stored value so `email_signature` can be
    # VALIDATED against it on save — a signature that does not contain the
    # agent's own NPN is refused.
    "identity_npn": {"default": "", "secret": False},
    # PART 11: the free-text email signature that replaced the old
    # identity_title / identity_address fields. Appended to emails that
    # START a thread; replies within a thread do not carry it. The
    # unsubscribe line is NOT part of this and renders on every email.
    "email_signature": {"default": "", "secret": False},
    "email_daily_cap": {"default": 50, "secret": False},
    "new_lead_slots": {"default": 25, "secret": False},
    "followup_slots": {"default": 25, "secret": False},
    # Engaged/pipeline stale days (B4, doubled as the engaged-staleness
    # detection threshold since R-schema; editable in Caps & timing).
    "stale_days": {"default": 5, "secret": False},
    # Detection thresholds (R3 engine; editable in Caps & timing).
    "ghost_quiet_hours": {"default": 2, "secret": False},
    "hot_expire_hours": {"default": 72, "secret": False},
    "stale_quote_days": {"default": 2, "secret": False},
    # Text heat labels (R2 manual text logging; shown on the heat radio).
    "heat_label_mild": {"default": "Mild — curious / engaged",
                        "secret": False},
    "heat_label_warm": {"default": "Warm — wants options", "secret": False},
    "heat_label_hot": {"default": "Hot — wants quotes or a call now",
                       "secret": False},
    "quiet_start": {"default": "08:00", "secret": False},
    "quiet_end": {"default": "20:00", "secret": False},
    "my_timezone": {"default": "America/New_York", "secret": False},
    "system_alerts_enabled": {"default": True, "secret": False},
    "ai_tone_prompt": {"default": DEFAULT_AI_TONE_PROMPT, "secret": False},
    "unsub_secret": {"default": "", "secret": True},  # auto-generated on first access
    "public_base_url": {"default": "http://localhost:8765", "secret": False},
    "intake_lookback_hours": {"default": 24, "secret": False},
    # VA assistant (B5, resized in R-schema): queue size and the R4 slot
    # split. The master toggle that used to live here is `accounts.va_active`
    # as of PART 13 — access is the AND of two account columns and a gate
    # cannot answer half its question out of a JSON settings row.
    "va_daily_quota": {"default": 125, "secret": False},
    "va_volume_slots": {"default": 90, "secret": False},
    "va_recovery_slots": {"default": 35, "secret": False},
    # S3: no-contact window 30 -> 90 days (tenants who saved 30 keep it).
    "va_nocontact_window_days": {"default": 90, "secret": False},
    # S3: a lead enters the volume pool only once it is this old.
    "va_nocontact_min_age_hours": {"default": 6, "secret": False},
    # S3: leads within this many days of the window edge jump the line.
    "va_near_expiry_days": {"default": 7, "secret": False},
    # S3: retry rotation — comma-separated lead-local hours inside the
    # calling window; a volume lead's Nth queued day uses slot N mod len.
    "va_retry_slots": {"default": "8,9,11,13,15,17,19", "secret": False},
    # NOTE: the four twilio_* keys and the two va_call_* analytics keys are
    # RETIRED. Ancora placed and costed its own calls until the calling
    # system was removed; dialing happens in Ringy now, outside the app.
    # Their rows are deleted by migration 17.
    #
    # ATTEMPT LOGGING is what Ancora sees of a call now, so the two
    # protections that used to live in the dialer's pre-dial gate ladder
    # are settings on the LOG instead (leadflow/attempts.py).
    # A hard ceiling on logged attempts per lead per LEAD-LOCAL day.
    "max_attempts_per_lead_per_day": {"default": 3, "secret": False},
    # The double-submit window, ported from the deleted
    # twilio_client.DUPE_DIAL_SECONDS at its original value. 0 disables it.
    "attempt_dupe_seconds": {"default": 60, "secret": False},
    # DIALER BLOCK 1: how old a lead's consent may be before the dialer
    # refuses it, in days. Six months by default. DIALER ONLY — email
    # sequences and the dispatcher never read it. The default lives in
    # leadflow/consent.py so the module that enforces the rule and the
    # registry that stores it cannot drift to two different numbers.
    consent.MAX_AGE_SETTING: {"default": consent.DEFAULT_MAX_AGE_DAYS,
                              "secret": False},
    # T1 appointment confirmations (PART 6). The app NEVER sends a text:
    # these drive WHEN the agent is reminded to send one by hand and WHAT
    # it suggests they send. `appt_confirm_anchor` is a lead-local
    # time-of-day floor ("never remind before this on the appointment
    # day"); `appt_confirm_lead_hours` remind this many hours ahead. The
    # trigger is the LATER of the two.
    "appt_confirm_anchor": {"default": "08:00", "secret": False},
    "appt_confirm_lead_hours": {"default": 8, "secret": False},
    "appt_confirm_template": {"default": DEFAULT_APPT_CONFIRM_TEMPLATE,
                              "secret": False},
    # S8 pre-provision (Wave B builds the UI + gcal client): the tenant's
    # own Google OAuth client + tokens for calendar sync.
    "gcal_client_id": {"default": "", "secret": False},
    "gcal_client_secret": {"default": "", "secret": True},
    "gcal_refresh_token": {"default": "", "secret": True},
    "gcal_calendar_id": {"default": "primary", "secret": False},
    # NOTE: the six pay_* settings (pay_daily_base, pay_floor_leads,
    # pay_send_options, pay_appt_scheduled, pay_appt_showed, pay_won_bonus)
    # are retired (R-schema); migration 6 seeded pay_rates from them and
    # deleted the rows. Pay rates are versioned in the pay_rates table.
    # Referrals (R7): days after a sale to prompt each referral ask
    # (exactly 3 non-negative ascending day offsets).
    "referral_ask_days": {"default": [0, 14, 365], "secret": False},
    # VA scripts (R5): editable copy in Settings → VA scripts.
    "script_nc_opening": {"default": DEFAULT_SCRIPT_NC_OPENING,
                          "secret": False},
    "script_nc_qualify": {"default": DEFAULT_SCRIPT_NC_QUALIFY,
                          "secret": False},
    "script_nc_disclaimer": {"default": DEFAULT_SCRIPT_NC_DISCLAIMER,
                             "secret": False},
    "script_nc_close": {"default": DEFAULT_SCRIPT_NC_CLOSE, "secret": False},
    "script_rec_opening": {"default": DEFAULT_SCRIPT_REC_OPENING,
                           "secret": False},
    "script_rec_reconnect": {"default": DEFAULT_SCRIPT_REC_RECONNECT,
                             "secret": False},
    "script_rec_deflect": {"default": DEFAULT_SCRIPT_REC_DEFLECT,
                           "secret": False},
    "script_rec_ask": {"default": DEFAULT_SCRIPT_REC_ASK, "secret": False},
    "script_panel_booking": {"default": DEFAULT_SCRIPT_PANEL_BOOKING,
                             "secret": False},
    "script_panel_rebuttals": {"default": DEFAULT_SCRIPT_PANEL_REBUTTALS,
                               "secret": False},
    # OUTREACH master switch (Settings → Mode, "Paused / Live"). False =
    # paused: no sequence email, no approved reply, no dial, none of the
    # nightly passes. Settings test buttons (self-email / Anthropic ping)
    # and owner notifications keep working. Since PART 6 T2 it no longer
    # covers lead INTAKE — that is `lead_intake_enabled` below. The key
    # name and the `building_mode` dial-gate code are kept deliberately
    # (renaming them is churn that would break the gate ladder contract).
    "outreach_live": {"default": False, "secret": False},
    # LEAD INTAKE switch (PART 6 T2, Settings → Mode). Whether the app
    # creates leads from Gmail lead-source parsing. Independent of
    # outreach: an account can take leads in without sending anything, and
    # can send without taking new leads in.
    "lead_intake_enabled": {"default": False, "secret": False},
    # THE HARD CUTOFF: UTC ISO stamp of the moment intake was last switched
    # OFF -> ON. Only lead emails that ARRIVED AFTER this moment may ever
    # become leads, so weeks of build-period mail sitting in the inbox is
    # never imported retroactively. Re-saving while intake is already ON
    # must NOT move it (that would silently drop legitimate mail). Blank or
    # unparseable while enabled fails CLOSED — nothing is imported.
    "lead_intake_enabled_at": {"default": "", "secret": False},
    # AGENT LEADS. Master gate: "I am an FTA." Off by default; unlocks the
    # roster, the CSV upload and the agent-lead views. It NEVER hides money
    # (the source_agent tag on the SOLD -> premium -> commission card is
    # rendered unconditionally — a payment obligation cannot be toggled
    # away), and it CANNOT be switched off while any deletable agent lead
    # is live (routes_settings._save_agent_leads refuses).
    "fta_enabled": {"default": False, "secret": False},
    # Unworked residency for an agent lead, in days from the UPLOAD date
    # (the export carries no original lead date, so leads.received_at is
    # stamped at import). GLOBAL, not per batch. The clock STOPS at the
    # first positive contact — after that the lead is an ordinary working
    # lead and only the 90-day va_nocontact_window_days applies.
    "agent_lead_expiry_days": {"default": 14, "secret": False},
}

MASK = "••••"


def _registry_entry(key):
    entry = SETTINGS_REGISTRY.get(key)
    if entry is None:
        raise KeyError("unknown setting: %s" % key)
    return entry


def _resolve_account(account_id):
    # type: (object) -> int
    """None -> the current request/worker account (S1 per-tenant settings)."""
    if account_id is None:
        from leadflow.auth import current_account_id  # deferred: avoid cycle
        return current_account_id()
    return int(account_id)


def get_setting(key, db=None, account_id=None):
    """Return the decoded value for key (secrets decrypted); default if
    unset. Settings are PER ACCOUNT (S1): account_id=None resolves to the
    current request's account (worker code passes it explicitly)."""
    entry = _registry_entry(key)
    if db is None:
        db = get_db()
    account_id = _resolve_account(account_id)
    row = db.execute(
        "SELECT value FROM settings WHERE account_id = ? AND key = ?",
        (account_id, key)).fetchone()
    if row is None:
        if key == "unsub_secret":
            # Generates PER ACCOUNT on first access (S1).
            value = _secrets.token_hex(32)
            set_setting(key, value, db=db, account_id=account_id)
            return value
        return copy.deepcopy(entry["default"])
    value = json.loads(row["value"])
    if entry["secret"] and crypto.is_encrypted(value):
        value = crypto.decrypt(value)
    return value


def set_setting(key, value, db=None, account_id=None):
    """Store value (JSON-encoded; registered secrets encrypted at rest)
    for one account (S1; account_id=None -> current account)."""
    entry = _registry_entry(key)
    if db is None:
        db = get_db()
    account_id = _resolve_account(account_id)
    stored = value
    if entry["secret"] and isinstance(value, str) and value:
        stored = crypto.encrypt(value)
    own = not db.in_transaction
    db.execute(
        "INSERT INTO settings (account_id, key, value, is_secret, updated_at) "
        "VALUES (?,?,?,?,?) "
        "ON CONFLICT(account_id, key) DO UPDATE SET value=excluded.value, "
        "is_secret=excluded.is_secret, updated_at=excluded.updated_at",
        (account_id, key, json.dumps(stored), 1 if entry["secret"] else 0,
         utcnow()),
    )
    if own:
        db.commit()


def all_settings_masked(db=None, account_id=None):
    """Dict of every registered setting for the UI; secret values masked.
    Per account (S1; account_id=None -> current account)."""
    if db is None:
        db = get_db()
    account_id = _resolve_account(account_id)
    out = {}
    for key, entry in SETTINGS_REGISTRY.items():
        value = get_setting(key, db=db, account_id=account_id)
        if entry["secret"] and isinstance(value, str) and value:
            value = MASK + (value[-4:] if len(value) > 4 else "")
        out[key] = value
    return out
