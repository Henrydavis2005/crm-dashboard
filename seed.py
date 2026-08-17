"""Idempotent seed data: lead sources, blocklist, templates, sequence steps.

Since Part 4 (S1 multi-tenant) seeding is PER ACCOUNT: `seed_account(db,
account_id)` seeds one tenant's defaults (lead sources incl field maps +
costs, blocklist, templates, sequence steps, one pay_rates row, unsub
secret) and is called both by `seed_defaults` (account 1, first boot) and
by the /signup flow for every new account.

The default sequence is the Part 4 (S4) timing: email 1 instant, 2 day 2,
3 day 4, RUN QUOTES day 6 (step_kind 'run_quotes' — an action, not a
send; the dispatcher surfaces it as a task), 5 day 7, 6 day 31, 7 day 90. The
pre-Part-4 email_day0..38 templates live in LEGACY_TEMPLATES (migration 5
still needs email_day38; migration 9 uses the old slugs to detect
old-default sequences).
"""
import json
import logging

from leadflow.db import utcnow

logger = logging.getLogger("leadflow.seed")

LEAD_SOURCES = [
    {
        "name": "NextGen Leads",
        "sender_addresses": ["no-reply@nextgenleads.com"],
        "subject_pattern": None,
        "cost_cents": 12000,  # S5 pre-provision: $120.00 per lead
        "field_map": {
            "name_mode": "full",
            "labels": {
                "name": ["Name"],
                "phone": ["Phone Number"],
                "email": ["Email Address"],
                "city": ["City"],
                "state": ["State"],
                "zip": ["Zip"],
            },
        },
    },
    {
        "name": "USHA Marketplace",
        "sender_addresses": ["leads@ushamarketplace.com"],
        "subject_pattern": None,
        "cost_cents": 4000,  # S5 pre-provision: $40.00 per lead
        "field_map": {
            "name_mode": "split",
            "labels": {
                "first_name": ["First Name"],
                "last_name": ["Last Name"],
                "phone": ["Primary Phone"],
                "email": ["Email"],
                "city": ["City"],
                "state": ["State"],
                "zip": ["Zip"],
            },
        },
    },
]

BLOCKLIST_PLAIN = [
    "guaranteed",
    "you qualify",
    "approved",
    "free",
    "pre-existing conditions covered",
    "no cost",
    "act now",
    "risk-free",
    "UnitedHealthcare",
    "United Healthcare",
    "Aetna",
    "Cigna",
    "Humana",
    "Blue Cross",
    "Blue Shield",
    "Anthem",
    "Kaiser",
    "Ambetter",
    "Oscar",
    "Molina",
    "WellCare",
]

BLOCKLIST_REGEX = [
    r"\$\s?\d",
    r"\b\d+\s?(?:/|per\s)(?:mo|month)\b",
]

# The quote template (S4): seeded EXACTLY as the user wrote it — line
# breaks and emoji preserved. {curly} fields are hand-filled by the admin
# in the Run Quotes form (Wave B); {name} auto-fills. This template is
# deliberately non-compliant with the blocklist (carrier names, dollar
# placeholders): the S4 run_quotes send path skips the compliance filter
# by design; it is NEVER auto-sent.
QUOTE_EMAIL_BODY = """Hello {name},

Based on the information provided, I've gathered a list of health insurance options you may qualify for.

✅ Private Underwritten PPO Plans (Health-based, must qualify)
* Network: UnitedHealthcare Choice Plus PPO and PHCS PPO (widely accepted nationwide)
* Monthly cost range: ${ppo_low} to ${ppo_high} (Gold and Platinum level options)
* Highlights: These plans often offer lower premiums and broader networks for healthy individuals, but do require health qualification and are not available through the Marketplace.

I highly recommend these plans if you and your family are generally healthy. They offer excellent coverage and affordability thanks to large in-network discounts. Plan pricing and availability vary by zip code and are subject to medical underwriting.

✅ Marketplace (ObamaCare) Plans
* Carriers: Ambetter, BCBS, WellFirst Health, Cigna
* Monthly cost range: ${mkt_low} to ${mkt_high} (Bronze, Silver, Gold options)
* Highlights: Guaranteed issue, no health questions required, so premiums are typically higher because these plans cover everyone, regardless of health.

⚠️ Private - Short-term / Discount / Share Plans
* Carriers: Chubb, GoldenRule, Aetna/National General, First Health
* Monthly cost range: ${short_low} to ${short_high}
* Note: These are not true full coverage plans. They don't offer catastrophic protection, so I generally don't recommend them. These plans are not minimum essential coverage as defined by the Affordable Care Act and may not include all mandated benefits.

\U0001f31f Personally, I have a plan through the UnitedHealthcare Choice Plus PPO with no deductible. The plan I'm seeing has a monthly cost of ${recommended}. Would you like more details on this plan?

________________________________________________________
\U0001f4a1 Key things to consider when choosing coverage:
1️⃣ Deductible – What you pay before the insurance starts paying.
2️⃣ Network type – PPOs are accepted by about 95% of doctors/hospitals; HMO/EPO networks are much more limited.
3️⃣ Out-of-pocket maximum – The most you'll ever pay in a year

It's not just about the insurance company name — the details of the plan are what protect you.
Let me know if you'd like to explore these options further!"""

TEMPLATES = [
    {
        "slug": "email_1",
        "name": "Email 1 (instant)",
        "channel": "email",
        "subject": "Your health coverage options, {{first_name}}",
        "body": (
            "Hi {{first_name}},\n\n"
            "Thanks for requesting information about health coverage - I "
            "just received your inquiry. I'm a licensed agent, and my job "
            "is to narrow the options down to the two or three that "
            "actually fit your situation.\n\n"
            "I'm pulling together what's available to you in {{state}} "
            "right now. Want me to send those quotes over by email so you "
            "have everything in writing?"
        ),
    },
    {
        "slug": "email_2",
        "name": "Email 2 (day 2)",
        "channel": "email",
        "subject": "Want me to send those quotes over, {{first_name}}?",
        "body": (
            "Hi {{first_name}},\n\n"
            "Just following up on your health coverage request from the "
            "other day. I have your options ready to go on my end.\n\n"
            "Want me to send those quotes over by email? Just reply "
            "\"yes\" and I'll get them right out to you."
        ),
    },
    {
        "slug": "email_3",
        "name": "Email 3 (day 4)",
        "channel": "email",
        "subject": "Still comparing coverage, {{first_name}}?",
        "body": (
            "Hi {{first_name}},\n\n"
            "I don't want your request to slip through the cracks - most "
            "people tell me comparing plans on their own is the hard "
            "part, and that's exactly what I do all day.\n\n"
            "Should I email you the quotes I put together for {{state}}? "
            "One quick reply and they're yours - no obligation either way."
        ),
    },
    {
        # S4: attached to the day-6 RUN QUOTES step (step_kind
        # 'run_quotes'). Never auto-sent; the admin hand-fills the {curly}
        # dollar fields in the Run Quotes form (Wave B).
        "slug": "quote_email",
        "name": "Quote email (Run Quotes)",
        "channel": "email",
        "subject": "Health insurance options for {name}",
        "body": QUOTE_EMAIL_BODY,
    },
    {
        # S4 email 5 (day 7): follows up on the quote thread. Body wording
        # is the user's exact text; sends on the quote thread in Wave B.
        "slug": "email_5_nudge",
        "name": "Email 5 (day 7 nudge)",
        "channel": "email",
        "subject": "Following up on your options",
        # {{first_name}} in DOUBLE braces, like every other sequence
        # template. It shipped as single-brace {name}, which render_tpl
        # never substitutes, so this went out reading "Hi {name},” — the
        # message a lead reads the day after receiving real prices.
        # Migration 13 repairs tenants still holding the broken default.
        "body": (
            "Hi {{first_name}}, just following up on the options I sent "
            "over — would you like more details on the plan I recommended?"
        ),
    },
    {
        "slug": "email_6",
        "name": "Email 6 (day 31)",
        "channel": "email",
        "subject": "Checking back on the options I sent, {{first_name}}",
        "body": (
            "Hi {{first_name}},\n\n"
            "It's been a few weeks since I sent over the options for your "
            "health coverage request, so I wanted to check back in. "
            "Situations change, and that's completely fine either way.\n\n"
            "If you'd like me to take another look - or walk you through "
            "the options I sent over - just reply with a good time and "
            "I'll make it easy."
        ),
    },
    {
        "slug": "email_7",
        "name": "Email 7 (day 90)",
        "channel": "email",
        "subject": "Last note from me, {{first_name}}",
        "body": (
            "Hi {{first_name}},\n\n"
            "This is my last note about the health coverage request you "
            "sent in. The options I sent over may have changed by now, "
            "but if you're still looking I'm glad to pull a fresh set "
            "together - just reply and I'll jump right on it.\n\n"
            "If the timing never worked out, no worries at all - I'll "
            "leave you be. Wishing you the best either way."
        ),
    },
    {
        "slug": "holding_line",
        "name": "Quote holding line",
        "channel": "email",
        "subject": None,
        "body": (
            "Perfect - I'll pull your options together today and get back to "
            "you shortly."
        ),
    },
    {
        "slug": "fallback_reply",
        "name": "Fallback reply",
        "channel": "email",
        "subject": None,
        "body": "Thanks for reaching out - I'll get back to you shortly.",
    },
    {
        # R-schema: the R7 referral track renders this for each due ask.
        # Compliant: no prices, no carrier names, no guaranteed/free/
        # approved/you qualify.
        "slug": "referral_ask",
        "name": "Referral ask",
        "channel": "email",
        "subject": "A quick favor, {{first_name}}?",
        "body": (
            "Hi {{first_name}},\n\n"
            "It was a pleasure helping you get your health coverage in "
            "place. A quick favor: most of the people I work with come "
            "through introductions from clients like you.\n\n"
            "If a friend or family member is shopping for coverage or "
            "just has questions about their options, would you mind "
            "passing along my info, or replying with theirs? I'll take "
            "good care of them, no pressure either way.\n\n"
            "Thanks again for trusting me with your coverage - I'm here "
            "whenever you need anything.\n\n"
            "{{agent_name}}"
        ),
    },
]

# Pre-Part-4 default templates. Migration 5 (R1) seeds email_day38 from
# here; migration 9 (S4 timing) uses the slugs to detect an old-default
# sequence. Never seeded on fresh installs anymore.
LEGACY_TEMPLATES = [
    {
        "slug": "email_day0",
        "name": "Day 0 email",
        "channel": "email",
        "subject": "Your health coverage options, {{first_name}}",
        "body": (
            "Hi {{first_name}},\n\n"
            "Thanks for requesting information about health coverage - I just "
            "received your inquiry. I'm a licensed agent, and my job is to "
            "narrow the options down to the two or three that actually fit "
            "your situation.\n\n"
            "I'll try you by phone shortly, but if it's easier, just reply "
            "with a good time to talk and I'll work around your schedule.\n\n"
            "What questions can I answer first?"
        ),
    },
    {
        "slug": "email_day6",
        "name": "Day 6 email",
        "channel": "email",
        "subject": "Still comparing coverage options, {{first_name}}?",
        "body": (
            "Hi {{first_name}},\n\n"
            "I wanted to follow up on the health coverage request you sent in "
            "earlier this week. Most people tell me the options feel "
            "overwhelming on their own - it goes a lot faster with someone "
            "who looks at them every day.\n\n"
            "If phone tag is a pain, you can grab a time that works for you "
            "here: {{booking_link}}\n\n"
            "Happy to help either way."
        ),
    },
    {
        "slug": "email_day14",
        "name": "Day 14 email",
        "channel": "email",
        "subject": "Checking in on your coverage search",
        "body": (
            "Hi {{first_name}},\n\n"
            "Just checking in - are you still looking into health coverage? "
            "Situations change, and that's completely fine either way.\n\n"
            "If you are, I can walk you through what's available in your area "
            "and help you compare, no pressure. Reply with a good time and "
            "I'll make it easy."
        ),
    },
    {
        "slug": "email_day28",
        "name": "Day 28 email",
        "channel": "email",
        "subject": "Should I keep your file open, {{first_name}}?",
        "body": (
            "Hi {{first_name}},\n\n"
            "I don't want to clutter your inbox. If you're still weighing "
            "your health coverage options, I'm glad to help you sort through "
            "them - a short call is usually all it takes to get clarity.\n\n"
            "If now isn't the right time, just say so and I'll check back "
            "down the road. Either way, thanks for your time."
        ),
    },
    {
        "slug": "email_day38",
        "name": "Day 38 email",
        "channel": "email",
        "subject": "Last note from me, {{first_name}}",
        "body": (
            "Hi {{first_name}},\n\n"
            "This is my last note about the health coverage request you sent "
            "in. If you'd still like help comparing what's available in your "
            "area, just reply and I'll jump right on it.\n\n"
            "If the timing never worked out, no worries at all - I'll leave "
            "you be. Wishing you the best either way."
        ),
    },
]

# The pre-Part-4 default sequence (R1 seed): used by migration 9 to detect
# sequences that still match the old defaults (customized ones are left
# alone).
OLD_DEFAULT_STEPS = [
    (0, "email_day0"),
    (6, "email_day6"),
    (14, "email_day14"),
    (28, "email_day28"),
    (38, "email_day38"),
]

# Fresh-install pay rates (cents), matching migration 6's seeded row:
# $20 base at a 125-lead floor, $2.50 send-options, $2.50 scheduled,
# $5 showed, $10 sold bonus, effective since the epoch.
PAY_RATE_DEFAULTS = {
    "effective_date": "1970-01-01",
    "daily_base_cents": 2000,
    "floor_leads": 125,
    "send_options_cents": 250,
    "appt_scheduled_cents": 250,
    "appt_showed_cents": 500,
    "sold_bonus_cents": 1000,
}

# (day_offset, channel, template_slug, sort_order, step_kind) — the S4
# default timing. The day-6 step is RUN QUOTES: an action, not a send
# (step_kind 'run_quotes'; the dispatcher surfaces it as an admin task).
SEQUENCE_STEPS = [
    (0, "email", "email_1", 1, "email"),
    (2, "email", "email_2", 2, "email"),
    (4, "email", "email_3", 3, "email"),
    (6, "email", "quote_email", 4, "run_quotes"),
    (7, "email", "email_5_nudge", 5, "email"),
    (31, "email", "email_6", 6, "email"),
    (90, "email", "email_7", 7, "email"),
]


def seed_account(db, account_id):
    """Seed one account's defaults (S1): lead sources, blocklist,
    templates, sequence steps, one pay_rates row, unsub secret.
    Idempotent per account. Never commits inside a caller's transaction."""
    own = not db.in_transaction
    now = utcnow()

    for src in LEAD_SOURCES:
        row = db.execute(
            "SELECT id FROM lead_sources WHERE account_id = ? AND name = ?",
            (account_id, src["name"])).fetchone()
        if row is None:
            db.execute(
                "INSERT INTO lead_sources "
                "(account_id, name, enabled, sender_addresses, "
                " subject_pattern, field_map, cost_cents, created_at, "
                " updated_at) VALUES (?,?,1,?,?,?,?,?,?)",
                (
                    account_id,
                    src["name"],
                    json.dumps(src["sender_addresses"]),
                    src["subject_pattern"],
                    json.dumps(src["field_map"]),
                    src.get("cost_cents", 0),
                    now,
                    now,
                ),
            )

    for phrase in BLOCKLIST_PLAIN:
        row = db.execute(
            "SELECT id FROM blocklist WHERE account_id = ? AND phrase = ? "
            "AND is_regex = 0", (account_id, phrase)).fetchone()
        if row is None:
            db.execute(
                "INSERT INTO blocklist (account_id, phrase, is_regex, "
                "enabled) VALUES (?,?,0,1)", (account_id, phrase))
    for pattern in BLOCKLIST_REGEX:
        row = db.execute(
            "SELECT id FROM blocklist WHERE account_id = ? AND phrase = ? "
            "AND is_regex = 1", (account_id, pattern)).fetchone()
        if row is None:
            db.execute(
                "INSERT INTO blocklist (account_id, phrase, is_regex, "
                "enabled) VALUES (?,?,1,1)", (account_id, pattern))

    template_ids = seed_templates(db, account_id, TEMPLATES, now)

    # Sequence steps are user-editable; only seed when the account has none.
    count = db.execute(
        "SELECT COUNT(*) AS n FROM sequence_steps WHERE account_id = ?",
        (account_id,)).fetchone()["n"]
    if count == 0:
        for day_offset, channel, slug, sort_order, step_kind in SEQUENCE_STEPS:
            db.execute(
                "INSERT INTO sequence_steps "
                "(account_id, day_offset, channel, template_id, sort_order, "
                " enabled, step_kind) VALUES (?,?,?,?,?,1,?)",
                (account_id, day_offset, channel, template_ids[slug],
                 sort_order, step_kind),
            )

    # Pay rates: one tenant-default row per account (user_id NULL).
    if db.execute("SELECT 1 FROM pay_rates WHERE account_id = ? LIMIT 1",
                  (account_id,)).fetchone() is None:
        pr = PAY_RATE_DEFAULTS
        db.execute(
            "INSERT INTO pay_rates (account_id, user_id, effective_date, "
            "daily_base_cents, floor_leads, send_options_cents, "
            "appt_scheduled_cents, appt_showed_cents, sold_bonus_cents, "
            "created_at) VALUES (?,NULL,?,?,?,?,?,?,?,?)",
            (account_id, pr["effective_date"], pr["daily_base_cents"],
             pr["floor_leads"], pr["send_options_cents"],
             pr["appt_scheduled_cents"], pr["appt_showed_cents"],
             pr["sold_bonus_cents"], now))

    if own:
        db.commit()

    # Ensure the account's unsubscribe secret exists from the start.
    from leadflow.settings import get_setting
    get_setting("unsub_secret", db=db, account_id=account_id)


def seed_templates(db, account_id, templates, now=None):
    """Seed missing templates rows for one account; returns slug -> id for
    every listed slug (existing or created). Never commits."""
    if now is None:
        now = utcnow()
    template_ids = {}
    for tpl in templates:
        row = db.execute(
            "SELECT id FROM templates WHERE account_id = ? AND slug = ?",
            (account_id, tpl["slug"])).fetchone()
        if row is None:
            cur = db.execute(
                "INSERT INTO templates (account_id, slug, name, channel, "
                "subject, body, updated_at) VALUES (?,?,?,?,?,?,?)",
                (account_id, tpl["slug"], tpl["name"], tpl["channel"],
                 tpl["subject"], tpl["body"], now),
            )
            template_ids[tpl["slug"]] = cur.lastrowid
        else:
            template_ids[tpl["slug"]] = row["id"]
    return template_ids


# PART 12 Step 9: the legal document registry seed.
# v2, 2026-08-14. The scheme is csa-<standard terms version>-<product>-<date>;
# v1 was published earlier the same day, so the suffix disambiguates rather
# than inventing a second date. Bumping this string is the WHOLE mechanism:
# seed_legal_documents is idempotent by version, so a new value publishes a
# new row, stands v1 down, and re-gates every account at its next request.
# v1 keeps its text, its hash and its acceptances forever.
#
# What changed in v2:
#   - The Cover Page said calling functionality "is not available to customer
#     accounts", which implies a provider-side dialer that has never existed
#     for anyone (tests/test_no_dial_path.py guards that). Replaced with a
#     statement of what the service does: it places no calls, and displays
#     numbers for the Customer to dial themselves.
#   - Access to the VA plan no longer references an access code. Redemption
#     was removed in PART 13 Stage 1; the operator enables the plan directly.
#   - The Provider signature block carries the full legal name.
#   - The product is named Ancora throughout.
CSA_VERSION = "csa-2.1-ancora-2026-08-15-v3"
# ORDER MATTERS. The Cover Page comes FIRST because it controls over the
# Standard Terms on any inconsistency, and because a tenant should meet
# the business terms — plan, fees, what the service does — before the
# boilerplate. The two files are one document, not two.
CSA_PARTS = ("docs/legal/csa-cover-page.md", "docs/legal/standard-terms-2.1.md")


def csa_text():
    """The CSA as one document, read from the repository at seed time.

    Read ONCE, here, and then stored in the registry row. After that the
    files are documentation and the ROW is the legal instrument: editing
    a file cannot change what anybody agreed to, and losing one cannot
    make an acceptance unreadable.
    """
    import pathlib as _p
    root = _p.Path(__file__).resolve().parent.parent
    parts = []
    for rel in CSA_PARTS:
        path = root / rel
        parts.append(path.read_text(encoding="utf-8").strip())
    return "\n\n".join(parts) + "\n"


def seed_legal_documents(db):
    """Publish the CSA, and create the DPA as an INACTIVE slot.

    Idempotent by version: re-running does not republish, so seeding can
    never supersede a live document with an identical copy of itself and
    re-gate every account for nothing.
    """
    from leadflow import agreements
    if agreements.by_version(db, "csa", CSA_VERSION) is None:
        try:
            agreements.publish(db, "csa", CSA_VERSION, csa_text())
        except (OSError, ValueError):
            logger.exception("could not seed the CSA; leaving the registry "
                             "empty rather than publishing a partial one")
    # The DPA exists as a SLOT: a row with no text and active = 0, so the
    # shape is there without gating signup on a blank page. It cannot be
    # switched on until it has text — the CHECK constraint refuses.
    if agreements.by_version(db, "dpa", "unpublished") is None:
        # sha256 is ALWAYS the hash of `text`, including when the text is
        # empty. Storing '' instead would make "the hash of this row's
        # text" true for every row except one, and a rule with an
        # exception is not a rule anybody can check.
        db.execute(
            "INSERT INTO legal_documents (slug, version, text, sha256, "
            "active, published_at) VALUES ('dpa','unpublished','',?,0,?)",
            (agreements.sha256(""), utcnow()))


def seed_defaults(db):
    """First-boot seeding: account 1 + its defaults. Idempotent."""
    own = not db.in_transaction
    now = utcnow()

    # Default account (B3): fresh installs need account 1 to exist before the
    # first user is created at /setup; migrations seed it on existing DBs.
    #
    # Account 1 is the OPERATOR account, the one /setup bootstraps. It is
    # eligible and active by definition: there is nobody above it to grant
    # it anything. Every OTHER account is
    # created by /signup and takes the column defaults of 0 — PART 13
    # removed the access code that used to let a tenant grant itself
    # eligibility, so the only path to va_eligible is the operator.
    # B3: and it is a TEAM MANAGER, on a fresh install exactly as
    # migration 30 makes it one on an upgraded database. A schema change
    # goes in both paths or the two installs diverge — here that would
    # mean /team existing on every upgraded install and on no fresh one.
    db.execute(
        "INSERT OR IGNORE INTO accounts (id, name, status, va_eligible, "
        "va_active, team_role, created_at) "
        "VALUES (1, 'Default', 'active', 1, 1, 'manager', ?)", (now,))
    # ...and if account 1 already existed (the INSERT is OR IGNORE), make
    # sure it still carries the role. A database created between B3's
    # schema landing and this line would otherwise keep the column default.
    db.execute("UPDATE accounts SET team_role = 'manager' "
               "WHERE id = 1 AND team_role != 'manager'")

    seed_account(db, 1)

    seed_legal_documents(db)
    if own:
        db.commit()
