PRAGMA journal_mode=WAL;

-- Settings are PER ACCOUNT since Part 4 (S1 multi-tenant).
CREATE TABLE IF NOT EXISTS settings (
  account_id INTEGER NOT NULL DEFAULT 1,
  key TEXT NOT NULL,
  value TEXT NOT NULL,           -- JSON-encoded
  is_secret INTEGER NOT NULL DEFAULT 0,
  updated_at TEXT NOT NULL,
  PRIMARY KEY (account_id, key)
);

CREATE TABLE IF NOT EXISTS lead_sources (
  id INTEGER PRIMARY KEY,
  account_id INTEGER NOT NULL DEFAULT 1,
  name TEXT NOT NULL,
  enabled INTEGER NOT NULL DEFAULT 1,
  sender_addresses TEXT NOT NULL,   -- JSON array of email addresses
  subject_pattern TEXT,             -- optional regex; NULL = any subject
  field_map TEXT NOT NULL,          -- JSON, see parser section
  cost_cents INTEGER NOT NULL DEFAULT 0,  -- S5: per-lead cost snapshot source
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  UNIQUE(account_id, name)
);

CREATE TABLE IF NOT EXISTS leads (
  id INTEGER PRIMARY KEY,
  account_id INTEGER NOT NULL DEFAULT 1,
  source_id INTEGER REFERENCES lead_sources(id),
  first_name TEXT NOT NULL DEFAULT '',
  last_name TEXT NOT NULL DEFAULT '',
  email TEXT,                       -- lowercased; NULL if missing
  phone TEXT,                       -- '000-000-0000' (leadflow.phone.normalize_phone,
                                    -- THE storage format); NULL if missing/invalid.
                                    -- NOT E.164: that survives in exactly one place,
                                    -- the carrier boundary, where `to_e164` converts.
                                    -- Suppression matching compares DIGITS and depends
                                    -- on this column not being re-normalised.
  city TEXT, state TEXT, zip TEXT,
  timezone TEXT NOT NULL DEFAULT 'America/New_York',
  metadata TEXT NOT NULL DEFAULT '{}',  -- JSON of all parsed label/value pairs
  stage TEXT NOT NULL DEFAULT 'new',    -- engine-internal: new|active|replied|quote|booked|exhausted|suppressed
  sequence_halted INTEGER NOT NULL DEFAULT 0,
  outreach_number TEXT,             -- historical (pre-R1 texting era); no new writers
  outreach_email TEXT,              -- pinned mailbox address, set at first successful email send
  phone_bad INTEGER NOT NULL DEFAULT 0,  -- set by call disposition bad_number ('Wrong Number');
                                    -- phone_bad=1 AND closed_state IS NULL == Needs Review (C2a, derived)
  pipeline_stage TEXT NOT NULL DEFAULT 'cold',  -- B11 computed, one of three LANES:
                                    --   COLD      cold  (no stages; told apart by age bucket)
                                    --   WORKING   engaged|quote|appointment|client
                                    --   NEGATIVE  not_interested|wrong_person|ghosted|
                                    --             bad_number|do_not_call|revoked
                                    -- The lane is derived from the stage and the Cold age
                                    -- bucket from received_at; NEITHER is stored. This
                                    -- DEFAULT only reaches a FRESH database — an upgraded
                                    -- one still carries B4's DEFAULT 'new', because SQLite
                                    -- cannot alter a column default without rebuilding the
                                    -- table. Every INSERT INTO leads therefore names this
                                    -- column explicitly, and a test enforces that it does.
  pipeline_stage_at TEXT,           -- UTC ISO of the last pipeline_stage change
  closed_state TEXT,                -- NULL|'sold'|'dead'|'no_number' (manual/admin; 'dead' also set by
                                    -- the C1 not_qualified disposition, 'no_number' by C2a's
                                    -- "can't find a real number" action). No CHECK constraint.
  hot_since TEXT,                   -- UTC ISO; stamped by hot signals, drives ghost detection (R3)
  followup_on TEXT,                 -- YYYY-MM-DD; the admin's own pending follow-up (R3)
  followup_note TEXT,
  referred_by INTEGER REFERENCES leads(id),  -- the referring client (R7; referral firewall)
  cost_cents INTEGER,               -- S5: cost snapshot at intake (NULL = unknown)
  -- PART 13 Stage 2: this lead's automated sequence was ended by a
  -- BILLING PAUSE and never resumes. NOT `sequence_halted` on purpose —
  -- a pause is not a pipeline halt, the tenant did nothing wrong, and
  -- showing twelve leads as "halted" would send them hunting for a
  -- cause. It is set once, at the pause, and is PERMANENT: paying again
  -- resumes intake, not this lead's sequence. `schedule_lead` refuses a
  -- lead carrying it, which is what makes "do not recreate the canceled
  -- rows by any path" structural rather than a promise.
  manual_only_at TEXT,
  source_agent TEXT,                -- agent-lead tag: the source agent's NAME,
                                    -- snapshotted at import (the roster row may be
                                    -- deleted; a sold lead's obligation may not).
                                    -- NULL = an ordinary bought lead. NOT referred_by.
  -- DIALER BLOCK 1: when this person consented to be contacted, as
  -- YYYY-MM-DD, or NULL for "we do not know". Every intake path derives
  -- it from something the LEAD supplied — the inquiry's own timestamp,
  -- or a column in the uploaded file, or a date the uploader typed. No
  -- path defaults it to today: a manufactured consent date is worse than
  -- none, because none refuses the call and a fake one authorises it.
  -- NULL is treated exactly like an expired date at the dialer.
  -- See leadflow/consent.py.
  consent_date TEXT,
  received_at TEXT NOT NULL,        -- lead email Date (UTC)
  created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_leads_email ON leads(email);
CREATE INDEX IF NOT EXISTS idx_leads_phone ON leads(phone);
-- idx_leads_source_agent is NOT here on purpose: source_agent arrives by
-- migration 14 on an existing DB, and schema.sql runs BEFORE migrations,
-- so an index over that column fails on every upgrade. It lives in
-- db._ensure_partial_indexes, which runs after both paths have the column.

CREATE TABLE IF NOT EXISTS templates (
  id INTEGER PRIMARY KEY,
  account_id INTEGER NOT NULL DEFAULT 1,
  slug TEXT NOT NULL,               -- e.g. 'email_1', 'quote_email', 'holding_line'
  name TEXT NOT NULL,
  channel TEXT NOT NULL,            -- email (text retired in R1)
  subject TEXT,                     -- supports {{first_name}} etc.
  body TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  UNIQUE(account_id, slug)
);

CREATE TABLE IF NOT EXISTS sequence_steps (
  id INTEGER PRIMARY KEY,
  account_id INTEGER NOT NULL DEFAULT 1,
  day_offset INTEGER NOT NULL,
  channel TEXT NOT NULL,            -- email (text retired in R1)
  template_id INTEGER NOT NULL REFERENCES templates(id),
  sort_order INTEGER NOT NULL,
  enabled INTEGER NOT NULL DEFAULT 1,
  step_kind TEXT NOT NULL DEFAULT 'email'  -- S4: email | run_quotes
);

CREATE TABLE IF NOT EXISTS messages (
  id INTEGER PRIMARY KEY,
  account_id INTEGER NOT NULL DEFAULT 1,
  lead_id INTEGER REFERENCES leads(id),
  direction TEXT NOT NULL,          -- out|in
  channel TEXT NOT NULL,            -- email ('text' on historical pre-R1 rows)
  kind TEXT NOT NULL,               -- sequence|reply|holding|first_touch (out) | lead|bounce (in)
  step_id INTEGER REFERENCES sequence_steps(id),
  template_id INTEGER REFERENCES templates(id),
  subject TEXT, body TEXT NOT NULL,
  status TEXT NOT NULL,             -- pending|sending|sent|failed|blocked|canceled|skipped|bounced|draft|received
  due_at TEXT,                      -- when a pending outbound becomes eligible
  is_first_touch INTEGER NOT NULL DEFAULT 0,
  external_id TEXT,                 -- SMTP Message-ID (legacy text ids on old rows)
  classification TEXT,              -- inbound only
  classification_evidence TEXT,
  quote_request INTEGER NOT NULL DEFAULT 0,
  error TEXT,
  channel_id INTEGER,               -- send_channels row used for the send (out only)
  in_reply_to TEXT,                 -- S4: parent Message-ID for threaded sends
  created_at TEXT NOT NULL,
  sent_at TEXT
);
CREATE UNIQUE INDEX IF NOT EXISTS uq_messages_lead_step
  ON messages(lead_id, step_id) WHERE step_id IS NOT NULL AND status != 'canceled' AND status != 'skipped';
CREATE INDEX IF NOT EXISTS idx_messages_status_due ON messages(status, due_at);
CREATE INDEX IF NOT EXISTS idx_messages_lead ON messages(lead_id);

CREATE TABLE IF NOT EXISTS approvals (
  id INTEGER PRIMARY KEY,
  account_id INTEGER NOT NULL DEFAULT 1,
  lead_id INTEGER NOT NULL REFERENCES leads(id),
  message_id INTEGER NOT NULL REFERENCES messages(id),  -- the draft
  code TEXT,                                -- legacy SMS code (unused; written NULL since R1)
  status TEXT NOT NULL DEFAULT 'pending',  -- pending|approved|revoked|expired
  approved_via TEXT,                        -- web ('sms' on historical rows)
  compliance_warning TEXT,                  -- non-NULL if draft trips blocklist
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  resolved_at TEXT
);
CREATE UNIQUE INDEX IF NOT EXISTS uq_approvals_active_code ON approvals(code) WHERE status = 'pending' AND code IS NOT NULL;

CREATE TABLE IF NOT EXISTS suppressions (
  id INTEGER PRIMARY KEY,
  account_id INTEGER NOT NULL DEFAULT 1,
  email TEXT, phone TEXT,
  lead_id INTEGER REFERENCES leads(id),
  reason TEXT NOT NULL,             -- unsubscribe|stop|not_interested|hard_bounce|manual
  reversible INTEGER NOT NULL DEFAULT 0,
  note TEXT,
  created_at TEXT NOT NULL
);
-- B4 PER-STATE LICENSURE. One row per (account, state).
--
-- TWO SHAPES, ONE TABLE. An AGENT's row carries a number, an expiry and
-- optionally a scan, and the expiry drives warnings and blocking. The
-- OPERATOR's is a plain checklist: a state and nothing else, where
-- `expires_on IS NULL` means "does not expire" and never warns or
-- blocks. The DATA carries the distinction so there is one code path.
--
-- `pdf_filename` is a RANDOMISED name inside data/licenses/ (gitignored
-- with the rest of data/). It carries nothing — not the account, not the
-- state, not what the uploader called it — because a directory listing
-- of licence scans must not itself be a list of who is licensed where.
-- NOTHING IN THIS APPLICATION PARSES THE FILE.
--
-- leadflow/licensure.py is the only writer, and the only reader of the
-- rules built on it.
CREATE TABLE IF NOT EXISTS licenses (
  id INTEGER PRIMARY KEY,
  account_id INTEGER NOT NULL,
  state TEXT NOT NULL,              -- two letters, upper case
  license_number TEXT,
  expires_on TEXT,                  -- YYYY-MM-DD; NULL = never expires
  pdf_filename TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  created_by INTEGER
);
CREATE UNIQUE INDEX IF NOT EXISTS uq_licenses_account_state
  ON licenses(account_id, state);

-- B6 SEND TO VA. The record that a lead was handed to the team's call
-- queue, and the enforcement of "no duplicate phone ever reaches it".
--
-- UNIQUE(team_account_id, phone) IS the duplicate rule. First send wins;
-- the second agent's send is refused by the DATABASE rather than by a
-- check that two simultaneous requests could both pass. That agent keeps
-- the lead and works it by email.
--
-- team_account_id is the MANAGER's account (leadflow/va_send.team_root),
-- so two agents on one team may not both send a number and two agents on
-- different teams may.
--
-- phone is 000-000-0000, like every other telephone column since B6.
CREATE TABLE IF NOT EXISTS va_sends (
  id INTEGER PRIMARY KEY,
  team_account_id INTEGER NOT NULL,
  account_id INTEGER NOT NULL,
  lead_id INTEGER NOT NULL,
  phone TEXT NOT NULL,
  sent_by INTEGER,
  created_at TEXT NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS uq_va_sends_team_phone
  ON va_sends(team_account_id, phone);
CREATE UNIQUE INDEX IF NOT EXISTS uq_va_sends_lead ON va_sends(lead_id);

CREATE INDEX IF NOT EXISTS idx_suppr_email ON suppressions(email);
CREATE INDEX IF NOT EXISTS idx_suppr_phone ON suppressions(phone);

-- DIALER BLOCK 2: a revocation is a PERMANENT record, enforced by the
-- database and not only by the code above it. Same shape as the
-- legal_documents and document_acceptances triggers, for the same reason:
-- `suppression.unsuppress` refusing a reversible = 0 row is the rule, and
-- these are what make a bug in that rule fail loudly instead of quietly
-- deleting the record of somebody asking to be left alone.
--
-- Only the three REVOCATION reasons are protected. A `not_interested` or
-- `manual` row is still deletable, which is the whole point of it being
-- reversible. The reason list is duplicated from
-- leadflow/suppression.REVOCATION_REASONS and a test fails if the two
-- ever disagree.
CREATE TRIGGER IF NOT EXISTS suppressions_revocation_no_delete
BEFORE DELETE ON suppressions
WHEN OLD.reason IN ('unsubscribe', 'do_not_call', 'stop')
BEGIN
  SELECT RAISE(ABORT, 'a revocation is permanent: this person asked to be left alone');
END;

-- `reason` and `reversible` are frozen once a row is a revocation, so it
-- cannot be laundered into a reversible row and then deleted. Everything
-- else about the row (note, and the lead_id that reset.py nulls) stays
-- writable — the compliance record survives a reset by design.
--
-- B8 ADDED `account_id` TO THE FROZEN LIST (migration 34). A revocation is
-- global now, so that column no longer decides who the row binds; it is
-- pure record — the answer to "who were they told" — and that is exactly
-- what makes it worth freezing. `reset.py` only ever sets `lead_id = NULL`
-- on these rows, so nothing legitimate writes it.
CREATE TRIGGER IF NOT EXISTS suppressions_revocation_stays_permanent
BEFORE UPDATE ON suppressions
WHEN OLD.reason IN ('unsubscribe', 'do_not_call', 'stop')
 AND (NEW.reversible != 0 OR NEW.reason != OLD.reason
      OR NEW.email IS NOT OLD.email OR NEW.phone IS NOT OLD.phone
      OR NEW.account_id != OLD.account_id)
BEGIN
  SELECT RAISE(ABORT, 'a revocation is permanent: its reason, contact details and originating account cannot change');
END;

-- PK (account_id, gmail_message_id): two tenants may legitimately both
-- receive an email carrying the same Message-ID (S1 accepted decision).
CREATE TABLE IF NOT EXISTS processed_emails (
  account_id INTEGER NOT NULL DEFAULT 1,
  gmail_message_id TEXT NOT NULL,      -- RFC822 Message-ID header
  uid INTEGER,
  kind TEXT NOT NULL,                  -- lead|reply|bounce|booking|ignored|dead_letter
                                       -- |intake_off|pre_intake (T2: a lead-source email
                                       -- refused by the intake gate — recorded so it is
                                       -- permanently seen and never reconsidered)
  lead_id INTEGER,
  processed_at TEXT NOT NULL,
  PRIMARY KEY (account_id, gmail_message_id)
);

CREATE TABLE IF NOT EXISTS dead_letters (
  id INTEGER PRIMARY KEY,
  account_id INTEGER NOT NULL DEFAULT 1,
  source_id INTEGER,
  from_addr TEXT, subject TEXT,
  -- BLOCK 2: THE MESSAGE BODY IS NOT STORED. `raw_body` held the vendor
  -- email verbatim so a re-parse could re-run over it, which meant every
  -- lead email that failed to parse deposited that vendor's medical
  -- conditions, tobacco use, height and weight into this table — and
  -- /dead-letters rendered the lot in a <pre>. The app working exactly as
  -- designed was the leak, not anything the tenant did.
  --
  -- What is kept is the DIAGNOSIS: the LABEL NAMES the parser found, with
  -- no values at all. That is the actionable half — a parse failure is
  -- almost always a field_map that names labels the vendor does not use,
  -- and comparing expected labels to found labels is how it is fixed.
  labels_found TEXT,                   -- JSON array of label names, no values
  -- The message's own id, so a corrected field_map can requeue it: the
  -- re-parse clears the `processed_emails` mark and rewinds the poll
  -- cursor, and the NEXT poll re-ingests the real message through the one
  -- real intake pipeline. See routes_settings.requeue_source.
  gmail_message_id TEXT,
  error TEXT,
  status TEXT NOT NULL DEFAULT 'open', -- open|resolved|requeued
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS blocklist (
  id INTEGER PRIMARY KEY,
  account_id INTEGER NOT NULL DEFAULT 1,
  phrase TEXT NOT NULL,
  is_regex INTEGER NOT NULL DEFAULT 0,
  enabled INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS notifications (
  id INTEGER PRIMARY KEY,
  account_id INTEGER NOT NULL DEFAULT 1,
  ntype TEXT NOT NULL,                 -- approval|quote|booking|bounce_pause|recovery|referral|task|system
  subtype TEXT,                        -- for system rate limiting
  body TEXT NOT NULL,
  status TEXT NOT NULL,                -- owner-EMAIL outcome: sent|failed|skipped
  lead_id INTEGER,                     -- optional lead the alert is about
  read_at TEXT,                        -- NULL = unread in the notification center
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS events (
  id INTEGER PRIMARY KEY,
  account_id INTEGER NOT NULL DEFAULT 1,
  lead_id INTEGER,
  user_id INTEGER,                     -- acting user; NULL = system/worker
  etype TEXT NOT NULL,                 -- lead_created|re_inquiry|halted|suppressed|sent|reply|... free-form
  detail TEXT,
  created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_events_lead ON events(lead_id);

CREATE TABLE IF NOT EXISTS app_state (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS accounts (
  id INTEGER PRIMARY KEY,
  name TEXT NOT NULL,
  created_at TEXT NOT NULL,
  -- PART 12 Step 5: where the account sits between signing up and being
  -- allowed to operate — pending | active | rejected. ONLY 'active' may
  -- use the app or send anything. It no longer means "has the
  -- attestation been signed"; that moved to document_acceptances.
  -- leadflow/accounts.py is the ONLY writer, and a test enforces it.
  -- B3 removed 'suspended': there is no freeze, only the approval
  -- decision and deletion.
  status TEXT NOT NULL DEFAULT 'active',
  -- B3 TEAM HIERARCHY. An edge, not a container: every agent keeps their
  -- own account and their own tenant scope, and the manager named here
  -- gets COUNTS about them and nothing else — never a lead row, never
  -- client PII, never their pipeline. See leadflow/team.py, which owns
  -- every rule below and is the only writer of both columns.
  --
  -- upline_id — the account that manages this one. NULL is a real state
  -- (top of the tree, or not yet assigned), not missing data. Refused:
  -- pointing at yourself, pointing at an account that is not a manager,
  -- and any assignment that would close a cycle.
  upline_id INTEGER,
  -- team_role — agent | manager. Only a manager may be named by another
  -- account's upline_id. SUPERADMIN ONLY, like va_eligible: there is no
  -- tenant route that writes it, because a tenant who could promote
  -- themselves could then attach agents and read their counts.
  team_role TEXT NOT NULL DEFAULT 'agent',
  -- PART 13: the VA plan is TWO flags and access is the AND of them.
  -- Neither is a substitute for the other and neither is ever derived
  -- from the other.
  --
  -- va_eligible — MAY this account have VA at all. SUPERADMIN ONLY.
  -- There is no tenant route that sets it; migration 23 renamed it from
  -- `va_entitled`, which meant exactly this and is the value every
  -- existing account keeps.
  va_eligible INTEGER NOT NULL DEFAULT 0,
  -- va_active — does the tenant WANT VA on right now. The tenant sets
  -- this, and only while va_eligible is 1. Migration 23 moved it off the
  -- `va_enabled` SETTING, which is what it has always been; putting it
  -- on the account row is what lets one query answer both halves.
  --
  -- Turning it off HIDES features. It deletes nothing: no queue row, no
  -- disposition, no pay record is touched, so turning it back on returns
  -- the same data.
  va_active INTEGER NOT NULL DEFAULT 0,
  -- The approval decision's audit trail (migration 21). approved_by is
  -- NULL on accounts the migration grandfathered: nobody approved them.
  status_changed_at TEXT,
  status_changed_by INTEGER,
  status_note TEXT,
  approved_at TEXT,
  approved_by INTEGER
);
-- accounts.upline_id's index is NOT here: this file runs BEFORE
-- apply_migrations on every existing database, so an index naming a
-- migration-added column fails against the pre-migration table. It lives
-- in db._ensure_partial_indexes with the others.

-- Redeemable VA-access codes. `account_id` is the ISSUING account, so the
-- Settings section that manages them scopes normally; redemption looks a
-- code up ACROSS tenants by design (a code is handed to another account).
-- Unlimited use until revoked; `revoked_at` blocks FUTURE redemptions only
-- and is never consulted again, so revoking a leaked code cannot take
-- access away from an account already running on it.
CREATE TABLE IF NOT EXISTS access_codes (
  id INTEGER PRIMARY KEY,
  account_id INTEGER NOT NULL DEFAULT 1,
  code TEXT NOT NULL,
  label TEXT NOT NULL DEFAULT '',
  created_by INTEGER,
  created_at TEXT NOT NULL,
  revoked_at TEXT,
  revoked_by INTEGER
);
-- Codes are matched by VALUE across tenants, so the value is globally
-- unique rather than unique per account.
CREATE UNIQUE INDEX IF NOT EXISTS uq_access_codes_code
  ON access_codes(code);

-- HISTORY ONLY as of PART 13: redemption was removed, so nothing writes
-- either table again and no read path ever granted access from them.
-- Eligibility lives on accounts.va_eligible and always did.
CREATE TABLE IF NOT EXISTS access_code_redemptions (
  id INTEGER PRIMARY KEY,
  code_id INTEGER NOT NULL REFERENCES access_codes(id),
  account_id INTEGER NOT NULL,
  user_id INTEGER,
  redeemed_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_redemptions_code
  ON access_code_redemptions(code_id, redeemed_at);
CREATE INDEX IF NOT EXISTS idx_redemptions_account
  ON access_code_redemptions(account_id, redeemed_at);

-- PART 12 Step 4: acceptance of the three legal documents (ToS, DPA, the
-- account-holder attestation). ONE table for all three -- migration 20
-- folded the old `attestations` table in here and dropped it, because two
-- tables would mean two answers to "has this tenant agreed".
--
-- APPEND-ONLY, enforced by the triggers below rather than by convention:
-- there is no code path, present or future, that can edit or remove an
-- acceptance. `text` is the document as it read at that moment, so editing
-- a file in leadflow/legal/ can never change what somebody already agreed
-- to. `signed_name` is the typed signature and is NULL for the checkbox
-- documents. ip/user_agent carry '(not recorded)' on the rows migrated out
-- of `attestations`, which predate them.
CREATE TABLE IF NOT EXISTS document_acceptances (
  id INTEGER PRIMARY KEY,
  account_id INTEGER NOT NULL,
  user_id INTEGER NOT NULL,
  document_type TEXT NOT NULL
    CHECK (document_type IN ('tos', 'dpa', 'account_holder', 'csa')),
  version TEXT NOT NULL,
  text TEXT NOT NULL,
  sha256 TEXT,
  signed_name TEXT,
  legal_entity TEXT,
  signer_title TEXT,
  signer_email TEXT,
  notice_address TEXT,
  npn TEXT,
  plan TEXT,
  -- The access code REFERENCE, never its value. Which code was presented
  -- is a fact about the deal; the code itself is a secret and has no
  -- business in a permanent legal record.
  access_code_id INTEGER,
  accepted_at TEXT NOT NULL,
  ip TEXT NOT NULL,
  user_agent TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_doc_acceptances_account
  ON document_acceptances(account_id, document_type, id);
CREATE INDEX IF NOT EXISTS idx_doc_acceptances_user
  ON document_acceptances(user_id, document_type, id);

CREATE TRIGGER IF NOT EXISTS document_acceptances_no_update
BEFORE UPDATE ON document_acceptances
BEGIN
  SELECT RAISE(ABORT, 'document_acceptances is append-only: an acceptance cannot be edited');
END;

CREATE TRIGGER IF NOT EXISTS document_acceptances_no_delete
BEFORE DELETE ON document_acceptances
BEGIN
  SELECT RAISE(ABORT, 'document_acceptances is append-only: an acceptance cannot be deleted');
END;

-- PART 12 Step 9: the versioned legal document registry.
--
-- THE TEXT IS STORED, NOT REFERENCED. A file on disk can be edited, moved
-- or lost with the repository; a row cannot. `sha256` is the hash of that
-- text and is what an acceptance points at, so "which words did they
-- agree to" is answered by a byte comparison.
--
-- IMMUTABLE ONCE PUBLISHED, enforced below rather than in routes. `active`
-- is the ONE column left movable, because publishing v2 has to stand v1
-- down; everything else is frozen at insert. Superseding never destroys —
-- the old row keeps its text and hash forever, because acceptances point
-- at it and an acceptance whose document vanished records nothing.
CREATE TABLE IF NOT EXISTS legal_documents (
  id INTEGER PRIMARY KEY,
  slug TEXT NOT NULL,                  -- csa | dpa
  version TEXT NOT NULL,
  text TEXT NOT NULL DEFAULT '',
  sha256 TEXT NOT NULL DEFAULT '',
  active INTEGER NOT NULL DEFAULT 0,
  published_at TEXT NOT NULL,
  UNIQUE (slug, version),
  CHECK (active IN (0, 1)),
  -- An active document with no text would gate every account on a blank
  -- page. Applies to UPDATE as well as INSERT, so an inactive slot cannot
  -- be switched on and filled in afterwards.
  CHECK (active = 0 OR length(trim(text)) > 0)
);
CREATE INDEX IF NOT EXISTS idx_legal_documents_active
  ON legal_documents(slug, active, id);

CREATE TRIGGER IF NOT EXISTS legal_documents_immutable
BEFORE UPDATE OF slug, version, text, sha256, published_at ON legal_documents
BEGIN
  SELECT RAISE(ABORT, 'legal_documents is immutable once published: only the active flag may change');
END;

CREATE TRIGGER IF NOT EXISTS legal_documents_no_delete
BEFORE DELETE ON legal_documents
BEGIN
  SELECT RAISE(ABORT, 'legal_documents is append-only: a published version is what acceptances point at and cannot be removed');
END;

-- Autosaved partial forms. A DRAFT IS NOT AN ACCEPTANCE: separate table,
-- no document_type, no signature column, and nothing joins it to
-- document_acceptances. A half-filled form must never be readable as a
-- signed agreement. Drafts are deleted the moment the real row is written.
CREATE TABLE IF NOT EXISTS form_drafts (
  id INTEGER PRIMARY KEY,
  account_id INTEGER NOT NULL,
  user_id INTEGER NOT NULL,
  form_key TEXT NOT NULL,
  payload TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  UNIQUE (account_id, user_id, form_key)
);

CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY,
  account_id INTEGER NOT NULL DEFAULT 1,
  username TEXT NOT NULL UNIQUE COLLATE NOCASE,
  role TEXT NOT NULL,                -- admin|va
  password_hash TEXT NOT NULL,
  -- PART 13: platform operator. Its OWN flag, not a role and not derived
  -- from account_id, so it is never inherited: /settings/users/add
  -- hardcodes role='va' and never writes this column, which is what makes
  -- an assistant login under the operator's own account still just an
  -- assistant. Nothing a tenant can reach sets it.
  is_superadmin INTEGER NOT NULL DEFAULT 0,
  -- BLOCK 2: MAY THIS SEAT PLACE A CALL. Its own flag, for the same
  -- reason `is_superadmin` is: the dialer used to be gated on
  -- `role = 'va'`, and `/settings/users/add` is a TENANT route that
  -- hardcodes that role — so a customer could create their own dialing
  -- seat. A capability nobody outside the operator may grant cannot be
  -- derived from a string a tenant route writes.
  --
  -- Written ONLY by the superadmin console, and only onto a `role='va'`
  -- seat. Defaults to 0, so every seat that exists and every seat a
  -- tenant creates from now on is silent. Enforced at the routing layer
  -- by `auth.DIAL_ROUTES` together with `entitlements.va_access`;
  -- tests/test_dial_gate.py enumerates the URL map and proves no
  -- tenant-reachable route can set it or reach a dial path without it.
  can_dial INTEGER NOT NULL DEFAULT 0,
  -- B7: TEAM seat or PERSONAL seat. A team seat works the shared call
  -- queue for the team under account 1 and is the only kind that may
  -- ever place a call; a personal seat works only its own account's
  -- leads and never dials — which is what "FTA personal VAs do not
  -- dial" means. DEFAULTS TO 'personal', the scope with fewer
  -- capabilities, so a seat that appears without anybody choosing
  -- cannot dial. Written only by the superadmin console; read only
  -- through leadflow/va_scope.py, which fails closed on any value it
  -- does not recognise.
  va_scope TEXT NOT NULL DEFAULT 'personal',
  -- B3: the address signup collects. `username` stays the login handle
  -- (and holds the same string for an account created at signup). NULL on
  -- seats created before B3 and on any seat named something that is not
  -- an address — never invented.
  --
  -- B10 WAS EXPECTED TO MAIL THE WEEKLY STATEMENT TO THIS ADDRESS AND
  -- DOES NOT. The statement is a download at /pay/statement.pdf, visible
  -- to the seat and to its owning FTA. `gmail/smtp_send.py` is the one
  -- function every lead email passes and it carries the signature gate
  -- and the CAN-SPAM unsubscribe line; putting a payslip through it would
  -- either footer somebody's pay with an unsubscribe link or add a second
  -- send path with its own gates to keep in step.
  email TEXT,
  enabled INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL,
  daily_quota INTEGER,               -- S2: per-VA quota (NULL = tenant default)
  fixed_monthly_cost_cents INTEGER,  -- S6: recurring per-VA overhead
  started_on TEXT,                   -- S6: ramp-view start date (YYYY-MM-DD)
  phone TEXT,                        -- C1 pre-provision: '000-000-0000' (normalize_phone,
                                     -- as every phone column holds); the VA leg of the
                                     -- C3 dialer. NOT E.164 — see leads.phone.
  -- B10: hours a week this seat works. NULL = nobody has entered it, and
  -- the profitability dashboard reports no profit-per-hour for that seat
  -- rather than dividing by an assumed 40. There is no default: the
  -- dashboard exists to rank seats, and ranking them on an assumed
  -- denominator is worse than a blank that says why.
  weekly_hours REAL,
  -- B12: the seat's daily allocation, set by its owning FTA. NULL means
  -- UNCONFIGURED, never zero — same rule as weekly_hours above. An
  -- unconfigured seat keeps exactly its prior behaviour: its effective
  -- quota, filled own -> team -> overflow with no per-source cap.
  own_leads_target INTEGER,
  team_leads_target INTEGER
);

CREATE TABLE IF NOT EXISTS interactions (
  id INTEGER PRIMARY KEY,
  account_id INTEGER NOT NULL DEFAULT 1,
  lead_id INTEGER NOT NULL REFERENCES leads(id),
  user_id INTEGER,                   -- NULL = system/worker
  itype TEXT NOT NULL,               -- call|email|text|appointment|sold_credit
  direction TEXT,                    -- out|in (email/text mirrors)
  disposition TEXT,                  -- calls (C1 active): no_answer|voicemail|bad_number|
                                     --   answered_not_interested|callback_requested|
                                     --   appointment_set|not_qualified|answered_send_options
                                     -- calls (legacy, read-only): answered_interested|
                                     --   answered_callback
                                     -- appointments: scheduled|showed|no_show|
                                     --   rescheduled|cancelled (T1 adds the last two —
                                     --   the TERMINAL outcomes: the appointment did not happen)
  note TEXT,
  callback_on TEXT,                  -- YYYY-MM-DD; legacy answered_callback rows + followup rows
                                     -- (C1: no active call disposition writes it)
  appointment_at TEXT,               -- UTC ISO, for appointment/scheduled
  parent_id INTEGER,                 -- outcome row → their scheduled row
  message_id INTEGER,                -- for email/text mirror rows
  gcal_event_id TEXT,                -- S8: linked Google Calendar event
  confirmation_sent_at TEXT,         -- T1: UTC ISO, stamped when the agent confirms they
                                     -- texted the lead by hand. NULL = not confirmed.
                                     -- Meaningful only on appointment/scheduled rows.
  confirmation_notified_at TEXT,     -- T1: UTC ISO, stamped by the worker once it has fired
                                     -- this appointment's ONE reminder (idempotency marker)
  created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_interactions_lead ON interactions(lead_id);
CREATE INDEX IF NOT EXISTS idx_interactions_user_day ON interactions(user_id, created_at);

CREATE TABLE IF NOT EXISTS va_queue (
  id INTEGER PRIMARY KEY,
  account_id INTEGER NOT NULL DEFAULT 1,
  qdate TEXT NOT NULL,               -- YYYY-MM-DD in my_timezone
  lead_id INTEGER NOT NULL REFERENCES leads(id),
  position INTEGER NOT NULL,         -- 1-based within the day's queue
  source TEXT NOT NULL,              -- callback|ghost|stale|volume (legacy aged|fresh readable)
  status TEXT NOT NULL DEFAULT 'pending',  -- pending|worked
  worked_by INTEGER,                 -- users.id of the caller who worked it
  worked_at TEXT,
  script_json TEXT,                  -- cached per-lead AI script lines (R5)
  assigned_to INTEGER,               -- S2: user who claimed the row (NULL = free)
  slot_hour INTEGER,                 -- S3: lead-local retry slot hour (volume rows)
  allocated_to INTEGER,              -- B12: the VA this row was BUILT for. Distinct
                                     -- from assigned_to, which is who CLAIMED it.
  UNIQUE(qdate, lead_id)
);
CREATE INDEX IF NOT EXISTS idx_va_queue_date ON va_queue(qdate, position);

CREATE TABLE IF NOT EXISTS send_channels (
  id INTEGER PRIMARY KEY,
  account_id INTEGER NOT NULL DEFAULT 1,
  channel TEXT NOT NULL,             -- email (text rows retired in R1)
  identifier TEXT NOT NULL,          -- gmail address
  secret TEXT,                       -- encrypted gmail app password (NULL for the
                                     -- primary mailbox = use gmail_app_password setting)
  role TEXT NOT NULL DEFAULT 'overflow',   -- primary|overflow
  sort_order INTEGER NOT NULL DEFAULT 0,
  enabled INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL,
  UNIQUE(account_id, channel, identifier)
);

CREATE TABLE IF NOT EXISTS recovery_flags (
  id INTEGER PRIMARY KEY,
  account_id INTEGER NOT NULL DEFAULT 1,
  lead_id INTEGER NOT NULL REFERENCES leads(id),
  kind TEXT NOT NULL,                -- fast_ghost|stale_quote|stale_engaged
  flagged_at TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'open',  -- open|queued|done|cleared
  outcome TEXT,                      -- recovery attempt result (R4)
  resolved_at TEXT,
  created_at TEXT NOT NULL
);
-- One active (open or queued) flag per lead; fast_ghost upgrades in place.
CREATE UNIQUE INDEX IF NOT EXISTS uq_recovery_flags_active
  ON recovery_flags(lead_id) WHERE status IN ('open', 'queued');
CREATE INDEX IF NOT EXISTS idx_recovery_flags_status
  ON recovery_flags(status, kind);

CREATE TABLE IF NOT EXISTS pay_rates (
  id INTEGER PRIMARY KEY,
  account_id INTEGER NOT NULL DEFAULT 1,
  user_id INTEGER,                   -- S2: NULL = tenant default; else per-VA row
  effective_date TEXT NOT NULL,      -- YYYY-MM-DD; each day pays at the rate row
                                     -- active that day (max effective_date <= day)
  daily_base_cents INTEGER NOT NULL,
  floor_leads INTEGER NOT NULL,
  send_options_cents INTEGER NOT NULL,
  appt_scheduled_cents INTEGER NOT NULL,
  appt_showed_cents INTEGER NOT NULL,
  sold_bonus_cents INTEGER NOT NULL,
  created_at TEXT NOT NULL
);
-- SQLite treats NULLs as distinct in UNIQUE constraints, so per-user
-- uniqueness needs two partial indexes (S2): uq_pay_rates_default on
-- (account_id, effective_date) WHERE user_id IS NULL and uq_pay_rates_user
-- on (account_id, user_id, effective_date) WHERE user_id IS NOT NULL.
-- They reference a migration-added column, so init_db creates them AFTER
-- migrations run (db._ensure_partial_indexes); migration 8 also creates
-- them on upgraded DBs.

CREATE TABLE IF NOT EXISTS sales (
  id INTEGER PRIMARY KEY,
  account_id INTEGER NOT NULL DEFAULT 1,
  lead_id INTEGER NOT NULL UNIQUE REFERENCES leads(id),
  premium_cents INTEGER,             -- monthly premium
  status TEXT NOT NULL DEFAULT 'pending',  -- pending|approved|denied
  commission_cents INTEGER,          -- NULL until approved
  sold_at TEXT,
  resolved_at TEXT,
  note TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

-- ===================================================================
-- B9 — THE APPOINTMENT TRACKER
--
-- The money record for an appointment, distinct from `interactions`,
-- which stays the operational timeline. One row per tracked appointment.
--
-- THE LEAD IS A REFERENCE, NEVER A NAME. `lead_id` and nothing else
-- identifies the client. Both sides of a split see this row — the VA who
-- set it may be a seat on the team account and not on the agent's tenant
-- at all — so a denormalised name here would be this table handing one
-- tenant's client identity to another. `state` IS snapshotted, because
-- the other side legitimately needs to know which state was worked and
-- cannot read the lead row to find out.
--
-- THE SPLIT AMOUNT IS NOT STORED. It derives from `commission_cents` and
-- the split rate effective on this row's own date, so changing the rate
-- later re-prices nothing that already happened and re-enters nothing.
-- See `split_rates` below and leadflow/appointments.py.
CREATE TABLE IF NOT EXISTS appointment_tracker (
  id INTEGER PRIMARY KEY,
  account_id INTEGER NOT NULL DEFAULT 1,   -- the AGENT's account: whose business
  team_account_id INTEGER NOT NULL DEFAULT 1,  -- team root, for the team calendar
  lead_id INTEGER NOT NULL REFERENCES leads(id),
  state TEXT,                        -- snapshot; the other side cannot read the lead
  set_by_user_id INTEGER,            -- the VA who set the appointment
  ran_by_user_id INTEGER,            -- who ran it (NULL until run)
  agent_user_id INTEGER,             -- whose business it is
  date_set TEXT NOT NULL,            -- YYYY-MM-DD
  date_run TEXT,                     -- YYYY-MM-DD; NULL until run
  outcome TEXT,                      -- scheduled|showed|no_show|cancelled|sold|not_sold
  premium_cents INTEGER,             -- monthly premium, when sold
  commission_cents INTEGER,          -- entered by WHOEVER CLOSED
  closed_by_user_id INTEGER,         -- who entered the commission
  paid_at TEXT,                      -- UTC ISO; marked by whoever closed
  paid_by_user_id INTEGER,
  interaction_id INTEGER,            -- the appointment row this came from, if any
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_apptrack_team
  ON appointment_tracker(team_account_id, date_set);
CREATE INDEX IF NOT EXISTS idx_apptrack_ran
  ON appointment_tracker(ran_by_user_id, date_run);
CREATE INDEX IF NOT EXISTS idx_apptrack_lead
  ON appointment_tracker(lead_id);

-- EFFECTIVE-DATED, exactly like `pay_rates`, and for exactly the same
-- reason: "changing it later must not require re-entering anything". A
-- rate change is an INSERT with a new effective_date, so every row
-- already recorded keeps deriving from the rate that was in force on its
-- own date, and nothing historical moves. A single mutable number on the
-- account would have re-priced every closed appointment the moment it
-- was edited, including ones already paid.
--
-- Scoped to the TEAM ROOT account: the split is the arrangement between
-- a team and the agents on it, and an FTA manager's team sets its own.
CREATE TABLE IF NOT EXISTS split_rates (
  id INTEGER PRIMARY KEY,
  account_id INTEGER NOT NULL DEFAULT 1,   -- the TEAM ROOT account
  effective_date TEXT NOT NULL,            -- YYYY-MM-DD
  va_split_bps INTEGER NOT NULL,           -- basis points to the setting side
  note TEXT,
  created_at TEXT NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS uq_split_rates
  ON split_rates(account_id, effective_date);

CREATE TABLE IF NOT EXISTS referral_asks (
  id INTEGER PRIMARY KEY,
  account_id INTEGER NOT NULL DEFAULT 1,
  lead_id INTEGER NOT NULL REFERENCES leads(id),  -- the client being asked
  ask_no INTEGER NOT NULL,           -- 1|2|3
  due_at TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending',  -- pending|prompted|sent|dismissed
  approval_id INTEGER,               -- approvals row once prompted (R7)
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS tasks (
  id INTEGER PRIMARY KEY,
  account_id INTEGER NOT NULL DEFAULT 1,
  kind TEXT NOT NULL,                -- needs_email|new_referral|run_quotes|callback_review
  lead_id INTEGER,
  body TEXT,
  status TEXT NOT NULL DEFAULT 'open',  -- open|done
  created_at TEXT NOT NULL,
  done_at TEXT
);

-- C1 pre-provision for Part 5 waves 2-3 (schema only; C3/C4 add behavior).
-- C3 HOOK: the dialer writes these rows and polls Twilio to fill status /
-- duration / cost. C4 HOOK: call analytics reads them per VA and period.
-- One row per outbound Twilio call. Money in cents (CLAUDE.md): cost_cents
-- is Twilio's reported price when published (cost_is_actual=1), otherwise
-- the estimate from twilio_call_rate_cents_per_min (cost_is_actual=0).
-- NO RECORDING IS EVER REQUESTED OR STORED — outcome, duration, timestamps
-- and cost only.
CREATE TABLE IF NOT EXISTS calls (
  id INTEGER PRIMARY KEY,
  account_id INTEGER NOT NULL DEFAULT 1,
  lead_id INTEGER NOT NULL REFERENCES leads(id),
  user_id INTEGER,                   -- the caller (users.id); NULL = system
  twilio_sid TEXT UNIQUE,            -- Twilio Call SID (NULL until created)
  from_number TEXT,                  -- the local-presence number shown to the lead
  to_number TEXT,                    -- the VA leg (users.phone) Twilio rings first
  status TEXT,                       -- Twilio call status (queued|ringing|completed|...)
  duration_seconds INTEGER,
  cost_cents INTEGER,
  cost_is_actual INTEGER NOT NULL DEFAULT 0,  -- 1 = Twilio price, 0 = estimate
  error TEXT,
  started_at TEXT,
  ended_at TEXT,
  created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_calls_account_day ON calls(account_id, created_at);
CREATE INDEX IF NOT EXISTS idx_calls_user_day ON calls(user_id, created_at);

-- C1 pre-provision. C3 HOOK: the tenant's local-presence number pool (C3
-- manages it in Settings -> Twilio and rotates within it).
CREATE TABLE IF NOT EXISTS twilio_numbers (
  id INTEGER PRIMARY KEY,
  account_id INTEGER NOT NULL DEFAULT 1,
  number TEXT NOT NULL,              -- E.164
  enabled INTEGER NOT NULL DEFAULT 1,
  sort_order INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL,
  UNIQUE(account_id, number)
);

-- AGENT LEADS. Leads handed over by another licensed agent (a downline /
-- FTA arrangement), worked in the NORMAL pipeline and split on commission.
-- NOT referrals: `leads.referred_by` is the R7 referral firewall (zero
-- automation, routed to the owner personally) and means the opposite thing.
--
-- Both tables are tenant CONFIG, like lead_sources — reset.py KEEPS them
-- while deleting the leads themselves.
CREATE TABLE IF NOT EXISTS source_agents (
  id INTEGER PRIMARY KEY,
  account_id INTEGER NOT NULL DEFAULT 1,
  name TEXT NOT NULL,                -- the roster spelling; leads snapshot it
  enabled INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL,
  UNIQUE(account_id, name COLLATE NOCASE)
);

-- One saved CSV header -> lead field mapping per agent, per tenant.
-- Confirmed once on the first upload, auto-applied on every one after.
CREATE TABLE IF NOT EXISTS source_agent_maps (
  id INTEGER PRIMARY KEY,
  account_id INTEGER NOT NULL DEFAULT 1,
  agent_id INTEGER NOT NULL REFERENCES source_agents(id),
  field_map TEXT NOT NULL,           -- JSON {lead_field: csv_header}
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  UNIQUE(account_id, agent_id)
);

-- OVERFLOW POOL. The cold-start backfill: a new tenant's VA has an empty
-- queue on day one because organic lead flow has not started yet, and
-- overflow leads fill the gap until it does.
--
-- These are NOT leads and this is NOT a flag on the leads table. An
-- overflow row is not a real lead until positive contact, and a flag holds
-- that invariant only for as long as every current AND FUTURE query
-- remembers to filter. Physical separation makes the violation impossible.
-- Promotion MOVES the row into `leads` and deletes it from here.
CREATE TABLE IF NOT EXISTS overflow_leads (
  id INTEGER PRIMARY KEY,
  account_id INTEGER NOT NULL DEFAULT 1,
  first_name TEXT NOT NULL DEFAULT '',
  last_name TEXT NOT NULL DEFAULT '',
  email TEXT,                        -- lowercased; NULL if missing
  phone TEXT,                        -- '000-000-0000' (normalize_phone), same as
                                     -- leads.phone. NOT E.164.
  city TEXT, state TEXT, zip TEXT,
  timezone TEXT NOT NULL DEFAULT 'America/New_York',
  metadata TEXT NOT NULL DEFAULT '{}',  -- JSON of unmapped CSV columns
  batch_id TEXT,                     -- one upload drop
  file_order INTEGER NOT NULL DEFAULT 0,  -- row order within the file; the
                                     -- tie-break under newest-first draw
  status TEXT NOT NULL DEFAULT 'pool',    -- pool|promoted|dead|expired
  -- DIALER BLOCK 1: carried from the upload and copied onto the lead at
  -- promotion. Deliberately NOT derived from uploaded_at, which is when
  -- the file was handed over and says nothing about when the person
  -- agreed to be called.
  consent_date TEXT,
  uploaded_at TEXT NOT NULL,         -- the 45-day residency clock starts here
  created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_overflow_pool ON overflow_leads(account_id, status, uploaded_at);
CREATE INDEX IF NOT EXISTS idx_overflow_phone ON overflow_leads(account_id, phone);
CREATE INDEX IF NOT EXISTS idx_overflow_email ON overflow_leads(account_id, email);

-- The pool's own lightweight call log. A VA who dials an overflow row and
-- gets no answer must record it somewhere that is not `interactions` —
-- interactions.lead_id points at `leads`, and an overflow row has no lead.
-- These records DIE WITH THE ROW.
CREATE TABLE IF NOT EXISTS overflow_attempts (
  id INTEGER PRIMARY KEY,
  account_id INTEGER NOT NULL DEFAULT 1,
  overflow_id INTEGER NOT NULL REFERENCES overflow_leads(id),
  user_id INTEGER,                   -- the VA who worked it (pay floor)
  disposition TEXT NOT NULL,         -- interactions.CALL_DISPOSITIONS + HEAT_LEVELS
  note TEXT,
  created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_overflow_attempts_row ON overflow_attempts(overflow_id, created_at);
CREATE INDEX IF NOT EXISTS idx_overflow_attempts_user ON overflow_attempts(account_id, user_id, created_at);

-- Today's drawn overflow rows. Deliberately SEPARATE from va_queue, whose
-- lead_id stays NOT NULL REFERENCES leads(id) — no existing queue query
-- becomes a union type. /today merges the two for display, overflow last,
-- which is exactly the backfill order.
CREATE TABLE IF NOT EXISTS overflow_queue (
  id INTEGER PRIMARY KEY,
  account_id INTEGER NOT NULL DEFAULT 1,
  qdate TEXT NOT NULL,               -- YYYY-MM-DD in my_timezone
  overflow_id INTEGER NOT NULL REFERENCES overflow_leads(id),
  position INTEGER NOT NULL,         -- continues va_queue's numbering
  source TEXT NOT NULL,              -- overflow_volume|overflow_recovery
  status TEXT NOT NULL DEFAULT 'pending',
  worked_by INTEGER,
  worked_at TEXT,
  assigned_to INTEGER,
  allocated_to INTEGER,              -- B12: see va_queue.allocated_to
  UNIQUE(qdate, overflow_id)
);
CREATE INDEX IF NOT EXISTS idx_overflow_queue_date ON overflow_queue(qdate, position);

-- PART 12 Step 2: TOTP two-factor authentication.
-- `secret` is AES-256-GCM ciphertext (leadflow.crypto), never plaintext.
-- `confirmed_at` NULL means an enrollment that was started and abandoned;
-- only a confirmed row counts as enrolled. `last_used_step` is the TOTP
-- replay guard — a code is valid for a whole 30s step, so without it the
-- same six digits work twice.
-- DIALER BLOCK 3: every call this app places, and every one it refused to
-- place. APPEND-ONLY, same treatment as document_acceptances and
-- suppressions, and for the same reason: it is the record that answers
-- "who called this person, when, and what permitted it". Nothing prunes
-- it and no reset path reaches it (reset.KEEP_TABLES).
--
-- `permitted_by` is the rung of leadflow/dialer.check that ALLOWED the
-- call, or `refused:<rule>` in `outcome` for one that never reached a
-- carrier. A log that only records successes cannot answer the question
-- an auditor actually asks, which is whether the refusals worked.
--
-- `duration_seconds` is NULL for now: the call is placed with inline
-- TwiML and no status callback, so Twilio has nowhere to report a
-- completed call's length. See SPEC.
CREATE TABLE IF NOT EXISTS dial_attempts (
  id INTEGER PRIMARY KEY,
  account_id INTEGER NOT NULL,
  -- NO FOREIGN KEYS on lead_id or user_id, deliberately. The call log
  -- OUTLIVES both: `reset.py` deletes every lead on the account, and a
  -- real FK would either block the reset or take the call record down
  -- with the lead — and a record of who was called that disappears when
  -- the lead does is not a record. Same reasoning that keeps a
  -- suppression alive after its overflow row is gone.
  lead_id INTEGER NOT NULL,
  user_id INTEGER,                        -- the VA seat that clicked
  to_number TEXT NOT NULL,                -- E.164, the lead's handset
  from_number TEXT NOT NULL,              -- the ONE Twilio number
  permitted_by TEXT NOT NULL,             -- which rule allowed it
  outcome TEXT NOT NULL,                  -- placed|failed:*|refused:*
  call_sid TEXT,                          -- Twilio's id, when there is one
  duration_seconds INTEGER,
  created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_dial_number ON dial_attempts(account_id, to_number, created_at);
CREATE INDEX IF NOT EXISTS idx_dial_lead ON dial_attempts(lead_id, created_at);

CREATE TRIGGER IF NOT EXISTS dial_attempts_no_update
BEFORE UPDATE ON dial_attempts
BEGIN
  SELECT RAISE(ABORT, 'dial_attempts is append-only: a call record cannot be edited');
END;

CREATE TRIGGER IF NOT EXISTS dial_attempts_no_delete
BEFORE DELETE ON dial_attempts
BEGIN
  SELECT RAISE(ABORT, 'dial_attempts is append-only: a call record cannot be deleted');
END;

CREATE TABLE IF NOT EXISTS user_mfa (
  user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  secret TEXT NOT NULL,
  confirmed_at TEXT,
  created_at TEXT NOT NULL,
  last_used_step INTEGER
);

-- One-time recovery codes, scrypt-hashed exactly like passwords: they are
-- typed into the same box as a TOTP code and are worth as much. Rows are
-- never deleted on use — `used_at` is stamped instead, so a spent code
-- stays visibly spent.
CREATE TABLE IF NOT EXISTS mfa_recovery_codes (
  id INTEGER PRIMARY KEY,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  code_hash TEXT NOT NULL,
  used_at TEXT,
  created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_mfa_recovery_user
  ON mfa_recovery_codes(user_id, used_at);
