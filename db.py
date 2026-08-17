"""Encrypted SQLite access layer: per-thread SQLCipher connections, WAL
mode, schema init, numbered migrations for existing databases.

PART 12: THE DATABASE IS ENCRYPTED AT REST (SQLCipher, AES-256).

The driver is `sqlcipher3`, NOT the stdlib `sqlite3`. That swap has one
sharp edge worth stating loudly, because it is silent and it is a
correctness bug rather than a crash: **sqlcipher3's exception classes are
not the stdlib's and do not inherit from them.** `except
sqlite3.IntegrityError` compiles fine, runs fine, and simply stops
catching. Every module that handles a database error therefore imports the
alias from HERE (`from leadflow.db import IntegrityError`) and never
touches `sqlite3` directly. The same goes for `Row`.

The passphrase comes from the environment and ONLY from the environment
(`LEADFLOW_DB_KEY`). There is deliberately no file fallback, no default,
and no "unencrypted mode" — a missing key raises `DatabaseKeyMissing` and
the app refuses to start. An app that quietly opened a plaintext database
when the key was absent would be worse than no encryption at all, because
it would look encrypted.

The key is NOT stored beside the data. `data/master.key` (the AES-GCM key
for encrypted settings columns) still lives in the data directory; the
database passphrase must not, or the encryption protects nothing against
someone who has the directory. This is also why backups moved to
`data/backups/` — see `leadflow.reset.backup_database`.
"""
import datetime
import json
import logging
import os
import pathlib
import threading

from sqlcipher3 import dbapi2 as _driver
from leadflow.branding import PRODUCT_NAME

logger = logging.getLogger("leadflow.db")

_local = threading.local()

DB_FILENAME = "leadflow.db"

# The environment variable holding the SQLCipher passphrase. Documented in
# README.md and .env.example; there is no other source for it.
DB_KEY_ENV = "LEADFLOW_DB_KEY"

# Re-exported driver names. Import these from leadflow.db rather than from
# sqlite3 — see the module docstring for why that matters.
Row = _driver.Row
Error = _driver.Error
DatabaseError = _driver.DatabaseError
IntegrityError = _driver.IntegrityError
OperationalError = _driver.OperationalError


class DatabaseKeyMissing(RuntimeError):
    """Raised when LEADFLOW_DB_KEY is absent or blank.

    Its own class so startup can catch exactly this and print an
    actionable message instead of a stack trace, and so no `except
    Exception` anywhere can be mistaken for handling it.
    """


class DatabaseKeyWrong(RuntimeError):
    """Raised when LEADFLOW_DB_KEY is set but does not open the database."""


def data_dir():
    # type: () -> pathlib.Path
    """Data directory: env LEADFLOW_DATA_DIR, default <repo>/data."""
    env = os.environ.get("LEADFLOW_DATA_DIR")
    if env:
        return pathlib.Path(env)
    return pathlib.Path(__file__).resolve().parents[1] / "data"


def backup_dir():
    # type: () -> pathlib.Path
    """Where database backups live: data/backups/.

    A SUBDIRECTORY, deliberately. Backups used to accumulate in data/
    directly, alongside `master.key` — so anyone who copied a backup for
    safekeeping was liable to copy the key that decrypts its secret
    columns along with it. Separating them means a backup can be moved
    off the machine on its own.
    """
    return data_dir() / "backups"


def db_path():
    # type: () -> pathlib.Path
    return data_dir() / DB_FILENAME


def db_key():
    # type: () -> str
    """The SQLCipher passphrase from the environment. Never falls back.

    Whitespace-only counts as missing: `LEADFLOW_DB_KEY=" "` is a
    misconfiguration, not a passphrase.
    """
    raw = os.environ.get(DB_KEY_ENV) or ""
    if not raw.strip():
        raise DatabaseKeyMissing(
            "%s is not set. %s's database is encrypted (SQLCipher) "
            "and cannot be opened without its passphrase. Set %s in the "
            "environment before starting the app. See README.md > "
            "Encryption at rest."
            % (DB_KEY_ENV, PRODUCT_NAME, DB_KEY_ENV))
    return raw


def apply_key(conn, key=None):
    # type: (object, object) -> object
    """Apply the passphrase to a freshly opened connection.

    The key is passed as a HEX LITERAL (`PRAGMA key = "x'...'"`) rather
    than a quoted string. SQLCipher parses a quoted passphrase, so a key
    containing a quote or backslash would otherwise be mangled or, worse,
    truncated into a weaker key that still "works" — silently. Hex has no
    escaping and no parsing.
    """
    if key is None:
        key = db_key()
    conn.execute('PRAGMA key = "x\'%s\'"'
                 % key.encode("utf-8").hex())
    return conn


def connect(path, key=None, timeout=30.0):
    # type: (object, object, float) -> object
    """Open an encrypted connection to `path` with row access by name.

    Used for the live database and for backup destinations alike, so
    there is exactly one place that knows how an encrypted Ancora
    database is opened.
    """
    conn = _driver.connect(str(path), timeout=timeout)
    conn.row_factory = Row
    apply_key(conn, key)
    return conn


def verify_key(conn):
    # type: (object) -> object
    """Force SQLCipher to actually decrypt a page, so a wrong key fails HERE.

    `PRAGMA key` does no work by itself: it stores the key and returns
    happily even when it is wrong. Without this, a bad passphrase would
    surface much later as a bewildering "file is not a database" from
    whatever innocent query happened to touch disk first. Reading
    sqlite_master is the cheapest read that must decrypt.
    """
    try:
        conn.execute("SELECT count(*) FROM sqlite_master").fetchone()
    except DatabaseError as exc:
        raise DatabaseKeyWrong(
            "%s does not open this database (%s). The passphrase is wrong, "
            "or the file is not a SQLCipher database." % (DB_KEY_ENV, exc))
    return conn


def get_db():
    # type: () -> object
    """Per-thread encrypted connection (keyed by db path so tests can
    switch dirs). Raises DatabaseKeyMissing when the passphrase is absent."""
    conns = getattr(_local, "conns", None)
    if conns is None:
        conns = {}
        _local.conns = conns
    path = db_path()
    key = str(path)
    conn = conns.get(key)
    if conn is None:
        path.parent.mkdir(parents=True, exist_ok=True)
        conn = connect(path)
        # Order matters: the key must prove itself BEFORE any pragma that
        # writes, or a wrong passphrase corrupts nothing but reports the
        # failure from the wrong place.
        verify_key(conn)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        conns[key] = conn
    return conn


def rollback_dangling(where=""):
    # type: (str) -> int
    """Roll back any UNCOMMITTED transaction left open on THIS thread.

    An operation that raises after its first write leaves the thread's
    connection inside an open write transaction, because nothing else
    ends it: sqlite3 opens the transaction on that first statement and
    only `commit()`/`rollback()` closes it. Three things then go wrong,
    all measured:

      1. the NEXT unrelated operation on the same thread commits the
         failed one's partial writes (a waitress thread serves the next
         request; the worker runs the next sub-task — including another
         TENANT's);
      2. that open write transaction holds SQLite's single writer slot,
         so every OTHER connection's write fails `database is locked`
         (the worker is blocked by a web thread, and vice versa);
      3. reads on that connection stay pinned to the pre-failure WAL
         snapshot, so it keeps serving stale rows.

    Called from the request teardown and from the worker's per-task
    shield, which are the two places a failure is swallowed. Returns the
    number of connections rolled back (0 in the normal case — a request
    or task that committed leaves nothing open). Never raises.
    """
    conns = getattr(_local, "conns", None)
    if not conns:
        return 0
    rolled = 0
    for conn in list(conns.values()):
        try:
            if not conn.in_transaction:
                continue
            conn.rollback()
            rolled += 1
        except Exception:  # pragma: no cover - rollback best-effort
            logger.exception("could not roll back a dangling transaction%s",
                             " (%s)" % where if where else "")
    if rolled:
        logger.warning("rolled back %d uncommitted transaction(s) left open "
                       "by a failed operation%s", rolled,
                       " (%s)" % where if where else "")
    return rolled


def close_db():
    # type: () -> None
    """Close all connections belonging to the current thread."""
    conns = getattr(_local, "conns", None)
    if not conns:
        return
    for key, conn in list(conns.items()):
        try:
            conn.close()
        except Exception:  # pragma: no cover - close best-effort
            logger.exception("error closing db connection %s", key)
        conns.pop(key, None)


# --- migrations ------------------------------------------------------------
#
# Ordered list of (version:int, sql_or_callable). init_db() applies every
# entry with a version greater than the app_state `schema_version` cursor,
# each inside its own transaction, then advances the cursor. Fresh installs
# get the full schema.sql and start at the latest version (no migrations
# run). Entries must be idempotent-safe ALTER/CREATE (an existing dev DB
# also gets schema.sql's CREATE IF NOT EXISTS first). Later batches append
# entries here; never renumber or reorder existing ones.

def _table_columns(db, table):
    # type: (sqlite3.Connection, str) -> set
    return set(
        r["name"] for r in db.execute("PRAGMA table_info(%s)" % table).fetchall()
    )


def _table_exists(db, table):
    # type: (sqlite3.Connection, str) -> bool
    return db.execute(
        "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?",
        (table,)).fetchone() is not None


def _add_column_if_missing(db, table, column, decl):
    if column not in _table_columns(db, table):
        db.execute("ALTER TABLE %s ADD COLUMN %s %s" % (table, column, decl))


def _raw_setting(db, key):
    """Read a settings value without the registry (for retired keys)."""
    row = db.execute(
        "SELECT value FROM settings WHERE key = ?", (key,)
    ).fetchone()
    if row is None:
        return None
    try:
        return json.loads(row["value"])
    except (ValueError, TypeError):
        return None


def _migration_0001_send_channels(db):
    """B2: send_channels table + messages.channel_id + leads.outreach_email,
    seeded from the retired quo_outreach_numbers setting and gmail_address."""
    db.execute(
        "CREATE TABLE IF NOT EXISTS send_channels ("
        " id INTEGER PRIMARY KEY,"
        " account_id INTEGER NOT NULL DEFAULT 1,"
        " channel TEXT NOT NULL,"
        " identifier TEXT NOT NULL,"
        " secret TEXT,"
        " role TEXT NOT NULL DEFAULT 'overflow',"
        " sort_order INTEGER NOT NULL DEFAULT 0,"
        " enabled INTEGER NOT NULL DEFAULT 1,"
        " created_at TEXT NOT NULL,"
        " UNIQUE(channel, identifier))"
    )
    _add_column_if_missing(db, "messages", "channel_id", "INTEGER")
    _add_column_if_missing(db, "leads", "outreach_email", "TEXT")

    now = utcnow()
    numbers = _raw_setting(db, "quo_outreach_numbers") or []
    if isinstance(numbers, list):
        for i, num in enumerate(numbers):
            if not num:
                continue
            db.execute(
                "INSERT OR IGNORE INTO send_channels "
                "(channel, identifier, role, sort_order, enabled, created_at) "
                "VALUES ('text', ?, ?, ?, 1, ?)",
                (num, "primary" if i == 0 else "overflow", i, now),
            )
    gmail_address = _raw_setting(db, "gmail_address")
    if isinstance(gmail_address, str) and gmail_address.strip():
        db.execute(
            "INSERT OR IGNORE INTO send_channels "
            "(channel, identifier, secret, role, sort_order, enabled, "
            " created_at) VALUES ('email', ?, NULL, 'primary', 0, 1, ?)",
            (gmail_address.strip(), now),
        )
    # Retired: code must no longer read this setting.
    db.execute("DELETE FROM settings WHERE key = 'quo_outreach_numbers'")


def _migration_0002_accounts_users(db):
    """B3: accounts + users tables, account scoping columns, events.user_id,
    admin user migrated from the retired app_password_hash setting."""
    db.execute(
        "CREATE TABLE IF NOT EXISTS accounts ("
        " id INTEGER PRIMARY KEY, name TEXT NOT NULL, created_at TEXT NOT NULL)"
    )
    db.execute(
        "CREATE TABLE IF NOT EXISTS users ("
        " id INTEGER PRIMARY KEY,"
        " account_id INTEGER NOT NULL DEFAULT 1,"
        " username TEXT NOT NULL UNIQUE COLLATE NOCASE,"
        " role TEXT NOT NULL,"
        " password_hash TEXT NOT NULL,"
        " enabled INTEGER NOT NULL DEFAULT 1,"
        " created_at TEXT NOT NULL)"
    )
    for table in ("leads", "messages", "approvals", "suppressions",
                  "dead_letters", "events", "notifications"):
        _add_column_if_missing(db, table, "account_id",
                               "INTEGER NOT NULL DEFAULT 1")
    # interactions / va_queue don't exist yet; B4/B5 create them WITH the
    # account_id (and user_id) columns. send_channels already has account_id.
    _add_column_if_missing(db, "events", "user_id", "INTEGER")

    now = utcnow()
    # Account 1 predates migration 16, so it has no eligibility column here
    # (migration 2 runs long before it). Migration 16 grandfathers this row
    # to 1 along with every other pre-existing account; on a fresh install
    # seed_defaults writes it entitled directly.
    db.execute(
        "INSERT OR IGNORE INTO accounts (id, name, created_at) "
        "VALUES (1, 'Default', ?)", (now,))
    users_empty = db.execute("SELECT 1 FROM users LIMIT 1").fetchone() is None
    password_hash = _raw_setting(db, "app_password_hash")
    if users_empty and password_hash:
        db.execute(
            "INSERT INTO users (account_id, username, role, password_hash, "
            "enabled, created_at) VALUES (1, 'admin', 'admin', ?, 1, ?)",
            (password_hash, now))
    # Retired: auth reads the users table only.
    db.execute("DELETE FROM settings WHERE key = 'app_password_hash'")


def _migration_0003_interactions_pipeline(db):
    """B4: interactions table (with account_id/user_id per B3 note), leads
    phone_bad + computed pipeline columns, and a backfill that recomputes
    pipeline_stage for every existing lead."""
    db.execute(
        "CREATE TABLE IF NOT EXISTS interactions ("
        " id INTEGER PRIMARY KEY,"
        " account_id INTEGER NOT NULL DEFAULT 1,"
        " lead_id INTEGER NOT NULL REFERENCES leads(id),"
        " user_id INTEGER,"
        " itype TEXT NOT NULL,"
        " direction TEXT,"
        " disposition TEXT,"
        " note TEXT,"
        " callback_on TEXT,"
        " appointment_at TEXT,"
        " parent_id INTEGER,"
        " message_id INTEGER,"
        " created_at TEXT NOT NULL)"
    )
    db.execute("CREATE INDEX IF NOT EXISTS idx_interactions_lead "
               "ON interactions(lead_id)")
    db.execute("CREATE INDEX IF NOT EXISTS idx_interactions_user_day "
               "ON interactions(user_id, created_at)")
    _add_column_if_missing(db, "leads", "phone_bad",
                           "INTEGER NOT NULL DEFAULT 0")
    _add_column_if_missing(db, "leads", "pipeline_stage",
                           "TEXT NOT NULL DEFAULT 'new'")
    _add_column_if_missing(db, "leads", "pipeline_stage_at", "TEXT")
    _add_column_if_missing(db, "leads", "closed_state", "TEXT")

    # Backfill: recompute the pipeline stage of every existing lead so the
    # new UI is truthful from the first request after upgrade.
    from leadflow.pipeline import recompute  # local import to avoid cycles
    for row in db.execute("SELECT id FROM leads").fetchall():
        recompute(db, row["id"])


def _migration_0004_va_queue(db):
    """B5: the auto-filled VA calling queue (account_id per the B3 note)."""
    db.execute(
        "CREATE TABLE IF NOT EXISTS va_queue ("
        " id INTEGER PRIMARY KEY,"
        " account_id INTEGER NOT NULL DEFAULT 1,"
        " qdate TEXT NOT NULL,"
        " lead_id INTEGER NOT NULL REFERENCES leads(id),"
        " position INTEGER NOT NULL,"
        " source TEXT NOT NULL,"
        " status TEXT NOT NULL DEFAULT 'pending',"
        " worked_by INTEGER,"
        " worked_at TEXT,"
        " UNIQUE(qdate, lead_id))"
    )
    db.execute("CREATE INDEX IF NOT EXISTS idx_va_queue_date "
               "ON va_queue(qdate, position)")


def _migration_0005_remove_texting(db):
    """R1: remove all texting — email-only sequence, in-app + email
    notifications, web-only approvals.

    - retargets holding_line / fallback_reply templates to channel email
    - cancels pending outbound texts, then deletes text sequence steps and
      text templates (message rows keep their history; FK refs are nulled)
    - seeds the email_day38 template + enabled day-38 email step
    - deletes text send_channels rows, retired quo/text settings rows and
      the quo webhook/poll cursor app_state rows
    - notifications gains lead_id + read_at (NULL = unread); the status
      column now records the email outcome (sent|failed|skipped)
    - rebuilds approvals so the legacy code column allows NULL (codes are
      no longer generated; approvals are web-only)
    """
    now = utcnow()

    # 1. holding_line / fallback_reply become email templates.
    db.execute(
        "UPDATE templates SET channel = 'email', updated_at = ? "
        "WHERE slug IN ('holding_line','fallback_reply') AND channel = 'text'",
        (now,))

    # 2. no text will ever send again: cancel pending outbound texts.
    db.execute(
        "UPDATE messages SET status = 'canceled' WHERE direction = 'out' "
        "AND channel = 'text' AND status = 'pending'")

    # 3. detach message history from the text steps/templates about to go
    #    (foreign keys are ON; history rows themselves are kept).
    db.execute(
        "UPDATE messages SET step_id = NULL WHERE step_id IN "
        "(SELECT id FROM sequence_steps WHERE channel = 'text')")
    db.execute(
        "UPDATE messages SET template_id = NULL WHERE template_id IN "
        "(SELECT id FROM templates WHERE channel = 'text')")
    db.execute("DELETE FROM sequence_steps WHERE channel = 'text'")
    db.execute("DELETE FROM templates WHERE channel = 'text'")

    # 4. day-38 email keeps the slow phase's tail (window still ends day 44).
    # (email_day38 moved to LEGACY_TEMPLATES when Part 4's S4 timing
    # replaced the default sequence — this migration predates that.)
    from leadflow.seed import LEGACY_TEMPLATES  # local import to avoid cycles
    day38 = next(t for t in LEGACY_TEMPLATES if t["slug"] == "email_day38")
    row = db.execute(
        "SELECT id FROM templates WHERE slug = 'email_day38'").fetchone()
    if row is None:
        cur = db.execute(
            "INSERT INTO templates (slug, name, channel, subject, body, "
            "updated_at) VALUES (?,?,?,?,?,?)",
            (day38["slug"], day38["name"], day38["channel"],
             day38["subject"], day38["body"], now))
        tpl_id = cur.lastrowid
    else:
        tpl_id = row["id"]
    # Only append the step to an ESTABLISHED sequence; an empty table means
    # seed_defaults will seed the whole email-only sequence (incl day 38).
    has_steps = db.execute(
        "SELECT 1 FROM sequence_steps LIMIT 1").fetchone() is not None
    step = db.execute(
        "SELECT 1 FROM sequence_steps WHERE template_id = ?", (tpl_id,)
    ).fetchone()
    if has_steps and step is None:
        max_sort = db.execute(
            "SELECT COALESCE(MAX(sort_order), 0) AS m FROM sequence_steps"
        ).fetchone()["m"]
        db.execute(
            "INSERT INTO sequence_steps (day_offset, channel, template_id, "
            "sort_order, enabled) VALUES (38, 'email', ?, ?, 1)",
            (tpl_id, max_sort + 1))

    # 5. retire the text transport: channels, settings, webhook/poll state.
    db.execute("DELETE FROM send_channels WHERE channel = 'text'")
    db.execute(
        "DELETE FROM settings WHERE key IN ('quo_api_key', "
        "'quo_notification_number', 'owner_cell', "
        "'text_daily_cap_per_number', 'text_daily_global_cap')")
    db.execute(
        "DELETE FROM app_state WHERE key IN "
        "('quo_poll_cursor', 'quo_webhook_key')")

    # 6. notification center columns.
    _add_column_if_missing(db, "notifications", "lead_id", "INTEGER")
    _add_column_if_missing(db, "notifications", "read_at", "TEXT")

    # 7. approvals.code loses NOT NULL (legacy column, written NULL now).
    #    SQLite needs a table rebuild; skip when already nullable (fresh
    #    schema.sql installs).
    code_col = next(
        (r for r in db.execute("PRAGMA table_info(approvals)").fetchall()
         if r["name"] == "code"), None)
    if code_col is not None and code_col["notnull"]:
        db.execute(
            "CREATE TABLE approvals_new ("
            " id INTEGER PRIMARY KEY,"
            " account_id INTEGER NOT NULL DEFAULT 1,"
            " lead_id INTEGER NOT NULL REFERENCES leads(id),"
            " message_id INTEGER NOT NULL REFERENCES messages(id),"
            " code TEXT,"
            " status TEXT NOT NULL DEFAULT 'pending',"
            " approved_via TEXT,"
            " compliance_warning TEXT,"
            " created_at TEXT NOT NULL,"
            " expires_at TEXT NOT NULL,"
            " resolved_at TEXT)"
        )
        db.execute(
            "INSERT INTO approvals_new (id, account_id, lead_id, message_id, "
            "code, status, approved_via, compliance_warning, created_at, "
            "expires_at, resolved_at) "
            "SELECT id, account_id, lead_id, message_id, code, status, "
            "approved_via, compliance_warning, created_at, expires_at, "
            "resolved_at FROM approvals")
        db.execute("DROP TABLE approvals")
        db.execute("ALTER TABLE approvals_new RENAME TO approvals")
        db.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS uq_approvals_active_code "
            "ON approvals(code) WHERE status = 'pending' AND code IS NOT NULL")


def _migration_0006_part3_schema(db):
    """R-schema: Part 3 tables + columns, versioned pay rates.

    - leads gains hot_since / followup_on / followup_note / referred_by
    - recovery_flags table (one active flag per lead)
    - va_queue gains script_json (R5 cache)
    - pay_rates table seeded with ONE row effective '1970-01-01' from the
      current pay_* settings values converted to cents, EXCEPT
      floor_leads = 125 (new default); the six pay_* settings rows are then
      deleted (retired — the VA pay UI reads/writes pay_rates from now on)
    - sales, referral_asks, tasks tables
    """
    now = utcnow()

    _add_column_if_missing(db, "leads", "hot_since", "TEXT")
    _add_column_if_missing(db, "leads", "followup_on", "TEXT")
    _add_column_if_missing(db, "leads", "followup_note", "TEXT")
    _add_column_if_missing(db, "leads", "referred_by",
                           "INTEGER REFERENCES leads(id)")

    db.execute(
        "CREATE TABLE IF NOT EXISTS recovery_flags ("
        " id INTEGER PRIMARY KEY,"
        " account_id INTEGER NOT NULL DEFAULT 1,"
        " lead_id INTEGER NOT NULL REFERENCES leads(id),"
        " kind TEXT NOT NULL,"
        " flagged_at TEXT NOT NULL,"
        " status TEXT NOT NULL DEFAULT 'open',"
        " outcome TEXT,"
        " resolved_at TEXT,"
        " created_at TEXT NOT NULL)"
    )
    db.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS uq_recovery_flags_active "
        "ON recovery_flags(lead_id) WHERE status IN ('open', 'queued')")
    db.execute(
        "CREATE INDEX IF NOT EXISTS idx_recovery_flags_status "
        "ON recovery_flags(status, kind)")

    _add_column_if_missing(db, "va_queue", "script_json", "TEXT")

    db.execute(
        "CREATE TABLE IF NOT EXISTS pay_rates ("
        " id INTEGER PRIMARY KEY,"
        " account_id INTEGER NOT NULL DEFAULT 1,"
        " effective_date TEXT NOT NULL,"
        " daily_base_cents INTEGER NOT NULL,"
        " floor_leads INTEGER NOT NULL,"
        " send_options_cents INTEGER NOT NULL,"
        " appt_scheduled_cents INTEGER NOT NULL,"
        " appt_showed_cents INTEGER NOT NULL,"
        " sold_bonus_cents INTEGER NOT NULL,"
        " created_at TEXT NOT NULL,"
        " UNIQUE(account_id, effective_date))"
    )

    def cents(value, default):
        try:
            return int(round(float(value) * 100))
        except (TypeError, ValueError):
            return int(round(default * 100))

    empty = db.execute("SELECT 1 FROM pay_rates LIMIT 1").fetchone() is None
    if empty:
        db.execute(
            "INSERT INTO pay_rates (account_id, effective_date, "
            "daily_base_cents, floor_leads, send_options_cents, "
            "appt_scheduled_cents, appt_showed_cents, sold_bonus_cents, "
            "created_at) VALUES (1, '1970-01-01', ?,?,?,?,?,?,?)",
            (cents(_raw_setting(db, "pay_daily_base"), 20.00),
             125,  # new default floor; deliberately NOT the old setting value
             cents(_raw_setting(db, "pay_send_options"), 2.50),
             cents(_raw_setting(db, "pay_appt_scheduled"), 2.50),
             cents(_raw_setting(db, "pay_appt_showed"), 5.00),
             cents(_raw_setting(db, "pay_won_bonus"), 10.00),
             now))
    # Retired: code must no longer read the pay_* settings.
    db.execute(
        "DELETE FROM settings WHERE key IN ('pay_daily_base', "
        "'pay_floor_leads', 'pay_send_options', 'pay_appt_scheduled', "
        "'pay_appt_showed', 'pay_won_bonus')")

    db.execute(
        "CREATE TABLE IF NOT EXISTS sales ("
        " id INTEGER PRIMARY KEY,"
        " account_id INTEGER NOT NULL DEFAULT 1,"
        " lead_id INTEGER NOT NULL UNIQUE REFERENCES leads(id),"
        " premium_cents INTEGER,"
        " status TEXT NOT NULL DEFAULT 'pending',"
        " commission_cents INTEGER,"
        " sold_at TEXT,"
        " resolved_at TEXT,"
        " note TEXT,"
        " created_at TEXT NOT NULL,"
        " updated_at TEXT NOT NULL)"
    )
    db.execute(
        "CREATE TABLE IF NOT EXISTS referral_asks ("
        " id INTEGER PRIMARY KEY,"
        " account_id INTEGER NOT NULL DEFAULT 1,"
        " lead_id INTEGER NOT NULL REFERENCES leads(id),"
        " ask_no INTEGER NOT NULL,"
        " due_at TEXT NOT NULL,"
        " status TEXT NOT NULL DEFAULT 'pending',"
        " approval_id INTEGER,"
        " created_at TEXT NOT NULL)"
    )
    db.execute(
        "CREATE TABLE IF NOT EXISTS tasks ("
        " id INTEGER PRIMARY KEY,"
        " account_id INTEGER NOT NULL DEFAULT 1,"
        " kind TEXT NOT NULL,"
        " lead_id INTEGER,"
        " body TEXT,"
        " status TEXT NOT NULL DEFAULT 'open',"
        " created_at TEXT NOT NULL,"
        " done_at TEXT)"
    )


def _migration_0007_sold_rename(db):
    """R-schema: SOLD/client rename — closed_state 'won' -> 'sold',
    interactions itype 'won_credit' -> 'sold_credit', and the computed
    pipeline stage 'won' -> 'client' on existing rows."""
    db.execute(
        "UPDATE leads SET closed_state = 'sold' WHERE closed_state = 'won'")
    db.execute(
        "UPDATE interactions SET itype = 'sold_credit' "
        "WHERE itype = 'won_credit'")
    db.execute(
        "UPDATE leads SET pipeline_stage = 'client' "
        "WHERE pipeline_stage = 'won'")


def _migration_0008_part4_multitenant(db):
    """S1/S2/S3 (+ S4/S5/S8 pre-provision) schema — Part 4 Wave A.

    Runs with foreign keys OFF (fk_off attribute below): several tables are
    REBUILT to change their constraints, and messages/sequence_steps/leads
    rows reference two of them.

    - accounts.status ('active' for existing rows; signups write 'pending')
    - attestations table (S1 signup attestation)
    - settings REBUILT: PK (account_id, key); existing rows -> account 1
    - templates REBUILT: account_id + UNIQUE(account_id, slug)
    - lead_sources REBUILT: account_id + UNIQUE(account_id, name) +
      cost_cents (S5 pre-provision; NextGen $120 / USHA $40 backfilled)
    - send_channels REBUILT: UNIQUE(account_id, channel, identifier)
    - processed_emails REBUILT: account_id + PK (account_id,
      gmail_message_id) (two tenants may legitimately both receive an
      email carrying the same Message-ID)
    - pay_rates REBUILT: user_id (NULL = tenant default, S2) + partial
      unique indexes replacing UNIQUE(account_id, effective_date)
      (SQLite treats NULLs as distinct, so the per-user uniqueness needs
      two partial indexes)
    - sequence_steps: account_id + step_kind (S4 pre-provision)
    - blocklist: account_id
    - users: daily_quota (S2), fixed_monthly_cost_cents + started_on (S6
      pre-provision)
    - va_queue: assigned_to (S2 claims) + slot_hour (S3 retry slots)
    - messages.in_reply_to (S4 threading pre-provision)
    - leads.cost_cents (S5 pre-provision)
    - interactions.gcal_event_id (S8 pre-provision)
    """
    now = utcnow()

    # -- accounts / attestations (S1) --------------------------------------
    _add_column_if_missing(db, "accounts", "status",
                           "TEXT NOT NULL DEFAULT 'active'")
    db.execute(
        "CREATE TABLE IF NOT EXISTS attestations ("
        " id INTEGER PRIMARY KEY,"
        " account_id INTEGER NOT NULL,"
        " user_id INTEGER NOT NULL,"
        " version INTEGER NOT NULL,"
        " text TEXT NOT NULL,"
        " signed_name TEXT NOT NULL,"
        " signed_at TEXT NOT NULL)")

    # -- settings: PK (account_id, key) ------------------------------------
    if "account_id" not in _table_columns(db, "settings"):
        db.execute(
            "CREATE TABLE settings_new ("
            " account_id INTEGER NOT NULL DEFAULT 1,"
            " key TEXT NOT NULL,"
            " value TEXT NOT NULL,"
            " is_secret INTEGER NOT NULL DEFAULT 0,"
            " updated_at TEXT NOT NULL,"
            " PRIMARY KEY (account_id, key))")
        db.execute(
            "INSERT INTO settings_new (account_id, key, value, is_secret, "
            "updated_at) SELECT 1, key, value, is_secret, updated_at "
            "FROM settings")
        db.execute("DROP TABLE settings")
        db.execute("ALTER TABLE settings_new RENAME TO settings")

    # -- templates: account_id + UNIQUE(account_id, slug) -------------------
    if "account_id" not in _table_columns(db, "templates"):
        db.execute(
            "CREATE TABLE templates_new ("
            " id INTEGER PRIMARY KEY,"
            " account_id INTEGER NOT NULL DEFAULT 1,"
            " slug TEXT NOT NULL,"
            " name TEXT NOT NULL,"
            " channel TEXT NOT NULL,"
            " subject TEXT,"
            " body TEXT NOT NULL,"
            " updated_at TEXT NOT NULL,"
            " UNIQUE(account_id, slug))")
        db.execute(
            "INSERT INTO templates_new (id, account_id, slug, name, channel, "
            "subject, body, updated_at) SELECT id, 1, slug, name, channel, "
            "subject, body, updated_at FROM templates")
        db.execute("DROP TABLE templates")
        db.execute("ALTER TABLE templates_new RENAME TO templates")

    # -- lead_sources: account_id + UNIQUE(account_id, name) + cost_cents --
    if "account_id" not in _table_columns(db, "lead_sources"):
        db.execute(
            "CREATE TABLE lead_sources_new ("
            " id INTEGER PRIMARY KEY,"
            " account_id INTEGER NOT NULL DEFAULT 1,"
            " name TEXT NOT NULL,"
            " enabled INTEGER NOT NULL DEFAULT 1,"
            " sender_addresses TEXT NOT NULL,"
            " subject_pattern TEXT,"
            " field_map TEXT NOT NULL,"
            " cost_cents INTEGER NOT NULL DEFAULT 0,"
            " created_at TEXT NOT NULL,"
            " updated_at TEXT NOT NULL,"
            " UNIQUE(account_id, name))")
        db.execute(
            "INSERT INTO lead_sources_new (id, account_id, name, enabled, "
            "sender_addresses, subject_pattern, field_map, cost_cents, "
            "created_at, updated_at) SELECT id, 1, name, enabled, "
            "sender_addresses, subject_pattern, field_map, 0, created_at, "
            "updated_at FROM lead_sources")
        db.execute("DROP TABLE lead_sources")
        db.execute("ALTER TABLE lead_sources_new RENAME TO lead_sources")
        # S5 pre-provision: seed the known source costs on existing rows.
        db.execute("UPDATE lead_sources SET cost_cents = 12000 "
                   "WHERE name = 'NextGen Leads' AND cost_cents = 0")
        db.execute("UPDATE lead_sources SET cost_cents = 4000 "
                   "WHERE name = 'USHA Marketplace' AND cost_cents = 0")

    # -- send_channels: UNIQUE(account_id, channel, identifier) -------------
    db.execute(
        "CREATE TABLE send_channels_new ("
        " id INTEGER PRIMARY KEY,"
        " account_id INTEGER NOT NULL DEFAULT 1,"
        " channel TEXT NOT NULL,"
        " identifier TEXT NOT NULL,"
        " secret TEXT,"
        " role TEXT NOT NULL DEFAULT 'overflow',"
        " sort_order INTEGER NOT NULL DEFAULT 0,"
        " enabled INTEGER NOT NULL DEFAULT 1,"
        " created_at TEXT NOT NULL,"
        " UNIQUE(account_id, channel, identifier))")
    db.execute(
        "INSERT INTO send_channels_new (id, account_id, channel, identifier, "
        "secret, role, sort_order, enabled, created_at) "
        "SELECT id, account_id, channel, identifier, secret, role, "
        "sort_order, enabled, created_at FROM send_channels")
    db.execute("DROP TABLE send_channels")
    db.execute("ALTER TABLE send_channels_new RENAME TO send_channels")

    # -- processed_emails: PK (account_id, gmail_message_id) ----------------
    if "account_id" not in _table_columns(db, "processed_emails"):
        db.execute(
            "CREATE TABLE processed_emails_new ("
            " account_id INTEGER NOT NULL DEFAULT 1,"
            " gmail_message_id TEXT NOT NULL,"
            " uid INTEGER,"
            " kind TEXT NOT NULL,"
            " lead_id INTEGER,"
            " processed_at TEXT NOT NULL,"
            " PRIMARY KEY (account_id, gmail_message_id))")
        db.execute(
            "INSERT INTO processed_emails_new (account_id, gmail_message_id, "
            "uid, kind, lead_id, processed_at) SELECT 1, gmail_message_id, "
            "uid, kind, lead_id, processed_at FROM processed_emails")
        db.execute("DROP TABLE processed_emails")
        db.execute(
            "ALTER TABLE processed_emails_new RENAME TO processed_emails")

    # -- pay_rates: user_id + partial unique indexes (S2) --------------------
    if "user_id" not in _table_columns(db, "pay_rates"):
        db.execute(
            "CREATE TABLE pay_rates_new ("
            " id INTEGER PRIMARY KEY,"
            " account_id INTEGER NOT NULL DEFAULT 1,"
            " user_id INTEGER,"
            " effective_date TEXT NOT NULL,"
            " daily_base_cents INTEGER NOT NULL,"
            " floor_leads INTEGER NOT NULL,"
            " send_options_cents INTEGER NOT NULL,"
            " appt_scheduled_cents INTEGER NOT NULL,"
            " appt_showed_cents INTEGER NOT NULL,"
            " sold_bonus_cents INTEGER NOT NULL,"
            " created_at TEXT NOT NULL)")
        db.execute(
            "INSERT INTO pay_rates_new (id, account_id, user_id, "
            "effective_date, daily_base_cents, floor_leads, "
            "send_options_cents, appt_scheduled_cents, appt_showed_cents, "
            "sold_bonus_cents, created_at) "
            "SELECT id, account_id, NULL, effective_date, daily_base_cents, "
            "floor_leads, send_options_cents, appt_scheduled_cents, "
            "appt_showed_cents, sold_bonus_cents, created_at FROM pay_rates")
        db.execute("DROP TABLE pay_rates")
        db.execute("ALTER TABLE pay_rates_new RENAME TO pay_rates")
    db.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS uq_pay_rates_default "
        "ON pay_rates(account_id, effective_date) WHERE user_id IS NULL")
    db.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS uq_pay_rates_user "
        "ON pay_rates(account_id, user_id, effective_date) "
        "WHERE user_id IS NOT NULL")

    # -- simple column additions --------------------------------------------
    _add_column_if_missing(db, "sequence_steps", "account_id",
                           "INTEGER NOT NULL DEFAULT 1")
    _add_column_if_missing(db, "sequence_steps", "step_kind",
                           "TEXT NOT NULL DEFAULT 'email'")
    _add_column_if_missing(db, "blocklist", "account_id",
                           "INTEGER NOT NULL DEFAULT 1")
    _add_column_if_missing(db, "users", "daily_quota", "INTEGER")
    _add_column_if_missing(db, "users", "fixed_monthly_cost_cents", "INTEGER")
    _add_column_if_missing(db, "users", "started_on", "TEXT")
    _add_column_if_missing(db, "va_queue", "assigned_to", "INTEGER")
    _add_column_if_missing(db, "va_queue", "slot_hour", "INTEGER")
    _add_column_if_missing(db, "messages", "in_reply_to", "TEXT")
    _add_column_if_missing(db, "leads", "cost_cents", "INTEGER")
    _add_column_if_missing(db, "interactions", "gcal_event_id", "TEXT")
    # Silence "unused" warning; kept for symmetry with earlier migrations.
    _ = now


_migration_0008_part4_multitenant.fk_off = True


def _migration_0009_part4_sequence(db):
    """S4 default-sequence DATA migration (schema shipped in migration 8).

    Per account: seed the S4 templates (email_1..3, quote_email — the
    user's exact text, email_5_nudge, email_6, email_7) when missing, then
    REPLACE the default sequence for accounts whose enabled steps still
    match the pre-Part-4 defaults (0/6/14/28/38 email steps on the
    email_day* templates). Customized sequences are left alone; historical
    message rows keep their step_id (steps are deleted only after their
    message references are detached, mirroring migration 5)."""
    from leadflow.seed import (  # local import to avoid cycles
        OLD_DEFAULT_STEPS, SEQUENCE_STEPS, TEMPLATES, seed_templates,
    )
    now = utcnow()
    accounts = [r["id"] for r in
                db.execute("SELECT id FROM accounts ORDER BY id").fetchall()]
    for account_id in accounts:
        template_ids = seed_templates(db, account_id, TEMPLATES, now)

        steps = db.execute(
            "SELECT s.*, t.slug AS slug FROM sequence_steps s "
            "JOIN templates t ON t.id = s.template_id "
            "WHERE s.account_id = ? AND s.enabled = 1",
            (account_id,)).fetchall()
        current = sorted((s["day_offset"], s["slug"]) for s in steps)
        if current != sorted(OLD_DEFAULT_STEPS):
            continue  # customized (or already migrated): leave it alone

        step_ids = [s["id"] for s in db.execute(
            "SELECT id FROM sequence_steps WHERE account_id = ?",
            (account_id,)).fetchall()]
        if step_ids:
            marks = ",".join("?" for _ in step_ids)
            # Detach message history (keep the rows), then drop the steps.
            db.execute(
                "UPDATE messages SET status = 'canceled' "
                "WHERE step_id IN (%s) AND status = 'pending'" % marks,
                step_ids)
            db.execute(
                "UPDATE messages SET step_id = NULL WHERE step_id IN (%s)"
                % marks, step_ids)
            db.execute(
                "DELETE FROM sequence_steps WHERE id IN (%s)" % marks,
                step_ids)
        for day_offset, channel, slug, sort_order, step_kind in SEQUENCE_STEPS:
            db.execute(
                "INSERT INTO sequence_steps (account_id, day_offset, "
                "channel, template_id, sort_order, enabled, step_kind) "
                "VALUES (?,?,?,?,?,1,?)",
                (account_id, day_offset, channel, template_ids[slug],
                 sort_order, step_kind))


def _migration_0010_reschedule_stranded(db):
    """S4 heal-forward DATA migration: migration 9 canceled every pending
    old-default-sequence send but scheduled NOTHING from the new sequence,
    so a mid-sequence lead silently exhausted with steps unsent.

    Per account: every lead that is still worth emailing — engine stage
    'active', not halted, not closed, not a referral (firewall), received
    within the last 90 days — and has ZERO live sequence sends (no
    pending/surfaced step rows) gets the enabled steps whose day is still
    AHEAD re-scheduled: due = received_at + day_offset using the
    scheduler's due-time rule (10:00 lead-local; replicated here so the
    migration never imports app modules mid-upgrade). run_quotes steps
    become pending rows the dispatcher will surface as tasks. Steps whose
    day already passed stay unsent — the lead is never spammed with
    catch-up emails. Idempotent: leads with any live step row are skipped
    entirely and each insert re-checks (lead_id, step_id), matching the
    uq_messages_lead_step unique index."""
    from zoneinfo import ZoneInfo
    now_dt = datetime.datetime.now(datetime.timezone.utc)
    now = now_dt.isoformat(timespec="seconds")
    window_floor = (now_dt - datetime.timedelta(days=90)
                    ).isoformat(timespec="seconds")
    default_zone = ZoneInfo("America/New_York")
    ten_am = datetime.time(10, 0)  # scheduler.LATER_STEP_LOCAL_TIME

    accounts = [r["id"] for r in
                db.execute("SELECT id FROM accounts ORDER BY id").fetchall()]
    for account_id in accounts:
        steps = db.execute(
            "SELECT * FROM sequence_steps WHERE account_id = ? "
            "AND enabled = 1 ORDER BY sort_order, id",
            (account_id,)).fetchall()
        if not steps:
            continue
        leads = db.execute(
            "SELECT * FROM leads WHERE account_id = ? "
            "AND stage = 'active' AND sequence_halted = 0 "
            "AND closed_state IS NULL AND referred_by IS NULL "
            "AND received_at >= ? "
            "AND NOT EXISTS (SELECT 1 FROM messages m "
            " WHERE m.lead_id = leads.id AND m.direction = 'out' "
            " AND m.step_id IS NOT NULL "
            " AND m.status IN ('pending','surfaced'))",
            (account_id, window_floor)).fetchall()
        for lead in leads:
            try:
                received = datetime.datetime.fromisoformat(
                    str(lead["received_at"]).replace("Z", "+00:00"))
            except ValueError:
                continue
            if received.tzinfo is None:
                received = received.replace(tzinfo=datetime.timezone.utc)
            try:
                zone = ZoneInfo(lead["timezone"] or "America/New_York")
            except Exception:
                zone = default_zone
            received_local = received.astimezone(zone)
            created = 0
            for step in steps:
                due = datetime.datetime.combine(
                    received_local.date()
                    + datetime.timedelta(days=step["day_offset"]),
                    ten_am, tzinfo=zone
                ).astimezone(datetime.timezone.utc)
                if due <= now_dt:
                    continue  # that day already passed — never re-send it
                if db.execute(
                        "SELECT 1 FROM messages WHERE lead_id = ? "
                        "AND step_id = ? "
                        "AND status NOT IN ('canceled','skipped')",
                        (lead["id"], step["id"])).fetchone() is not None:
                    continue  # uq_messages_lead_step already holds a row
                step_kind = step["step_kind"] or "email"
                db.execute(
                    "INSERT INTO messages (account_id, lead_id, direction, "
                    "channel, kind, step_id, template_id, subject, body, "
                    "status, due_at, is_first_touch, created_at) "
                    "VALUES (?,?,?,?,?,?,?,?,?,?,?,0,?)",
                    (account_id, lead["id"], "out", step["channel"],
                     "run_quotes" if step_kind == "run_quotes"
                     else "sequence",
                     step["id"], step["template_id"], None, "", "pending",
                     due.isoformat(timespec="seconds"), now))
                created += 1
            if created:
                db.execute(
                    "INSERT INTO events (account_id, lead_id, etype, "
                    "detail, created_at) VALUES (?,?,?,?,?)",
                    (account_id, lead["id"], "scheduled",
                     "migration 10: re-scheduled %d remaining sequence "
                     "send(s) stranded by the S4 sequence swap" % created,
                     now))


def _migration_0011_part5_calls(db):
    """C1 pre-provision for Part 5 waves 2-3 — SCHEMA ONLY, no behavior.

    - users.phone: the VA leg of the C3 click-to-call bridge (Twilio rings
      this number first, then dials the lead with the local-presence
      caller ID). Editable in Settings -> Users.
    - calls: one row per outbound Twilio call (C3 writes, C4 reads).
      Money in cents per CLAUDE.md; cost_is_actual distinguishes Twilio's
      published price from the per-minute estimate. No recording column
      exists because recording is never requested.
    - twilio_numbers: the tenant's local-presence pool (C3).
    - closed_state gains the value 'no_number' (C2a). closed_state has no
      CHECK constraint, so this is documentation only — recorded in
      schema.sql, pipeline.py and va.py so C2a can simply set it.

    Idempotent: ALTER only when the column is missing, CREATE IF NOT
    EXISTS for the tables and indexes (a fresh install already has all of
    it from schema.sql)."""
    _add_column_if_missing(db, "users", "phone", "TEXT")
    db.execute(
        "CREATE TABLE IF NOT EXISTS calls ("
        " id INTEGER PRIMARY KEY,"
        " account_id INTEGER NOT NULL DEFAULT 1,"
        " lead_id INTEGER NOT NULL REFERENCES leads(id),"
        " user_id INTEGER,"
        " twilio_sid TEXT UNIQUE,"
        " from_number TEXT,"
        " to_number TEXT,"
        " status TEXT,"
        " duration_seconds INTEGER,"
        " cost_cents INTEGER,"
        " cost_is_actual INTEGER NOT NULL DEFAULT 0,"
        " error TEXT,"
        " started_at TEXT,"
        " ended_at TEXT,"
        " created_at TEXT NOT NULL)")
    db.execute("CREATE INDEX IF NOT EXISTS idx_calls_account_day "
               "ON calls(account_id, created_at)")
    db.execute("CREATE INDEX IF NOT EXISTS idx_calls_user_day "
               "ON calls(user_id, created_at)")
    db.execute(
        "CREATE TABLE IF NOT EXISTS twilio_numbers ("
        " id INTEGER PRIMARY KEY,"
        " account_id INTEGER NOT NULL DEFAULT 1,"
        " number TEXT NOT NULL,"
        " enabled INTEGER NOT NULL DEFAULT 1,"
        " sort_order INTEGER NOT NULL DEFAULT 0,"
        " created_at TEXT NOT NULL,"
        " UNIQUE(account_id, number))")


def _migration_0012_appt_confirmations(db):
    """T1 (PART 6): appointment confirmation tracking — SCHEMA ONLY.

    The app NEVER sends a text; it reminds the AGENT to send one from
    their own phone and records that they did. Two nullable stamps on
    `interactions`, meaningful only on appointment/scheduled rows:

    - confirmation_sent_at: UTC ISO, written when the agent presses
      "Confirmed sent". NULL = this appointment still needs a
      confirmation text.
    - confirmation_notified_at: UTC ISO, written by the worker
      (confirmations.notify_due) once it has fired this appointment's ONE
      reminder notification. A pure idempotency marker — it is what makes
      a job that runs every tick fire exactly once per appointment.

    T1 also adds the terminal appointment outcomes `cancelled` and
    `rescheduled` to interactions.disposition. That needs no DDL (the
    column has no CHECK constraint), so it is documented in schema.sql,
    interactions.py and pipeline.py instead — exactly like C1's
    closed_state 'no_number'.

    Idempotent: ALTER only when the column is missing (a fresh install
    already has both from schema.sql)."""
    _add_column_if_missing(db, "interactions", "confirmation_sent_at", "TEXT")
    _add_column_if_missing(db, "interactions", "confirmation_notified_at",
                           "TEXT")



def _migration_0013_nudge_merge_field(db):
    """The day-7 nudge shipped with a SINGLE-brace {name}, which
    render_tpl never substitutes (it only replaces {{key}}), so every
    tenant's highest-intent follow-up went out reading "Hi {name},".

    Repairs ONLY rows still holding the exact broken default — a tenant
    who edited their own nudge keeps their wording, whatever it is. The
    dispatcher's unfilled-token rung is the backstop for that case: it
    refuses to send a body still carrying a token rather than mailing the
    braces to a lead.
    """
    if not _table_columns(db, "templates"):
        return  # nothing seeded yet (fresh/partial DB): schema.sql wins
    broken = ("Hi {name}, just following up on the options I sent over — "
              "would you like more details on the plan I recommended?")
    fixed = ("Hi {{first_name}}, just following up on the options I sent "
             "over — would you like more details on the plan I recommended?")
    cur = db.execute(
        "UPDATE templates SET body = ?, updated_at = ? "
        "WHERE slug = 'email_5_nudge' AND body = ?",
        (fixed, utcnow(), broken))
    if cur.rowcount:
        logger.info("migration 13: repaired %d day-7 nudge template(s)",
                    cur.rowcount)


def _migration_0014_agent_leads(db):
    """Agent leads: leads sourced from another licensed agent, worked in
    the NORMAL pipeline and split on commission.

    NOT a referral (`leads.referred_by`) — a referral gets zero automation
    and is routed to the owner personally. An agent lead is an ordinary
    working lead with a shorter unworked residency and no email sequence.

    - leads.source_agent: TEXT, nullable. The agent's NAME, SNAPSHOTTED at
      import — deliberately denormalised, exactly like leads.cost_cents
      snapshots lead_sources.cost_cents. The roster row can be deleted; a
      SOLD lead's payment obligation cannot, so the name has to survive
      independently of the roster. NULL = a normal bought lead.
    - source_agents: the tenant's roster. Upload picks from it; it is never
      free text, so spellings cannot fragment.
    - source_agent_maps: one saved CSV header->field mapping per agent, per
      tenant. Confirmed once on the first upload, auto-applied afterwards.

    NO BACKFILL LOOP, deliberately. Every existing lead is correctly
    `source_agent IS NULL`, which already means "not an agent lead" — so
    unlike migration 3 there is no per-row recompute to get wrong, and
    nothing here is unscoped across tenants.

    Idempotent: ALTER only when the column is missing, CREATE IF NOT EXISTS
    for the tables and indexes (a fresh install has all of it already from
    schema.sql)."""
    if not _table_columns(db, "leads"):
        return  # nothing seeded yet (fresh/partial DB): schema.sql wins
    _add_column_if_missing(db, "leads", "source_agent", "TEXT")
    db.execute("CREATE INDEX IF NOT EXISTS idx_leads_source_agent "
               "ON leads(account_id, source_agent)")
    db.execute(
        "CREATE TABLE IF NOT EXISTS source_agents ("
        " id INTEGER PRIMARY KEY,"
        " account_id INTEGER NOT NULL DEFAULT 1,"
        " name TEXT NOT NULL,"
        " enabled INTEGER NOT NULL DEFAULT 1,"
        " created_at TEXT NOT NULL,"
        " UNIQUE(account_id, name COLLATE NOCASE))")
    db.execute(
        "CREATE TABLE IF NOT EXISTS source_agent_maps ("
        " id INTEGER PRIMARY KEY,"
        " account_id INTEGER NOT NULL DEFAULT 1,"
        " agent_id INTEGER NOT NULL REFERENCES source_agents(id),"
        " field_map TEXT NOT NULL,"
        " created_at TEXT NOT NULL,"
        " updated_at TEXT NOT NULL,"
        " UNIQUE(account_id, agent_id))")


def _migration_0015_overflow_pool(db):
    """The overflow pool: cold-start backfill for a new tenant whose VA has
    an empty queue on day one because organic lead flow has not started.

    THREE tables, and the separation is the point:

    - overflow_leads: NOT the leads table and NOT a flag on it. An overflow
      row is not a real lead until positive contact, and a flag holds that
      invariant only as long as every current AND FUTURE query remembers to
      filter. Physical separation makes the violation impossible instead of
      merely discouraged. Promotion MOVES the row into `leads`.
    - overflow_attempts: the pool's own lightweight call log. A VA who
      dials an overflow row and gets no answer must record it somewhere
      that is not `interactions`, because `interactions.lead_id` points at
      `leads`. These records DIE WITH THE ROW (ON DELETE CASCADE is not
      used — the delete paths clear children explicitly, matching the rest
      of the app).
    - overflow_queue: today's drawn overflow rows. `va_queue` is left
      completely untouched — its lead_id stays NOT NULL REFERENCES
      leads(id), so no existing queue query becomes a union type.

    Idempotent: CREATE TABLE / INDEX IF NOT EXISTS throughout (a fresh
    install already has all of it from schema.sql). No backfill: there is
    nothing to convert, the pool starts empty."""
    db.execute(
        "CREATE TABLE IF NOT EXISTS overflow_leads ("
        " id INTEGER PRIMARY KEY,"
        " account_id INTEGER NOT NULL DEFAULT 1,"
        " first_name TEXT NOT NULL DEFAULT '',"
        " last_name TEXT NOT NULL DEFAULT '',"
        " email TEXT,"
        " phone TEXT,"
        " city TEXT, state TEXT, zip TEXT,"
        " timezone TEXT NOT NULL DEFAULT 'America/New_York',"
        " metadata TEXT NOT NULL DEFAULT '{}',"
        " batch_id TEXT,"
        " file_order INTEGER NOT NULL DEFAULT 0,"
        " status TEXT NOT NULL DEFAULT 'pool',"
        " uploaded_at TEXT NOT NULL,"
        " created_at TEXT NOT NULL)")
    db.execute("CREATE INDEX IF NOT EXISTS idx_overflow_pool "
               "ON overflow_leads(account_id, status, uploaded_at)")
    db.execute("CREATE INDEX IF NOT EXISTS idx_overflow_phone "
               "ON overflow_leads(account_id, phone)")
    db.execute("CREATE INDEX IF NOT EXISTS idx_overflow_email "
               "ON overflow_leads(account_id, email)")
    db.execute(
        "CREATE TABLE IF NOT EXISTS overflow_attempts ("
        " id INTEGER PRIMARY KEY,"
        " account_id INTEGER NOT NULL DEFAULT 1,"
        " overflow_id INTEGER NOT NULL REFERENCES overflow_leads(id),"
        " user_id INTEGER,"
        " disposition TEXT NOT NULL,"
        " note TEXT,"
        " created_at TEXT NOT NULL)")
    db.execute("CREATE INDEX IF NOT EXISTS idx_overflow_attempts_row "
               "ON overflow_attempts(overflow_id, created_at)")
    db.execute("CREATE INDEX IF NOT EXISTS idx_overflow_attempts_user "
               "ON overflow_attempts(account_id, user_id, created_at)")
    db.execute(
        "CREATE TABLE IF NOT EXISTS overflow_queue ("
        " id INTEGER PRIMARY KEY,"
        " account_id INTEGER NOT NULL DEFAULT 1,"
        " qdate TEXT NOT NULL,"
        " overflow_id INTEGER NOT NULL REFERENCES overflow_leads(id),"
        " position INTEGER NOT NULL,"
        " source TEXT NOT NULL,"
        " status TEXT NOT NULL DEFAULT 'pending',"
        " worked_by INTEGER,"
        " worked_at TEXT,"
        " assigned_to INTEGER,"
        " UNIQUE(qdate, overflow_id))")
    db.execute("CREATE INDEX IF NOT EXISTS idx_overflow_queue_date "
               "ON overflow_queue(qdate, position)")


def _migration_0016_va_entitlement(db):
    """Account-level VA entitlement, redeemed with an optional access code.

    THE ENTITLEMENT IS NOT A TOGGLE. `accounts.va_entitled` answers "may
    this account have VAs at all" — set once at signup (or later, by
    redeeming a code) and rarely changed. The existing `va_enabled` setting
    answers a DIFFERENT question, "are VAs active right now", and stays
    exactly as it was: an entitled account's day-to-day pause switch. A
    non-entitled account never sees that toggle and it stays off.

    - accounts.va_entitled: INTEGER 0/1, DEFAULT 0 so every account created
      from here on is pipeline-only until a code says otherwise.

      EVERY EXISTING ACCOUNT IS GRANDFATHERED to 1 by the UPDATE below.
      Nobody loses a surface they already use, and that includes account 1.
      The DEFAULT is 0 and the backfill is 1 on purpose: the two disagree
      because "what a new account gets" and "what a running account keeps"
      are genuinely different answers. The UPDATE is unscoped BY DESIGN —
      it is a one-time grandfather of every tenant that predates the
      feature, which is the only correct scope for it.

    - access_codes: the redeemable codes. `account_id` is the ISSUING
      account (the owner's), so the Settings section that creates, lists
      and revokes them scopes normally. Redemption LOOKUP is the one query
      in the app that deliberately crosses tenants — a code is handed to a
      DIFFERENT account by definition — and it is marked as such at the
      call site.

      `revoked_at` stops FUTURE redemptions only. It is not consulted
      again afterwards: entitlement lives on the account row, so revoking
      a leaked code can never silently break an account already using it.

    - access_code_redemptions: who redeemed what, when. Audit only; no
      read path grants access from it. Deleting every row here would not
      cost a single account its entitlement, which is exactly the property
      that makes revocation safe.

    Idempotent: ALTER only when the column is missing, CREATE IF NOT EXISTS
    for the tables and indexes. The grandfathering UPDATE only touches rows
    the ALTER just defaulted to 0, so a re-run is a no-op — it is guarded
    by the same `column missing` check."""
    if not _table_columns(db, "accounts"):
        return  # nothing seeded yet (fresh/partial DB): schema.sql wins
    if "va_entitled" not in _table_columns(db, "accounts"):
        _add_column_if_missing(db, "accounts", "va_entitled",
                               "INTEGER NOT NULL DEFAULT 0")
        # Grandfather EVERY pre-existing account. Runs once, inside the
        # `column was missing` branch, so re-applying never re-grants an
        # account whose access was deliberately removed later.
        db.execute("UPDATE accounts SET va_entitled = 1")
    db.execute(
        "CREATE TABLE IF NOT EXISTS access_codes ("
        " id INTEGER PRIMARY KEY,"
        " account_id INTEGER NOT NULL DEFAULT 1,"   # the ISSUING account
        " code TEXT NOT NULL,"
        " label TEXT NOT NULL DEFAULT '',"
        " created_by INTEGER,"
        " created_at TEXT NOT NULL,"
        " revoked_at TEXT,"                          # future redemptions only
        " revoked_by INTEGER)")
    # Codes are matched by value across tenants at redemption, so the value
    # has to be globally unique — not unique per account.
    db.execute("CREATE UNIQUE INDEX IF NOT EXISTS uq_access_codes_code "
               "ON access_codes(code)")
    db.execute(
        "CREATE TABLE IF NOT EXISTS access_code_redemptions ("
        " id INTEGER PRIMARY KEY,"
        " code_id INTEGER NOT NULL REFERENCES access_codes(id),"
        " account_id INTEGER NOT NULL,"              # the REDEEMING account
        " user_id INTEGER,"
        " redeemed_at TEXT NOT NULL)")
    db.execute("CREATE INDEX IF NOT EXISTS idx_redemptions_code "
               "ON access_code_redemptions(code_id, redeemed_at)")
    db.execute("CREATE INDEX IF NOT EXISTS idx_redemptions_account "
               "ON access_code_redemptions(account_id, redeemed_at)")


def _migration_0017_remove_dialer(db):
    """Retire the internal calling system's SETTINGS rows.

    The app placed and costed its own calls through Twilio until the
    calling system was removed; dialing happens in Ringy now, outside
    Ancora, and a VA records the outcome by hand.

    WHAT THIS DELETES: the four `twilio_*` settings rows and the two
    `va_call_*` call-analytics rows. They have no reader left — the
    registry entries are gone, so `get_setting` would raise KeyError on
    them anyway; leaving the rows would only be dead weight carrying a
    tenant's Twilio auth token (encrypted, but still) forever.

    WHAT THIS DELIBERATELY DOES NOT DO: it does not drop the `calls` or
    `twilio_numbers` TABLES, and migration 11 still creates them.

      - `reset.DELETE_TABLES` and `agent_leads.delete_agent_leads` both
        name those tables. Dropping them without changing those lists in
        the same breath makes `reset.preview`'s `_count` raise "no such
        table" on the reset screen; changing the lists without dropping
        the tables leaves FK children that block `DELETE FROM leads`.
        Neither half is safe alone.
      - `settings_reset.html` reads the table names back out of
        `account_reset` events ALREADY WRITTEN, so the labels have to
        outlive the feature to render historical reset records.

    So the tables stay, empty, and the column-drop work is a separate,
    deliberate migration. Idempotent: DELETE of rows that are already
    gone is a no-op.
    """
    if not _table_columns(db, "settings"):
        return  # nothing seeded yet (fresh/partial DB)
    db.execute(
        "DELETE FROM settings WHERE key IN ("
        "'twilio_account_sid', 'twilio_auth_token',"
        "'twilio_call_rate_cents_per_min', 'twilio_monthly_cap_dollars',"
        "'va_call_gap_minutes', 'va_short_call_seconds')")


def _migration_0018_email_signature(db):
    """Retire the identity_title / identity_address settings rows.

    PART 11 replaced the four-field identity block with one free-text
    `email_signature`. TWO of the four survive and are NOT touched here:

      identity_name — it is the {{agent_name}} / {agent_name} merge token
        in email templates, AI reply drafts, VA call scripts and
        appointment confirmation texts. It was never only an email field.
      identity_npn  — the signature is validated against it on save
        (`signature.validate`), which is what makes "the signature must
        carry the NPN" enforceable instead of advisory.

    The two being deleted had exactly one reader between them apart from
    the footer: `ai/core.py` used identity_title in the drafting system
    prompt, and that read is removed in the same commit. Their registry
    entries are gone, so `get_setting` would raise KeyError on them —
    leaving the rows would be dead weight only.

    NO DATA IS LOST: both keys had zero rows in production at the time
    this was written (every identity_* key did, including identity_npn).
    The DELETE is written anyway because other installs may have set
    them, and because a migration that assumes production's state is a
    migration that breaks the first time it meets a different database.
    Idempotent: deleting rows that are already gone is a no-op.
    """
    if not _table_columns(db, "settings"):
        return  # nothing seeded yet (fresh/partial DB)
    db.execute(
        "DELETE FROM settings WHERE key IN "
        "('identity_title', 'identity_address')")


def _migration_0019_mfa(db):
    """PART 12 Step 2: TOTP two-factor authentication tables.

    Additive only. No existing user is enrolled by this migration, which
    matters: enrolling anyone automatically would lock them out of an
    account whose secret they have never seen. Admins become REQUIRED to
    enroll, and the request guard walks them through it at next login.
    """
    db.execute(
        "CREATE TABLE IF NOT EXISTS user_mfa ("
        "  user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,"
        "  secret TEXT NOT NULL,"
        "  confirmed_at TEXT,"
        "  created_at TEXT NOT NULL,"
        "  last_used_step INTEGER)")
    db.execute(
        "CREATE TABLE IF NOT EXISTS mfa_recovery_codes ("
        "  id INTEGER PRIMARY KEY,"
        "  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,"
        "  code_hash TEXT NOT NULL,"
        "  used_at TEXT,"
        "  created_at TEXT NOT NULL)")
    db.execute("CREATE INDEX IF NOT EXISTS idx_mfa_recovery_user "
               "ON mfa_recovery_codes(user_id, used_at)")


def _migration_0020_document_acceptances(db):
    """PART 12 Step 4: one append-only table for ToS, DPA and the
    account-holder attestation, replacing the `attestations` table.

    THE COPY IS VERIFIED BEFORE THE DROP. Every attestations row is
    re-inserted as an `account_holder` acceptance and then counted back; a
    mismatch raises before the DROP is ever reached, so a short copy
    cannot destroy the source.

    What is and is not transactional here was measured, not assumed. The
    CREATE statements are DDL and autocommit — sqlite3 starts a
    transaction lazily, on the first DML — so a failure at the verify step
    leaves an EMPTY document_acceptances behind with `attestations` intact
    and schema_version unmoved. That state is recoverable by construction:
    the CREATEs are IF NOT EXISTS and `already` discounts rows a previous
    attempt copied, so simply re-running the migration completes it with
    no duplicates. The INSERT, the DROP and the version bump DO share one
    transaction, which is the pairing that matters — the source table can
    never be dropped without its rows landing.

    Signed text, name and timestamp carry over unchanged, so nobody has to
    re-sign anything they have already signed. The integer version becomes
    the string '1', matching the Version header on
    leadflow/legal/account_holder.md, whose body is byte-identical to the
    text this app used to hold in code. ip and user_agent did not exist on
    the old table and are recorded as '(not recorded)' rather than
    back-filled with a plausible-looking guess.

    The append-only triggers are created HERE as well as in schema.sql
    because schema.sql only reaches a database that runs init_db; a
    database that arrives at this table through the migration path must
    get the same protection.
    """
    db.execute(
        "CREATE TABLE IF NOT EXISTS document_acceptances ("
        "  id INTEGER PRIMARY KEY,"
        "  account_id INTEGER NOT NULL,"
        "  user_id INTEGER NOT NULL,"
        "  document_type TEXT NOT NULL"
        "    CHECK (document_type IN ('tos', 'dpa', 'account_holder')),"
        "  version TEXT NOT NULL,"
        "  text TEXT NOT NULL,"
        "  signed_name TEXT,"
        "  accepted_at TEXT NOT NULL,"
        "  ip TEXT NOT NULL,"
        "  user_agent TEXT NOT NULL)")
    db.execute("CREATE INDEX IF NOT EXISTS idx_doc_acceptances_account "
               "ON document_acceptances(account_id, document_type, id)")
    db.execute("CREATE INDEX IF NOT EXISTS idx_doc_acceptances_user "
               "ON document_acceptances(user_id, document_type, id)")

    legacy = db.execute(
        "SELECT name FROM sqlite_master WHERE type = 'table' "
        "AND name = 'attestations'").fetchone()
    if legacy is not None:
        expected = db.execute(
            "SELECT COUNT(*) AS c FROM attestations").fetchone()["c"]
        already = db.execute(
            "SELECT COUNT(*) AS c FROM document_acceptances "
            "WHERE document_type = 'account_holder'").fetchone()["c"]
        db.execute(
            "INSERT INTO document_acceptances (account_id, user_id, "
            "document_type, version, text, signed_name, accepted_at, ip, "
            "user_agent) "
            "SELECT account_id, user_id, 'account_holder', "
            "CAST(version AS TEXT), text, signed_name, signed_at, "
            "'(not recorded)', '(not recorded)' FROM attestations ORDER BY id")
        moved = db.execute(
            "SELECT COUNT(*) AS c FROM document_acceptances "
            "WHERE document_type = 'account_holder'").fetchone()["c"] - already
        if moved != expected:
            raise RuntimeError(
                "migration 20 copied %d of %d attestations; refusing to drop "
                "the original table" % (moved, expected))
        db.execute("DROP TABLE attestations")

    # Created last: the triggers refuse UPDATE and DELETE, and the copy
    # above only INSERTs, but ordering it this way keeps the migration
    # readable as "build, fill, verify, seal".
    db.execute(
        "CREATE TRIGGER IF NOT EXISTS document_acceptances_no_update "
        "BEFORE UPDATE ON document_acceptances BEGIN "
        "SELECT RAISE(ABORT, 'document_acceptances is append-only: an "
        "acceptance cannot be edited'); END")
    db.execute(
        "CREATE TRIGGER IF NOT EXISTS document_acceptances_no_delete "
        "BEFORE DELETE ON document_acceptances BEGIN "
        "SELECT RAISE(ABORT, 'document_acceptances is append-only: an "
        "acceptance cannot be deleted'); END")


def _migration_0021_account_approval(db):
    """PART 12 Step 5: the account approval gate.

    Additive only — four nullable columns on `accounts`. `status` already
    existed and already held 'pending'/'active'; this migration gives the
    decision an audit trail and grandfathers everyone currently active.

    NO EXISTING ACCOUNT CHANGES STATUS. Every account that reads 'active'
    today keeps reading 'active', and gets approved_at stamped from its
    own created_at so the console does not show a blank where a decision
    should be. approved_by stays NULL: nobody approved them, the migration
    grandfathered them, and inventing an approver would be a lie in an
    audit column. Anything not 'active' is left exactly as it is.
    """
    for column, decl in (("status_changed_at", "TEXT"),
                         ("status_changed_by", "INTEGER"),
                         ("status_note", "TEXT"),
                         ("approved_at", "TEXT"),
                         ("approved_by", "INTEGER")):
        _add_column_if_missing(db, "accounts", column, decl)
    db.execute("UPDATE accounts SET approved_at = created_at "
               "WHERE status = 'active' AND approved_at IS NULL")
    db.execute("UPDATE accounts SET status_note = 'grandfathered: active "
               "before the approval gate existed' "
               "WHERE status = 'active' AND status_note IS NULL")



def _migration_0022_legal_registry(db):
    """PART 12 Step 9: the versioned legal document registry, and the
    acceptance columns that record who signed what.

    TWO PARTS, and the second one REBUILDS A TABLE THAT HOLDS A LEGAL
    RECORD, so it is done with the count and content verified before the
    original is dropped — a short copy raises and the whole migration
    rolls back with the source untouched.

    Why a rebuild at all: `document_acceptances.document_type` carries a
    CHECK constraint, and SQLite cannot alter a CHECK in place. Adding
    'csa' to the allowed set therefore means the standard 12-step
    rebuild. The append-only triggers go with the old table when it is
    dropped and are recreated on the new one; DROP TABLE does not fire
    row triggers, which is what makes the rebuild possible at all.
    """
    # ---- 1. the registry ------------------------------------------------
    db.execute(
        "CREATE TABLE IF NOT EXISTS legal_documents ("
        "  id INTEGER PRIMARY KEY,"
        "  slug TEXT NOT NULL,"
        "  version TEXT NOT NULL,"
        "  text TEXT NOT NULL DEFAULT '',"
        "  sha256 TEXT NOT NULL DEFAULT '',"
        "  active INTEGER NOT NULL DEFAULT 0,"
        "  published_at TEXT NOT NULL,"
        "  UNIQUE (slug, version),"
        "  CHECK (active IN (0, 1)),"
        # An active document with no text would gate every account on a
        # blank page. Applies to UPDATE as well as INSERT, so a slot
        # cannot be switched on and filled later.
        "  CHECK (active = 0 OR length(trim(text)) > 0))")
    db.execute("CREATE INDEX IF NOT EXISTS idx_legal_documents_active "
               "ON legal_documents(slug, active, id)")
    # Published text is immutable. `active` is the ONE column left
    # movable, because publishing v2 must be able to stand v1 down.
    db.execute(
        "CREATE TRIGGER IF NOT EXISTS legal_documents_immutable "
        "BEFORE UPDATE OF slug, version, text, sha256, published_at "
        "ON legal_documents BEGIN "
        "SELECT RAISE(ABORT, 'legal_documents is immutable once published: "
        "only the active flag may change'); END")
    db.execute(
        "CREATE TRIGGER IF NOT EXISTS legal_documents_no_delete "
        "BEFORE DELETE ON legal_documents BEGIN "
        "SELECT RAISE(ABORT, 'legal_documents is append-only: a published "
        "version is what acceptances point at and cannot be removed'); END")

    # ---- 2. the acceptance columns --------------------------------------
    cols = _table_columns(db, "document_acceptances")
    if "sha256" in cols:
        return

    before = db.execute(
        "SELECT COUNT(*) AS c FROM document_acceptances").fetchone()["c"]
    fingerprint = db.execute(
        "SELECT COALESCE(GROUP_CONCAT(account_id || '|' || user_id || '|' "
        "|| document_type || '|' || version || '|' || accepted_at, ';'), '') "
        "AS f FROM (SELECT * FROM document_acceptances ORDER BY id)"
    ).fetchone()["f"]

    db.execute("DROP TRIGGER IF EXISTS document_acceptances_no_update")
    db.execute("DROP TRIGGER IF EXISTS document_acceptances_no_delete")
    db.execute(
        "CREATE TABLE document_acceptances_new ("
        "  id INTEGER PRIMARY KEY,"
        "  account_id INTEGER NOT NULL,"
        "  user_id INTEGER NOT NULL,"
        "  document_type TEXT NOT NULL"
        "    CHECK (document_type IN ('tos','dpa','account_holder','csa')),"
        "  version TEXT NOT NULL,"
        "  text TEXT NOT NULL,"
        "  sha256 TEXT,"
        "  signed_name TEXT,"
        "  legal_entity TEXT,"
        "  signer_title TEXT,"
        "  signer_email TEXT,"
        "  notice_address TEXT,"
        "  npn TEXT,"
        "  plan TEXT,"
        # The access code REFERENCE, never its value. Which code was
        # presented is a fact about the deal; the code itself is a secret
        # and has no business in a permanent record.
        "  access_code_id INTEGER,"
        "  accepted_at TEXT NOT NULL,"
        "  ip TEXT NOT NULL,"
        "  user_agent TEXT NOT NULL)")
    db.execute(
        "INSERT INTO document_acceptances_new (id, account_id, user_id, "
        "document_type, version, text, signed_name, accepted_at, ip, "
        "user_agent) SELECT id, account_id, user_id, document_type, "
        "version, text, signed_name, accepted_at, ip, user_agent "
        "FROM document_acceptances ORDER BY id")

    after = db.execute(
        "SELECT COUNT(*) AS c FROM document_acceptances_new").fetchone()["c"]
    after_fp = db.execute(
        "SELECT COALESCE(GROUP_CONCAT(account_id || '|' || user_id || '|' "
        "|| document_type || '|' || version || '|' || accepted_at, ';'), '') "
        "AS f FROM (SELECT * FROM document_acceptances_new ORDER BY id)"
    ).fetchone()["f"]
    if after != before or after_fp != fingerprint:
        raise RuntimeError(
            "migration 22 copied %d of %d acceptance rows (fingerprint "
            "match: %s); refusing to drop the original"
            % (after, before, after_fp == fingerprint))

    db.execute("DROP TABLE document_acceptances")
    db.execute("ALTER TABLE document_acceptances_new "
               "RENAME TO document_acceptances")
    db.execute("CREATE INDEX IF NOT EXISTS idx_doc_acceptances_account "
               "ON document_acceptances(account_id, document_type, id)")
    db.execute("CREATE INDEX IF NOT EXISTS idx_doc_acceptances_user "
               "ON document_acceptances(user_id, document_type, id)")
    db.execute(
        "CREATE TRIGGER document_acceptances_no_update "
        "BEFORE UPDATE ON document_acceptances BEGIN "
        "SELECT RAISE(ABORT, 'document_acceptances is append-only: an "
        "acceptance cannot be edited'); END")
    db.execute(
        "CREATE TRIGGER document_acceptances_no_delete "
        "BEFORE DELETE ON document_acceptances BEGIN "
        "SELECT RAISE(ABORT, 'document_acceptances is append-only: an "
        "acceptance cannot be deleted'); END")

    # ---- 3. drafts ------------------------------------------------------
    # A DRAFT IS NOT AN ACCEPTANCE. Separate table, no document_type, no
    # signature column, and nothing joins it to document_acceptances —
    # a half-filled form must never be readable as a signed agreement.
    db.execute(
        "CREATE TABLE IF NOT EXISTS form_drafts ("
        "  id INTEGER PRIMARY KEY,"
        "  account_id INTEGER NOT NULL,"
        "  user_id INTEGER NOT NULL,"
        "  form_key TEXT NOT NULL,"
        "  payload TEXT NOT NULL,"
        "  updated_at TEXT NOT NULL,"
        "  UNIQUE (account_id, user_id, form_key))")


_migration_0022_legal_registry.fk_off = True


def _migration_0023_va_plan_flags(db):
    """PART 13: the VA plan becomes TWO flags, and the operator gets one.

    WHY A RENAME AND NOT A NEW COLUMN. `accounts.va_entitled` has always
    answered "may this account have VA at all" — set at approval, never by
    the tenant. That is precisely `va_eligible`, so the value every
    account already carries is the correct one and the rename preserves it
    byte for byte. Introducing `va_eligible` as a fresh DEFAULT 0 column
    instead would have silently revoked both existing tenants.

    WHY va_active MOVES OFF A SETTING. `settings.va_enabled` has always
    answered the other half — "are VAs on right now" — and the tenant has
    always owned it. It moves onto the account row for one reason: access
    is now the AND of both flags, and a gate that has to read a JSON
    settings row to answer half its question is a gate that fails open the
    day that read throws. One row, one query, both halves.

    The backfill therefore reads the SETTING, not `va_entitled`. Those two
    genuinely disagree today — an account can be eligible with VA switched
    off — and the setting is the one that records what the tenant chose.
    Accounts whose setting was off keep VA hidden, which is what they were
    already seeing.

    The `va_enabled` rows are DELETED once copied. Leaving them would
    leave a third flag that still looks authoritative, still parses, and
    is read by nothing — the exact failure this migration exists to end.

    ACCOUNT 1 is the operator account: eligible, active and billing-exempt
    by definition, since there is nobody to grant it anything. Its
    superadmin flag lands on the account's FIRST admin USER, not on the
    account, so it cannot be inherited by a login created later.

    THE ONE-TIME SEEDING SITS BEHIND `first_run`, and a rehearsal against
    a copy of production is what proved it had to. Without that guard,
    re-running the migration re-granted an operator flag somebody had
    deliberately removed, and re-asserted a tenant switch somebody had
    deliberately turned off — a privilege re-grant dressed up as
    idempotence. `is_superadmin` missing from `users` is the marker that
    this migration has never run here; migration 16 uses the same shape
    for the same reason.

    Idempotent throughout: every step is guarded by its own "is this
    already done" check rather than by the version number alone.
    """
    if not _table_columns(db, "accounts"):
        return  # fresh/partial DB: schema.sql already has the new shape

    # Computed BEFORE the ALTER below adds the column it looks for.
    first_run = "is_superadmin" not in _table_columns(db, "users")

    if ("va_eligible" not in _table_columns(db, "accounts")
            and "va_entitled" in _table_columns(db, "accounts")):
        # RENAME COLUMN (SQLite 3.25+) rather than add/copy/drop: there is
        # no instant at which the value lives in neither column.
        db.execute("ALTER TABLE accounts "
                   "RENAME COLUMN va_entitled TO va_eligible")

    if "va_active" not in _table_columns(db, "accounts"):
        _add_column_if_missing(db, "accounts", "va_active",
                               "INTEGER NOT NULL DEFAULT 0")
        # Settings values are JSON, so a stored True is the literal
        # 'true'. Anything else — false, missing, malformed — reads as
        # off, which is the safe direction for a flag that reveals a
        # surface.
        db.execute(
            "UPDATE accounts SET va_active = 1 WHERE id IN ("
            "  SELECT account_id FROM settings "
            "   WHERE key = 'va_enabled' AND value = 'true')")
    db.execute("DELETE FROM settings WHERE key = 'va_enabled'")

    _add_column_if_missing(db, "accounts", "billing_exempt",
                           "INTEGER NOT NULL DEFAULT 0")
    _add_column_if_missing(db, "users", "is_superadmin",
                           "INTEGER NOT NULL DEFAULT 0")

    if first_run:
        db.execute("UPDATE accounts SET va_eligible = 1, va_active = 1, "
                   "billing_exempt = 1 WHERE id = 1")
        db.execute(
            "UPDATE users SET is_superadmin = 1 WHERE id = ("
            "  SELECT MIN(id) FROM users "
            "   WHERE account_id = 1 AND role = 'admin' AND enabled = 1)")


def _migration_0024_billing(db):
    """PART 13 Stage 2: the trial clock, the billing pause and plan changes.

    EXISTING ACCOUNTS ARE GRANDFATHERED, NOT EXEMPTED — and the difference
    matters. Both options end the same way today (nobody pauses), but
    `billing_exempt` is a SUPERADMIN DECISION meaning "this account never
    bills, ever"; stamping it on every pre-launch account would silently
    make them permanently free and leave somebody to un-pick it one row at
    a time later. `trial_ends_at` stays NULL instead, which means "no
    trial clock is running": no warnings, no pause, and no decision
    recorded that was never taken. Starting a clock later is one UPDATE
    from the superadmin console. Account 1 keeps the exemption migration
    23 gave it, because the operator account really is exempt by
    definition.

    `period_start` is backfilled from `created_at` so the derived
    `current_period_end` has an anchor for accounts that predate billing.
    It is the ONE value Stripe would have replaced. MIGRATION 28 DROPS
    EVERY COLUMN THIS ONE ADDS, along with `plan_changes`: BLOCK 1 STEP
    C removed billing entirely. This migration stays because an
    existing database has to pass through it to reach 28.

    Idempotent: every step is an "is this already done" check, and there
    is no one-time seeding here at all, so the re-grant class of defect
    migration 23 hit cannot arise. Re-running changes nothing.
    """
    if not _table_columns(db, "accounts"):
        return  # fresh/partial DB: schema.sql already has the new shape

    for column in ("trial_ends_at", "payment_method_at", "paused_at",
                   "period_start"):
        _add_column_if_missing(db, "accounts", column, "TEXT")
    _add_column_if_missing(db, "leads", "manual_only_at", "TEXT")

    # Only where it is missing: an account whose period Stripe has already
    # moved must not be dragged back to its signup date by a re-run.
    db.execute("UPDATE accounts SET period_start = created_at "
               "WHERE period_start IS NULL")

    db.execute(
        "CREATE TABLE IF NOT EXISTS plan_changes ("
        "  id INTEGER PRIMARY KEY,"
        "  account_id INTEGER NOT NULL,"
        "  direction TEXT NOT NULL,"
        "  old_plan TEXT NOT NULL,"
        "  new_plan TEXT NOT NULL,"
        "  price_cents INTEGER NOT NULL,"
        "  scheduled_for TEXT,"
        "  actor_user_id INTEGER,"
        "  actor_role TEXT NOT NULL,"
        "  ip TEXT NOT NULL,"
        "  created_at TEXT NOT NULL)")
    db.execute("CREATE INDEX IF NOT EXISTS idx_plan_changes_account "
               "ON plan_changes(account_id, id)")
    # The append-only triggers are part of the TABLE, not decoration: a
    # migration that created the table without them would leave an
    # upgraded install editable while a fresh one is not.
    db.execute(
        "CREATE TRIGGER IF NOT EXISTS plan_changes_no_update "
        "BEFORE UPDATE ON plan_changes BEGIN "
        "SELECT RAISE(ABORT, 'plan_changes is append-only: a plan change "
        "cannot be edited'); END")
    db.execute(
        "CREATE TRIGGER IF NOT EXISTS plan_changes_no_delete "
        "BEFORE DELETE ON plan_changes BEGIN "
        "SELECT RAISE(ABORT, 'plan_changes is append-only: a plan change "
        "cannot be deleted'); END")


def _migration_0025_consent_date(db):
    """DIALER BLOCK 1: `consent_date` on leads and on the overflow pool.

    THE BACKFILL IS DELIBERATELY NARROW, and the narrowness is the whole
    design. `leads.received_at` means two different things depending on
    which path wrote the row:

      - Gmail intake and the dead-letter re-parse put the INQUIRY'S OWN
        timestamp there (the lead email's Date header), which is a real
        record of when the person filled the form in. Those rows can be
        backfilled honestly.
      - The manual Add-lead form, the agent-lead CSV import and the
        overflow promotion all pass `utcnow()` for BOTH `received_at` and
        `created_at`, because there was no external timestamp to carry.
        For those rows `received_at` is when somebody typed or uploaded —
        i.e. today's date wearing a different name. Backfilling from it
        is exactly the "never default to today" this block forbids.

    So the discriminator is `received_at <> created_at`: two different
    values mean an EXTERNAL timestamp was carried in, one value means the
    row stamped itself. Rows that stamped themselves are left NULL, which
    reads as "we do not know" and refuses the call. That is a smaller
    number of dialable leads and the only defensible one.

    `overflow_leads` is backfilled by NOTHING for the same reason: its
    only date is `uploaded_at`, which is when the file was handed over.

    Idempotent: both steps are guarded, and the UPDATE only fills NULLs,
    so a re-run cannot overwrite a date a real intake path has since
    written.
    """
    if not _table_columns(db, "leads"):
        return  # fresh/partial DB: schema.sql already has the new shape

    _add_column_if_missing(db, "leads", "consent_date", "TEXT")
    if _table_columns(db, "overflow_leads"):
        _add_column_if_missing(db, "overflow_leads", "consent_date", "TEXT")

    db.execute(
        "UPDATE leads SET consent_date = substr(received_at, 1, 10) "
        "WHERE consent_date IS NULL "
        "  AND received_at IS NOT NULL "
        "  AND received_at <> created_at "
        # A carried-in timestamp still has to look like a date. Anything
        # that does not is left NULL rather than stored malformed.
        "  AND substr(received_at, 1, 10) GLOB "
        "      '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]'")


def _migration_0026_revocation_is_permanent(db):
    """DIALER BLOCK 2: every revocation becomes irreversible, and stays so.

    TWO STEPS, and the data one is the smaller of them.

    THE DATA. Any existing row whose reason is a revocation
    (`unsubscribe`, `do_not_call`, `stop`) and whose `reversible` is 1 is
    flipped to 0. Those rows are people who told a tenant to stop and
    whose record still had an Undo button behind it. `not_interested`,
    `hard_bounce` and `manual` rows are NOT touched: a soft close is
    meant to be reversible, and a bounce is a fact about a mailbox rather
    than an instruction from a person.

    THE TRIGGERS, which are the part that lasts. `reversible = 0` plus
    `unsuppress` refusing such a row was a convention held by four call
    sites; these make it a property of the database. A revocation row
    cannot be deleted, and cannot be updated back into a reversible one
    or have its reason or contact details rewritten. Everything else
    about the row stays writable, because `reset.py` nulls `lead_id` on
    every suppression and the compliance record must survive that.

    Idempotent: the UPDATE is a no-op once run (nothing matches), and the
    triggers are CREATE TRIGGER IF NOT EXISTS. Re-running changes nothing.
    """
    if not _table_columns(db, "suppressions"):
        return  # fresh/partial DB: schema.sql already has the new shape

    moved = db.execute(
        "UPDATE suppressions SET reversible = 0 "
        "WHERE reversible != 0 "
        "  AND reason IN ('unsubscribe', 'do_not_call', 'stop')").rowcount
    if moved:
        logger.info("migration 26: %d revocation row(s) made irreversible",
                    moved)

    db.execute(
        "CREATE TRIGGER IF NOT EXISTS suppressions_revocation_no_delete "
        "BEFORE DELETE ON suppressions "
        "WHEN OLD.reason IN ('unsubscribe', 'do_not_call', 'stop') BEGIN "
        "SELECT RAISE(ABORT, 'a revocation is permanent: this person asked "
        "to be left alone'); END")
    db.execute(
        "CREATE TRIGGER IF NOT EXISTS suppressions_revocation_stays_permanent "
        "BEFORE UPDATE ON suppressions "
        "WHEN OLD.reason IN ('unsubscribe', 'do_not_call', 'stop') "
        " AND (NEW.reversible != 0 OR NEW.reason != OLD.reason "
        "      OR NEW.email IS NOT OLD.email OR NEW.phone IS NOT OLD.phone) "
        "BEGIN SELECT RAISE(ABORT, 'a revocation is permanent: its reason "
        "and contact details cannot change'); END")


def _migration_0027_dial_attempts(db):
    """DIALER BLOCK 3: the call log, append-only from the first row.

    `calls` and `twilio_numbers` are NOT reused. They are the fossils of
    the calling system PART 10 removed, kept as history by SPEC Part 10
    and asserted empty; writing into them would erase the record of the
    removal and blur "what the old dialer did" into "what this one does".
    A new table also means the append-only triggers apply from row one
    rather than to a table that already holds mutable history.

    Idempotent: CREATE TABLE / INDEX / TRIGGER IF NOT EXISTS throughout,
    and there is nothing to backfill — a call log starts empty.
    """
    db.execute(
        "CREATE TABLE IF NOT EXISTS dial_attempts ("
        "  id INTEGER PRIMARY KEY,"
        "  account_id INTEGER NOT NULL,"
        # No FKs: the log outlives the lead a reset deletes.
        "  lead_id INTEGER NOT NULL,"
        "  user_id INTEGER,"
        "  to_number TEXT NOT NULL,"
        "  from_number TEXT NOT NULL,"
        "  permitted_by TEXT NOT NULL,"
        "  outcome TEXT NOT NULL,"
        "  call_sid TEXT,"
        "  duration_seconds INTEGER,"
        "  created_at TEXT NOT NULL)")
    db.execute("CREATE INDEX IF NOT EXISTS idx_dial_number "
               "ON dial_attempts(account_id, to_number, created_at)")
    db.execute("CREATE INDEX IF NOT EXISTS idx_dial_lead "
               "ON dial_attempts(lead_id, created_at)")
    db.execute(
        "CREATE TRIGGER IF NOT EXISTS dial_attempts_no_update "
        "BEFORE UPDATE ON dial_attempts BEGIN "
        "SELECT RAISE(ABORT, 'dial_attempts is append-only: a call record "
        "cannot be edited'); END")
    db.execute(
        "CREATE TRIGGER IF NOT EXISTS dial_attempts_no_delete "
        "BEFORE DELETE ON dial_attempts BEGIN "
        "SELECT RAISE(ABORT, 'dial_attempts is append-only: a call record "
        "cannot be deleted'); END")


def _migration_0028_remove_billing(db):
    """BLOCK 1 STEP C: billing is removed. Accounts are free.

    Drops the five subscription columns migration 24 added to `accounts`
    and the `plan_changes` table, because nothing is billed and nothing
    has a plan to change. What replaced the billing pause was not another
    flag: freezing an account was `accounts.status = 'suspended'`, which
    already existed, was already enforced by the request guard and by
    `gmail.smtp_send`, and only lacked a control to set it. (B3 removed
    suspension outright — see migration 30. Nothing freezes an account
    now; an account is pending, active, rejected or deleted.)

    DROPPING AN APPEND-ONLY TABLE IS DELIBERATE AND NARROW. `plan_changes`
    recorded what a tenant was billed; with no fees there is no such
    record to keep, and leaving an unwritable table nothing writes would
    leave `reset.TABLE_RULES` classifying a fiction. Its triggers go with
    it. The OTHER append-only tables — `document_acceptances`,
    `dial_attempts`, `suppressions` — are untouched.

    Idempotent: every drop is guarded by a schema read, so a re-run on an
    already-migrated database does nothing. `leads.manual_only_at` is NOT
    dropped — the billing pause was its only writer, but a lead that
    already carries the permanent mark must keep it, and
    `outreach.scheduler` must keep refusing to schedule one.
    """
    for trigger in ("plan_changes_no_update", "plan_changes_no_delete"):
        db.execute("DROP TRIGGER IF EXISTS %s" % trigger)
    db.execute("DROP INDEX IF EXISTS idx_plan_changes_account")
    db.execute("DROP TABLE IF EXISTS plan_changes")
    existing = _table_columns(db, "accounts")
    for column in ("billing_exempt", "trial_ends_at", "payment_method_at",
                   "paused_at", "period_start"):
        if column in existing:
            db.execute("ALTER TABLE accounts DROP COLUMN %s" % column)


def _migration_0029_dial_seat_and_dead_letter_bodies(db):
    """BLOCK 2: the dialing seat becomes a flag, and dead letters stop
    storing the email.

    TWO FIXES, ONE MIGRATION, because both are about a capability or a
    payload a tenant route could reach and neither is worth a schema
    version of its own.

    `users.can_dial` — the dialer was gated on `role = 'va'`, and
    `/settings/users/add` is a TENANT route that hardcodes that role, so a
    customer could create their own dialing seat. The flag defaults to 0
    and is BACKFILLED TO 0 FOR EVERY EXISTING ROW, including any VA seat
    that could dial a moment ago: a capability that quietly survives the
    gate being tightened is the gate not being tightened. The operator
    re-grants it deliberately.

    `dead_letters.raw_body` — DROPPED, along with every body already in
    it. It held the vendor email verbatim, which is how medical
    conditions, tobacco use, height and weight reached the database on
    every failed parse. `labels_found` (label names, no values) and
    `gmail_message_id` replace it: the first is the diagnosis, the second
    is what lets a corrected field_map requeue the real message.

    Dropping the column is what makes this a fix rather than a promise —
    a nulled column is one `UPDATE` away from being a leak again.

    Idempotent: `_add_column_if_missing` throughout, and the DROP is
    guarded by a schema read.
    """
    _add_column_if_missing(db, "users", "can_dial",
                           "INTEGER NOT NULL DEFAULT 0")
    db.execute("UPDATE users SET can_dial = 0")
    # `dead_letters` postdates the oldest database this chain has to
    # upgrade, so its absence is a real state and not an error — the
    # Part-4 shape in tests/test_migrations.py is exactly that state, and
    # schema.sql creates the table in its final shape for a fresh install.
    if _table_exists(db, "dead_letters"):
        _add_column_if_missing(db, "dead_letters", "labels_found", "TEXT")
        _add_column_if_missing(db, "dead_letters", "gmail_message_id", "TEXT")
        if "raw_body" in _table_columns(db, "dead_letters"):
            db.execute("ALTER TABLE dead_letters DROP COLUMN raw_body")


def _migration_0030_team_hierarchy(db):
    """B3: accounts get a team, and suspension is retired.

    THE TEAM IS AN EDGE, NOT A CONTAINER. `accounts.upline_id` names the
    account that manages this one; `accounts.team_role` says whether an
    account may be named by that column at all. Every agent keeps their
    OWN account, their own leads and their own tenant scope — the edge
    grants a manager counts about their agents and nothing else. Modelling
    a team as a shared account would have merged two agents' lead data
    into one tenant, which no later filter could unmerge.

    NULL upline is a first-class state, not missing data: account 1 is the
    top of the tree and every account starts unattached. Account 1 is
    stamped `manager` here because it is the install's own account and the
    only one that can have agents on day one.

    `users.email` — signup collects a real address now, and B10 mails
    weekly statements to VAs and their manager. It is backfilled from
    `username` only where that already looks like an address; a seat named
    `henry` is left NULL rather than turned into a fake address.

    SUSPENSION IS REMOVED, including from the data. `accounts.status` no
    longer has a `suspended` value, so any row still carrying one is moved
    to `pending` — the same "cannot act" side of `accounts.USABLE`, and a
    state the console can act on. Left alone the value would still read as
    pending (`accounts.status` fails closed on an unknown value) but would
    sit in the column as a state nothing could clear.

    Idempotent: `_add_column_if_missing` throughout, and both UPDATEs are
    no-ops on a second run.
    """
    _add_column_if_missing(db, "accounts", "upline_id", "INTEGER")
    _add_column_if_missing(db, "accounts", "team_role",
                           "TEXT NOT NULL DEFAULT 'agent'")
    _add_column_if_missing(db, "users", "email", "TEXT")
    db.execute("UPDATE accounts SET team_role = 'manager' "
               "WHERE id = 1 AND team_role != 'manager'")
    db.execute("UPDATE accounts SET status = 'pending' "
               "WHERE status = 'suspended'")
    db.execute("UPDATE users SET email = username "
               "WHERE email IS NULL AND username LIKE '%_@_%._%'")
    db.execute("CREATE INDEX IF NOT EXISTS idx_accounts_upline "
               "ON accounts(upline_id)")


def _migration_0031_licensure(db):
    """B4: per-state licensure.

    ONE ROW PER (account, state). The unique index is the rule: an account
    cannot hold two licences for one state, so "which licence covers this
    lead" has exactly one answer and no ordering to get wrong.

    NOTHING IS BACKFILLED, and that is the point. Every existing account
    starts with no licence, which means no intake and no sending until
    somebody enters one. A migration that granted a licence would be this
    application asserting a regulatory fact about a person on the strength
    of the row already being there.

    `expires_on` is nullable because the operator's own record is a plain
    checklist with no expiry; `licensure.is_expired` reads NULL as "never
    expires". Agent rows are required to carry a date by the ROUTE, so
    both shapes share one table and one code path.

    Idempotent: CREATE TABLE / CREATE INDEX IF NOT EXISTS.
    """
    db.execute(
        "CREATE TABLE IF NOT EXISTS licenses ("
        " id INTEGER PRIMARY KEY,"
        " account_id INTEGER NOT NULL,"
        " state TEXT NOT NULL,"
        " license_number TEXT,"
        " expires_on TEXT,"
        " pdf_filename TEXT,"
        " created_at TEXT NOT NULL,"
        " updated_at TEXT NOT NULL,"
        " created_by INTEGER)")
    db.execute("CREATE UNIQUE INDEX IF NOT EXISTS uq_licenses_account_state "
               "ON licenses(account_id, state)")


def _migration_0032_send_to_va_and_phone_format(db):
    """B6: the team send queue, and ONE stored phone format.

    `va_sends` is the record that a lead was handed to the team's call
    queue. UNIQUE(team_account_id, phone) IS the duplicate rule — first
    send wins, and the second agent's send is refused by the database
    rather than by a check two requests could both pass. UNIQUE(lead_id)
    stops one lead being sent twice.

    THE PHONE FORMAT. Every column that holds a telephone number is
    rewritten to `000-000-0000`, because duplicate detection, the
    per-number daily attempt cap and suppression matching all compare
    these strings and were one unnormalised caller away from reading two
    spellings of one number as two people.

    `dial_attempts` IS NOT REWRITTEN and must not be: it is append-only by
    trigger, and an UPDATE against it raises at runtime. The dialer's cap
    query compares the ten digits instead, so a number called before the
    change still counts toward its three.

    Idempotent: `normalize_phone` is stable on an already-converted value,
    and every row is written back through it.
    """
    db.execute(
        "CREATE TABLE IF NOT EXISTS va_sends ("
        " id INTEGER PRIMARY KEY,"
        # The MANAGER's account — whose queue this landed on. The
        # duplicate rule is scoped to it: two agents on one team may not
        # both send one number, two agents on different teams may.
        " team_account_id INTEGER NOT NULL,"
        " account_id INTEGER NOT NULL,"      # the agent who sent it
        " lead_id INTEGER NOT NULL,"
        " phone TEXT NOT NULL,"              # 000-000-0000
        " sent_by INTEGER,"
        " created_at TEXT NOT NULL)")
    db.execute("CREATE UNIQUE INDEX IF NOT EXISTS uq_va_sends_team_phone "
               "ON va_sends(team_account_id, phone)")
    db.execute("CREATE UNIQUE INDEX IF NOT EXISTS uq_va_sends_lead "
               "ON va_sends(lead_id)")

    # `suppressions` IS NOT REWRITTEN. Revocation rows are append-only by
    # trigger — D2 made a revocation permanent on purpose, and "permanent"
    # includes the contact details it names — so an UPDATE against one
    # raises at runtime. `suppression.is_suppressed` and `revocation_for`
    # compare on DIGITS instead (`phone.digits_sql`), which is why leaving
    # these rows alone costs nothing: a revocation written as +1XXXXXXXXXX
    # still blocks a lead stored as 000-000-0000.
    #
    # `dial_attempts` is left alone for the same reason; the dialer's
    # per-number daily cap compares on digits too.
    from leadflow.phone import normalize_phone
    for table, column, key in (("leads", "phone", "id"),
                               ("users", "phone", "id")):
        if not _table_exists(db, table):
            continue
        if column not in _table_columns(db, table):
            continue
        rows = db.execute(
            "SELECT %s AS k, %s AS v FROM %s WHERE %s IS NOT NULL "
            "AND %s != ''" % (key, column, table, column, column)
        ).fetchall()
        for row in rows:
            converted = normalize_phone(row["v"])
            # An unconvertible value is LEFT ALONE, never blanked. It is
            # already useless for dialling and a record of what the vendor
            # actually sent is worth more than a tidy NULL.
            if converted and converted != row["v"]:
                db.execute("UPDATE %s SET %s = ? WHERE %s = ?"
                           % (table, column, key), (converted, row["k"]))


def _migration_0033_va_scope(db):
    """B7: an assistant seat is a TEAM seat or a PERSONAL one.

    `users.va_scope` defaults to `personal` and every existing row is
    backfilled to it — the scope with FEWER capabilities. A seat that
    quietly became a team seat because that was the friendlier default
    would be a seat that could dial without anybody deciding it should,
    which is the whole hazard `va_scope` exists to close.

    THE OPERATOR RE-GRANTS DELIBERATELY, exactly as migration 29 did with
    `can_dial`. A capability that survives the gate being tightened is the
    gate not actually being tightened.

    Idempotent: `_add_column_if_missing`, and the backfill only writes
    rows whose value is not already one of the two.
    """
    _add_column_if_missing(db, "users", "va_scope",
                           "TEXT NOT NULL DEFAULT 'personal'")
    db.execute("UPDATE users SET va_scope = 'personal' "
               "WHERE va_scope NOT IN ('team', 'personal')")


def _migration_0034_global_revocation(db):
    """B8: a revocation covers the person on EVERY account.

    THE SCOPE CHANGE ITSELF NEEDS NO MIGRATION. Nothing about a
    suppression row's shape decides who it binds — that was always a
    `WHERE account_id = ?` in `suppression.py`, and B8 removes it from the
    revocation half. The rows already on disk become global the moment the
    code ships, which is the point: a revocation somebody gave last year
    should not have needed a backfill to start meaning what it said.

    WHAT DOES NEED A MIGRATION IS D2, EXTENDED. The revocation UPDATE
    trigger froze `reversible`, `reason`, `email` and `phone`. It did not
    freeze `account_id`, because under per-tenant scope that column was
    merely where the row lived. Under global scope it is no longer what
    decides who the row bites — and that is exactly why freezing it now
    matters: it has become PURE RECORD, the answer to "who were they
    told", and a compliance record a bug can rewrite is not a record.

    `reset.py` is the only writer that touches a preserved revocation row
    and it sets `lead_id = NULL` and nothing else, so nothing legitimate
    is broken by this.

    Idempotent: DROP IF EXISTS then CREATE. A trigger cannot be ALTERed,
    and `CREATE TRIGGER IF NOT EXISTS` against the OLD body would silently
    leave the old body in place — which is the failure mode this docstring
    exists to stop somebody re-introducing.

    GUARDED ON THE TABLE. `suppressions` postdates the oldest upgradeable
    database, so a chain replayed from before it exists reaches here with
    no table to hang a trigger on. Migration 26, which created these
    triggers in the first place, guards the same way.
    """
    if not _table_exists(db, "suppressions"):
        return
    db.execute("DROP TRIGGER IF EXISTS suppressions_revocation_stays_permanent")
    db.execute("""
CREATE TRIGGER suppressions_revocation_stays_permanent
BEFORE UPDATE ON suppressions
WHEN OLD.reason IN ('unsubscribe', 'do_not_call', 'stop')
 AND (NEW.reversible != 0 OR NEW.reason != OLD.reason
      OR NEW.email IS NOT OLD.email OR NEW.phone IS NOT OLD.phone
      OR NEW.account_id != OLD.account_id)
BEGIN
  SELECT RAISE(ABORT, 'a revocation is permanent: its reason, contact details and originating account cannot change');
END""")


def _migration_0035_appointment_tracker(db):
    """B9: the appointment tracker and the effective-dated split rate.

    Two new tables, no column touched on an existing one — the tracker is
    a money record that sits BESIDE `interactions` rather than inside it.
    `interactions` stays the operational timeline and is scoped to the
    agent's tenant; the setting side is frequently a seat that cannot read
    it at all, which is the whole reason a second table exists.

    `split_rates` is effective-dated, exactly like `pay_rates`. The block's
    requirement was "changing it later must not require re-entering
    anything", and a single mutable number would have failed it twice:
    edit it and either every historical row is wrong or somebody re-keys
    them all. An INSERT with a new `effective_date` leaves every recorded
    row resolving to the rate that was in force on its own date.

    NO BACKFILL. Existing `interactions` appointment rows are NOT swept
    into the tracker: they carry no commission, no split and nobody who
    ran them, so importing them would create rows that look tracked and
    are not. The tracker starts empty and fills as appointments are set.

    Idempotent: CREATE TABLE / CREATE INDEX IF NOT EXISTS throughout.
    """
    db.execute("""
CREATE TABLE IF NOT EXISTS appointment_tracker (
  id INTEGER PRIMARY KEY,
  account_id INTEGER NOT NULL DEFAULT 1,
  team_account_id INTEGER NOT NULL DEFAULT 1,
  lead_id INTEGER NOT NULL REFERENCES leads(id),
  state TEXT,
  set_by_user_id INTEGER,
  ran_by_user_id INTEGER,
  agent_user_id INTEGER,
  date_set TEXT NOT NULL,
  date_run TEXT,
  outcome TEXT,
  premium_cents INTEGER,
  commission_cents INTEGER,
  closed_by_user_id INTEGER,
  paid_at TEXT,
  paid_by_user_id INTEGER,
  interaction_id INTEGER,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
)""")
    db.execute("CREATE INDEX IF NOT EXISTS idx_apptrack_team "
               "ON appointment_tracker(team_account_id, date_set)")
    db.execute("CREATE INDEX IF NOT EXISTS idx_apptrack_ran "
               "ON appointment_tracker(ran_by_user_id, date_run)")
    db.execute("CREATE INDEX IF NOT EXISTS idx_apptrack_lead "
               "ON appointment_tracker(lead_id)")
    db.execute("""
CREATE TABLE IF NOT EXISTS split_rates (
  id INTEGER PRIMARY KEY,
  account_id INTEGER NOT NULL DEFAULT 1,
  effective_date TEXT NOT NULL,
  va_split_bps INTEGER NOT NULL,
  note TEXT,
  created_at TEXT NOT NULL
)""")
    db.execute("CREATE UNIQUE INDEX IF NOT EXISTS uq_split_rates "
               "ON split_rates(account_id, effective_date)")


def _migration_0036_va_weekly_hours(db):
    """B10: how many hours a week this seat works.

    THE APP HAS NEVER RECORDED HOURS, and the profitability dashboard
    compares seats on profit per VA HOUR — the only figure that is fair
    across the two arrangements, since a team seat earns a share of the
    commission it sets and a personal seat's closes belong to its agent.

    NULLABLE, AND NULL MEANS UNKNOWN. No default of 40, no backfill. A
    seat whose hours nobody has entered reports no profit-per-hour at all
    rather than a number derived from a guess — the dashboard exists to
    rank people, and ranking them on an assumed denominator is worse than
    showing a blank and saying why.

    Idempotent: `_add_column_if_missing`.
    """
    _add_column_if_missing(db, "users", "weekly_hours", "REAL")


def _migration_0037_pipeline_lanes(db):
    """B11: the flat stage list becomes three lanes.

    NO SCHEMA CHANGE. The lane is a pure function of the stage
    (`pipeline.STAGE_LANE`) and the Cold age bucket is a pure function of
    received_at, so neither is stored: a second stored column can disagree
    with the first, and a stored bucket is right for one day and silently
    wrong every day after. What changes is the VOCABULARY inside
    leads.pipeline_stage, which is a data migration, not a DDL one.

    TWO PASSES, and the order matters.

    1. The rename that needs no evidence. `new`, `contacted` and `nurture`
       were three ways of writing "we have never heard back" — dialled
       nobody, dialled and got nothing, ran out of sequence and still got
       nothing — and B11 has one lane for that. Every one of them becomes
       `cold`. THIS IS WHERE THE NURTURE ROWS LAND: `nurture` meant the
       sequence was exhausted with no higher signal, which is exactly a
       Cold lead that has aged, and the age bucket now says so without
       going stale overnight.

    2. Everything else is RE-DERIVED rather than mapped. `dead` was one
       rung holding four different facts — revoked, verbally opted out,
       no working number, and manually closed — and no lookup table can
       recover which. So the second pass recomputes every lead from its
       actual signals, which is also the only way a lead reaches the new
       `wrong_person` and `ghosted` stages: both come from rows
       (a `bad_number` call, a recovery flag resolved `no_contact`) that
       have always been written and never had a stage of their own.

    Pass 2 covers pass 1's rows too, deliberately. A lead that was
    `contacted` may have a negative signal that B4 had nowhere to put, and
    re-deriving finds it; a lead with nothing lands back on `cold`.

    Idempotent: pass 1's WHERE matches nothing on a second run, and pass 2
    is a recompute, which is idempotent by construction.

    PASS 2 IS GUARDED ON THE TABLES IT READS. Migration 34 hit this same
    edge: a replayed or partial chain reaches a migration whose helper
    queries a table that chain has not created yet, and the whole upgrade
    dies. compute_stage reads four tables besides `leads`, and a database
    missing any of them has no signals to derive a lane from — so pass 1's
    rename is already the complete and correct answer there.
    """
    if not _table_exists(db, "leads"):
        return
    db.execute(
        "UPDATE leads SET pipeline_stage = 'cold' "
        "WHERE pipeline_stage IN ('new', 'contacted', 'nurture')")
    signal_tables = ("suppressions", "interactions", "messages",
                     "recovery_flags")
    if not all(_table_exists(db, t) for t in signal_tables):
        return
    from leadflow.pipeline import recompute  # local import to avoid cycles
    for row in db.execute("SELECT id FROM leads ORDER BY id").fetchall():
        recompute(db, row["id"])


def _migration_0038_va_allocation(db):
    """B12: per-VA daily allocation, and per-VA labelling of a SHARED queue.

    `own_leads_target` / `team_leads_target` on `users`: how many of each
    kind of lead this seat's day should be built from. **Nullable, and
    NULL means UNCONFIGURED, not zero** — the same rule B10 used for
    `weekly_hours`. Every seat that exists when this runs is NULL, and an
    unconfigured seat keeps exactly the behaviour it had: its effective
    quota, filled own-then-team-then-overflow with no per-source cap. A
    default of any number would silently re-shape every existing tenant's
    day on upgrade.

    `allocated_to` on `va_queue` and `overflow_queue`: which VA this row
    was built for. **A NEW COLUMN RATHER THAN REUSING `assigned_to`.**
    `assigned_to` means "the VA who CLAIMED this row" (S2) and is NULL
    until somebody does; allocation is decided at build time and says
    nothing about who has picked it up. Overloading one column with both
    would have made "claimed" untestable — every row would look claimed
    the moment it was built — and the claim path is what stops two VAs
    dialling the same person.

    The queue stays SHARED. Nothing here partitions it: `allocated_to` is
    a label the build writes and the console reads, so an unallocated day,
    a seat that goes offline, or an admin working the list all behave
    exactly as before.

    Idempotent: `_add_column_if_missing` four times, each guarded on its
    table existing. Migrations 34 and 37 both hit the same edge — a
    replayed or partial chain reaches a migration whose table that chain
    has not created yet — and `va_queue` / `overflow_queue` arrive at
    migrations 4 and 29, well after `users`.
    """
    if _table_exists(db, "users"):
        _add_column_if_missing(db, "users", "own_leads_target", "INTEGER")
        _add_column_if_missing(db, "users", "team_leads_target", "INTEGER")
    if _table_exists(db, "va_queue"):
        _add_column_if_missing(db, "va_queue", "allocated_to", "INTEGER")
    if _table_exists(db, "overflow_queue"):
        _add_column_if_missing(db, "overflow_queue", "allocated_to",
                               "INTEGER")


MIGRATIONS = [
    (1, _migration_0001_send_channels),
    (2, _migration_0002_accounts_users),
    (3, _migration_0003_interactions_pipeline),
    (4, _migration_0004_va_queue),
    (5, _migration_0005_remove_texting),
    (6, _migration_0006_part3_schema),
    (7, _migration_0007_sold_rename),
    (8, _migration_0008_part4_multitenant),
    (9, _migration_0009_part4_sequence),
    (10, _migration_0010_reschedule_stranded),
    (11, _migration_0011_part5_calls),
    (12, _migration_0012_appt_confirmations),
    (13, _migration_0013_nudge_merge_field),
    (14, _migration_0014_agent_leads),
    (15, _migration_0015_overflow_pool),
    (16, _migration_0016_va_entitlement),
    (17, _migration_0017_remove_dialer),
    (18, _migration_0018_email_signature),
    (19, _migration_0019_mfa),
    (20, _migration_0020_document_acceptances),
    (21, _migration_0021_account_approval),
    (22, _migration_0022_legal_registry),
    (23, _migration_0023_va_plan_flags),
    (24, _migration_0024_billing),
    (25, _migration_0025_consent_date),
    (26, _migration_0026_revocation_is_permanent),
    (27, _migration_0027_dial_attempts),
    (28, _migration_0028_remove_billing),
    (29, _migration_0029_dial_seat_and_dead_letter_bodies),
    (30, _migration_0030_team_hierarchy),
    (31, _migration_0031_licensure),
    (32, _migration_0032_send_to_va_and_phone_format),
    (33, _migration_0033_va_scope),
    (34, _migration_0034_global_revocation),
    (35, _migration_0035_appointment_tracker),
    (36, _migration_0036_va_weekly_hours),
    (37, _migration_0037_pipeline_lanes),
    (38, _migration_0038_va_allocation),
]

LATEST_SCHEMA_VERSION = max(v for v, _ in MIGRATIONS) if MIGRATIONS else 0


def get_schema_version(db):
    # type: (sqlite3.Connection) -> int
    row = db.execute(
        "SELECT value FROM app_state WHERE key = 'schema_version'"
    ).fetchone()
    if row is None:
        return 0
    try:
        return int(row["value"])
    except (ValueError, TypeError):
        return 0


def _set_schema_version(db, version):
    db.execute(
        "INSERT INTO app_state (key, value) VALUES ('schema_version', ?) "
        "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        (str(version),),
    )


def apply_migrations(db):
    # type: (sqlite3.Connection) -> list
    """Apply unapplied MIGRATIONS in order, one transaction each.

    A migration callable with a truthy `fk_off` attribute runs with
    foreign-key enforcement disabled (table rebuilds whose old table is
    referenced by other tables need this — the standard SQLite rebuild
    procedure), then re-enables it and runs PRAGMA foreign_key_check.

    Returns the list of versions applied.
    """
    applied = []
    for version, action in sorted(MIGRATIONS, key=lambda entry: entry[0]):
        if version <= get_schema_version(db):
            continue
        logger.info("applying migration %d", version)
        fk_off = bool(getattr(action, "fk_off", False))
        if fk_off:
            db.execute("PRAGMA foreign_keys=OFF")
        try:
            with db:
                if callable(action):
                    action(db)
                else:
                    for statement in str(action).split(";"):
                        if statement.strip():
                            db.execute(statement)
                _set_schema_version(db, version)
            if fk_off:
                bad = db.execute("PRAGMA foreign_key_check").fetchall()
                if bad:
                    raise RuntimeError(
                        "migration %d broke foreign keys: %s"
                        % (version, [tuple(r) for r in bad[:5]]))
        finally:
            if fk_off:
                db.execute("PRAGMA foreign_keys=ON")
        applied.append(version)
    return applied


def _ensure_partial_indexes(db):
    """Indexes on migration-added columns (pay_rates.user_id, S2;
    leads.source_agent, agent leads; accounts.upline_id, B3) cannot live in
    schema.sql — executed there they would fail against a pre-migration
    table, because schema.sql runs BEFORE apply_migrations on every
    existing database. Created here after BOTH paths (fresh schema /
    migrations) have the column; migrations 8, 14 and 30 also create
    them."""
    with db:
        db.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS uq_pay_rates_default "
            "ON pay_rates(account_id, effective_date) WHERE user_id IS NULL")
        db.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS uq_pay_rates_user "
            "ON pay_rates(account_id, user_id, effective_date) "
            "WHERE user_id IS NOT NULL")
        db.execute(
            "CREATE INDEX IF NOT EXISTS idx_leads_source_agent "
            "ON leads(account_id, source_agent)")
        db.execute(
            "CREATE INDEX IF NOT EXISTS idx_accounts_upline "
            "ON accounts(upline_id)")
        # B11: /pipeline counts each lane per tenant and the COLD lane
        # reads every cold lead's received_at to bucket it. Both are
        # (account_id, pipeline_stage) lookups on the largest table in the
        # app, and neither had an index — the page did a full scan per
        # load and got away with it only because the books are small.
        db.execute(
            "CREATE INDEX IF NOT EXISTS idx_leads_account_stage "
            "ON leads(account_id, pipeline_stage)")
        # B12: the console reads a day's rows by seat.
        db.execute(
            "CREATE INDEX IF NOT EXISTS idx_va_queue_allocated "
            "ON va_queue(qdate, allocated_to)")
        db.execute(
            "CREATE INDEX IF NOT EXISTS idx_overflow_queue_allocated "
            "ON overflow_queue(qdate, allocated_to)")


def init_db():
    # type: () -> sqlite3.Connection
    """Create schema (idempotent), migrate existing DBs, seed defaults.

    Fresh installs get the full schema.sql and start at the latest schema
    version; existing databases get every unapplied migration. Returns the
    connection.
    """
    db = get_db()
    fresh = db.execute(
        "SELECT name FROM sqlite_master WHERE type = 'table' "
        "AND name = 'settings'"
    ).fetchone() is None
    schema_path = pathlib.Path(__file__).resolve().parent / "schema.sql"
    with open(str(schema_path), "r", encoding="utf-8") as f:
        db.executescript(f.read())
    db.commit()
    if fresh:
        with db:
            _set_schema_version(db, LATEST_SCHEMA_VERSION)
    else:
        apply_migrations(db)
    _ensure_partial_indexes(db)
    from leadflow.seed import seed_defaults  # local import to avoid cycles
    seed_defaults(db)
    return db


def utcnow():
    # type: () -> str
    """UTC now as ISO-8601 string, e.g. '2026-08-11T14:00:00+00:00'."""
    return datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")


def account_state_key(base, account_id):
    # type: (str, int) -> str
    """Per-account app_state key (S1). Account 1 keeps the LEGACY bare key
    name (imap_since, email_bounce_window, email_paused, va_queue_date,
    worker_exhausted_date, referral_asks_date, consecutive_failures_email,
    nocontact_expire_date) so upgraded installs keep their cursors and
    window state; every other account gets '<base>_<account_id>'.
    worker_heartbeat and schema_version stay global (never suffixed)."""
    account_id = int(account_id)
    if account_id == 1:
        return base
    return "%s_%d" % (base, account_id)
