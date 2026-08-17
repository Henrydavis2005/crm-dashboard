"""Reset to a clean slate (SPEC PART 6 §T2).

ONE tenant's lead data, wiped, so the owner can launch on a real database
instead of their build-period test data. Everything they CONFIGURED is
kept: settings, templates, the sequence, lead sources and their costs, the
blocklist, sending channels, Twilio numbers, pay rates, VA accounts, the
account itself, its accepted documents, and the configuration audit trail.

Order of operations (`reset_account`):

  1. BACK UP FIRST, and abort the whole reset if the backup fails. The
     backup uses `sqlite3.Connection.backup()` — the Python binding of the
     SAME SQLite online-backup API that `sqlite3 data/leadflow.db
     ".backup ..."` (the command CLAUDE.md prescribes) invokes. It is
     therefore WAL-safe in exactly the same way, with no subprocess and no
     PATH dependency. The file lands next to the live database via
     `leadflow.db.data_dir()`, so tests land in their tmp dir.
  2. CANCEL pending scheduled actions explicitly, before anything is
     deleted, so the audit trail is honest and nothing is left half-armed
     if a later step fails.
  3. DELETE the lead-tied rows, children before parents (foreign_keys is
     ON).
  4. KEEP the configuration rows, and UNLINK — never delete — the two
     tables that must outlive the data:
       * `suppressions` — a COMPLIANCE record. `suppression.is_suppressed`
         matches on email/phone and NEVER on lead_id, so clearing the link
         drops the lead association while preserving every unsubscribe and
         do-not-contact. DELETING THEM COULD LET THE APP EMAIL SOMEONE WHO
         OPTED OUT. This is deliberate.
       * `processed_emails` — the dedupe ledger. Keeping it means no old
         Gmail message can ever be reprocessed after the reset, which is
         what makes the T2 "never retroactively import" guarantee hold
         across a reset too.
  5. RESET the per-account app_state cursors (imap_since moves to NOW, so
     nothing from before the reset is reconsidered).
  6. Write ONE `events` row (lead_id NULL, so it survives step 3) naming
     who ran it, the backup path and the counts.

Steps 2-6 run in ONE transaction: if anything fails, nothing changes and
the backup is simply a spare file. Step 1 is outside it.

Everything is scoped by account_id — a reset by tenant A never touches a
row of tenant B.

WHICH TABLE GETS WHICH TREATMENT IS DATA, NOT PROSE. `TABLE_RULES` below
names every table in the schema exactly once and gives it a disposition
for BOTH destructive paths — `reset_account` (this tenant's lead data)
and `delete_account` (the whole tenant). DELETE_TABLES, KEEP_TABLES and
UNLINK_TABLES are derived from it, and tests/test_reset.py fails if the
schema grows a table nobody has classified.

The completeness check is what makes the compliance carve-out structural.
Before it, a table missing from all three lists was not an error — it was
silently never deleted and never consciously kept, and `form_drafts`
(which can hold a half-typed lead) had been sitting in exactly that gap.
`suppressions`, the append-only records and the configuration half of
`events` survive BOTH paths, so the proof that somebody revoked consent
outlives not just their lead row but their whole tenant.

KNOWN CONSEQUENCE, surfaced in the UI on purpose: VA pay and profitability
figures are computed from `interactions`, `calls` and `sales`, which are
lead-tied and therefore deleted. Historical pay figures go to zero. Pay
RATES, VA accounts, quotas and fixed costs are kept. See SPEC T2 for why
this tension is resolved this way.
"""
import csv
import datetime
import json
import logging
import os
import pathlib
import re

from leadflow.db import (
    account_state_key, backup_dir, connect as db_connect, data_dir, utcnow,
)

logger = logging.getLogger("leadflow.reset")

# PART 12 backup retention. Env-configurable because it is an operational
# property of the install, not a per-tenant preference — a tenant must not
# be able to shorten the window that protects their own data.
BACKUP_KEEP_ENV = "LEADFLOW_BACKUP_KEEP"
# FOUR, not fourteen. A backup is a complete copy of every lead, message
# and secret in the database — fourteen of them is fourteen copies of
# everything the encryption exists to protect, and the oldest is the one
# nobody remembers is there. The number was 14 until a purge of 41 stale
# backups made the size of that pile obvious.
DEFAULT_BACKUP_KEEP = 4

# backup-YYYYmmdd-HHMMSS.db, optionally with the -N collision suffix.
_BACKUP_NAME_RE = re.compile(r"^backup-\d{8}-\d{6}(-\d+)?\.db$")


def backup_keep():
    # type: () -> int
    """How many backups to retain. Env override, else 14.

    An unparseable or negative value falls back to the default rather
    than being treated as 0 — a typo in the environment must never be the
    thing that deletes every backup.
    """
    raw = os.environ.get(BACKUP_KEEP_ENV)
    if raw is None or not str(raw).strip():
        return DEFAULT_BACKUP_KEEP
    try:
        value = int(str(raw).strip())
    except ValueError:
        logger.warning("%s=%r is not an integer; using %d",
                       BACKUP_KEEP_ENV, raw, DEFAULT_BACKUP_KEEP)
        return DEFAULT_BACKUP_KEEP
    if value < 1:
        logger.warning("%s=%r is below 1; using %d",
                       BACKUP_KEEP_ENV, raw, DEFAULT_BACKUP_KEEP)
        return DEFAULT_BACKUP_KEEP
    return value

# ------------------------------------------------- table dispositions
#
# ONE table drives BOTH destructive paths. Every table in the schema is
# named here exactly once, and tests/test_reset.py fails if the schema
# grows a table this list has not classified.
#
# That completeness check is the point. The old shape was three
# hand-maintained tuples, and a table missing from all three was not an
# error — it was silently never deleted and never consciously kept. The
# compliance carve-out below (`suppressions`, the audit half of `events`,
# and the append-only records) has to be a property of the structure,
# not a promise someone remembers to keep, because the reset path is run
# by the owner on launch day and again whenever a tenant leaves.

PURGE = "purge"          # DELETE the account's rows
UNLINK = "unlink"        # keep every row, clear only lead_id
PRESERVE = "preserve"    # never touched on this path
SPLIT = "split"          # per-row: lead timeline purged, audit preserved
BY_USER = "by_user"      # keyed by user_id, deleted with its user
SELF = "self"            # the `accounts` row itself
GLOBAL = "global"        # not tenant-scoped; neither path touches it

# (table, on_reset, on_delete_account, why)
#
# ORDER IS THE DELETE ORDER — children before parents, because
# foreign_keys is ON. It is not alphabetical and must not be sorted:
# `approvals` precedes `messages` (approvals.message_id -> messages.id),
# the overflow trio leads (overflow_queue/_attempts -> overflow_leads),
# `leads` precedes `lead_sources` (leads.source_id -> lead_sources.id),
# `messages` and `sequence_steps` precede `templates`, and the two
# MFA tables precede `users`.
TABLE_RULES = (
    # ---- lead data: gone on both paths -----------------------------
    ("overflow_queue", PURGE, PURGE, "overflow pool"),
    ("overflow_attempts", PURGE, PURGE, "overflow pool"),
    ("overflow_leads", PURGE, PURGE, "overflow pool: lead data, not a roster"),
    ("approvals", PURGE, PURGE, "lead data"),
    ("messages", PURGE, PURGE, "lead data"),
    ("interactions", PURGE, PURGE, "lead data, incl. appointments/calendar"),
    ("calls", PURGE, PURGE, "lead data (pre-block-3 fossil, no writers)"),
    ("va_queue", PURGE, PURGE, "lead data"),
    ("recovery_flags", PURGE, PURGE, "lead data"),
    ("sales", PURGE, PURGE, "lead data"),
    # B9. LEAD DATA, not a compliance record. The tracker's whole purpose
    # is a lead's appointment and what it earned, `lead_id` is NOT NULL
    # and a real foreign key, and a reset deletes the leads — so keeping
    # the rows is not on the menu without inventing an orphan.
    #
    # It is money, which is why this is worth stating rather than
    # assuming: a reset is the tenant deliberately wiping their own lead
    # data, and the split owed on an appointment for a lead they have
    # just erased is not a record the app can meaningfully keep. `pay`
    # and `sales` take the same view directly above.
    ("appointment_tracker", PURGE, PURGE, "lead data (appointments + split)"),
    ("referral_asks", PURGE, PURGE, "lead data"),
    ("tasks", PURGE, PURGE, "lead data"),
    ("dead_letters", PURGE, PURGE, "unparsed lead mail"),
    ("notifications", PURGE, PURGE, "the in-app inbox: a clean slate is empty"),
    # A saved draft of /leads/new holds a half-typed lead. It was in none
    # of the three old tuples, which is exactly the gap the completeness
    # test now closes.
    ("form_drafts", PURGE, PURGE, "half-typed forms can hold lead PII"),
    ("leads", PURGE, PURGE, "lead data"),

    # ---- the audit trail: split per row, never wholesale ------------
    ("events", SPLIT, SPLIT,
     "lead timeline (lead_id NOT NULL) purged; the configuration audit "
     "trail (lead_id NULL) is preserved on BOTH paths"),

    # ---- compliance records: outlive the data they describe ---------
    # DELETING A REVOCATION DESTROYS THE PROOF IT WAS GIVEN. A reset
    # clears the lead link only (`suppression.is_suppressed` matches on
    # email/phone and never on lead_id, so the record still bites);
    # deleting the whole tenant keeps the rows outright. The revocation
    # triggers refuse the DELETE anyway — this list agrees with them
    # rather than relying on them.
    ("suppressions", UNLINK, PRESERVE,
     "compliance: the proof this person asked to be left alone"),
    ("document_acceptances", PRESERVE, PRESERVE,
     "append-only: who signed what, and when"),
    ("dial_attempts", PRESERVE, PRESERVE,
     "append-only: who was called, and which rule permitted it"),
    # `plan_changes` was here until BLOCK 1 STEP C dropped the table with
    # the rest of billing. The completeness test is what forced this line
    # to be deleted rather than left behind describing a table that no
    # longer exists.
    ("access_codes", PRESERVE, PRESERVE,
     "read-only history; document_acceptances.access_code_id points here"),
    ("access_code_redemptions", PRESERVE, PRESERVE, "read-only history"),

    # ---- the dedupe ledger ------------------------------------------
    # Kept across a reset so no old Gmail message can be reprocessed —
    # that is what makes the T2 "never retroactively import" guarantee
    # hold across a reset. Once the TENANT is gone there is nothing left
    # to protect from a reimport, so it goes with them.
    ("processed_emails", UNLINK, PURGE, "dedupe ledger"),

    # ---- tenant configuration: survives a reset, dies with the tenant
    ("settings", PRESERVE, PURGE, "tenant config"),
    ("sequence_steps", PRESERVE, PURGE, "tenant config"),
    ("templates", PRESERVE, PURGE, "tenant config"),
    ("lead_sources", PRESERVE, PURGE, "tenant config, with its costs"),
    ("blocklist", PRESERVE, PURGE, "tenant config"),
    ("send_channels", PRESERVE, PURGE, "tenant config"),
    ("twilio_numbers", PRESERVE, PURGE, "tenant config (empty fossil)"),
    ("pay_rates", PRESERVE, PURGE, "tenant config"),
    # B9. The split rate is tenant CONFIG, exactly like pay_rates and for
    # the same reason: it is an arrangement between people, not a fact
    # about a lead. A reset must not silently reset the split back to the
    # default — the team would go on closing business at a rate nobody
    # chose.
    ("split_rates", PRESERVE, PURGE, "tenant config (appointment split)"),
    # The roster and its saved CSV mappings are tenant CONFIG, exactly
    # like lead_sources. `leads` is purged above, so the source_agent
    # tags go with the leads; the roster survives a reset so the next
    # upload still knows who's who.
    ("source_agent_maps", PRESERVE, PURGE, "agent-lead CSV mappings"),
    ("source_agents", PRESERVE, PURGE, "agent roster"),
    ("mfa_recovery_codes", GLOBAL, BY_USER, "keyed by user_id"),
    ("user_mfa", GLOBAL, BY_USER, "keyed by user_id"),
    ("users", PRESERVE, PURGE, "the seats themselves"),
    # B4: a licence is CONFIGURATION, not lead data. A reset wipes the
    # leads and keeps the licence, exactly as it keeps the sequence and
    # the pay rates — wiping it would silently switch intake and sending
    # off, which is not what "start with a clean lead list" means.
    # Deleting the tenant takes it, and `delete_account` unlinks the
    # SCAN FILES on disk before the rows go: a database row is what
    # remembers where a stored scan lives, so deleting the row first
    # would strand a photograph of a government document forever.
    ("licenses", PRESERVE, PURGE, "tenant config"),
    # B6: the record that a lead was handed to the team queue. PURGED on
    # a reset, because it is keyed to leads that are being deleted and a
    # send whose lead is gone blocks a phone number nothing can release.
    ("va_sends", PURGE, PURGE, "team queue sends, keyed to leads"),

    # ---- not tenant-scoped ------------------------------------------
    ("accounts", GLOBAL, SELF, "keyed by id, not account_id"),
    ("app_state", GLOBAL, GLOBAL,
     "keyed by `key`; the account's cursors are handled explicitly"),
    ("legal_documents", GLOBAL, GLOBAL,
     "the immutable published registry, shared by every tenant"),
)

RESET_DISPOSITION = dict((t, r) for t, r, _d, _w in TABLE_RULES)
DELETE_DISPOSITION = dict((t, d) for t, _r, d, _w in TABLE_RULES)
DISPOSITION_REASON = dict((t, w) for t, _r, _d, w in TABLE_RULES)
ALL_TABLES = tuple(t for t, _r, _d, _w in TABLE_RULES)


def _tables_where(index, *dispositions):
    """The classified tables carrying one of `dispositions`, IN ORDER."""
    wanted = frozenset(dispositions)
    return tuple(t for t in ALL_TABLES if index[t] in wanted)


# Derived so the lists and the dispositions cannot drift. `events` is in
# none of them: it is SPLIT, and handled row-wise by its own statements.
DELETE_TABLES = _tables_where(RESET_DISPOSITION, PURGE)
UNLINK_TABLES = _tables_where(RESET_DISPOSITION, UNLINK)
KEEP_TABLES = _tables_where(RESET_DISPOSITION, PRESERVE)
# Full-tenant deletion, in FK-safe order.
ACCOUNT_PURGE_TABLES = _tables_where(DELETE_DISPOSITION, PURGE)
ACCOUNT_KEEP_TABLES = _tables_where(DELETE_DISPOSITION, PRESERVE)
BY_USER_TABLES = _tables_where(DELETE_DISPOSITION, BY_USER)

# app_state cursors cleared outright (the key is removed, so readers fall
# back to their defaults). imap_since is handled separately — it is SET to
# now rather than cleared, so nothing from before the reset is polled again.
CLEARED_STATE_KEYS = (
    "va_queue_date",
    "worker_exhausted_date",
    "nocontact_expire_date",
    "agent_lead_expire_date",
    "overflow_expire_date",
    "referral_asks_date",
    "email_bounce_window",
    "bounce_window",            # legacy name still read by the dashboard
    "email_paused",
    "gcal_sync",
    "gcal_events",
    # Worker failure counters. One base name exists today; a new counter
    # must be added here so a reset really does start from zero.
    "consecutive_failures_email",
)

RESET_EVENT = "account_reset"


class ResetDeleteFailed(RuntimeError):
    """Steps 2-6 failed and were rolled back — NOTHING was deleted.

    Raised only when the BACKUP SUCCEEDED (its path is on the exception)
    and the delete pass itself failed: an FK violation, or `database is
    locked` from the live worker. A backup failure propagates unchanged,
    so the two are distinguishable at the call site. Telling the owner to
    chase a disk problem that does not exist sends them either on a wild
    goose chase or straight into a blind retry.
    """

    def __init__(self, backup_path, cause):
        RuntimeError.__init__(self, str(cause))
        self.backup_path = backup_path
        self.cause = cause


class TeamStillAttached(ValueError):
    """B3: refusing to delete a manager who still has agents assigned.

    Raised BEFORE the backup and before the export, so a refused deletion
    leaves no artefacts behind at all. Carries the agents so the caller can
    name them — "reassign them first" is useless advice without a list.

    A ValueError, like the account-1 refusal, because both are the same
    kind of answer: this deletion is not allowed, not this deletion failed.
    """

    def __init__(self, account_id, blocking):
        ValueError.__init__(
            self,
            "refusing to delete account %d: %d account(s) still report to "
            "it (%s). Reassign them first — deleting a manager does not "
            "move their agents, and it must not orphan them."
            % (int(account_id), len(blocking),
               ", ".join("%s #%s" % (b["name"], b["account_id"])
                         for b in blocking)))
        self.account_id = int(account_id)
        self.blocking = blocking


# ---------------------------------------------------------------- preview

def _count(db, table, account_id, where="", params=()):
    sql = "SELECT COUNT(*) AS c FROM %s WHERE account_id = ?" % table
    if where:
        sql += " AND " + where
    return db.execute(sql, (account_id,) + tuple(params)).fetchone()["c"]


def preview(db, account_id):
    # type: (object, int) -> dict
    """What a reset WOULD do, as row counts. Pure reads.

    Returns dict(delete=..., cancel=..., unlink=..., keep=...), each a
    table/label -> count mapping, for the confirmation screen and for the
    before/after record written into the audit event.
    """
    account_id = int(account_id)
    delete = {}
    for table in DELETE_TABLES:
        delete[table] = _count(db, table, account_id)
    # Lead timeline entries only; configuration events are kept.
    delete["events (lead timeline)"] = _count(
        db, "events", account_id, "lead_id IS NOT NULL")

    cancel = {
        "scheduled emails still pending": _count(
            db, "messages", account_id,
            "direction = 'out' AND status IN ('pending','surfaced')"),
        "referral asks still pending": _count(
            db, "referral_asks", account_id, "status = 'pending'"),
        "open recovery flags": _count(
            db, "recovery_flags", account_id,
            "status IN ('open','queued')"),
        "open tasks": _count(db, "tasks", account_id, "status = 'open'"),
    }

    unlink = {}
    for table in UNLINK_TABLES:
        unlink[table] = _count(db, table, account_id)

    keep = {}
    for table in KEEP_TABLES:
        keep[table] = _count(db, table, account_id)
    keep["events (configuration audit)"] = _count(
        db, "events", account_id, "lead_id IS NULL")
    # `accounts` is kept and never written, but it is keyed by `id`, not
    # `account_id`, so it cannot live in KEEP_TABLES (which is iterated
    # with the account-scoped _count). It is listed here explicitly so the
    # UI's "Kept" panel matches SPEC's keep/delete table instead of
    # quietly omitting the account row itself.
    keep["accounts"] = db.execute(
        "SELECT COUNT(*) AS c FROM accounts WHERE id = ?",
        (account_id,)).fetchone()["c"]
    # Google Calendar events the reset would ORPHAN. A read, and only a
    # read: the reset deletes every appointment row and the gcal_event_id
    # with it, but never calls gcal.delete_event — that function has
    # exactly one caller in the codebase, the Cancelled outcome. So the
    # events survive on Google, become unreachable from inside the app,
    # and the cleared sync cursor lets the next full resync file them back
    # into the overlay cache, putting deleted leads' names on /calendar
    # permanently.
    #
    # Deleting them inside the reset was considered and rejected as too
    # dangerous — a reset that reaches out to Google can fail halfway. The
    # owner gets the number before they type the confirmation phrase and
    # decides what to do about the calendar themselves.
    orphaned_gcal = _count(
        db, "interactions", account_id,
        "itype = 'appointment' AND gcal_event_id IS NOT NULL")

    return {"delete": delete, "cancel": cancel, "unlink": unlink,
            "keep": keep, "orphaned_gcal": orphaned_gcal}


# ---------------------------------------------------------------- backup

BACKUP_NAME_ATTEMPTS = 100


def _claim_backup_path(now):
    """Reserve an UNUSED backup path and create the file exclusively.

    The stamp is only second-granular, so collisions are real rather than
    theoretical: a double submit (the confirmation form's only guard is a
    `window.confirm`, which neither disables the button nor debounces), or
    a reset landing in the same second as the manual
    `sqlite3 data/leadflow.db ".backup data/backup-$(date +%Y%m%d-%H%M%S).db"`
    that CLAUDE.md prescribes with an identical naming scheme and
    granularity. Both used to resolve to the same path, and the second
    writer silently overwrote the first — destroying the pre-reset copy,
    which is the one thing this function exists to protect.

    O_CREAT|O_EXCL means the returned path is one WE created, which is
    also what makes the failure path safe to clean up.
    """
    directory = backup_dir()
    directory.mkdir(parents=True, exist_ok=True)
    stamp = now.strftime("%Y%m%d-%H%M%S")
    for attempt in range(1, BACKUP_NAME_ATTEMPTS + 1):
        name = ("backup-%s.db" % stamp if attempt == 1
                else "backup-%s-%d.db" % (stamp, attempt))
        target = directory / name
        try:
            handle = os.open(str(target),
                             os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        except FileExistsError:
            continue
        os.close(handle)
        return target
    raise RuntimeError(
        "could not claim an unused backup filename in %s after %d attempts"
        % (directory, BACKUP_NAME_ATTEMPTS))


def prune_backups(keep=None, directory=None):
    # type: (object, object) -> list
    """Delete all but the newest `keep` backups. Returns what was removed.

    PART 12. Backups are full copies of every lead, message and secret in
    the account, so an unbounded pile of them is both a disk problem and a
    disclosure problem — the oldest copy is the one nobody remembers is
    there. `keep` defaults to LEADFLOW_BACKUP_KEEP, itself defaulting to
    14.

    Ordering is by FILENAME, not mtime: the names are
    `backup-YYYYmmdd-HHMMSS[-N].db`, which sorts chronologically as text,
    and unlike mtime that cannot be perturbed by a copy or a restore.
    Anything not matching the pattern is ignored rather than deleted —
    this function must never be the reason an unrelated file disappears.

    Never raises: a retention failure must not abort the backup it follows.
    """
    if keep is None:
        keep = backup_keep()
    directory = pathlib.Path(directory) if directory else backup_dir()
    removed = []
    try:
        if not directory.exists():
            return removed
        names = sorted(p for p in directory.iterdir()
                       if _BACKUP_NAME_RE.match(p.name))
        if keep <= 0:
            return removed
        for stale in names[:-keep] if len(names) > keep else []:
            try:
                os.remove(str(stale))
                removed.append(str(stale))
            except OSError:  # pragma: no cover - best effort
                logger.exception("could not prune backup %s", stale)
    except Exception:  # pragma: no cover - retention is never fatal
        logger.exception("backup retention pass failed")
    if removed:
        logger.info("pruned %d old backup(s), keeping %d", len(removed), keep)
    return removed


def backup_database(db, now=None):
    # type: (object, object) -> str
    """Copy the whole database to data/backups/backup-YYYYmmdd-HHMMSS.db.

    Uses Connection.backup() — the Python binding of the same SQLite
    ONLINE BACKUP API the `.backup` shell command uses, so it is WAL-safe:
    it copies a consistent snapshot including everything sitting in the
    write-ahead log, with no subprocess and no PATH dependency.

    PART 12: the destination is opened through `leadflow.db.connect`, so
    the copy is SQLCipher-encrypted under the same passphrase as the
    live database. A backup is a complete copy of the data the encryption
    exists to protect; writing it in the clear would defeat the whole
    feature. After a successful copy, old backups are pruned to the
    retention limit.

    NEVER overwrites an existing file: the path is claimed exclusively and
    a collision takes a `-2`, `-3`, ... suffix (see `_claim_backup_path`).

    Raises on any failure (the caller must abort the reset). The partially
    written file is removed on the way out so a failed backup never looks
    like a good one — and only ever the file THIS call created, never one
    that was already sitting there.
    """
    # sqlite3's online backup BLOCKS FOREVER when the SOURCE connection is
    # itself inside a transaction — it waits on a lock only that same
    # connection could release. Measured at >15s with no progress and no
    # error. A hang in a request thread is a far worse failure than an
    # exception, and this is a once-ever launch-day action, so refuse
    # loudly instead. Callers must reach step 1 with nothing open; the
    # reset route does (only SELECTs run before it).
    if db.in_transaction:
        raise RuntimeError(
            "refusing to back up while this connection has an open "
            "transaction: sqlite3's online backup would block forever. "
            "Commit or roll back before resetting.")
    now = now or datetime.datetime.now()
    target = _claim_backup_path(now)
    dest = None
    try:
        dest = db_connect(target)
        db.backup(dest)
        dest.close()
        dest = None
    except Exception:
        if dest is not None:
            try:
                dest.close()
            except Exception:  # pragma: no cover - close best-effort
                pass
        try:
            if target.exists():
                os.remove(str(target))
        except OSError:  # pragma: no cover - cleanup best-effort
            logger.exception("could not remove partial backup %s", target)
        raise
    logger.info("database backed up to %s", target)
    prune_backups()
    return str(target)


# ---------------------------------------------------------------- reset

def _cancel_pending(db, account_id, now):
    """Step 2: stand every scheduled action down explicitly, BEFORE
    anything is deleted, so the trail is honest and nothing is left
    half-armed if a later step fails."""
    counts = {}
    counts["messages canceled"] = db.execute(
        "UPDATE messages SET status = 'canceled' WHERE account_id = ? "
        "AND direction = 'out' AND status IN ('pending','surfaced')",
        (account_id,)).rowcount
    counts["referral asks dismissed"] = db.execute(
        "UPDATE referral_asks SET status = 'dismissed' WHERE account_id = ? "
        "AND status = 'pending'", (account_id,)).rowcount
    counts["recovery flags cleared"] = db.execute(
        "UPDATE recovery_flags SET status = 'cleared', resolved_at = ? "
        "WHERE account_id = ? AND status IN ('open','queued')",
        (now, account_id)).rowcount
    counts["tasks closed"] = db.execute(
        "UPDATE tasks SET status = 'done', done_at = ? WHERE account_id = ? "
        "AND status = 'open'", (now, account_id)).rowcount
    return counts


def _unlink_kept_rows(db, account_id, tables=UNLINK_TABLES):
    """Step 4: keep the rows, drop the lead link. Runs BEFORE the leads
    delete because suppressions.lead_id is a real foreign key.

    Nulling lead_id on a revocation is explicitly allowed by the
    `suppressions_revocation_stays_permanent` trigger, which freezes
    reason/reversible/email/phone and nothing else.
    """
    counts = {}
    for table in tables:
        counts[table] = db.execute(
            "UPDATE %s SET lead_id = NULL WHERE account_id = ? "
            "AND lead_id IS NOT NULL" % table, (account_id,)).rowcount
    return counts


def _purge_tables(db, tables, account_id):
    """DELETE one account's rows from `tables`, in the order given.

    `leads` gets its self-referencing `referred_by` (the R7 referral
    firewall) nulled first so the delete can never trip that FK.
    """
    counts = {}
    for table in tables:
        if table == "leads":
            db.execute(
                "UPDATE leads SET referred_by = NULL WHERE account_id = ? "
                "AND referred_by IS NOT NULL", (account_id,))
        counts[table] = db.execute(
            "DELETE FROM %s WHERE account_id = ?" % table,
            (account_id,)).rowcount
    return counts


def _purge_lead_timeline(db, account_id):
    """The SPLIT half of `events`: the lead timeline goes, the
    configuration audit trail (lead_id NULL) stays. Both destructive
    paths use this — an audit trail that a tenant deletion can erase is
    not an audit trail."""
    return db.execute(
        "DELETE FROM events WHERE account_id = ? AND lead_id IS NOT NULL",
        (account_id,)).rowcount


def _delete_rows(db, account_id):
    """Step 3: delete the lead-tied rows for ONE account."""
    counts = _purge_tables(db, DELETE_TABLES, account_id)
    counts["events (lead timeline)"] = _purge_lead_timeline(db, account_id)
    return counts


def _reset_cursors(db, account_id, now):
    """Step 5: per-account app_state cursors. imap_since moves to NOW so
    no message from before the reset is polled again; the rest are removed
    so their readers fall back to defaults."""
    db.execute(
        "INSERT INTO app_state (key, value) VALUES (?,?) "
        "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        (account_state_key("imap_since", account_id), now))
    for base in CLEARED_STATE_KEYS:
        db.execute("DELETE FROM app_state WHERE key = ?",
                   (account_state_key(base, account_id),))


def reset_account(db, account_id, user_id=None):
    # type: (object, int, object) -> dict
    """Wipe ONE account's lead data. See the module docstring for the
    order, the keep/delete/unlink split and the reasoning.

    Returns dict(backup_path=..., before=..., after=..., canceled=...,
    deleted=..., unlinked=...). Raises if the backup fails, having changed
    nothing.
    """
    account_id = int(account_id)
    before = preview(db, account_id)

    # STEP 1 — outside the transaction. If this raises, nothing is deleted.
    backup_path = backup_database(db)

    now = utcnow()
    try:
        with db:  # STEPS 2-6, atomically
            canceled = _cancel_pending(db, account_id, now)
            unlinked = _unlink_kept_rows(db, account_id)
            deleted = _delete_rows(db, account_id)
            _reset_cursors(db, account_id, now)
            after = preview(db, account_id)
            detail = json.dumps({
                "backup_path": backup_path,
                "canceled": canceled,
                "deleted": deleted,
                "unlinked": unlinked,
                "before": before,
                "after": after,
            }, sort_keys=True)
            # Written INSIDE the transaction but AFTER the deletes, with
            # lead_id NULL, so it survives step 3 and lands only if the
            # whole reset lands.
            db.execute(
                "INSERT INTO events (account_id, lead_id, user_id, etype, "
                "detail, created_at) VALUES (?, NULL, ?, ?, ?, ?)",
                (account_id, user_id, RESET_EVENT, detail, now))
    except Exception as exc:
        # `with db` has already rolled the whole thing back. Re-raised as
        # a DISTINCT type so the caller can say "the backup was written;
        # the delete pass failed" instead of blaming the backup.
        logger.exception("account %s reset rolled back after the backup "
                         "at %s was written", account_id, backup_path)
        raise ResetDeleteFailed(backup_path, exc)

    logger.warning("account %s reset to a clean slate by user %s "
                   "(backup: %s)", account_id, user_id, backup_path)
    return {"backup_path": backup_path, "before": before, "after": after,
            "canceled": canceled, "deleted": deleted, "unlinked": unlinked}


# -------------------------------------------------------- delete a tenant

ACCOUNT_DELETE_EVENT = "account_deleted"


def delete_preview(db, account_id):
    # type: (object, int) -> dict
    """What `delete_account` WOULD do, as row counts. Pure reads."""
    account_id = int(account_id)
    purge = {}
    for table in ACCOUNT_PURGE_TABLES:
        purge[table] = _count(db, table, account_id)
    purge["events (lead timeline)"] = _count(
        db, "events", account_id, "lead_id IS NOT NULL")
    for table in BY_USER_TABLES:
        purge[table] = db.execute(
            "SELECT COUNT(*) AS c FROM %s WHERE user_id IN "
            "(SELECT id FROM users WHERE account_id = ?)" % table,
            (account_id,)).fetchone()["c"]
    purge["accounts"] = db.execute(
        "SELECT COUNT(*) AS c FROM accounts WHERE id = ?",
        (account_id,)).fetchone()["c"]

    preserve = {}
    for table in ACCOUNT_KEEP_TABLES:
        preserve[table] = _count(db, table, account_id)
    preserve["events (configuration audit)"] = _count(
        db, "events", account_id, "lead_id IS NULL")
    return {"purge": purge, "preserve": preserve}


EXPORT_COLUMNS = ("id", "first_name", "last_name", "email", "phone",
                  "city", "source_agent", "pipeline_stage", "closed_state",
                  "consent_date", "received_at", "created_at")


def export_dir():
    """Where lead exports land: data/exports/. Beside the backups and for
    the same reason — an export is a plaintext copy of everything the
    encryption protects, so it does not sit loose in data/."""
    directory = data_dir() / "exports"
    directory.mkdir(parents=True, exist_ok=True)
    return directory


def export_leads_csv(db, account_id, now=None):
    # type: (object, int, object) -> object
    """Write this account's leads to a CSV and return the path.

    B3: an agent's leads are EXPORTED BEFORE THE ACCOUNT IS DELETED. The
    backup is a full encrypted copy of the whole install and is the wrong
    artefact for "give me my book of business" — it needs the passphrase,
    it needs this application to read it, and it contains every other
    tenant too. This is the readable, single-tenant one.

    Written OUTSIDE the deletion transaction and before it, so a failure
    to write the export stops the deletion instead of completing it with
    nothing handed back.

    Deliberately NOT the health fields, which no longer exist, and not
    `metadata`, which is the parsed extras blob: the columns are named
    explicitly so a future column joins this file only if somebody decides
    it should.
    """
    account_id = int(account_id)
    stamp = (now or datetime.datetime.now(datetime.timezone.utc)).strftime(
        "%Y%m%d-%H%M%S")
    target = export_dir() / ("account-%d-leads-%s.csv" % (account_id, stamp))
    rows = db.execute(
        "SELECT %s FROM leads WHERE account_id = ? ORDER BY id"
        % ", ".join(EXPORT_COLUMNS), (account_id,)).fetchall()
    handle = os.open(str(target), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(handle, "w", newline="") as fh:
        writer = csv.writer(fh)
        writer.writerow(EXPORT_COLUMNS)
        for row in rows:
            writer.writerow([row[column] for column in EXPORT_COLUMNS])
    logger.info("exported %d lead(s) for account %s to %s",
                len(rows), account_id, target)
    return target


def delete_account(db, account_id, user_id=None, actor_account_id=None):
    # type: (object, int, object, object) -> dict
    """Delete ONE tenant outright — data, configuration, seats, account row.

    The bigger sibling of `reset_account`, sharing its order (back up
    first, then one transaction), its FK-safe table order and — this is
    the point — its compliance carve-out, read from the SAME
    `TABLE_RULES`. `suppressions`, `document_acceptances`,
    `dial_attempts`, the access-code history and the
    configuration half of `events` all SURVIVE the tenant they belong to.

    Those preserved rows keep their `account_id`, which now names an
    account that no longer exists. That is deliberate and it is what an
    orphan is FOR: the record says which tenant asked, and no FK
    references `accounts`, so nothing dangles. Note the practical limit —
    `suppression.is_suppressed` is per-tenant (S1), so a preserved
    suppression is a readable record rather than a live block once its
    account is gone. There is no account left to import into.

    The audit event is written against `actor_account_id` (the operator
    who ran it), NOT the deleted account: an event filed under a deleted
    tenant is one no audit view can ever reach.

    Refuses account 1 — the install's own account, whose deletion would
    orphan the superadmin and the global app_state cursors.
    """
    account_id = int(account_id)
    if account_id == 1:
        raise ValueError(
            "refusing to delete account 1: it is the install's own account, "
            "holds the superadmin seat and owns the unsuffixed app_state "
            "cursors. Reset it instead.")
    before = delete_preview(db, account_id)
    name_row = db.execute("SELECT name FROM accounts WHERE id = ?",
                          (account_id,)).fetchone()
    if name_row is None:
        raise ValueError("no such account: %s" % account_id)

    # B3: A MANAGER WITH AGENTS STILL ATTACHED CANNOT BE DELETED. Deleting
    # one would leave every agent pointing at an account that no longer
    # exists — an upline `team.set_upline` would refuse to create, arrived
    # at by deletion instead. Reassignment is a decision, and it is not one
    # this function is allowed to make silently by cascading.
    from leadflow import team
    blocking = team.blocking_downline(db, account_id)
    if blocking:
        raise TeamStillAttached(account_id, blocking)

    # B4: the licence SCANS on disk, read before the rows that name them
    # are deleted. A stored scan is a photograph of a government document
    # and the database row is the only thing that knows where it lives, so
    # deleting the row first would strand the file forever.
    from leadflow import licensure
    scan_files = [r["pdf_filename"] for r in db.execute(
        "SELECT pdf_filename FROM licenses WHERE account_id = ? "
        "AND pdf_filename IS NOT NULL", (account_id,)).fetchall()]

    # STEP 1 — outside the transaction, and BEFORE the backup: if the
    # export cannot be written, nothing has happened yet.
    export_path = export_leads_csv(db, account_id)
    backup_path = backup_database(db)

    now = utcnow()
    try:
        with db:
            canceled = _cancel_pending(db, account_id, now)
            # Preserved rows that carry a lead FK lose the link, not the row.
            unlinked = _unlink_kept_rows(
                db, account_id,
                tuple(t for t in ACCOUNT_KEEP_TABLES if t in UNLINK_TABLES
                      or t == "suppressions"))
            deleted = {}
            for table in BY_USER_TABLES:
                deleted[table] = db.execute(
                    "DELETE FROM %s WHERE user_id IN "
                    "(SELECT id FROM users WHERE account_id = ?)" % table,
                    (account_id,)).rowcount
            deleted.update(_purge_tables(db, ACCOUNT_PURGE_TABLES, account_id))
            deleted["events (lead timeline)"] = _purge_lead_timeline(
                db, account_id)
            for base in CLEARED_STATE_KEYS + ("imap_since",):
                db.execute("DELETE FROM app_state WHERE key = ?",
                           (account_state_key(base, account_id),))
            deleted["accounts"] = db.execute(
                "DELETE FROM accounts WHERE id = ?", (account_id,)).rowcount
            after = delete_preview(db, account_id)
            db.execute(
                "INSERT INTO events (account_id, lead_id, user_id, etype, "
                "detail, created_at) VALUES (?, NULL, ?, ?, ?, ?)",
                (int(actor_account_id or 1), user_id, ACCOUNT_DELETE_EVENT,
                 json.dumps({
                     "deleted_account_id": account_id,
                     "deleted_account_name": name_row["name"],
                     "backup_path": backup_path,
                     "export_path": str(export_path),
                     "canceled": canceled,
                     "deleted": deleted,
                     "unlinked": unlinked,
                     "before": before,
                     "after": after,
                 }, sort_keys=True), now))
    except Exception as exc:
        logger.exception("account %s deletion rolled back after the backup "
                         "at %s was written", account_id, backup_path)
        raise ResetDeleteFailed(backup_path, exc)

    # AFTER the transaction committed, never before: a rolled-back
    # deletion must leave the scans where the surviving rows still point.
    for filename in scan_files:
        licensure.delete_pdf(filename)

    logger.warning("account %s (%s) DELETED by user %s (backup: %s, "
                   "export: %s)", account_id, name_row["name"], user_id,
                   backup_path, export_path)
    return {"backup_path": backup_path, "export_path": str(export_path),
            "before": before, "after": after, "canceled": canceled,
            "deleted": deleted, "unlinked": unlinked}


def last_reset(db, account_id):
    # type: (object, int) -> object
    """The most recent reset's recorded counts, or None. Used to render the
    before/after summary after the action has run."""
    row = db.execute(
        "SELECT * FROM events WHERE account_id = ? AND etype = ? "
        "ORDER BY id DESC LIMIT 1", (int(account_id), RESET_EVENT)
    ).fetchone()
    if row is None:
        return None
    try:
        payload = json.loads(row["detail"] or "{}")
    except (TypeError, ValueError):
        return None
    payload["created_at"] = row["created_at"]
    return payload
