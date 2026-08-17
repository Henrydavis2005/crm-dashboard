"""Google Calendar client (S8): raw OAuth2 + REST via `requests`, no SDK.

Owns the tenant's Google Calendar connection end to end:

- OAuth2 authorization-code flow helpers (authorize_url / oauth state
  signing / connect = code exchange + encrypted refresh-token storage).
- Access tokens minted from the stored refresh token with a small
  in-memory per-account cache (module-level; cleared on disconnect).
- Event REST calls: insert_event / patch_event / delete_event,
  test_connection (calendar metadata GET).
- Incremental two-way sync (sync_account): list_changes with a per-account
  syncToken cursor in app_state (db.account_state_key 'gcal_sync' —
  account 1 keeps the bare key, others get 'gcal_sync_<id>'). A 410 GONE
  from Google expires the cursor -> automatic full resync. External
  (non-app) events land in a JSON overlay cache in app_state (key
  'gcal_events') for the /calendar view ONLY — they NEVER create pipeline
  appointments. A Google-side deletion of an app-created event writes an
  event-log note; the appointment interaction is kept.
- retry_unsynced: the worker's catch-up pass for appointment rows that
  are missing gcal_event_id (silent-degrade leftovers).

Every HTTP call carries a timeout and raises GcalError on failure; sync
callers (interactions hooks, worker) degrade silently — Google being down
never blocks an appointment. All settings/state reads are per account.
"""
import datetime
import hashlib
import hmac
import json
import logging
import threading
import time
import urllib.parse
from typing import Optional

import requests

from leadflow.db import account_state_key
from leadflow.branding import PRODUCT_NAME

logger = logging.getLogger("leadflow.gcal")

AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth"
TOKEN_URL = "https://oauth2.googleapis.com/token"
API_BASE = "https://www.googleapis.com/calendar/v3"
SCOPE = "https://www.googleapis.com/auth/calendar.events"

TIMEOUT = 15  # seconds, every HTTP call
EVENT_MINUTES = 30  # default appointment length on the calendar
STATE_MAX_AGE = 600  # seconds an OAuth state token stays valid
SYNC_KEY = "gcal_sync"  # app_state cursor base (account_state_key)
CACHE_KEY = "gcal_events"  # app_state overlay-cache base
FULL_SYNC_LOOKBACK_DAYS = 30  # first/re-sync window (bounds payload size)
CACHE_KEEP_PAST_DAYS = 60  # overlay entries older than this are pruned
RETRY_LOOKBACK_HOURS = 24  # retry pass ignores older past appointments
RETRY_BATCH = 10  # appointments pushed per retry pass
# Rows younger than this stay the inline post-commit write's business —
# retrying them immediately races that write into a duplicate event.
RETRY_MIN_AGE_MINUTES = 5

TITLE_PREFIX = PRODUCT_NAME + ": "
OUTCOME_PREFIXES = {"showed": "✓ ", "no_show": "✗ "}


class GcalError(Exception):
    """Any Google Calendar API/OAuth failure (status carried when known)."""

    def __init__(self, message, status=None):
        super(GcalError, self).__init__(message)
        self.status = status


class GcalSyncTokenExpired(GcalError):
    """410 GONE: the syncToken expired — do a full resync."""


# ---------------------------------------------------------------- helpers

def _resolve_account(account_id):
    # type: (object) -> int
    if account_id is None:
        from leadflow.auth import current_account_id  # deferred: avoid cycle
        return current_account_id()
    return int(account_id)


def _setting(db, key, account_id):
    from leadflow.settings import get_setting
    return get_setting(key, db=db, account_id=account_id)


def _state_get(db, base, account_id):
    key = account_state_key(base, account_id)
    row = db.execute("SELECT value FROM app_state WHERE key = ?",
                     (key,)).fetchone()
    return row["value"] if row is not None else None


def _state_set(db, base, account_id, value):
    key = account_state_key(base, account_id)
    own = not db.in_transaction
    db.execute(
        "INSERT INTO app_state (key, value) VALUES (?, ?) "
        "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        (key, str(value)))
    if own:
        db.commit()


def _state_del(db, base, account_id):
    key = account_state_key(base, account_id)
    own = not db.in_transaction
    db.execute("DELETE FROM app_state WHERE key = ?", (key,))
    if own:
        db.commit()


def _parse_utc(value):
    # type: (str) -> Optional[datetime.datetime]
    """ISO-8601 string -> aware UTC datetime (None on garbage)."""
    try:
        dt = datetime.datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except (ValueError, TypeError):
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=datetime.timezone.utc)
    return dt.astimezone(datetime.timezone.utc)


def is_connected(db, account_id=None):
    # type: (object, object) -> bool
    """True when this account has a full Google Calendar connection
    (OAuth client + stored refresh token). Read errors -> False."""
    account_id = _resolve_account(account_id)
    try:
        return bool(_setting(db, "gcal_refresh_token", account_id)
                    and _setting(db, "gcal_client_id", account_id)
                    and _setting(db, "gcal_client_secret", account_id))
    except Exception:
        logger.exception("could not read gcal settings for account %s",
                         account_id)
        return False


# ---------------------------------------------------------------- OAuth

def oauth_state(account_id):
    # type: (int) -> str
    """Signed OAuth state token: '<account_id>.<ts>.<hmac>' keyed by the
    app session secret. Verified on the callback (verify_state)."""
    from leadflow.auth import get_secret_key
    payload = "%d.%d" % (int(account_id), int(time.time()))
    sig = hmac.new(get_secret_key(), payload.encode("ascii"),
                   hashlib.sha256).hexdigest()
    return "%s.%s" % (payload, sig)


def verify_state(state, account_id, max_age=STATE_MAX_AGE):
    # type: (str, int, int) -> bool
    """Check signature, freshness and that the token was minted for THIS
    account (the returning admin's own tenant)."""
    from leadflow.auth import get_secret_key
    parts = (state or "").split(".")
    if len(parts) != 3:
        return False
    payload = "%s.%s" % (parts[0], parts[1])
    expect = hmac.new(get_secret_key(), payload.encode("ascii"),
                      hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expect, parts[2]):
        return False
    try:
        state_account = int(parts[0])
        ts = int(parts[1])
    except ValueError:
        return False
    if state_account != int(account_id):
        return False
    return 0 <= (time.time() - ts) <= max_age


def authorize_url(client_id, redirect_uri, state):
    # type: (str, str, str) -> str
    """The Google consent-screen URL for the auth-code flow.
    access_type=offline + prompt=consent force a refresh token."""
    params = urllib.parse.urlencode({
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "response_type": "code",
        "scope": SCOPE,
        "access_type": "offline",
        "prompt": "consent",
        "state": state,
    })
    return "%s?%s" % (AUTH_URL, params)


def _token_post(data):
    """POST the OAuth token endpoint; returns the parsed payload dict."""
    try:
        resp = requests.post(TOKEN_URL, data=data, timeout=TIMEOUT)
    except Exception as exc:
        raise GcalError("token endpoint unreachable: %s" % exc)
    try:
        payload = resp.json()
    except Exception:
        payload = {}
    if resp.status_code != 200:
        detail = payload.get("error_description") or payload.get("error") \
            or ("HTTP %s" % resp.status_code)
        raise GcalError("token request failed: %s" % detail,
                        status=resp.status_code)
    return payload


def connect(db, code, redirect_uri, account_id=None):
    # type: (object, str, str, object) -> None
    """Exchange the callback code and store the refresh token (encrypted
    via the secret gcal_refresh_token setting). Primes the access-token
    cache. Raises GcalError when Google says no."""
    from leadflow.settings import set_setting
    account_id = _resolve_account(account_id)
    payload = _token_post({
        "code": code,
        "client_id": _setting(db, "gcal_client_id", account_id) or "",
        "client_secret": _setting(db, "gcal_client_secret", account_id) or "",
        "redirect_uri": redirect_uri,
        "grant_type": "authorization_code",
    })
    refresh = payload.get("refresh_token")
    if not refresh:
        raise GcalError("Google returned no refresh token — remove the "
                        "app's access at myaccount.google.com and connect "
                        "again")
    set_setting("gcal_refresh_token", refresh, db=db, account_id=account_id)
    access = payload.get("access_token")
    if access:
        expires = int(payload.get("expires_in") or 3600)
        with _token_lock:
            _token_cache[account_id] = (access, time.time() + expires - 60)
    logger.info("google calendar connected for account %s", account_id)


def disconnect(db, account_id=None):
    # type: (object, object) -> None
    """Clear the refresh token, the sync cursor and the overlay cache
    (per tenant). The OAuth client id/secret settings are kept."""
    from leadflow.settings import set_setting
    account_id = _resolve_account(account_id)
    set_setting("gcal_refresh_token", "", db=db, account_id=account_id)
    _state_del(db, SYNC_KEY, account_id)
    _state_del(db, CACHE_KEY, account_id)
    with _token_lock:
        _token_cache.pop(account_id, None)
    logger.info("google calendar disconnected for account %s", account_id)


# --------------------------------------------------------- access tokens

# account_id -> (access_token, epoch_expiry). One worker process serves
# every tenant, so the cache is keyed per account and lock-guarded.
_token_cache = {}
_token_lock = threading.Lock()


def reset_token_cache():
    """Testing helper: drop every cached access token."""
    with _token_lock:
        _token_cache.clear()


def _access_token(db, account_id, force=False):
    # type: (object, int, bool) -> str
    with _token_lock:
        cached = _token_cache.get(account_id)
    if cached is not None and not force and cached[1] > time.time():
        return cached[0]
    refresh = _setting(db, "gcal_refresh_token", account_id)
    if not refresh:
        raise GcalError("Google Calendar is not connected")
    payload = _token_post({
        "client_id": _setting(db, "gcal_client_id", account_id) or "",
        "client_secret": _setting(db, "gcal_client_secret", account_id) or "",
        "refresh_token": refresh,
        "grant_type": "refresh_token",
    })
    access = payload.get("access_token")
    if not access:
        raise GcalError("token refresh returned no access token")
    expires = int(payload.get("expires_in") or 3600)
    with _token_lock:
        _token_cache[account_id] = (access, time.time() + expires - 60)
    return access


# ----------------------------------------------------------- REST client

def _request(db, account_id, method, path, params=None, json_body=None,
             _retry=True):
    """One authenticated Calendar API call. Returns the parsed JSON body
    (None on 204). Raises GcalSyncTokenExpired on 410, GcalError on any
    other failure; retries exactly once on 401 with a fresh token."""
    token = _access_token(db, account_id)
    url = API_BASE + path
    try:
        resp = requests.request(
            method, url, params=params, json=json_body,
            headers={"Authorization": "Bearer %s" % token}, timeout=TIMEOUT)
    except Exception as exc:
        raise GcalError("calendar API unreachable: %s" % exc)
    if resp.status_code == 401 and _retry:
        _access_token(db, account_id, force=True)
        return _request(db, account_id, method, path, params=params,
                        json_body=json_body, _retry=False)
    if resp.status_code == 410:
        raise GcalSyncTokenExpired("sync token expired", status=410)
    if resp.status_code >= 400:
        detail = ""
        try:
            detail = (resp.json().get("error") or {}).get("message") or ""
        except Exception:
            pass
        raise GcalError("calendar API %s %s failed: HTTP %s %s"
                        % (method, path, resp.status_code, detail),
                        status=resp.status_code)
    if resp.status_code == 204 or not (resp.text or "").strip():
        return None
    try:
        return resp.json()
    except Exception as exc:
        raise GcalError("calendar API returned unparseable JSON: %s" % exc)


def _calendar_id(db, account_id):
    return _setting(db, "gcal_calendar_id", account_id) or "primary"


def _events_path(db, account_id, suffix=""):
    return "/calendars/%s/events%s" % (
        urllib.parse.quote(_calendar_id(db, account_id), safe=""), suffix)


# ------------------------------------------------------------ event CRUD

def event_title(lead_name, outcome=None):
    # type: (str, Optional[str]) -> str
    """'Ancora: <name>', prefixed with a check/cross once an outcome is
    marked (showed -> check, no_show -> cross)."""
    return OUTCOME_PREFIXES.get(outcome or "", "") + TITLE_PREFIX + lead_name


def lead_link(db, lead_id, account_id=None):
    # type: (object, int, object) -> str
    """The lead's app URL via public_base_url (empty when unset)."""
    account_id = _resolve_account(account_id)
    base = (_setting(db, "public_base_url", account_id) or "").rstrip("/")
    if not base:
        return ""
    return "%s/leads/%d" % (base, lead_id)


def insert_event(db, account_id, summary, start_utc, description=None,
                 minutes=EVENT_MINUTES):
    # type: (object, int, str, str, Optional[str], int) -> str
    """Create a calendar event (start_utc = UTC ISO string, default 30
    minutes). Returns the Google event id."""
    start = _parse_utc(start_utc)
    if start is None:
        raise GcalError("bad appointment timestamp: %r" % start_utc)
    end = start + datetime.timedelta(minutes=minutes)
    body = {
        "summary": summary,
        "description": description or "",
        "start": {"dateTime": start.isoformat(timespec="seconds")},
        "end": {"dateTime": end.isoformat(timespec="seconds")},
    }
    data = _request(db, account_id, "POST",
                    _events_path(db, account_id), json_body=body)
    event_id = (data or {}).get("id")
    if not event_id:
        raise GcalError("event insert returned no id")
    return event_id


def patch_event(db, account_id, event_id, body):
    # type: (object, int, str, dict) -> None
    """PATCH fields on an existing event."""
    _request(db, account_id, "PATCH",
             _events_path(db, account_id,
                          "/" + urllib.parse.quote(event_id, safe="")),
             json_body=body)


def delete_event(db, account_id, event_id):
    # type: (object, int, str) -> None
    """Delete an event; an already-gone event (404/410) is success."""
    try:
        _request(db, account_id, "DELETE",
                 _events_path(db, account_id,
                              "/" + urllib.parse.quote(event_id, safe="")))
    except GcalError as exc:
        if exc.status in (404, 410):
            return
        raise


def test_connection(db, account_id=None):
    # type: (object, object) -> tuple
    """Settings 'Test connection' button: GET the calendar's metadata.
    Returns (ok, detail) — never raises."""
    account_id = _resolve_account(account_id)
    if not is_connected(db, account_id):
        return (False, "not connected — save the OAuth client and press "
                       "Connect first")
    try:
        data = _request(db, account_id, "GET", "/calendars/%s"
                        % urllib.parse.quote(_calendar_id(db, account_id),
                                             safe=""))
    except GcalError as exc:
        return (False, str(exc))
    name = (data or {}).get("summary") or _calendar_id(db, account_id)
    return (True, "calendar '%s' reachable" % name)


# ------------------------------------------------------ incremental sync

def list_changes(db, account_id, sync_token=None):
    # type: (object, int, Optional[str]) -> tuple
    """One sync round: (items, next_sync_token).

    With sync_token -> incremental (only changed/cancelled events since
    the last round). Without -> full sync bounded to the last
    FULL_SYNC_LOOKBACK_DAYS (singleEvents so recurring series expand).
    Follows pageToken pagination. Raises GcalSyncTokenExpired on 410."""
    items = []
    page_token = None
    next_sync = None
    while True:
        params = {"maxResults": 250}
        if sync_token:
            params["syncToken"] = sync_token
        else:
            time_min = (datetime.datetime.now(datetime.timezone.utc)
                        - datetime.timedelta(days=FULL_SYNC_LOOKBACK_DAYS))
            params["singleEvents"] = "true"
            params["timeMin"] = time_min.isoformat(timespec="seconds")
        if page_token:
            params["pageToken"] = page_token
        data = _request(db, account_id, "GET",
                        _events_path(db, account_id), params=params) or {}
        items.extend(data.get("items") or [])
        page_token = data.get("nextPageToken")
        if not page_token:
            next_sync = data.get("nextSyncToken")
            break
    return items, next_sync


def _load_cache(db, account_id):
    raw = _state_get(db, CACHE_KEY, account_id)
    if not raw:
        return {}
    try:
        cache = json.loads(raw)
        return cache if isinstance(cache, dict) else {}
    except ValueError:
        return {}


def _cache_entry(item):
    """Normalize a Google event for the overlay cache. All-day events
    carry 'date'; timed events carry 'dateTime'."""
    start = item.get("start") or {}
    end = item.get("end") or {}
    all_day = "date" in start
    return {
        "id": item.get("id"),
        "summary": item.get("summary") or "(busy)",
        "start": start.get("dateTime") or start.get("date") or "",
        "end": end.get("dateTime") or end.get("date") or "",
        "all_day": all_day,
    }


def _prune_cache(cache):
    """Drop overlay entries that ended over CACHE_KEEP_PAST_DAYS ago."""
    cutoff = (datetime.datetime.now(datetime.timezone.utc)
              - datetime.timedelta(days=CACHE_KEEP_PAST_DAYS))
    keep = {}
    for eid, entry in cache.items():
        stamp = entry.get("end") or entry.get("start") or ""
        dt = _parse_utc(stamp)
        if dt is None and len(stamp) == 10:  # bare all-day date
            try:
                dt = datetime.datetime.combine(
                    datetime.date.fromisoformat(stamp),
                    datetime.time(0, 0),
                    tzinfo=datetime.timezone.utc)
            except ValueError:
                dt = None
        if dt is None or dt >= cutoff:
            keep[eid] = entry
    return keep


def _app_interaction_for_event(db, account_id, event_id):
    """The account's appointment interaction linked to this Google event
    (or None): app-created events never enter the overlay cache."""
    return db.execute(
        "SELECT id, lead_id FROM interactions "
        "WHERE account_id = ? AND gcal_event_id = ? LIMIT 1",
        (account_id, event_id)).fetchone()


def _has_terminal_outcome(db, interaction_id):
    """True when this appointment was cancelled/rescheduled IN THE APP.

    A cancel deletes the Google event on purpose and deliberately KEEPS
    gcal_event_id (clearing it would let retry_unsynced recreate the
    event), so the next sync sees a Google-side deletion that the app
    itself performed."""
    return db.execute(
        "SELECT 1 FROM interactions WHERE parent_id = ? "
        "AND disposition IN ('cancelled','rescheduled') LIMIT 1",
        (interaction_id,)).fetchone() is not None


def sync_account(db, account_id=None):
    # type: (object, object) -> int
    """The worker's 5-minute Google->app pass for ONE connected account.

    Incremental via the per-account syncToken cursor; 410 clears the
    cursor and re-runs one full sync. External events are merged into the
    overlay cache (calendar view ONLY — never pipeline appointments).
    Google-side deletion of an app-created event -> event-log note, the
    appointment row is kept. Returns the number of processed changes."""
    from leadflow.audit import log_event
    account_id = _resolve_account(account_id)
    if not is_connected(db, account_id):
        return 0
    cursor = _state_get(db, SYNC_KEY, account_id)
    try:
        items, next_sync = list_changes(db, account_id, sync_token=cursor)
    except GcalSyncTokenExpired:
        logger.info("gcal sync token expired for account %s; full resync",
                    account_id)
        _state_del(db, SYNC_KEY, account_id)
        items, next_sync = list_changes(db, account_id, sync_token=None)

    cache = _load_cache(db, account_id)
    for item in items:
        event_id = item.get("id")
        if not event_id:
            continue
        cancelled = (item.get("status") == "cancelled")
        app_row = _app_interaction_for_event(db, account_id, event_id)
        if app_row is not None:
            # App-created: never cached. A Google-side delete is noted on
            # the lead's event log; the appointment itself is NOT deleted
            # (the pipeline owns appointment data).
            #
            # UNLESS the app deleted it itself: an appointment carrying a
            # terminal outcome had its event removed by _gcal_after_cancel
            # moments earlier. Telling the owner "it was deleted on
            # Google; the appointment is kept in Ancora" right after
            # they clicked Cancelled reads like a sync failure, and
            # invites them to go looking for a problem they created.
            if cancelled and not _has_terminal_outcome(db, app_row["id"]):
                log_event(db, app_row["lead_id"], "gcal_event_deleted",
                          "Google Calendar event %s was deleted on Google; "
                          "the appointment is kept in %s"
                          % (event_id, PRODUCT_NAME))
            continue
        if cancelled:
            cache.pop(event_id, None)
        else:
            cache[event_id] = _cache_entry(item)
    cache = _prune_cache(cache)
    _state_set(db, CACHE_KEY, account_id, json.dumps(cache))
    if next_sync:
        _state_set(db, SYNC_KEY, account_id, next_sync)
    return len(items)


def overlay_events(db, account_id=None):
    # type: (object, object) -> list
    """The cached external Google events for the /calendar overlay
    (read-only; empty when not connected/synced)."""
    account_id = _resolve_account(account_id)
    return list(_load_cache(db, account_id).values())


# ------------------------------------------------------------ retry pass

def retry_unsynced(db, account_id=None, limit=RETRY_BATCH):
    # type: (object, object, int) -> int
    """The worker's app->Google catch-up: appointment/scheduled rows with
    no gcal_event_id (a silent-degrade insert failure, or scheduled while
    disconnected) get their event written now. Only future appointments
    and the last RETRY_LOOKBACK_HOURS are pushed — connecting Google never
    floods the calendar with ancient history. Rows created within the
    last RETRY_MIN_AGE_MINUTES are skipped: the interactions post-commit
    insert may still be in flight for them, and racing it would create a
    duplicate event. Titles reflect the current outcome (check/cross
    prefix). Returns events created."""
    account_id = _resolve_account(account_id)
    if not is_connected(db, account_id):
        return 0
    now = datetime.datetime.now(datetime.timezone.utc)
    floor = (now - datetime.timedelta(hours=RETRY_LOOKBACK_HOURS)
             ).isoformat(timespec="seconds")
    created_before = (now - datetime.timedelta(minutes=RETRY_MIN_AGE_MINUTES)
                      ).isoformat(timespec="seconds")
    rows = db.execute(
        "SELECT i.id, i.lead_id, i.appointment_at, "
        "l.first_name, l.last_name "
        "FROM interactions i JOIN leads l ON l.id = i.lead_id "
        "WHERE i.account_id = ? AND i.itype = 'appointment' "
        "AND i.disposition = 'scheduled' AND i.gcal_event_id IS NULL "
        "AND i.appointment_at IS NOT NULL AND i.appointment_at >= ? "
        "AND i.created_at <= ? "
        # T1: never push an appointment that has since been cancelled or
        # rescheduled — the catch-up pass would put a dead appointment on
        # the calendar (a cancel that DID have an event keeps its
        # gcal_event_id, so this clause is what covers the rest).
        "AND NOT EXISTS (SELECT 1 FROM interactions o "
        "                WHERE o.parent_id = i.id "
        "                AND o.disposition IN ('cancelled','rescheduled')) "
        "ORDER BY i.appointment_at LIMIT ?",
        (account_id, floor, created_before, limit)).fetchall()
    pushed = 0
    for row in rows:
        name = ("%s %s" % (row["first_name"] or "", row["last_name"] or "")
                ).strip() or ("Lead #%d" % row["lead_id"])
        outcome_row = db.execute(
            "SELECT disposition FROM interactions WHERE parent_id = ? "
            "AND disposition IN ('showed','no_show') "
            "ORDER BY id DESC LIMIT 1", (row["id"],)).fetchone()
        outcome = outcome_row["disposition"] if outcome_row else None
        try:
            event_id = insert_event(
                db, account_id,
                event_title(name, outcome=outcome),
                row["appointment_at"],
                description=lead_link(db, row["lead_id"],
                                      account_id=account_id))
        except GcalError as exc:
            logger.warning("gcal retry insert failed (interaction %s): %s",
                           row["id"], exc)
            continue
        db.execute("UPDATE interactions SET gcal_event_id = ? WHERE id = ?",
                   (event_id, row["id"]))
        db.commit()
        pushed += 1
    return pushed
