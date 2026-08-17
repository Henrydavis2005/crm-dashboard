"""VA calling-integrity metrics.

Calls are SELF-REPORTED now. Ancora placed and timed its own calls until
the internal calling system was removed; dialing happens in Ringy, so the
only record this app has of a call is the attempt a VA chose to log. That
changes what analytics are for: not "how long were you on the phone" (a
question this app can no longer answer) but "does this logging pattern look
like someone working, and has it changed".

WEEK BOUNDARIES: Friday 00:00 to Thursday 23:59:59 in the account's
`my_timezone` — the SAME Fri-Thu week `pay.week_bounds` already defines for
the pay period and the ramp view. One week definition in the app, not two.
A week is COMPLETED once its Thursday has passed.

THE DRIFT BASIS is the ROLLING MEDIAN of the prior 6 COMPLETED weeks, per
metric — not the first week, not the best week. Those two are rendered
alongside as reference context only, because a VA's first week is a ramp
artefact and their best week is a survivorship artefact; comparing against
either punishes normal variance. Six completed weeks of history are
required, so the first real comparison appears in WEEK 7.

NO COMPOSITE SCORE. There is deliberately no 1-10 number here. A single
score invites managing to the score; the component metrics each say
something specific and are shown on their own.

THE VA SEES EXACTLY WHAT THE ADMIN SEES. `for_user` is the single
computation; /profit renders every VA through it and /pay/statement renders
the signed-in VA through the same function with the same arguments. There
is no hidden field and no admin-only column.
"""
import datetime
import logging

from leadflow.interactions import (
    ANSWERED_DISPOSITIONS, CALL_DISPOSITION_LABELS,
    LEGACY_CALL_DISPOSITION_LABELS,
)
from leadflow.pay import _my_zone, _utc_window, week_bounds

logger = logging.getLogger("leadflow.integrity")

# Completed weeks of history the rolling median needs before any drift
# comparison is shown. The first comparison therefore lands in week 7.
BASELINE_WEEKS = 6

# Below this many logged attempts in a week, every drift flag is suppressed
# and the UI says so: a light week produces wild percentages that mean
# nothing.
MIN_WEEK_ATTEMPTS = 50

# "Logged quicker than a real call could plausibly have happened."
RAPID_SECONDS = 30

# Metrics where a RISE is the bad direction. The drift badge colours on
# meaning, not on sign: more sub-30-second logging is worse, not better.
HIGHER_IS_WORSE = ("rapid_attempts",)

# How far back to look for six WORKED weeks. A VA who took a week off must
# not be stuck on "comparison starts in week 7" forever, which is what
# demanding six CONSECUTIVE worked weeks did.
BASELINE_LOOKBACK_WEEKS = 26

# The metrics the drift comparison runs over.
DRIFT_FIELDS = (
    "attempts",
    "contact_rate",
    "median_gap_seconds",
    "rapid_attempts",
    "appts_per_100",
)

_LABELS = dict(CALL_DISPOSITION_LABELS + LEGACY_CALL_DISPOSITION_LABELS)


def _median(values):
    values = sorted(v for v in values if v is not None)
    if not values:
        return None
    mid = len(values) // 2
    if len(values) % 2:
        return float(values[mid])
    return (values[mid - 1] + values[mid]) / 2.0


def _rate(n, d):
    return (100.0 * n / d) if d else None


def _pct_deviation(current, baseline):
    """Percent deviation of `current` from `baseline`. None when there is
    no baseline or the baseline is zero — a change from nothing has no
    percentage, and saying "+infinity%" would be worse than saying
    nothing."""
    if current is None or baseline is None or not baseline:
        return None
    return 100.0 * (current - baseline) / baseline


def completed_weeks(db, count, before=None):
    """The `count` most recent COMPLETED Fri-Thu weeks, oldest first, as
    (start, end) ISO date pairs. A week is completed once its Thursday has
    passed in my_timezone."""
    today = datetime.datetime.now(datetime.timezone.utc).astimezone(
        _my_zone(db)).date() if before is None else before
    current_start = datetime.date.fromisoformat(
        week_bounds(db, today.isoformat())[0])
    out = []
    for i in range(count, 0, -1):
        start = current_start - datetime.timedelta(weeks=i)
        out.append((start.isoformat(),
                    (start + datetime.timedelta(days=6)).isoformat()))
    return out


def week_metrics(db, account_id, user_id, start, end):
    """Every component metric for ONE VA over ONE week.

    Reads `interactions` call rows only — the same rows the pay floor and
    the /profit contact rate already count. There is no second definition
    of "an attempt" in this app.
    """
    start_utc, end_utc = _utc_window(db, start, end)
    rows = db.execute(
        "SELECT disposition, created_at FROM interactions "
        "WHERE account_id = ? AND user_id = ? AND itype = 'call' "
        "AND created_at >= ? AND created_at < ? "
        "ORDER BY created_at, id",
        (account_id, user_id, start_utc, end_utc)).fetchall()

    attempts = len(rows)
    answered = sum(1 for r in rows if r["disposition"] in ANSWERED_DISPOSITIONS)

    # Gaps between CONSECUTIVE logged attempts, in seconds.
    stamps = []
    for r in rows:
        try:
            dt = datetime.datetime.fromisoformat(
                str(r["created_at"]).replace("Z", "+00:00"))
        except (ValueError, TypeError):
            continue
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=datetime.timezone.utc)
        stamps.append(dt)
    gaps = [int((stamps[i] - stamps[i - 1]).total_seconds())
            for i in range(1, len(stamps))]
    rapid = sum(1 for g in gaps if g < RAPID_SECONDS)

    # Disposition mix as percentages of this VA's logged dispositions.
    counts = {}
    for r in rows:
        key = r["disposition"] or "(none)"
        counts[key] = counts.get(key, 0) + 1
    mix = sorted(
        ({"disposition": k,
          "label": _LABELS.get(k, k),
          "count": v,
          "pct": _rate(v, attempts)} for k, v in counts.items()),
        key=lambda d: (-d["count"], d["disposition"]))

    appts = db.execute(
        "SELECT COUNT(*) AS c FROM interactions WHERE account_id = ? "
        "AND user_id = ? AND itype = 'appointment' "
        "AND disposition = 'scheduled' "
        "AND created_at >= ? AND created_at < ?",
        (account_id, user_id, start_utc, end_utc)).fetchone()["c"]

    return {
        "start": start,
        "end": end,
        "attempts": attempts,
        "answered": answered,
        "contact_rate": _rate(answered, attempts),
        "median_gap_seconds": _median(gaps),
        "rapid_attempts": rapid,
        "rapid_threshold": RAPID_SECONDS,
        "mix": mix,
        "appointments": appts,
        "appts_per_100": (100.0 * appts / attempts) if attempts else None,
        "thin": attempts < MIN_WEEK_ATTEMPTS,
    }


def for_user(db, account_id, user_id, before=None):
    """THE single computation, shared by /profit (admin, every VA) and
    /pay/statement (the VA, themselves). Same numbers either way.

    LIKE FOR LIKE. The current week is only PARTLY elapsed, so comparing it
    against six complete weeks would report a huge negative drift every
    Monday and a shrinking one all week — an artefact of the calendar, not
    of anyone's behaviour. Each baseline week is therefore truncated to the
    SAME number of elapsed days as the current one: on a Monday, days 1-4
    of the current week are compared against days 1-4 of each prior week.
    `days_elapsed` is reported so the UI can say what it is comparing.
    """
    today = datetime.datetime.now(datetime.timezone.utc).astimezone(
        _my_zone(db)).date() if before is None else before
    cur_start, cur_end = week_bounds(db, today.isoformat())
    # Clamp the current week to what has actually happened.
    cur_through = min(today, datetime.date.fromisoformat(cur_end))
    days_elapsed = (cur_through
                    - datetime.date.fromisoformat(cur_start)).days + 1
    current = week_metrics(db, account_id, user_id, cur_start,
                           cur_through.isoformat())
    current["days_elapsed"] = days_elapsed
    current["partial"] = days_elapsed < 7

    # Baselines truncated to the same elapsed slice, taken from the most
    # recent WORKED weeks within a wider lookback (a week off must not
    # freeze the baseline forever).
    history = []
    for start, _end in reversed(
            completed_weeks(db, BASELINE_LOOKBACK_WEEKS, before=today)):
        through = (datetime.date.fromisoformat(start)
                   + datetime.timedelta(days=days_elapsed - 1)).isoformat()
        w = week_metrics(db, account_id, user_id, start, through)
        w["days_elapsed"] = days_elapsed
        history.append(w)
        if len([x for x in history if x["attempts"] > 0]) >= BASELINE_WEEKS:
            break
    history.reverse()
    # Only weeks the VA actually worked count toward the baseline; a week
    # of zero attempts is absence, not a performance figure.
    worked = [w for w in history if w["attempts"] > 0][-BASELINE_WEEKS:]

    baseline = None
    drift = None
    baseline_note = None
    if len(worked) < BASELINE_WEEKS:
        baseline_note = ("Baseline builds over your first %d weeks — "
                         "comparison starts in week %d."
                         % (BASELINE_WEEKS, BASELINE_WEEKS + 1))
    elif current["thin"]:
        baseline_note = ("Fewer than %d logged attempts this week, so drift "
                         "flags are suppressed — a light week makes these "
                         "percentages meaningless."
                         % MIN_WEEK_ATTEMPTS)
        baseline = {f: _median([w[f] for w in worked]) for f in DRIFT_FIELDS}
    else:
        baseline = {f: _median([w[f] for w in worked]) for f in DRIFT_FIELDS}
        drift = {f: _pct_deviation(current[f], baseline[f])
                 for f in DRIFT_FIELDS}

    # REFERENCE CONTEXT ONLY — never the comparison basis. `first_week` is
    # the OLDEST worked week inside the lookback, which is the VA's first
    # week only if they started inside it; the label says "earliest on
    # record" rather than claiming more than that.
    all_worked = [w for w in history + [current] if w["attempts"] > 0]
    first_week = ([w for w in history if w["attempts"] > 0] or [None])[0]
    best_week = (max(all_worked, key=lambda w: w["attempts"])
                 if all_worked else None)

    return {
        "user_id": user_id,
        "current": current,
        "history": history,
        "baseline": baseline,
        "baseline_weeks": BASELINE_WEEKS,
        "baseline_note": baseline_note,
        "drift": drift,
        "drift_fields": DRIFT_FIELDS,
        "min_week_attempts": MIN_WEEK_ATTEMPTS,
        "first_week": first_week,
        "best_week": best_week,
        "higher_is_worse": HIGHER_IS_WORSE,
        "days_elapsed": days_elapsed,
    }


def dashboard(db, account_id, before=None):
    """Every VA of the account, each through `for_user`. Disabled VAs are
    included — they have history worth reading."""
    users = db.execute(
        "SELECT id, username FROM users WHERE account_id = ? AND role = 'va' "
        "ORDER BY enabled DESC, username COLLATE NOCASE",
        (account_id,)).fetchall()
    return [{"user": u,
             "metrics": for_user(db, account_id, u["id"], before=before)}
            for u in users]
