"""VA pay tracking (SPEC B6; versioned rates per SPEC R6).

All attribution comes from interactions, per user_id, bucketed by day in
my_timezone. Money is computed in cents (ints); rates live in the pay_rates
table (cents columns), one row per effective_date. Each day is priced at
the rate row active THAT day (max effective_date <= day) — mid-period rate
changes never reprice earlier days; period totals sum the per-day results.

Per day: leads worked = DISTINCT leads with a call interaction by that VA;
the daily base is earned on days worked >= that day's floor_leads; plus the
send-options bonus x answered_send_options calls, scheduled/showed bonuses
per appointment outcome, and the sold bonus x sold_credit rows (see
interactions.on_lead_sold) — each priced at the interaction's own
created_at day (my_timezone).

The pay week is Fri-Thu (R6): week_bounds returns the most recent Friday
through the following Thursday.
"""
import datetime
import logging
from zoneinfo import ZoneInfo

logger = logging.getLogger("leadflow.pay")

# Fallback rates (cents) when no pay_rates row exists yet — matches the
# seeded defaults (migration 6 / seed.py).
DEFAULT_RATES = {
    "daily_base": 2000,
    "floor_leads": 125,
    "send_options": 250,
    "appt_scheduled": 250,
    "appt_showed": 500,
    "sold_bonus": 1000,
}


def _my_zone(db):
    from leadflow.settings import get_setting
    try:
        return ZoneInfo(get_setting("my_timezone", db=db))
    except Exception:
        return ZoneInfo("America/New_York")


def _local_today(db):
    return datetime.datetime.now(datetime.timezone.utc).astimezone(
        _my_zone(db)).date().isoformat()


def current_rate_row(db, on_date=None, user_id=None):
    # type: (object, object, object) -> object
    """The pay_rates row effective on on_date (default: today in
    my_timezone). S2 resolution: the newest (account, user_id) row with
    effective_date <= on_date when user_id is given and one exists, else
    the newest tenant-default row (user_id NULL). None when the table is
    empty (fresh installs seed one default row, so that is exceptional)."""
    from leadflow.auth import current_account_id
    account_id = current_account_id()
    if on_date is None:
        on_date = _local_today(db)
    if user_id is not None:
        row = db.execute(
            "SELECT * FROM pay_rates WHERE account_id = ? AND user_id = ? "
            "AND effective_date <= ? ORDER BY effective_date DESC, id DESC "
            "LIMIT 1", (account_id, user_id, on_date)).fetchone()
        if row is not None:
            return row
    return db.execute(
        "SELECT * FROM pay_rates WHERE account_id = ? AND user_id IS NULL "
        "AND effective_date <= ? ORDER BY effective_date DESC, id DESC "
        "LIMIT 1", (account_id, on_date)).fetchone()


def _rates_from_row(row):
    # type: (object) -> dict
    return {
        "daily_base": row["daily_base_cents"],
        "floor_leads": row["floor_leads"],
        "send_options": row["send_options_cents"],
        "appt_scheduled": row["appt_scheduled_cents"],
        "appt_showed": row["appt_showed_cents"],
        "sold_bonus": row["sold_bonus_cents"],
    }


def rates(db, user_id=None):
    # type: (object, object) -> dict
    """The CURRENT effective pay rates, in cents (per-VA override when
    user_id is given and an override row exists, S2). Display/settings
    only — reports price each day at its own row (R6)."""
    row = current_rate_row(db, user_id=user_id)
    if row is None:
        return dict(DEFAULT_RATES)
    return _rates_from_row(row)


def week_bounds(db, ref_date=None):
    # type: (object, object) -> tuple
    """(friday_iso, thursday_iso) of the Fri-Thu pay week (SPEC R6)
    containing ref_date (default: today in my_timezone): the most recent
    Friday through the following Thursday. If ref_date IS a Friday the week
    starts that day."""
    if ref_date is None:
        ref_date = datetime.datetime.now(datetime.timezone.utc).astimezone(
            _my_zone(db)).date()
    elif isinstance(ref_date, str):
        ref_date = datetime.date.fromisoformat(ref_date)
    friday = ref_date - datetime.timedelta(
        days=(ref_date.weekday() - 4) % 7)  # Mon=0 .. Fri=4
    thursday = friday + datetime.timedelta(days=6)
    return friday.isoformat(), thursday.isoformat()


def _utc_window(db, start_date, end_date):
    """UTC ISO bounds covering [start_date .. end_date] in my_timezone."""
    zone = _my_zone(db)
    start = datetime.date.fromisoformat(start_date)
    end = datetime.date.fromisoformat(end_date)
    start_dt = datetime.datetime(start.year, start.month, start.day,
                                 tzinfo=zone)
    end_dt = datetime.datetime(end.year, end.month, end.day,
                               tzinfo=zone) + datetime.timedelta(days=1)
    return (start_dt.astimezone(datetime.timezone.utc).isoformat(
                timespec="seconds"),
            end_dt.astimezone(datetime.timezone.utc).isoformat(
                timespec="seconds"))


def _local_date(created_at, zone):
    dt = datetime.datetime.fromisoformat(
        str(created_at).replace("Z", "+00:00"))
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=datetime.timezone.utc)
    return dt.astimezone(zone).date().isoformat()


def report(db, user_id, start_date, end_date):
    # type: (object, int, str, str) -> dict
    """Pay breakdown for one user over [start_date .. end_date] inclusive
    (YYYY-MM-DD, my_timezone days).

    Returns {"days": [day rows with counts + cents + that day's "rates"],
    "totals": {...}, "current_rates": rates(db)} ("rates" is kept as an
    alias of current_rates for shared display code). Each day is priced at
    the pay_rates row active that day (R6); days with no attributable
    interactions are omitted; all money values are cents (ints)."""
    from leadflow.auth import current_account_id
    account_id = current_account_id()
    zone = _my_zone(db)
    start_utc, end_utc = _utc_window(db, start_date, end_date)

    # R6: per-day rate lookup — all rows once, then max effective_date <=
    # day. S2: the VA's own override rows (user_id match) beat the tenant
    # default rows (user_id NULL) for any day an override is effective.
    rate_rows = db.execute(
        "SELECT * FROM pay_rates WHERE account_id = ? "
        "AND (user_id IS NULL OR user_id = ?) "
        "ORDER BY effective_date, id", (account_id, user_id)).fetchall()

    def rates_for(day):
        picked_user = None
        picked_default = None
        for rate_row in rate_rows:
            if rate_row["effective_date"] > day:
                break
            if rate_row["user_id"] is not None:
                picked_user = rate_row
            else:
                picked_default = rate_row
        picked = picked_user if picked_user is not None else picked_default
        if picked is None:
            return dict(DEFAULT_RATES)
        return _rates_from_row(picked)

    per_day = {}

    def day(d):
        if d not in per_day:
            per_day[d] = {"lead_ids": set(), "send_options": 0,
                          "appt_scheduled": 0, "appt_showed": 0, "sold": 0}
        return per_day[d]

    rows = db.execute(
        "SELECT itype, disposition, lead_id, created_at FROM interactions "
        "WHERE account_id = ? AND user_id = ? "
        "AND created_at >= ? AND created_at < ? "
        "AND (itype IN ('call', 'sold_credit') OR (itype = 'appointment' "
        "     AND disposition IN ('scheduled', 'showed')))",
        (account_id, user_id, start_utc, end_utc)).fetchall()
    for row in rows:
        d = day(_local_date(row["created_at"], zone))
        if row["itype"] == "call":
            d["lead_ids"].add(row["lead_id"])
            if row["disposition"] == "answered_send_options":
                d["send_options"] += 1
        elif row["itype"] == "appointment":
            if row["disposition"] == "scheduled":
                d["appt_scheduled"] += 1
            else:
                d["appt_showed"] += 1
        else:  # sold_credit
            d["sold"] += 1

    # OVERFLOW POOL work counts toward the daily LEAD FLOOR. Those calls
    # cannot live in `interactions` — its lead_id points at `leads` and a
    # pool row is not a lead — so they are counted from the pool's own
    # attempt log and folded into the same per-day lead count.
    #
    # It is the floor they affect, deliberately, and nothing else: the
    # pool exists precisely so a VA has a full day's calling on day one,
    # and a floor they cannot reach because their queue was backfilled
    # would dock their base pay for the tenant's cold start. The per-
    # outcome BONUSES stay lead-only — a bonus is paid on a real
    # pipeline event, and an overflow row that produced one has been
    # promoted into a lead, so the bonus arrives through `interactions`
    # on the promoted lead like any other.
    #
    # `lead_ids` is a set of lead ids, so overflow ids are namespaced
    # ("overflow:7") before being added — a pool row and a lead sharing
    # an integer id must never collapse into one worked lead.
    # Attempts MIRRORED AS A CALL are excluded, and that is not a
    # rounding decision: those promote by writing a `call` row on the new
    # lead, so the same conversation already arrives above and counting
    # the attempt too would credit one call as two leads worked. A heat
    # level (mirrors as a text_log) and appointment_set (mirrors as
    # nothing) are NOT excluded — the loop above counts only `call` rows,
    # so their floor credit has to come from the pool side or the VA
    # loses it for a call they really made.
    from leadflow.overflow import _mirrored_as_call
    mirrored = _mirrored_as_call()
    marks = ",".join("?" for _ in mirrored)
    for r in db.execute(
            "SELECT overflow_id, created_at FROM overflow_attempts "
            "WHERE account_id = ? AND user_id = ? "
            "AND created_at >= ? AND created_at < ? "
            "AND disposition NOT IN (%s)" % marks,
            (account_id, user_id, start_utc, end_utc)
            + tuple(mirrored)).fetchall():
        day(_local_date(r["created_at"], zone))["lead_ids"].add(
            "overflow:%s" % r["overflow_id"])

    days = []
    totals = {"leads_worked": 0, "base_days": 0, "base_cents": 0,
              "send_options": 0, "send_options_cents": 0,
              "appt_scheduled": 0, "appt_scheduled_cents": 0,
              "appt_showed": 0, "appt_showed_cents": 0,
              "sold": 0, "sold_cents": 0, "total_cents": 0}
    for d in sorted(per_day):
        bucket = per_day[d]
        r = rates_for(d)  # that day's rates (R6) — never a later row's
        leads_worked = len(bucket["lead_ids"])
        base_earned = leads_worked >= r["floor_leads"]
        row = {
            "date": d,
            "rates": r,
            "leads_worked": leads_worked,
            "base_earned": base_earned,
            "base_cents": r["daily_base"] if base_earned else 0,
            "send_options": bucket["send_options"],
            "send_options_cents": bucket["send_options"] * r["send_options"],
            "appt_scheduled": bucket["appt_scheduled"],
            "appt_scheduled_cents":
                bucket["appt_scheduled"] * r["appt_scheduled"],
            "appt_showed": bucket["appt_showed"],
            "appt_showed_cents": bucket["appt_showed"] * r["appt_showed"],
            "sold": bucket["sold"],
            "sold_cents": bucket["sold"] * r["sold_bonus"],
        }
        row["total_cents"] = (row["base_cents"] + row["send_options_cents"]
                              + row["appt_scheduled_cents"]
                              + row["appt_showed_cents"] + row["sold_cents"])
        days.append(row)
        totals["leads_worked"] += leads_worked
        totals["base_days"] += 1 if base_earned else 0
        for key in ("base_cents", "send_options", "send_options_cents",
                    "appt_scheduled", "appt_scheduled_cents", "appt_showed",
                    "appt_showed_cents", "sold", "sold_cents", "total_cents"):
            totals[key] += row[key]

    current = rates_for(_local_today(db))
    # "rates" stays as an alias of current_rates: the shared pay_breakdown
    # macro (today.html tally + period summaries) reads report.rates for its
    # display labels; the cents totals are exact per-day sums regardless.
    return {"days": days, "totals": totals, "current_rates": current,
            "rates": current, "start_date": start_date,
            "end_date": end_date}
