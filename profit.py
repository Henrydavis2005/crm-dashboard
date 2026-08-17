"""VA profitability (SPEC S6): per-VA net profit + ramp view. Admin-only.

Commission attribution — ONE VA per APPROVED sale, full commission:
1. The lead's sold_credit interactions row (VA-sourced marker, written by
   interactions.on_lead_sold) takes precedence — its user gets full credit.
2. Otherwise the user who logged the EARLIEST qualifying interaction on
   the lead — qualifying = a call with disposition answered_send_options
   or an appointment/scheduled row. System-logged rows (user_id NULL)
   never attribute; the earliest USER-logged qualifying row wins.
3. No qualifying user -> the sale is unattributed and lands in the
   "House" row (commission the business earned without a creditable VA).
An attribution that is not a VA of the account lands in House too: SPEC B6
credits the earliest qualifying logger WHATEVER THE ROLE, so the ADMIN who
works a lead themselves holds its sold_credit — and this page has no row
for an admin (one row per VA, plus House). Without that fall-through the
commission matched no row at all and disappeared from the page, which for
a solo agent is the normal case, not an edge one.
AGENT LEADS COUNT HERE, IN FULL AND UNCHANGED. This page's inputs are
commission, variable pay and prorated fixed cost — lead cost is not one of
them (the only cost_cents on this page is CALL spend), so a source_agent
lead flows through every calculation exactly like a bought one. That means
a VA who works many agent leads reads as LESS profitable, because half a
commission against a full day's pay genuinely IS less profitable. THAT IS
ACCURATE, NOT A BUG. Do not add an imputed lead cost to compensate, and do
not add a revenue-only mode. (/stats is the opposite call: agent leads are
excluded there, because that page asks about lead economics and these
leads cost nothing.)

Sales are counted in the period they were RESOLVED (sales.resolved_at,
my_timezone day): approved sales carry their commission; denied sales
enter only the approval-rate denominator. Pending sales appear nowhere
(no resolved_at yet).

Fixed-cost proration (users.fixed_monthly_cost_cents, NULL -> $0):
daily = monthly x 12 / 365.25 (rounded to a cent); weekly = daily x 7;
the month view charges the actual monthly figure. The full period figure
is charged regardless of started_on — proration by hire date only shows
up in the ramp view, which starts at started_on.

NO TELEPHONY COST TERM. Net profit = commission - variable pay - fixed
cost. The app placed and costed its own calls through Twilio until the
calling system was removed; dialing now happens in Ringy, outside Ancora,
so there is no price for this module to read. A carried-forward $0.00 call
column would have understated the true cost of a VA on every row, so the
term was removed rather than zeroed. A tenant who wants Ringy's cost in the
P&L puts it in that VA's `fixed_monthly_cost_cents`, which is prorated here.

started_on defaults to the user's created_at date (my_timezone) when NULL.
All money in cents; every query account-scoped.
"""
import datetime
import logging

from leadflow import pay
from leadflow.interactions import ANSWERED_DISPOSITIONS
from leadflow.pay import _local_date, _my_zone, _utc_window, week_bounds

logger = logging.getLogger("leadflow.profit")

RAMP_MAX_WEEKS = 26  # ramp view cap: first 26 Fri-Thu weeks since started_on


def _account():
    from leadflow.auth import current_account_id  # deferred: avoid cycles
    return current_account_id()


def _rate(n, d):
    return (100.0 * n / d) if d else None


def month_bounds(db, ref_date=None):
    # type: (object, object) -> tuple
    """(first_iso, last_iso) of the calendar month containing ref_date
    (default: today in my_timezone)."""
    if ref_date is None:
        ref_date = datetime.datetime.now(datetime.timezone.utc).astimezone(
            _my_zone(db)).date()
    elif isinstance(ref_date, str):
        ref_date = datetime.date.fromisoformat(ref_date)
    first = ref_date.replace(day=1)
    if first.month == 12:
        nxt = first.replace(year=first.year + 1, month=1)
    else:
        nxt = first.replace(month=first.month + 1)
    last = nxt - datetime.timedelta(days=1)
    return first.isoformat(), last.isoformat()


def daily_fixed_cents(monthly_cents):
    # type: (int) -> int
    """S6 proration: daily fixed = monthly x 12 / 365.25, rounded."""
    return int(round((monthly_cents or 0) * 12 / 365.25))


def fixed_for_period(monthly_cents, period):
    # type: (int, str) -> int
    """Prorated fixed cost for 'today' | 'week' | 'month'."""
    monthly_cents = monthly_cents or 0
    if period == "today":
        return daily_fixed_cents(monthly_cents)
    if period == "week":
        return daily_fixed_cents(monthly_cents) * 7
    if period == "month":
        return monthly_cents  # the actual monthly figure
    raise ValueError("unknown period: %s" % period)


def effective_started_on(db, user):
    # type: (object, object) -> str
    """users.started_on, defaulting to the created_at date (my_timezone)."""
    if user["started_on"]:
        return user["started_on"]
    return _local_date(user["created_at"], _my_zone(db))


def attribute_sale(db, lead_id):
    # type: (object, int) -> object
    """The user_id credited with the lead's sale, or None (House)."""
    account_id = _account()
    credit = db.execute(
        "SELECT user_id FROM interactions WHERE account_id = ? "
        "AND lead_id = ? AND itype = 'sold_credit' AND user_id IS NOT NULL "
        "ORDER BY created_at, id LIMIT 1", (account_id, lead_id)).fetchone()
    if credit is not None:
        return credit["user_id"]
    earliest = db.execute(
        "SELECT user_id FROM interactions WHERE account_id = ? "
        "AND lead_id = ? AND user_id IS NOT NULL AND ("
        " (itype = 'call' AND disposition = 'answered_send_options') OR"
        " (itype = 'appointment' AND disposition = 'scheduled')) "
        "ORDER BY created_at, id LIMIT 1", (account_id, lead_id)).fetchone()
    return earliest["user_id"] if earliest is not None else None


def va_ids(db):
    # type: (object) -> set
    """Every VA user id of the account — disabled ones included, they have
    history. The /profit tables are one row per VA plus House, so this is
    exactly the set of attributions that HAVE a row of their own."""
    return set(row["id"] for row in db.execute(
        "SELECT id FROM users WHERE role = 'va' AND account_id = ?",
        (_account(),)).fetchall())


def resolved_sales(db):
    # type: (object) -> list
    """Every RESOLVED sale of the account, attributed: [{user_id (or
    None), status, commission_cents, resolved_on (local date)}].

    An attribution that is not a VA of this account is normalised to None
    (House). B6 credits admins like VAs, and this page renders no admin
    row, so the alternative is money that appears nowhere."""
    zone = _my_zone(db)
    vas = va_ids(db)
    out = []
    for sale in db.execute(
            "SELECT * FROM sales WHERE account_id = ? "
            "AND resolved_at IS NOT NULL ORDER BY resolved_at, id",
            (_account(),)).fetchall():
        user_id = attribute_sale(db, sale["lead_id"])
        if user_id is not None and user_id not in vas:
            user_id = None  # -> House: no creditable VA
        out.append({
            "user_id": user_id,
            "status": sale["status"],
            "commission_cents": sale["commission_cents"] or 0,
            "resolved_on": _local_date(sale["resolved_at"], zone),
        })
    return out


def _sales_slice(attributed, user_id, start, end):
    """Approved/denied counts + commission for one attribution bucket
    (user_id None = House) over [start .. end] local days."""
    approved = denied = commission = 0
    for s in attributed:
        if s["user_id"] != user_id:
            continue
        if not (start <= s["resolved_on"] <= end):
            continue
        if s["status"] == "approved":
            approved += 1
            commission += s["commission_cents"]
        elif s["status"] == "denied":
            denied += 1
    return {"sales": approved, "approved": approved, "denied": denied,
            "approval_rate": _rate(approved, approved + denied),
            "commission_cents": commission}


def _activity(db, user_id, start, end):
    """Call/appointment counters for one VA over [start .. end]."""
    start_utc, end_utc = _utc_window(db, start, end)
    lead_ids = set()
    calls = answered = appts = showed = 0
    for row in db.execute(
            "SELECT itype, disposition, lead_id FROM interactions "
            "WHERE account_id = ? AND user_id = ? "
            "AND created_at >= ? AND created_at < ? "
            "AND itype IN ('call', 'appointment')",
            (_account(), user_id, start_utc, end_utc)).fetchall():
        if row["itype"] == "call":
            calls += 1
            lead_ids.add(row["lead_id"])
            # C1: "answered" is the disposition set that means a human
            # picked up (the three new outcomes do not share the
            # answered_ prefix, so the old startswith test would have
            # silently undercounted the contact rate).
            if row["disposition"] in ANSWERED_DISPOSITIONS:
                answered += 1
        else:
            if row["disposition"] == "scheduled":
                appts += 1
            elif row["disposition"] == "showed":
                showed += 1
    return {"leads_worked": len(lead_ids), "calls": calls,
            "answered": answered, "contact_rate": _rate(answered, calls),
            "appts_scheduled": appts, "appts_showed": showed}


def period_row(db, user, start, end, fixed_cents, attributed):
    # type: (object, object, str, str, int, list) -> dict
    """One VA x one period: activity + pay + attributed sales + net.

    NO TELEPHONY TERM. The app placed and costed its own calls until the
    calling system was removed; dialing now happens in Ringy, outside
    Ancora, which never sees a price. Rather than carry a column that
    would read $0.00 forever and quietly understate the true cost of a
    VA, the term is gone: net = commission - variable pay - fixed cost.
    A tenant who wants Ringy's cost in the P&L puts it in that VA's
    `fixed_monthly_cost_cents`, which is prorated here already."""
    row = _activity(db, user["id"], start, end)
    row.update(_sales_slice(attributed, user["id"], start, end))
    row["variable_cents"] = pay.report(
        db, user["id"], start, end)["totals"]["total_cents"]
    row["fixed_cents"] = fixed_cents
    row["net_cents"] = (row["commission_cents"] - row["variable_cents"]
                        - row["fixed_cents"])
    return row


def house_row(attributed, start, end):
    """The unattributed ("House") bucket for one period: sales resolved
    with no creditable VA.

    It used to carry a second half — the call spend belonging to nobody on
    the VA table, which on a single-agent tenant was the owner's own
    dialing. That half is gone with the telephony term (see period_row):
    Ancora no longer sees a call price. The bucket still earns its place,
    because a sale with no creditable VA is real commission that must not
    silently attach itself to someone. No pay or fixed cost applies here;
    net is simply that commission."""
    row = _sales_slice(attributed, None, start, end)
    row["net_cents"] = row["commission_cents"]
    return row


def dashboard(db):
    # type: (object) -> dict
    """Everything GET /profit renders: per-VA rows for Today / This week
    (Fri-Thu) / This month, House rows, and the month leaderboard."""
    today = pay._local_today(db)
    week = week_bounds(db)
    month = month_bounds(db)
    periods = {"today": (today, today), "week": week, "month": month}

    vas = db.execute(
        "SELECT * FROM users WHERE role = 'va' AND account_id = ? "
        "ORDER BY enabled DESC, username COLLATE NOCASE",
        (_account(),)).fetchall()
    attributed = resolved_sales(db)

    rows = []
    for user in vas:
        monthly = user["fixed_monthly_cost_cents"] or 0
        rows.append({
            "user": user,
            "started_on": effective_started_on(db, user),
            "today": period_row(db, user, today, today,
                                fixed_for_period(monthly, "today"),
                                attributed),
            "week": period_row(db, user, week[0], week[1],
                               fixed_for_period(monthly, "week"),
                               attributed),
            "month": period_row(db, user, month[0], month[1],
                                fixed_for_period(monthly, "month"),
                                attributed),
        })

    house = {}
    for name, (start, end) in periods.items():
        house[name] = house_row(attributed, start, end)
    leaderboard = sorted(rows, key=lambda r: r["month"]["net_cents"],
                         reverse=True)
    return {"periods": periods, "vas": rows, "house": house,
            "leaderboard": leaderboard}


def newest_va(db):
    """The default ramp VA: the newest start date (ties -> highest id)."""
    vas = db.execute(
        "SELECT * FROM users WHERE role = 'va' AND account_id = ?",
        (_account(),)).fetchall()
    if not vas:
        return None
    return max(vas, key=lambda u: (effective_started_on(db, u), u["id"]))


def ramp(db, user):
    # type: (object, object) -> dict
    """S6 ramp view: one row per Fri-Thu week since started_on (first
    RAMP_MAX_WEEKS weeks; capped flag set when the VA is older than
    that), each with commission / variable pay / weekly fixed / net —
    time-to-profitability week by week."""
    started = effective_started_on(db, user)
    attributed = resolved_sales(db)
    weekly_fixed = daily_fixed_cents(user["fixed_monthly_cost_cents"]) * 7
    first_friday = datetime.date.fromisoformat(week_bounds(db, started)[0])
    current_friday = datetime.date.fromisoformat(week_bounds(db)[0])
    n_weeks = (current_friday - first_friday).days // 7 + 1
    capped = n_weeks > RAMP_MAX_WEEKS
    weeks = []
    for i in range(min(n_weeks, RAMP_MAX_WEEKS)):
        start = (first_friday + datetime.timedelta(weeks=i)).isoformat()
        end = (first_friday
               + datetime.timedelta(weeks=i, days=6)).isoformat()
        slice_ = _sales_slice(attributed, user["id"], start, end)
        variable = pay.report(db, user["id"], start, end)[
            "totals"]["total_cents"]
        weeks.append({
            "week_no": i + 1, "start": start, "end": end,
            "commission_cents": slice_["commission_cents"],
            "variable_cents": variable,
            "fixed_cents": weekly_fixed,
            "net_cents": (slice_["commission_cents"] - variable
                          - weekly_fixed),
        })
    return {"user": user, "started_on": started, "weeks": weeks,
            "capped": capped, "max_weeks": RAMP_MAX_WEEKS}
