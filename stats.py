"""Lead statistics (SPEC R7): ROI math computed off sales x leads.

All aggregation happens here (routes_stats.py only renders) so the math is
unit-testable with plain fixtures. Conventions:

- "Non-referral leads" (referred_by IS NULL) are the denominator for every
  sale rate — referrals get no automated outreach, so they would distort
  the ROI of paid sources. The overall total-sales card counts EVERY sales
  row (referral clients included); the breakdown tables cover non-referral
  leads/sales only.
- Approval rate = approved / (approved + denied); pending sales are in
  sales counts and premium averages but not the approval rate.
- Commission totals/averages cover approved sales only.
- Lead age at sale = whole days received_at -> sold_at.
- Step attribution per sold lead: the sequence step of the LAST outbound
  sequence email sent before the lead's FIRST inbound message; leads with
  no inbound (or no prior sequence send) land in the "No email reply"
  bucket. Age/step tables have no sale-rate column (their cohorts are
  defined by the sale itself).
- C2a "Lost leads by reason" counts each lost non-referral lead ONCE, by
  the LOST_REASONS precedence (bad number > not qualified > not interested
  > other dead > other closed) — the signals overlap by design, so the
  precedence is what keeps the buckets summing to the total lost. A lead
  is LOST only while it is actually out of play (see `lost_leads`): the
  disposition/suppression buckets are intersected with the lost cohort, so
  a REOPENED lead leaves the table and a lead that was reopened and then
  SOLD is never both a sale and a loss. Counts only, no money.
- S5 ROI columns (spend / cost per sale / net ROI) cover ALL of a
  source's leads — referrals included (their snapshotted cost is real
  money spent) — while the RATE denominators above stay non-referral.
  spend = SUM(lead cost snapshots); cost per sale = spend / approved
  sales (None at zero approved sales); net ROI = approved commission
  - spend.

Money values are cents (render with the `money` filter). Rates are floats
0-100 or None when the denominator is empty.
"""
import datetime
import logging
from typing import Optional

logger = logging.getLogger("leadflow.stats")

AGE_BUCKETS = [
    ("0–1d", 0, 1),
    ("2–3d", 2, 3),
    ("4–7d", 4, 7),
    ("8–14d", 8, 14),
    ("15–30d", 15, 30),
    ("31+d", 31, None),
]

NO_REPLY_BUCKET = "No email reply"


def _parse_iso(value):
    # type: (object) -> Optional[datetime.datetime]
    if not value:
        return None
    try:
        dt = datetime.datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except (ValueError, TypeError):
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=datetime.timezone.utc)
    return dt


def _rate(n, d):
    return (100.0 * n / d) if d else None


def _agg(sales):
    """Shared per-bucket math over a list of sales rows/dicts."""
    approved = [s for s in sales if s["status"] == "approved"]
    denied = [s for s in sales if s["status"] == "denied"]
    premiums = [s["premium_cents"] for s in sales
                if s["premium_cents"] is not None]
    commissions = [s["commission_cents"] for s in approved
                   if s["commission_cents"] is not None]
    return {
        "sales": len(sales),
        "approved": len(approved),
        "denied": len(denied),
        "approval_rate": _rate(len(approved), len(approved) + len(denied)),
        "avg_premium": (sum(premiums) // len(premiums)) if premiums else None,
        "total_commission": sum(commissions),
        "avg_commission": (sum(commissions) // len(commissions))
        if commissions else None,
    }


def _account():
    from leadflow.auth import current_account_id  # deferred: avoid cycles
    return current_account_id()


def _sales_with_leads(db, non_referral_only=True):
    """The current account's sales rows joined to their lead's grouping
    columns.

    AGENT LEADS are excluded in BOTH branches, as a SEPARATE clause from
    the referral filter. They cost nothing by construction (cost_cents = 0)
    and pay half a commission, so leaving them in makes every cost-per-sale
    on this page divide a real spend by an inflated approved count. They
    are counted in full on /profit, where the question is VA economics
    rather than lead economics."""
    where = "AND l.referred_by IS NULL" if non_referral_only else ""
    return db.execute(
        "SELECT s.*, l.source_id, l.state AS lead_state, "
        "l.received_at AS lead_received_at, l.referred_by AS lead_referred_by "
        "FROM sales s JOIN leads l ON l.id = s.lead_id "
        "WHERE s.account_id = ? AND l.source_agent IS NULL " + where,
        (_account(),)).fetchall()


def _source_names(db):
    return {r["id"]: r["name"]
            for r in db.execute(
                "SELECT id, name FROM lead_sources WHERE account_id = ?",
                (_account(),))}

MANUAL_BUCKET = "Manual/none"


# ---------------------------------------------------------------- overview

def overview(db):
    account_id = _account()
    all_sales = db.execute("SELECT * FROM sales WHERE account_id = ?",
                           (account_id,)).fetchall()
    non_ref_leads = db.execute(
        "SELECT COUNT(*) AS c FROM leads WHERE account_id = ? "
        "AND referred_by IS NULL AND source_agent IS NULL",
        (account_id,)).fetchone()["c"]
    sold_non_ref = db.execute(
        "SELECT COUNT(*) AS c FROM sales s JOIN leads l ON l.id = s.lead_id "
        "WHERE s.account_id = ? AND l.referred_by IS NULL "
        "AND l.source_agent IS NULL",
        (account_id,)).fetchone()["c"]
    out = _agg(all_sales)
    out["total_sales"] = len(all_sales)
    out["non_referral_leads"] = non_ref_leads
    out["sold_non_referral"] = sold_non_ref
    out["sale_rate"] = _rate(sold_non_ref, non_ref_leads)
    # S5: overall spend covers EVERY lead's cost snapshot (referrals
    # included); net ROI = approved commission - spend.
    #
    # AGENT LEADS excluded. They are free by construction, so the SUM is
    # numerically unchanged today — the clause is here so it stays that way
    # if an agent lead ever acquires a nonzero cost, and so the spend base
    # and the sale-rate base above describe the SAME cohort. `all_sales`
    # above is deliberately NOT filtered: total sales and total commission
    # are money you actually made, agent lead or not.
    out["total_spend"] = db.execute(
        "SELECT COALESCE(SUM(COALESCE(cost_cents, 0)), 0) AS c "
        "FROM leads WHERE account_id = ? AND source_agent IS NULL",
        (account_id,)).fetchone()["c"]
    out["net_roi"] = out["total_commission"] - out["total_spend"]
    return out


# -------------------------------------------------------------- breakdowns

def _cohort_table(db, bucket_of):
    """Generic source/state style breakdown: cohort = non-referral leads,
    bucketed by `bucket_of(lead_row)`; sales joined per bucket."""
    buckets = {}
    order = []
    for lead in db.execute(
            "SELECT * FROM leads WHERE account_id = ? "
            "AND referred_by IS NULL AND source_agent IS NULL",
            (_account(),)).fetchall():
        key = bucket_of(lead)
        if key not in buckets:
            buckets[key] = {"leads": 0, "sales": []}
            order.append(key)
        buckets[key]["leads"] += 1
    for sale in _sales_with_leads(db):
        key = bucket_of(sale)
        if key not in buckets:  # sale on a lead outside the cohort snapshot
            buckets[key] = {"leads": 0, "sales": []}
            order.append(key)
        buckets[key]["sales"].append(sale)
    rows = []
    for key in sorted(order, key=lambda k: (k == MANUAL_BUCKET, str(k))):
        b = buckets[key]
        row = _agg(b["sales"])
        row["bucket"] = key
        row["leads"] = b["leads"]
        row["sale_rate"] = _rate(len(b["sales"]), b["leads"])
        rows.append(row)
    return rows


def by_source(db):
    names = _source_names(db)

    def bucket(row):
        sid = row["source_id"]
        return names.get(sid, MANUAL_BUCKET) if sid else MANUAL_BUCKET
    rows = _cohort_table(db, bucket)

    # ---------------------------------------------------------------
    # THE MONEY BASIS FOR THIS TABLE — read before changing anything here,
    # and match it in /profit's lead-spend line (proposals #8/#9).
    #
    #   MONEY columns (total commission, spend, cost per sale, net ROI):
    #       ALL leads attributed to the source, REFERRALS INCLUDED.
    #   RATE columns (leads, sale rate, approval rate, avg premium):
    #       NON-REFERRAL leads only — unchanged R7 semantics.
    #
    # This is the basis `overview()` already uses, so the source rows now
    # sum to the cards above them.
    #
    # It used to be mixed WITHIN the money columns: `total_commission` came
    # from the non-referral cohort while `spend` covered every lead, so a
    # source with any referral sale rendered COMMISSION − SPEND ≠ NET ROI.
    # The row is the number lead spend gets set from, and its arithmetic did
    # not check out on inspection. Both money terms now come from the same
    # accumulator below, and net ROI is computed FROM the commission the row
    # displays — so the identity is structural, not a coincidence.
    roi = {}

    def _roi(key):
        return roi.setdefault(key, {"spend": 0, "approved": 0,
                                    "commission": 0})
    # AGENT LEADS are excluded from BOTH halves of this accumulator (here,
    # and inside _sales_with_leads below). A free lead adds nothing to
    # `spend` but its sale WOULD add to `approved`, and cost_per_sale is
    # spend // approved — so leaving them in silently deflates the cost per
    # sale of whichever bucket they land in. There is no imputed cost and
    # no revenue-only mode: they are simply not part of lead economics.
    for lead in db.execute(
            "SELECT source_id, COALESCE(cost_cents, 0) AS cost "
            "FROM leads WHERE account_id = ? AND source_agent IS NULL",
            (_account(),)).fetchall():
        _roi(bucket(lead))["spend"] += lead["cost"]
    for sale in _sales_with_leads(db, non_referral_only=False):
        if sale["status"] != "approved":
            continue
        r = _roi(bucket(sale))
        r["approved"] += 1
        r["commission"] += sale["commission_cents"] or 0

    by_key = {r["bucket"]: r for r in rows}
    for key, r in roi.items():
        row = by_key.get(key)
        if row is None:  # source whose only leads are referrals
            row = _agg([])
            row["bucket"] = key
            row["leads"] = 0
            row["sale_rate"] = None
            rows.append(row)
        row["spend"] = r["spend"]
        row["cost_per_sale"] = ((r["spend"] // r["approved"])
                                if r["approved"] else None)
        # The displayed commission moves onto the money basis too, so the
        # column the owner reads and the column net ROI is derived from are
        # the same number.
        row["total_commission"] = r["commission"]
        row["net_roi"] = row["total_commission"] - row["spend"]
    for row in rows:  # cohort-only buckets (all leads cost NULL -> 0 spend)
        row.setdefault("spend", 0)
        row.setdefault("cost_per_sale", None)
        row.setdefault("net_roi", row.get("total_commission", 0))
    rows.sort(key=lambda r: (r["bucket"] == MANUAL_BUCKET, str(r["bucket"])))
    return rows


def by_state(db):
    def bucket(row):
        try:
            state = row["lead_state"]
        except (KeyError, IndexError):
            state = row["state"]
        return (state or "").strip().upper() or "—"
    return _cohort_table(db, bucket)


def _age_bucket(received_at, sold_at):
    r = _parse_iso(received_at)
    s = _parse_iso(sold_at)
    if r is None or s is None:
        return None
    days = max((s - r).days, 0)
    for label, lo, hi in AGE_BUCKETS:
        if days >= lo and (hi is None or days <= hi):
            return label
    return AGE_BUCKETS[-1][0]


def by_age(db):
    """Sold non-referral leads bucketed by whole-day age at sale."""
    buckets = {label: [] for label, _lo, _hi in AGE_BUCKETS}
    for sale in _sales_with_leads(db):
        label = _age_bucket(sale["lead_received_at"], sale["sold_at"])
        if label is not None:
            buckets[label].append(sale)
    rows = []
    for label, _lo, _hi in AGE_BUCKETS:
        sales = buckets[label]
        if not sales:
            continue
        row = _agg(sales)
        row["bucket"] = label
        rows.append(row)
    return rows


def _step_bucket(db, lead_id):
    """The sequence step (day offset) credited with producing the reply."""
    first_in = db.execute(
        "SELECT MIN(created_at) AS t FROM messages "
        "WHERE lead_id = ? AND direction = 'in'", (lead_id,)).fetchone()["t"]
    if not first_in:
        return NO_REPLY_BUCKET
    row = db.execute(
        "SELECT st.day_offset AS day_offset FROM messages m "
        "JOIN sequence_steps st ON st.id = m.step_id "
        "WHERE m.lead_id = ? AND m.direction = 'out' AND m.status = 'sent' "
        "AND m.step_id IS NOT NULL AND COALESCE(m.sent_at, m.created_at) < ? "
        "ORDER BY COALESCE(m.sent_at, m.created_at) DESC, m.id DESC LIMIT 1",
        (lead_id, first_in)).fetchone()
    if row is None:
        return NO_REPLY_BUCKET
    return "Day %d email" % row["day_offset"]


def by_step(db):
    """Sold non-referral leads by the sequence step producing the reply."""
    buckets = {}
    for sale in _sales_with_leads(db):
        label = _step_bucket(db, sale["lead_id"])
        buckets.setdefault(label, []).append(sale)

    def sort_key(label):
        if label == NO_REPLY_BUCKET:
            return (1, 0)
        try:
            return (0, int(label.split()[1]))
        except (IndexError, ValueError):
            return (0, 0)
    rows = []
    for label in sorted(buckets, key=sort_key):
        row = _agg(buckets[label])
        row["bucket"] = label
        rows.append(row)
    return rows


# ------------------------------------------------------------ lost leads

# C2a: the loss reasons, in PRECEDENCE order. A lead can carry more than one
# signal (a not_qualified disposition also writes closed_state='dead'; a
# not-interested suppression can precede either), so each lead is counted
# EXACTLY ONCE, in the first bucket it matches:
#   1. bad number    — closed_state='no_number' (C2a: no real number exists;
#                      the most specific and most recent verdict, and the
#                      only one an admin sets deliberately per lead)
#   2. not qualified — a not_qualified call disposition (the agent's own
#                      judgement about the lead; it is also what wrote the
#                      lead's 'dead' closed_state, so it must outrank
#                      "other dead" or the bucket would always be empty)
#   3. not interested — a suppression with reason 'not_interested' (the
#                      prospect's answer; a soft close that sets no
#                      closed_state of its own)
#   4. other dead    — closed_state='dead' with none of the above (marked
#                      dead by hand, or the S3 no-contact expiry)
#   5. other closed  — lost for a reason that is none of the above: a
#                      suppression the prospect or the compliance path
#                      raised (unsubscribe, complaint, hard bounce). Without
#                      this bucket the rows would not sum to the lost cohort
#                      and /stats would disagree with /pipeline.
LOST_REASONS = [
    ("no_number", "Bad number"),
    ("not_qualified", "Not qualified"),
    ("not_interested", "Not interested"),
    ("other_dead", "Other dead"),
    ("other_closed", "Other closed"),
]

# A lead is SUPPRESSED the way pipeline.compute_stage means it: a row for
# the lead itself, or an account-scoped row matching its email/phone.
# Account-scoped (S1): another tenant's suppression never closes this
# tenant's lead.
_SUPPRESSED_EXISTS = (
    " EXISTS (SELECT 1 FROM suppressions s"
    "   WHERE s.account_id = l.account_id AND (s.lead_id = l.id"
    "   OR (s.email IS NOT NULL AND l.email IS NOT NULL"
    "       AND s.email = l.email)"
    "   OR (s.phone IS NOT NULL AND l.phone IS NOT NULL"
    "       AND s.phone = l.phone))%s)"
)


def lost_leads(db):
    """C2a: non-referral leads lost, bucketed by reason (counts + % of all
    non-referral leads). Money-free — plain counts.

    THE LOST COHORT is the same set /pipeline renders on its dead rung:
    a non-referral lead whose `closed_state` is 'dead' or 'no_number', OR
    which carries a live suppression. `closed_state='sold'` is never lost —
    a lead that was written off and later reopened and sold is a SALE, and
    must not also appear here.

    Every bucket is INTERSECTED with that cohort, so a historical signal on
    a lead that is back in play (a reopened not_qualified lead, an
    un-suppressed not-interested lead) counts as nothing: the buckets are
    the reasons the CURRENTLY lost leads are lost. They are mutually
    exclusive by the LOST_REASONS precedence above and exhaustive by the
    trailing "other closed" bucket, so the counts always sum to
    `total_lost`."""
    account_id = _account()
    cohort = {}
    for r in db.execute(
            "SELECT l.id, l.closed_state FROM leads l "
            "WHERE l.account_id = ? AND l.referred_by IS NULL "
            "AND l.source_agent IS NULL "
            "AND (l.closed_state IS NULL OR l.closed_state != 'sold') "
            "AND (l.closed_state IN ('dead','no_number') OR"
            + (_SUPPRESSED_EXISTS % "") + ")",
            (account_id,)).fetchall():
        cohort[r["id"]] = r["closed_state"]
    lost_ids = set(cohort)

    no_number = set(i for i, cs in cohort.items() if cs == "no_number")
    dead = set(i for i, cs in cohort.items() if cs == "dead")
    not_qualified = lost_ids & set(r["lead_id"] for r in db.execute(
        "SELECT DISTINCT i.lead_id FROM interactions i "
        "JOIN leads l ON l.id = i.lead_id "
        "WHERE l.account_id = ? AND l.referred_by IS NULL "
        "AND l.source_agent IS NULL "
        "AND i.itype = 'call' AND i.disposition = 'not_qualified'",
        (account_id,)).fetchall())
    not_interested = lost_ids & set(r["id"] for r in db.execute(
        "SELECT l.id FROM leads l "
        "WHERE l.account_id = ? AND l.referred_by IS NULL "
        "AND l.source_agent IS NULL AND"
        + (_SUPPRESSED_EXISTS % " AND s.reason = 'not_interested'"),
        (account_id,)).fetchall())

    buckets = {}
    claimed = set()
    for key, pool in (("no_number", no_number),
                      ("not_qualified", not_qualified),
                      ("not_interested", not_interested),
                      ("other_dead", dead),
                      ("other_closed", lost_ids)):
        fresh = pool - claimed
        buckets[key] = fresh
        claimed |= fresh

    total = db.execute(
        "SELECT COUNT(*) AS c FROM leads WHERE account_id = ? "
        "AND referred_by IS NULL AND source_agent IS NULL",
        (account_id,)).fetchone()["c"]
    rows = []
    for key, label in LOST_REASONS:
        count = len(buckets[key])
        rows.append({"key": key, "bucket": label, "leads": count,
                     "pct": _rate(count, total)})
    lost_total = len(lost_ids)
    return {"rows": rows, "total_lost": lost_total,
            "non_referral_leads": total,
            "lost_pct": _rate(lost_total, total)}


def referral_by_source(db):
    """Per source: sold (non-referral) clients, % of them with >= 1 tagged
    referral, and total referrals produced."""
    names = _source_names(db)
    buckets = {}
    order = []
    for sale in _sales_with_leads(db):
        sid = sale["source_id"]
        key = names.get(sid, MANUAL_BUCKET) if sid else MANUAL_BUCKET
        if key not in buckets:
            buckets[key] = {"clients": 0, "with_referral": 0, "referrals": 0}
            order.append(key)
        b = buckets[key]
        b["clients"] += 1
        n_refs = db.execute(
            "SELECT COUNT(*) AS c FROM leads WHERE referred_by = ?",
            (sale["lead_id"],)).fetchone()["c"]
        b["referrals"] += n_refs
        if n_refs:
            b["with_referral"] += 1
    rows = []
    for key in sorted(order, key=lambda k: (k == MANUAL_BUCKET, str(k))):
        b = buckets[key]
        rows.append({
            "bucket": key,
            "sold_clients": b["clients"],
            "with_referral": b["with_referral"],
            "referral_rate": _rate(b["with_referral"], b["clients"]),
            "total_referrals": b["referrals"],
        })
    return rows
