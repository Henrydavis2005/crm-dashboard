"""B10 — the weekly statement, and VA profitability by seat scope.

TWO THINGS, ONE MODULE, because they are the same numbers read twice: a
statement is one VA's week, and the profitability dashboard is every VA's
week side by side.

DELIVERY IS A DOWNLOAD, NEVER A SEND. `/pay/statement.pdf` builds the
document on request and returns it. Nothing here emails anything and
nothing here touches `gmail/smtp_send.py`. That path is the ONE function
every lead email passes, it carries the signature gate and the CAN-SPAM
unsubscribe line, and a statement is neither a lead email nor a marketing
one — routing an internal pay document through it would either bolt an
unsubscribe footer onto somebody's payslip or add a second send path with
its own gates to keep in step. Both are worse than a link.

PERFORMANCE, defined once so the statement and the dashboard cannot
disagree:

  dials       `dial_attempts` rows that reached the carrier. Refusals are
              excluded — a call the app declined to place is not work the
              VA did, and counting it would reward hammering a blocked
              number.
  contacts    call interactions whose disposition means a human answered.
              `no_answer`, `voicemail` and `bad_number` are not contact.
  set         appointments this VA set, from B9's tracker.
  closed      of those, the ones that closed as sold.
  commission  the commission on those closes — the money the appointment
              produced, before anybody's share of it.

PROFIT PER VA HOUR needs hours, and the app has never recorded any. It is
NOT invented here: `users.weekly_hours` is an operator-entered number and
a VA with no hours recorded reports `None`, not a division by a guess. A
dashboard that silently assumed 40 would rank people on a number nobody
entered.
"""
import logging
from typing import Optional

from leadflow import pay
from leadflow.db import utcnow

logger = logging.getLogger("leadflow.statements")

# Dispositions that mean a person actually answered. `no_answer`,
# `voicemail` and `bad_number` are dials that did not reach anybody, and
# folding them in would make "contacts" mean "attempts".
CONTACT_DISPOSITIONS = (
    "answered_not_interested", "callback_requested", "appointment_set",
    "not_qualified", "answered_send_options", "answered_do_not_call",
    # Legacy, read-only (interactions.LEGACY_CALL_DISPOSITIONS): pre-C1
    # rows carry these and they were contact when they were written.
    "answered_interested", "answered_callback",
)

# A dial that reached the carrier. `dial_attempts` also logs refusals as
# `refused:<rule>` and failures as `failed:*`; a refusal is the app
# declining to place a call and is not work.
PLACED_PREFIX = "placed"


def week_bounds(db, ref_date=None):
    """The Fri–Thu pay week, shared with `pay` so a statement and a pay
    run can never disagree about which days they cover."""
    return pay.week_bounds(db, ref_date)


def _utc_window(db, start_date, end_date):
    return pay._utc_window(db, start_date, end_date)


# --------------------------------------------------------- performance

def performance(db, user_id, start_date, end_date):
    # type: (object, int, str, str) -> dict
    """Dials, contacts, appointments set/closed and the commission they
    produced, for one VA over one window."""
    start_utc, end_utc = _utc_window(db, start_date, end_date)

    dials = db.execute(
        "SELECT COUNT(*) AS n FROM dial_attempts WHERE user_id = ? "
        "AND created_at >= ? AND created_at <= ? AND outcome LIKE ?",
        (user_id, start_utc, end_utc, PLACED_PREFIX + "%")).fetchone()["n"]

    marks = ",".join("?" * len(CONTACT_DISPOSITIONS))
    contacts = db.execute(
        "SELECT COUNT(*) AS n FROM interactions WHERE user_id = ? "
        "AND itype = 'call' AND created_at >= ? AND created_at <= ? "
        "AND disposition IN (%s)" % marks,
        [user_id, start_utc, end_utc] + list(CONTACT_DISPOSITIONS)
    ).fetchone()["n"]

    # B9's tracker. `date_set` is a local YYYY-MM-DD, so it compares to
    # the window's dates directly rather than to the UTC bounds.
    set_rows = db.execute(
        "SELECT * FROM appointment_tracker WHERE set_by_user_id = ? "
        "AND date_set >= ? AND date_set <= ?",
        (user_id, start_date, end_date)).fetchall()
    closed = [r for r in set_rows if r["outcome"] == "sold"]
    commission = sum(r["commission_cents"] or 0 for r in closed)

    from leadflow import appointments
    share = 0
    for row in closed:
        part = appointments.split_cents(db, row)
        if part is not None:
            share += part

    return {
        "dials": dials,
        "contacts": contacts,
        "appointments_set": len(set_rows),
        "appointments_closed": len(closed),
        "commission_cents": commission,
        "split_cents": share,
        # Rates a reader would otherwise work out with a calculator, and
        # get wrong on a zero denominator.
        "contact_rate": (contacts * 100 // dials) if dials else None,
        "set_rate": (len(set_rows) * 100 // contacts) if contacts else None,
        "close_rate": ((len(closed) * 100 // len(set_rows))
                       if set_rows else None),
    }


# ------------------------------------------------------------ statement

def build(db, user, ref_date=None):
    # type: (object, object, Optional[str]) -> dict
    """Everything one weekly statement says, as data.

    Kept apart from the PDF so the numbers can be tested without parsing
    a document, and so a future HTML view of the same statement cannot
    drift from the printed one.
    """
    start, end = week_bounds(db, ref_date)
    perf = performance(db, user["id"], start, end)
    pay_report = pay.report(db, user["id"], start, end)
    scope = _scope_of(user)
    return {
        "user_id": user["id"],
        "username": user["username"],
        "scope": scope,
        "scope_label": SCOPE_LABELS[scope],
        "start": start,
        "end": end,
        "performance": perf,
        "pay": pay_report,
        "pay_total_cents": pay_report["totals"]["total_cents"],
        # What the VA is owed in total: their pay, plus their share of any
        # appointment they set that closed. A team seat earns the split; a
        # personal seat's closes are the agent's own business and its
        # commission is not the seat's to be paid.
        "earned_cents": (pay_report["totals"]["total_cents"]
                         + (perf["split_cents"] if scope == TEAM else 0)),
        "generated_at": utcnow(),
    }


TEAM = "team"
PERSONAL = "personal"
SCOPE_LABELS = {TEAM: "Team assistant", PERSONAL: "Personal assistant"}


def _scope_of(user):
    """B7's `users.va_scope`, failing closed to personal — the same
    reading `va_scope.scope` does, and the axis the dashboard splits on."""
    from leadflow import va_scope
    return va_scope.scope(user)


def _money(cents):
    return "$%.2f" % ((cents or 0) / 100.0)


def render_pdf(db, statement, product_name="Ancora"):
    # type: (object, dict, str) -> bytes
    """The statement as a PDF. Pay AND performance, on one page.

    Figures go through `Document.row`'s right-aligned Courier column, so
    money lines up without this module knowing anything about fonts.
    """
    from leadflow.pdf import Document

    perf = statement["performance"]
    doc = Document("%s weekly statement — %s"
                   % (product_name, statement["username"]))
    doc.heading("Weekly statement")
    doc.note("%s   |   %s   |   %s to %s"
             % (product_name, statement["username"],
                statement["start"], statement["end"]))
    doc.note("%s" % statement["scope_label"])
    doc.rule()

    doc.subheading("Performance")
    doc.row("Dials placed", str(perf["dials"]))
    doc.row("Contacts (someone answered)", str(perf["contacts"]))
    if perf["contact_rate"] is not None:
        doc.row("Contact rate", "%d%%" % perf["contact_rate"], indent=12)
    doc.row("Appointments set", str(perf["appointments_set"]))
    if perf["set_rate"] is not None:
        doc.row("Set rate (of contacts)", "%d%%" % perf["set_rate"],
                indent=12)
    doc.row("Appointments closed", str(perf["appointments_closed"]))
    if perf["close_rate"] is not None:
        doc.row("Close rate (of set)", "%d%%" % perf["close_rate"],
                indent=12)
    doc.row("Commission produced", _money(perf["commission_cents"]))

    doc.gap()
    doc.rule()
    doc.subheading("Pay")
    totals = statement["pay"]["totals"]
    doc.row("Daily base", _money(totals.get("base_cents")))
    doc.row("Send options", _money(totals.get("send_options_cents")))
    doc.row("Appointments scheduled", _money(totals.get("appt_scheduled_cents")))
    doc.row("Appointments showed", _money(totals.get("appt_showed_cents")))
    doc.row("Sold bonus", _money(totals.get("sold_bonus_cents")))
    doc.rule()
    doc.row("Pay total", _money(statement["pay_total_cents"]), bold=True)

    if statement["scope"] == TEAM:
        doc.row("Appointment split earned", _money(perf["split_cents"]))
        doc.rule()
        doc.row("Total earned", _money(statement["earned_cents"]), bold=True)
        doc.gap(4)
        doc.note("A team assistant earns a share of the commission on "
                 "appointments they set. The share is worked out from the "
                 "split rate in force on each appointment's own date.")
    else:
        doc.gap(4)
        doc.note("A personal assistant is paid by the rates above. "
                 "Commission on business they help close belongs to the "
                 "agent whose lead it was.")

    doc.gap()
    doc.note("Generated %s. Figures cover the Friday-to-Thursday pay week."
             % statement["generated_at"][:10])
    doc.note("This statement names no client. Appointments appear as a "
             "lead reference only.")
    return doc.build()


# ------------------------------------------------- profitability dashboard

def profitability(db, ref_date=None):
    # type: (object, Optional[str]) -> dict
    """Every VA's week, SPLIT BY SEAT SCOPE and compared on profit per
    VA hour.

    THE TWO GROUPS ARE NOT COMPARABLE ROW BY ROW, which is the whole
    reason the dashboard separates them rather than sorting one list.
    A TEAM seat earns a share of the commission on appointments it sets,
    so the business keeps the rest; a PERSONAL seat sets appointments its
    own agent closes for the full commission. Ranking a team VA against a
    personal VA on raw commission would make the personal seat look
    twice as good for the same work, which is an artefact of the
    arrangement and not a fact about the person.

    Profit per hour is the comparable figure — and it is `None` for
    anybody whose hours nobody has entered, never a guess.
    """
    from leadflow import appointments
    from leadflow.auth import current_account_id
    start, end = week_bounds(db, ref_date)
    account_id = current_account_id()
    rows = {TEAM: [], PERSONAL: []}
    for user in db.execute(
            "SELECT * FROM users WHERE role = 'va' AND account_id = ? "
            "ORDER BY username", (account_id,)).fetchall():
        perf = performance(db, user["id"], start, end)
        pay_total = pay.report(db, user["id"], start, end)["totals"][
            "total_cents"]
        scope = _scope_of(user)
        # What the BUSINESS keeps from this seat's week, before fixed
        # costs: the commission the seat's appointments produced, less
        # what the seat is paid, less the seat's share where it earns one.
        share = perf["split_cents"] if scope == TEAM else 0
        profit = perf["commission_cents"] - pay_total - share
        hours = _hours_of(user)
        rows[scope].append({
            "user_id": user["id"],
            "username": user["username"],
            "hours": hours,
            "performance": perf,
            "pay_cents": pay_total,
            "share_cents": share,
            "profit_cents": profit,
            # NEVER a default denominator. A blank here is "nobody has
            # entered this person's hours", which is a different fact from
            # "this person earned nothing per hour".
            "profit_per_hour_cents": (int(profit / hours) if hours
                                      else None),
        })
    return {
        "start": start, "end": end,
        "team": rows[TEAM], "personal": rows[PERSONAL],
        "team_totals": _group_totals(rows[TEAM]),
        "personal_totals": _group_totals(rows[PERSONAL]),
    }


def _hours_of(user):
    """`users.weekly_hours`, or None. Reads a column that may predate its
    migration the same way every other optional column here does."""
    try:
        value = user["weekly_hours"]
    except (IndexError, KeyError, TypeError):
        return None
    try:
        hours = float(value)
    except (TypeError, ValueError):
        return None
    return hours if hours > 0 else None


def _group_totals(rows):
    """Group figures. Profit per hour is the group's profit over the
    group's KNOWN hours — seats with no hours contribute their profit and
    not a fabricated denominator, and the count of them is reported so a
    reader knows how much of the group the figure covers."""
    profit = sum(r["profit_cents"] for r in rows)
    hours = sum(r["hours"] for r in rows if r["hours"])
    return {
        "vas": len(rows),
        "profit_cents": profit,
        "hours": hours,
        "without_hours": sum(1 for r in rows if not r["hours"]),
        "commission_cents": sum(r["performance"]["commission_cents"]
                                for r in rows),
        "pay_cents": sum(r["pay_cents"] for r in rows),
        "share_cents": sum(r["share_cents"] for r in rows),
        "appointments_set": sum(r["performance"]["appointments_set"]
                                for r in rows),
        "profit_per_hour_cents": int(profit / hours) if hours else None,
    }


# ------------------------------------------------------------ visibility

def may_read(db, viewer, target_user_id):
    # type: (object, object, int) -> bool
    """Who may download a statement.

    THE VA THEMSELVES, and THE OWNING FTA — the manager of the account the
    seat belongs to. Nobody else, and a VA never another VA.

    "Owning FTA" is B3's edge, resolved the same way `va_send` routes the
    queue: the seat's account, or the account its `upline_id` names. No
    new concept of ownership is invented for this block.
    """
    if not viewer:
        return False
    if viewer["id"] == target_user_id:
        return True
    if viewer["role"] != "admin":
        return False
    target = db.execute("SELECT * FROM users WHERE id = ?",
                        (int(target_user_id),)).fetchone()
    if target is None:
        return False
    if target["account_id"] == viewer["account_id"]:
        return True
    from leadflow.va_send import team_root
    return team_root(db, target["account_id"]) == viewer["account_id"]

