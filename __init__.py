"""Ancora application factory."""
import datetime
import importlib
import logging

from flask import Flask, render_template, request

logger = logging.getLogger("leadflow")

# Blueprint modules registered when present (other agents add them in parallel).
_BLUEPRINT_MODULES = [
    "leadflow.auth",
    "leadflow.web.routes_dashboard",
    "leadflow.web.routes_today",
    "leadflow.web.routes_leads",
    "leadflow.web.routes_pipeline",
    "leadflow.web.routes_needs_review",
    "leadflow.web.routes_calendar",
    "leadflow.web.routes_appointments",
    "leadflow.web.routes_pay",
    "leadflow.web.routes_stats",
    "leadflow.web.routes_profit",
    "leadflow.web.routes_export",
    "leadflow.web.routes_jarvis",
    "leadflow.web.routes_settings",
    "leadflow.web.routes_approvals",
    "leadflow.web.routes_notifications",
    "leadflow.web.routes_public",
    "leadflow.web.routes_agent_leads",
    "leadflow.web.routes_overflow",
    "leadflow.web.routes_audit",
    "leadflow.web.routes_team",
    "leadflow.web.routes_va_send",
    "leadflow.web.routes_legal",
    "leadflow.web.routes_superadmin",
]

_MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun",
           "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]


def _parse_iso(value):
    if isinstance(value, datetime.datetime):
        dt = value
    else:
        try:
            dt = datetime.datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        except (ValueError, TypeError):
            return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=datetime.timezone.utc)
    return dt


def humanize(value):
    """ISO timestamp -> 'just now' / '3m ago' / '2h ago' / 'Aug 11 9:04am'.

    A stamp in a DIFFERENT year than today carries its year ('Aug 11, 2027
    9:04am'). Without it the R7 renewal referral ask (sold_at + 365 days)
    rendered as the same string as the ask due today, and a lead received
    last August read like one received this August.
    """
    if not value:
        return ""
    dt = _parse_iso(value)
    if dt is None:
        return str(value)
    now = datetime.datetime.now(datetime.timezone.utc)
    delta = (now - dt).total_seconds()
    if delta >= 0:
        if delta < 60:
            return "just now"
        if delta < 3600:
            return "%dm ago" % (delta // 60)
        if delta < 86400:
            return "%dh ago" % (delta // 3600)
    # absolute date in the user's timezone
    from zoneinfo import ZoneInfo
    from leadflow.settings import get_setting
    try:
        zone = ZoneInfo(get_setting("my_timezone"))
    except Exception:
        zone = datetime.timezone.utc
    local = dt.astimezone(zone)
    hour = local.hour % 12 or 12
    ampm = "am" if local.hour < 12 else "pm"
    year = ", %d" % local.year if local.year != now.astimezone(
        zone).year else ""
    return "%s %d%s %d:%02d%s" % (_MONTHS[local.month - 1], local.day, year,
                                  hour, local.minute, ampm)


def tpl_preview(text, limit=200):
    """Render template placeholders with sample values for UI previews."""
    if not text:
        return ""
    from leadflow.settings import get_setting
    samples = {
        "{{first_name}}": "Sarah",
        "{{last_name}}": "Miller",
        "{{name}}": "Sarah Miller",
        "{{state}}": "FL",
        "{{booking_link}}": get_setting("booking_link") or "https://example.com/book",
        "{{agent_name}}": get_setting("identity_name") or "your agent",
    }
    out = str(text)
    for placeholder, sample in samples.items():
        out = out.replace(placeholder, sample)
    if limit and len(out) > limit:
        out = out[: limit - 1].rstrip() + "…"
    return out


def money(cents):
    """Jinja filter: cents (int) -> '$X.XX' (B6 pay views)."""
    try:
        return "$%.2f" % (int(cents) / 100.0)
    except (TypeError, ValueError):
        return "$0.00"


def _https_public_base_url():
    """True when this install is served over HTTPS (Settings → Public base
    URL). Drives SESSION_COOKIE_SECURE: a secure cookie is never sent over
    http, which would lock out plain-http localhost development."""
    from leadflow.settings import get_setting
    try:
        base = str(get_setting("public_base_url") or "")
    except Exception:
        logger.exception("could not read public_base_url; leaving the "
                         "session cookie usable over http")
        return False
    return base.strip().lower().startswith("https://")


def install_csrf(app):
    """C3: reject every state-changing request without a valid CSRF token.

    Registered BEFORE the auth guard so it also covers the unauthenticated
    POST forms (/login, /setup, /signup) — the auth guard's exempt-path list
    would otherwise wave those through unchecked. Templates get the matching
    token via the `csrf_token()` Jinja global."""
    from leadflow import csrf

    @app.before_request
    def _csrf_guard():
        if csrf.validate(request):
            return None
        logger.warning("CSRF check failed: %s %s from %s (token missing or "
                       "mismatched)", request.method, request.path,
                       request.remote_addr)
        return render_template("csrf_error.html"), 400

    app.jinja_env.globals["csrf_token"] = csrf.get_token


def create_app():
    app = Flask(
        __name__,
        template_folder="web/templates",
        static_folder="web/static",
        static_url_path="/static",
    )

    from leadflow import auth
    from leadflow.db import init_db

    app.secret_key = auth.get_secret_key()
    init_db()

    # Session cookie hardening. SameSite=Lax means a cross-site POST never
    # carries the session — defence in depth beneath the CSRF token check
    # installed below, which is the actual protection standing between a
    # forged form and every state-changing POST in the app (logging a call
    # attempt, marking a lead sold, running the quote send). Secure only
    # when the install is actually HTTPS, so http://localhost still logs in.
    app.config["SESSION_COOKIE_HTTPONLY"] = True
    app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
    app.config["SESSION_COOKIE_SECURE"] = _https_public_base_url()

    # PART 12 Step 8. Before the CSRF guard so the HTTPS redirect happens
    # ahead of any token check — a plain-http POST is refused for being
    # plain http, which is the more useful message of the two.
    from leadflow import security
    security.install(app)

    install_csrf(app)

    for modname in _BLUEPRINT_MODULES:
        try:
            mod = importlib.import_module(modname)
        except ImportError:
            logger.debug("blueprint module %s not present yet; skipping", modname)
            continue
        blueprint = getattr(mod, "bp", None)
        if blueprint is not None:
            app.register_blueprint(blueprint)

    auth.install_guard(app)

    @app.teardown_request
    def _rollback_dangling(exc):
        """No request may leave an uncommitted transaction behind.

        Connections are per-THREAD and waitress reuses threads, so a view
        that raises after its first write (a double-submitted Mark sold
        hitting `sales.lead_id UNIQUE`, any 500 past a write) hands the
        open transaction to whoever that thread serves next — which then
        commits the failed request's partial rows. It also holds SQLite's
        single writer slot, so the worker's writes fail `database is
        locked` until the thread happens to serve another write. Views
        that finished normally have already committed and this is a
        no-op. See db.rollback_dangling.
        """
        from leadflow.db import rollback_dangling
        rollback_dangling("request %s %s" % (request.method, request.path))

    @app.context_processor
    def _notifications_badge():
        """Unread-notification count for the nav bell (admins only)."""
        from flask import g
        user = getattr(g, "user", None)
        if not user or user.get("role") != "admin":
            return {"notif_unread": 0}
        try:
            from leadflow.db import get_db
            from leadflow.web.routes_notifications import unread_count
            return {"notif_unread": unread_count(get_db())}
        except Exception:
            logger.exception("could not compute the unread-notification badge")
            return {"notif_unread": 0}

    @app.context_processor
    def _team_nav():
        """B3: does the nav show Team? Admins of a manager account only.

        Fails CLOSED on any error — a nav link that appears when the
        lookup breaks is a link to a 404 at best, and at worst it tells a
        tenant they have a team they do not have.
        """
        from flask import g
        user = getattr(g, "user", None)
        if not user or user.get("role") != "admin":
            return {"is_team_manager": False}
        try:
            from leadflow import team
            from leadflow.db import get_db
            return {"is_team_manager": team.is_manager(
                get_db(), user["account_id"])}
        except Exception:
            logger.exception("could not resolve the team nav flag")
            return {"is_team_manager": False}

    from leadflow.interactions import disposition_label

    # The product name, for every template. A Jinja GLOBAL rather than a
    # context processor: it is a constant, so it needs no per-request
    # work, and a global cannot be shadowed by a view that happens to
    # pass a variable of the same name.
    from leadflow.branding import PRODUCT_NAME
    app.jinja_env.globals["product_name"] = PRODUCT_NAME

    app.jinja_env.filters["humanize"] = humanize
    app.jinja_env.filters["tpl_preview"] = tpl_preview
    app.jinja_env.filters["money"] = money
    # C1: renders active AND legacy call dispositions (and appointment
    # outcomes) with their human labels; unknown values render as-is.
    app.jinja_env.filters["disposition_label"] = disposition_label

    return app
