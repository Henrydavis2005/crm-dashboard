"""Security response headers and HTTPS enforcement (PART 12 Step 8).

THE CSP IS REAL, NOT A PLACEHOLDER. It was written against what this app
actually loads, and the app was changed to fit it rather than the other way
round:

  - `script-src 'self'` with NO 'unsafe-inline'. The only <script> in the
    whole template set is the external static/app.js. Three templates
    carried `onchange="this.form.submit()"`, which a strict script-src
    blocks; they became `data-autosubmit` handled by one delegated
    listener in app.js.
  - `style-src 'self'` with NO 'unsafe-inline'. The templates carried 95
    inline `style=` attributes, every one of which a strict style-src
    blocks. They were replaced with utility classes in style.css. 'unsafe-
    inline' on style-src is not harmless: it is what makes most CSS-based
    data exfiltration and UI-redress attacks possible, and it would have
    been the easy way out of the same 95 edits.
  - `default-src 'none'` so anything not named below is refused outright,
    rather than inheriting a permissive default.
  - `img-src 'self' data:` — base.html's favicon is `data:,`, which stops
    every page load from fetching a /favicon.ico that has no route.
  - `frame-ancestors 'none'` plus the legacy `X-Frame-Options: DENY`, so
    old browsers that ignore CSP still refuse to be framed.

HTTPS. In production TLS terminates UPSTREAM — Render's edge for
app.ancorahq.com; Caddy on the VPS path — so the request Flask sees is
plain http and `request.is_secure` is False until the proxy's forwarded
scheme is honoured. Caddy sends `X-Forwarded-Proto`. RENDER DOES NOT: read
from production, the only forwarded headers reaching waitress are
`Cf-Connecting-Ip` and `Cf-Visitor: {"scheme":"https"}`, so `CfVisitorProto`
folds the latter into X-Forwarded-Proto before ProxyFix reads it. Either
header is trusted ONLY when LEADFLOW_TRUST_PROXY says so — trusting a
client-suppliable header by default would let anyone claim their request
was secure. Without it, nothing about local development changes:
http://localhost:8765 keeps working, gets no redirect and no HSTS.

HSTS is sent only over a connection that is actually secure. Over http it
is ignored by browsers anyway, and emitting it from a dev box is noise
pretending to be protection. `preload` is deliberately NOT included: it is
a one-way door — removal from the preload list takes months — and it is
not this app's call to make for the whole domain.
"""
import json
import logging
import os

from flask import redirect, request

logger = logging.getLogger("leadflow.security")

TRUST_PROXY_ENV = "LEADFLOW_TRUST_PROXY"

# THE KILL SWITCH FOR THE HTTPS REDIRECT. Set to 1/true/yes/on and
# _force_https returns None on every request, whatever public_base_url
# says and whatever the proxy reports. It exists because the redirect
# locked the operator out of production twice — a redirect that misjudges
# the scheme sends the browser to where it already is, forever, and the
# only way back in was to reach Settings and unset public_base_url, which
# a looping app does not let you do. This is set in the platform's
# environment, outside the app, so it works while the app is unreachable.
#
# It disables the REDIRECT ONLY. is_secure, HSTS, the Secure cookie flag
# and every other security decision are untouched; a request the proxy
# reports as http is still treated as http everywhere else. TLS still
# terminates at the platform edge, so nothing about the wire changes —
# what is lost is the http->https upgrade for someone who typed http://,
# which the platform's own edge redirect covers anyway.
DISABLE_HTTPS_REDIRECT_ENV = "LEADFLOW_DISABLE_HTTPS_REDIRECT"

# One year, and subdomains. No `preload` — see the module docstring.
HSTS_VALUE = "max-age=31536000; includeSubDomains"

# Built from what the app actually loads. Keep it in this shape: one
# directive per line, each with a reason if it is not obvious.
CSP_DIRECTIVES = (
    ("default-src", "'none'"),        # deny by default; allow explicitly
    ("script-src", "'self'"),         # static/app.js only, never inline
    ("style-src", "'self'"),          # static/style.css only, never inline
    ("img-src", "'self' data:"),      # data: is base.html's empty favicon
    ("font-src", "'self'"),
    ("connect-src", "'self'"),        # app.js fetch() calls, same origin
    ("form-action", "'self'"),        # no form may post off-site
    ("frame-ancestors", "'none'"),    # clickjacking; X-Frame-Options too
    ("base-uri", "'none'"),           # no <base> can re-root relative URLs
    ("object-src", "'none'"),
)

CSP = "; ".join("%s %s" % (name, value) for name, value in CSP_DIRECTIVES)

# `same-origin`, not the commoner strict-origin-when-cross-origin: this
# app's URLs carry lead ids, and an agent clicking a booking link or a
# lead's own site should not hand the destination even the origin.
REFERRER_POLICY = "same-origin"

# Sent on every response regardless of scheme.
BASE_HEADERS = {
    "Content-Security-Policy": CSP,
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": REFERRER_POLICY,
}


def _flag(name):
    # type: (str) -> bool
    raw = (os.environ.get(name) or "").strip().lower()
    return raw in ("1", "true", "yes", "on")


def trust_proxy():
    # type: () -> bool
    """Whether X-Forwarded-* headers may be believed. Off unless set."""
    return _flag(TRUST_PROXY_ENV)


def https_redirect_disabled():
    # type: () -> bool
    """The operator has switched the http->https redirect off. Read per
    request, not at boot, so flipping the variable and restarting is not
    required to be sure — though on Render an env change restarts anyway."""
    return _flag(DISABLE_HTTPS_REDIRECT_ENV)


def forwarded_snapshot():
    # type: () -> dict
    """Everything the proxy chain told us about this request, and what we
    concluded from it. Read-only; nothing here is secret — every value is
    a header the caller sent or a derivation of one, plus the socket
    scheme. This is what /healthz/proxy returns and what the redirect
    logs, so that the header shape a platform actually sends is READ,
    not inferred. It was inferred, three times, and wrong each time."""
    fwd = {k: v for k, v in request.headers.items()
           if k.lower().startswith("x-forwarded-")
           or k.lower() in ("forwarded", "via", "x-real-ip",
                            "cf-visitor", "cf-connecting-ip")}
    return {
        "host": request.host,
        "scheme_seen": request.scheme,
        "is_secure": bool(request.is_secure),
        "outermost_forwarded_proto": outermost_forwarded_proto(),
        "trust_proxy": trust_proxy(),
        "https_configured": https_configured(),
        "redirect_disabled": https_redirect_disabled(),
        "forwarded_headers": fwd,
        "wsgi_url_scheme": request.environ.get("wsgi.url_scheme"),
        "proxy_fix_orig": request.environ.get("werkzeug.proxy_fix.orig"),
    }


# Paths the HTTPS redirect never touches. /healthz is the platform's
# liveness probe: it arrives over whatever scheme the platform uses, does
# not follow redirects, and a 308 makes a healthy service read as down —
# measured on Render, on both hosts, the moment public_base_url was set.
# Its own tuple rather than auth.EXEMPT_PATHS: that list is about who may
# see a page, this one is about which scheme it is served on, and /login
# being auth-exempt does not mean it should be served over plain http.
REDIRECT_EXEMPT_PATHS = ("/healthz", "/healthz/proxy")


def cf_visitor_scheme(raw):
    # type: (object) -> str
    """The `scheme` field of a Cf-Visitor header, or "" if it cannot be
    read. Defensive on purpose: it is JSON inside a header, and a header
    is a string somebody else built.

        Cf-Visitor: {"scheme":"https"}   -> "https"
        Cf-Visitor: {"scheme":"http"}    -> "http"
        Cf-Visitor: not json / {} / ""    -> ""

    Only "http" and "https" are ever returned; anything else — an unknown
    scheme, a number, a nested object — is "" so it can never be mistaken
    for evidence of TLS.
    """
    if not raw or not isinstance(raw, str):
        return ""
    try:
        data = json.loads(raw)
    except (ValueError, TypeError):
        return ""
    if not isinstance(data, dict):
        return ""
    scheme = data.get("scheme")
    if not isinstance(scheme, str):
        return ""
    scheme = scheme.strip().lower()
    return scheme if scheme in ("http", "https") else ""


class CfVisitorProto(object):
    """WSGI middleware: turn Cf-Visitor into the X-Forwarded-Proto that
    ProxyFix expects, and NOTHING more.

    WHY IT EXISTS. Render's edge does not send X-Forwarded-Proto. Read from
    production via /healthz/proxy after three wrong inferences, the whole
    forwarded picture on a request the browser made over https was:

        Cf-Connecting-Ip: <client ip>
        Cf-Visitor: {"scheme":"https"}

    and nothing else. So ProxyFix had nothing to promote, is_secure stayed
    False, and _force_https redirected the browser to the https:// URL it
    was already on, forever. Cf-Visitor IS the forwarded-proto header for
    this ingress. This class gives it exactly the standing that header
    would have had — no more.

    THE TRUST BOUNDARY, STATED WHERE THE NEXT READER WILL SEE IT. Cf-Visitor
    is believed for the same reason and under the same switch that
    X-Forwarded-Proto is: LEADFLOW_TRUST_PROXY is on, which is the operator
    asserting that exactly one trusted proxy is the SOLE INGRESS to this
    process and that it overwrites — not appends to — any client-supplied
    copy of these headers. On Render that proxy is Render's own Cloudflare
    edge, and it strips a client-sent Cf-Visitor before it reaches waitress.
    If this app is ever run where a client can reach waitress directly, or
    behind a proxy that passes client headers through, this middleware lets
    that client claim https and MUST be off — but so must ProxyFix, for
    precisely the same reason, and the same env var already governs both.
    Nothing here widens the boundary; it moves one more header inside it.

    HOW IT IS SCOPED. It runs BEFORE ProxyFix in the WSGI stack, and only
    fills HTTP_X_FORWARDED_PROTO when that header is ABSENT — a real
    X-Forwarded-Proto always wins. It writes exactly one environ key and
    touches nothing else. From then on ProxyFix(x_proto=1) does what it
    always did: one hop, values[-1], and everything downstream — is_secure,
    HSTS, the Secure cookie flag, "may this POST proceed" — reads the same
    single source of truth it read before. x_proto is unchanged.
    """

    def __init__(self, app):
        self.app = app

    def __call__(self, environ, start_response):
        if not environ.get("HTTP_X_FORWARDED_PROTO"):
            scheme = cf_visitor_scheme(environ.get("HTTP_CF_VISITOR"))
            if scheme:
                environ["HTTP_X_FORWARDED_PROTO"] = scheme
        return self.app(environ, start_response)


def outermost_forwarded_proto():
    # type: () -> str
    """The scheme the hop NEAREST THE BROWSER reported, lower-cased, or ""
    when there is no X-Forwarded-Proto at all.

    Cf-Visitor is folded into X-Forwarded-Proto by CfVisitorProto before
    the request reaches Flask (see that class for the trust argument), so
    on Render this reads the value that header carried.

    Distinct from `request.is_secure` on purpose, and the distinction is
    the whole fix. ProxyFix(x_proto=1) sets `is_secure` from the INNERMOST
    hop only (`values[-1]`), and that is correct for every security
    decision — HSTS, the Secure cookie flag, "may this POST proceed" — since
    trusting more hops than exist lets a client forge them. But it is the
    wrong question for "should I redirect this browser to https://":
    with Cloudflare in front of Render the innermost hop can read `http`
    (as `https,http`, or bare) while the browser is already on https, and
    a redirect to https:// then sends it exactly where it is. Production
    looped on that, `308 location: <the same URL>`, until the browser gave
    up.

    So the redirect asks the outermost hop. If ANY proxy saw https, the
    browser reached a TLS edge and a redirect cannot change anything —
    serve the page. If the outermost hop says http, the browser is
    genuinely on http and the redirect is right. A client that forges
    `X-Forwarded-Proto: https` skips a redirect it would otherwise get,
    and nothing else: is_secure stays False, HSTS stays off, the cookie
    stays non-Secure. That is the safe direction to be wrong in.

    Only meaningful when the proxy is trusted; when it is not, the caller
    ignores this and `is_secure` is simply the socket's scheme.
    """
    raw = request.headers.get("X-Forwarded-Proto") or ""
    first = raw.split(",", 1)[0].strip().lower()
    return first


# Hosts that are never the public deployment, whatever the settings say.
# An http request ARRIVING AT one of these is a developer on their own
# machine (or the test client), so redirecting it to https would send them
# somewhere that does not exist. In production the proxy rewrites Host to
# app.ancorahq.com, so none of these match and the redirect applies.
LOCAL_HOSTS = ("localhost", "127.0.0.1", "::1", "[::1]", "0.0.0.0")


def is_local_host(host):
    # type: (str) -> bool
    name = (host or "").strip().lower()
    if "@" in name:                     # userinfo, if anything ever sends it
        name = name.rsplit("@", 1)[1]
    if name.startswith("[") and "]" in name:      # [::1]:8765
        name = name[:name.index("]") + 1]
    elif ":" in name:
        name = name.rsplit(":", 1)[0]
    return name in LOCAL_HOSTS or name.endswith(".localhost")


def https_configured():
    # type: () -> bool
    """True when this install is meant to be served over HTTPS, i.e. its
    public base URL is an https:// one. Never raises: a settings read that
    fails leaves the app in its http-tolerant state, which breaks nothing
    and locks nobody out."""
    from leadflow.settings import get_setting
    try:
        base = str(get_setting("public_base_url") or "")
    except Exception:
        logger.exception("could not read public_base_url; not enforcing "
                         "HTTPS on this request")
        return False
    return base.strip().lower().startswith("https://")


def install(app):
    """Wire the proxy fix, the HTTPS redirect and the response headers."""
    if trust_proxy():
        # x_for/x_proto/x_host = 1: exactly ONE proxy in front of us. A
        # larger number would let a client prepend its own values to the
        # header and have them believed.
        from werkzeug.middleware.proxy_fix import ProxyFix
        app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)
        # OUTSIDE ProxyFix, so it runs first: Cf-Visitor becomes the
        # X-Forwarded-Proto that Render's edge does not send, and ProxyFix
        # then reads it exactly as it would have read the real header.
        # Same trust switch, same single hop — see CfVisitorProto.
        app.wsgi_app = CfVisitorProto(app.wsgi_app)
        logger.info("trusting X-Forwarded-* (and Cf-Visitor as its "
                    "stand-in) from one upstream proxy")

    @app.before_request
    def _force_https():
        """Redirect http -> https, but ONLY where https is configured.

        Two independent reasons this stays out of the way locally: a dev
        box has no public_base_url set, AND a request arriving at
        localhost is exempt regardless of what the setting says. The
        second matters — the setting is a per-tenant value a developer may
        well point at the real https host while working on unsubscribe
        links, and without the host check that would bounce every local
        page load to a host their machine does not serve.

        GET/HEAD only: replaying a POST through a redirect drops its body,
        and a form that silently loses its data is worse than a blocked
        one — anything else gets a 403 telling it to come back over https.

        THE OUTERMOST-HOP RULE. `is_secure` is not the question here — see
        `outermost_forwarded_proto`. Behind a trusted proxy the redirect
        fires only when the hop nearest the browser reported http; if any
        hop saw https the browser is already there and the redirect would
        loop. x_proto stays at 1: this narrows WHEN the redirect fires and
        touches nothing that decides what the request may do.
        """
        if request.is_secure or is_local_host(request.host):
            return None
        if request.path in REDIRECT_EXEMPT_PATHS:
            return None
        if https_redirect_disabled():
            return None
        if not https_configured():
            return None
        if trust_proxy():
            outer = outermost_forwarded_proto()
            if outer and outer != "http":
                # A TLS edge saw this request. Redirecting to https://
                # sends the browser to where it already is.
                return None
        if request.method not in ("GET", "HEAD"):
            return ("This site requires HTTPS. Re-submit over https://",
                    403, {"Content-Type": "text/plain; charset=utf-8"})
        target = request.url.replace("http://", "https://", 1)
        # Every redirect is logged with the whole forwarded picture. This
        # is a decision the app has got wrong twice by inference; when it
        # fires in production the log must show WHY, in the platform's own
        # header shape, not ours. Nothing secret is in it.
        logger.warning("https redirect %s -> %s | %s", request.url, target,
                       forwarded_snapshot())
        return redirect(target, code=308)

    @app.after_request
    def _security_headers(response):
        for name, value in BASE_HEADERS.items():
            response.headers.setdefault(name, value)
        if request.is_secure:
            response.headers.setdefault("Strict-Transport-Security",
                                        HSTS_VALUE)
        return response

    return app
