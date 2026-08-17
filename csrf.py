"""C3 CSRF protection: a per-session synchroniser token on every
state-changing request.

Design notes
------------
- One token per Flask session, minted lazily on first use — including for
  anonymous visitors, because /login, /setup and /signup are themselves POST
  forms that need protecting before anyone is logged in.
- The token lives in the session cookie itself (signed, HttpOnly,
  SameSite=Lax, Secure on https installs), so there is no server-side store
  to expire or scope per tenant.
- Templates render it with the `csrf_token()` Jinja global into a hidden
  `_csrf` field; requests may also present it as the `X-CSRF-Token` header
  (keeps any future fetch/XHR simple).
- Comparison is constant-time (`hmac.compare_digest`). Rejections are logged
  at WARNING and NEVER include the token value.

This module imports nothing from the rest of the package (flask + stdlib
only) so it can be imported from the app factory without an import cycle.
"""
import hmac
import logging
import secrets

from flask import request, session

logger = logging.getLogger("leadflow.csrf")

SESSION_KEY = "_csrf_token"
FORM_FIELD = "_csrf"
HEADER_NAME = "X-CSRF-Token"

# Methods that cannot change state and therefore need no token.
SAFE_METHODS = ("GET", "HEAD", "OPTIONS", "TRACE")

# Endpoints deliberately exempted from CSRF validation, by Flask endpoint
# name (e.g. "settings.gcal_callback"). Deliberately EMPTY: Ancora has no
# inbound webhooks (the Quo webhook was deleted in Part 3) and the only
# external callback left — Google Calendar OAuth (`/settings/gcal/callback`)
# — is a GET, which is safe by method. Add entries here only for endpoints
# an external system POSTs to, with a comment naming what authenticates them
# instead (a signature, a shared secret, …). The enumeration guard in
# tests/test_csrf.py keeps this list honest.
EXEMPT_ENDPOINTS = set()


def exempt(view):
    """Decorator: exclude a view from CSRF validation.

    Only for endpoints an external system POSTs to, which must carry their
    own authentication (signature/shared secret). Records the endpoint by
    the view function's name; blueprint-qualified names are matched too.
    """
    EXEMPT_ENDPOINTS.add(view.__name__)
    return view


def is_exempt(endpoint):
    # type: (object) -> bool
    """True when `endpoint` (a Flask endpoint name) is exempt."""
    if not endpoint:
        return False
    name = str(endpoint)
    return name in EXEMPT_ENDPOINTS or name.rsplit(".", 1)[-1] in EXEMPT_ENDPOINTS


def get_token():
    # type: () -> str
    """The current session's CSRF token, minting one on first use."""
    token = session.get(SESSION_KEY)
    if not token:
        token = secrets.token_urlsafe(32)
        session[SESSION_KEY] = token
    return token


def _presented(req):
    """The token the request presents: form field first, then header."""
    token = ""
    if req.method not in SAFE_METHODS:
        # request.form parses the body; safe methods never need it.
        try:
            token = req.form.get(FORM_FIELD) or ""
        except Exception:  # unparseable body — treat as no token
            logger.warning("could not parse the request body for a CSRF token")
            token = ""
    return token or req.headers.get(HEADER_NAME) or ""


def validate(req=None):
    # type: (object) -> bool
    """True when `req` (default: the current request) may proceed."""
    req = request if req is None else req
    if req.method in SAFE_METHODS:
        return True
    if is_exempt(getattr(req.url_rule, "endpoint", None)):
        return True
    expected = session.get(SESSION_KEY) or ""
    presented = _presented(req)
    if not expected or not presented:
        return False
    return hmac.compare_digest(str(expected), str(presented))
