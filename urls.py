"""One safe-redirect helper, shared by every `?next=`/`next` form field.

Four copies of this check used to live in auth.py, routes_leads.py,
routes_dashboard.py and routes_dialer.py; three of them accepted `/\\evil.com`,
which several browsers normalise to `//evil.com` and follow off-site. Keep the
single implementation here — this module imports nothing from the app, so both
`leadflow.auth` and the web blueprints can use it without an import cycle.
"""


def safe_next(raw, default):
    # type: (object, str) -> str
    """`raw` when it is a same-site absolute path, else `default`.

    Rejects: empty/non-string, anything not starting with '/', protocol-
    relative '//host', and the backslash variants ('/\\host', '/\\\\host')
    that browsers treat as protocol-relative.
    """
    if not raw or not isinstance(raw, str):
        return default
    if not raw.startswith("/"):
        return default
    # '//x', '/\x', and any mix of the two in the leading pair.
    if len(raw) > 1 and raw[1] in ("/", "\\"):
        return default
    return raw
