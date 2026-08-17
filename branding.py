"""The product name, in one place.

PRODUCT_NAME is the ONLY place the customer-facing name of this software
is written in code. Every user-facing string reads it: page titles, nav,
flash messages, email subjects and bodies, the setup and login screens.
Templates get it as the `product_name` Jinja global, registered in
create_app.

WHAT IS DELIBERATELY NOT RENAMED, and why a rebrand must stay a string
sweep rather than a migration:

  the repo path and the `leadflow` package     — renaming a module is a
      rewrite of every import in the tree, and Python module names are
      not something a customer ever sees.
  LEADFLOW_DB_KEY, LEADFLOW_DATA_DIR,          — renaming an environment
      LEADFLOW_TRUST_PROXY                       variable breaks every
      running deployment at once, and the failure mode for DB_KEY in
      particular is an app that cannot open its own encrypted database.
  database columns and table names             — a rename is a migration
      against live data to change a word nobody reads.
  the systemd unit (deploy/leadflow.service)   — an operator's own
      handle on the process.
  internal documentation (README, SPEC,        — written for whoever
      CLAUDE.md, docs/)                          maintains this, not for
      a tenant.

THE LEGAL DOCUMENTS CANNOT READ THIS CONSTANT, and that is on purpose,
not an oversight. docs/legal/*.md and leadflow/legal/*.md carry the name
as literal text, because a contract has to read as fixed words: a legal
instrument whose wording is interpolated at render time is one whose
signed meaning depends on a deploy. `csa_text()` reads those files
verbatim into the registry row, and the row is the instrument. A test
(tests/test_branding.py) asserts the literal name in those files equals
PRODUCT_NAME, so the two cannot drift even though one cannot import the
other.
"""

PRODUCT_NAME = "Ancora"
