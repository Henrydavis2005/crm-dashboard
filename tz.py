"""Timezone inference (state + area code) and quiet-hours window math."""
import datetime
import logging
import re
from typing import Optional
from zoneinfo import ZoneInfo

from leadflow.phone import normalize_phone

logger = logging.getLogger("leadflow.tz")

DEFAULT_TZ = "America/New_York"

_E = "America/New_York"
_C = "America/Chicago"
_M = "America/Denver"
_P = "America/Los_Angeles"

# Dominant IANA zone per state (50 states + DC).
STATE_TZ = {
    "AL": _C,
    "AK": "America/Anchorage",
    "AZ": "America/Phoenix",
    "AR": _C,
    "CA": _P,
    "CO": _M,
    "CT": _E,
    "DE": _E,
    "DC": _E,
    "FL": _E,
    "GA": _E,
    "HI": "Pacific/Honolulu",
    "ID": "America/Boise",
    "IL": _C,
    "IN": "America/Indiana/Indianapolis",
    "IA": _C,
    "KS": _C,
    "KY": _E,
    "LA": _C,
    "ME": _E,
    "MD": _E,
    "MA": _E,
    "MI": "America/Detroit",
    "MN": _C,
    "MS": _C,
    "MO": _C,
    "MT": _M,
    "NE": _C,
    "NV": _P,
    "NH": _E,
    "NJ": _E,
    "NM": _M,
    "NY": _E,
    "NC": _E,
    "ND": _C,
    "OH": _E,
    "OK": _C,
    "OR": _P,
    "PA": _E,
    "RI": _E,
    "SC": _E,
    "SD": _C,
    "TN": _C,
    "TX": _C,
    "UT": _M,
    "VT": _E,
    "VA": _E,
    "WA": _P,
    "WV": _E,
    "WI": _C,
    "WY": _M,
}

# States that span two timezones; refine with the area code when possible.
SPLIT_STATES = {
    "FL", "TX", "TN", "KY", "ID", "OR", "NE", "KS",
    "SD", "ND", "MI", "IN", "AZ",
}

# The zones each split state ACTUALLY SPANS, and the reason the
# refinement above is bounded rather than a straight override.
#
# A mobile number keeps its area code forever, so "state TX, area code
# 206" is an ordinary row: someone who moved from Seattle to Texas. The
# unbounded refinement read the 206 and returned America/Los_Angeles for
# a lead whose own state says Central — a real row in this database
# (lead 11). Harmless for email. For a dialer it is a two-hour error in
# the direction that calls people early: the queue thinks 8am Pacific,
# the lead's clock says 6am Central.
#
# So the area code may only pick BETWEEN the zones its state contains.
# Outside that set the state wins, because the state is where the person
# says they are and the area code is where their phone was issued.
SPLIT_STATE_ZONES = {
    "FL": frozenset((_E, _C)),
    "TX": frozenset((_C, _M)),
    "TN": frozenset((_E, _C)),
    "KY": frozenset((_E, _C)),
    "ID": frozenset(("America/Boise", _P)),
    "OR": frozenset((_P, _M)),
    "NE": frozenset((_C, _M)),
    "KS": frozenset((_C, _M)),
    "SD": frozenset((_C, _M)),
    "ND": frozenset((_C, _M)),
    "MI": frozenset(("America/Detroit", _C)),
    "IN": frozenset(("America/Indiana/Indianapolis", _C)),
    "AZ": frozenset(("America/Phoenix", _M)),
}

# Full US geographic area code -> IANA zone map (hand-written).
AREA_CODE_TZ = {
    # Alabama (Central)
    "205": _C, "251": _C, "256": _C, "334": _C, "659": _C, "938": _C,
    # Alaska
    "907": "America/Anchorage",
    # Arizona (no DST)
    "480": "America/Phoenix", "520": "America/Phoenix", "602": "America/Phoenix",
    "623": "America/Phoenix", "928": "America/Phoenix",
    # Arkansas (Central)
    "327": _C, "479": _C, "501": _C, "870": _C,
    # California (Pacific)
    "209": _P, "213": _P, "279": _P, "310": _P, "323": _P, "341": _P,
    "350": _P, "369": _P, "408": _P, "415": _P, "424": _P, "442": _P,
    "510": _P, "530": _P, "559": _P, "562": _P, "619": _P, "626": _P,
    "628": _P, "650": _P, "657": _P, "661": _P, "669": _P, "707": _P,
    "714": _P, "738": _P, "747": _P, "760": _P, "805": _P, "818": _P,
    "820": _P, "831": _P, "840": _P, "858": _P, "909": _P, "916": _P,
    "925": _P, "949": _P, "951": _P,
    # Colorado (Mountain)
    "303": _M, "719": _M, "720": _M, "970": _M, "983": _M,
    # Connecticut (Eastern)
    "203": _E, "475": _E, "860": _E, "959": _E,
    # Delaware
    "302": _E,
    # District of Columbia
    "202": _E, "771": _E,
    # Florida - peninsula (Eastern)
    "239": _E, "305": _E, "321": _E, "324": _E, "352": _E, "386": _E,
    "407": _E, "561": _E, "645": _E, "656": _E, "689": _E, "727": _E,
    "754": _E, "772": _E, "786": _E, "813": _E, "863": _E, "904": _E,
    "941": _E, "954": _E,
    # Florida - panhandle (Central: Pensacola/Panama City dominate 850/448)
    "850": _C, "448": _C,
    # Georgia (Eastern)
    "229": _E, "404": _E, "470": _E, "478": _E, "678": _E, "706": _E,
    "762": _E, "770": _E, "912": _E, "943": _E,
    # Hawaii
    "808": "Pacific/Honolulu",
    # Idaho (statewide overlays; dominant Mountain)
    "208": "America/Boise", "986": "America/Boise",
    # Illinois (Central)
    "217": _C, "224": _C, "309": _C, "312": _C, "331": _C, "447": _C,
    "464": _C, "618": _C, "630": _C, "708": _C, "773": _C, "779": _C,
    "815": _C, "847": _C, "872": _C,
    # Indiana - northwest corner (Central: Gary/Hammond)
    "219": _C,
    # Indiana - rest (Eastern)
    "260": "America/Indiana/Indianapolis", "317": "America/Indiana/Indianapolis",
    "463": "America/Indiana/Indianapolis", "574": "America/Indiana/Indianapolis",
    "765": "America/Indiana/Indianapolis", "812": "America/Indiana/Indianapolis",
    "930": "America/Indiana/Indianapolis",
    # Iowa (Central)
    "319": _C, "515": _C, "563": _C, "641": _C, "712": _C,
    # Kansas (Central; Mountain sliver has no dedicated code)
    "316": _C, "620": _C, "785": _C, "913": _C,
    # Kentucky - western (Central: Bowling Green/Paducah/Owensboro)
    "270": _C, "364": _C,
    # Kentucky - eastern (Eastern: Louisville/Lexington)
    "502": _E, "606": _E, "859": _E,
    # Louisiana (Central)
    "225": _C, "318": _C, "337": _C, "504": _C, "985": _C,
    # Maine
    "207": _E,
    # Maryland (Eastern)
    "227": _E, "240": _E, "301": _E, "410": _E, "443": _E, "667": _E,
    # Massachusetts (Eastern)
    "339": _E, "351": _E, "413": _E, "508": _E, "617": _E, "774": _E,
    "781": _E, "857": _E, "978": _E,
    # Michigan (Eastern; western UP Central minority within 906)
    "231": "America/Detroit", "248": "America/Detroit", "269": "America/Detroit",
    "313": "America/Detroit", "517": "America/Detroit", "586": "America/Detroit",
    "616": "America/Detroit", "679": "America/Detroit", "734": "America/Detroit",
    "810": "America/Detroit", "906": "America/Detroit", "947": "America/Detroit",
    # Minnesota (Central)
    "218": _C, "320": _C, "507": _C, "612": _C, "651": _C, "763": _C, "952": _C,
    # Mississippi (Central)
    "228": _C, "601": _C, "662": _C, "769": _C,
    # Missouri (Central)
    "314": _C, "417": _C, "557": _C, "573": _C, "636": _C, "660": _C,
    "816": _C, "975": _C,
    # Montana (Mountain)
    "406": _M,
    # Nebraska (Central; Mountain panhandle is a minority within 308)
    "308": _C, "402": _C, "531": _C,
    # Nevada (Pacific)
    "702": _P, "725": _P, "775": _P,
    # New Hampshire
    "603": _E,
    # New Jersey (Eastern)
    "201": _E, "551": _E, "609": _E, "640": _E, "732": _E, "848": _E,
    "856": _E, "862": _E, "908": _E, "973": _E,
    # New Mexico (Mountain)
    "505": _M, "575": _M,
    # New York (Eastern)
    "212": _E, "315": _E, "332": _E, "347": _E, "363": _E, "516": _E,
    "518": _E, "585": _E, "607": _E, "631": _E, "646": _E, "680": _E,
    "716": _E, "718": _E, "838": _E, "845": _E, "914": _E, "917": _E,
    "929": _E, "934": _E,
    # North Carolina (Eastern)
    "252": _E, "336": _E, "472": _E, "704": _E, "743": _E, "828": _E,
    "910": _E, "919": _E, "980": _E, "984": _E,
    # North Dakota (Central dominant; Mountain southwest corner)
    "701": _C,
    # Ohio (Eastern)
    "216": _E, "220": _E, "234": _E, "283": _E, "326": _E, "330": _E,
    "380": _E, "419": _E, "440": _E, "513": _E, "567": _E, "614": _E,
    "740": _E, "937": _E,
    # Oklahoma (Central)
    "405": _C, "539": _C, "572": _C, "580": _C, "918": _C,
    # Oregon (Pacific; Malheur County Mountain sliver has no dedicated code)
    "458": _P, "503": _P, "541": _P, "971": _P,
    # Pennsylvania (Eastern)
    "215": _E, "223": _E, "267": _E, "272": _E, "412": _E, "445": _E,
    "484": _E, "570": _E, "582": _E, "610": _E, "717": _E, "724": _E,
    "814": _E, "878": _E,
    # Rhode Island
    "401": _E,
    # South Carolina (Eastern)
    "803": _E, "821": _E, "839": _E, "843": _E, "854": _E, "864": _E,
    # South Dakota (Central dominant; Mountain west incl Rapid City)
    "605": _C,
    # Tennessee - east (Eastern: Knoxville/Chattanooga/Tri-Cities)
    "423": _E, "865": _E,
    # Tennessee - middle/west (Central: Nashville/Memphis)
    "615": _C, "629": _C, "731": _C, "901": _C, "931": _C,
    # Texas - most of the state (Central)
    "210": _C, "214": _C, "254": _C, "281": _C, "325": _C, "346": _C,
    "361": _C, "409": _C, "430": _C, "432": _C, "469": _C, "512": _C,
    "621": _C, "682": _C, "713": _C, "726": _C, "737": _C, "806": _C,
    "817": _C, "830": _C, "832": _C, "903": _C, "936": _C, "940": _C,
    "945": _C, "956": _C, "972": _C, "979": _C,
    # Texas - El Paso (Mountain)
    "915": _M,
    # Utah (Mountain)
    "385": _M, "435": _M, "801": _M,
    # Vermont
    "802": _E,
    # Virginia (Eastern)
    "276": _E, "434": _E, "540": _E, "571": _E, "703": _E, "757": _E,
    "804": _E, "826": _E, "948": _E,
    # Washington (Pacific)
    "206": _P, "253": _P, "360": _P, "425": _P, "509": _P, "564": _P,
    # West Virginia (Eastern)
    "304": _E, "681": _E,
    # Wisconsin (Central)
    "262": _C, "274": _C, "353": _C, "414": _C, "534": _C, "608": _C,
    "715": _C, "920": _C,
    # Wyoming (Mountain)
    "307": _M,
    # US territories
    "787": "America/Puerto_Rico", "939": "America/Puerto_Rico",
    "340": "America/St_Thomas",
    "671": "Pacific/Guam",
    "670": "Pacific/Saipan",
    "684": "Pacific/Pago_Pago",
}


def _area_code(phone):
    # type: (Optional[str]) -> Optional[str]
    """The first three digits, whatever the number is spelled like.

    B6: reads `phone.digits` rather than slicing the stored string. The
    old code took `normalized[2:5]`, which was the area code only while
    numbers were stored as `+1XXXXXXXXXX` — under the current
    `000-000-0000` it would have returned '0-5' and put every lead in the
    default zone.
    """
    if not phone:
        return None
    from leadflow.phone import digits as phone_digits
    value = phone_digits(phone)
    if value:
        return value[:3]
    raw = re.sub(r"\D+", "", str(phone))
    if len(raw) == 11 and raw.startswith("1"):
        raw = raw[1:]
    if len(raw) == 10:
        return raw[:3]
    return None


# How `derive_timezone` reached its answer. DEFAULT is the one that
# matters: it means NOTHING about the lead placed them in a zone, and the
# value being returned is a guess that happens to be Eastern.
BY_AREA_CODE = "area_code"      # split state refined by area code, or no state
BY_STATE = "state"              # the state's dominant zone
BY_DEFAULT = "default"          # neither said anything — a guess


def derive_timezone(state, phone):
    # type: (Optional[str], Optional[str]) -> tuple
    """(IANA zone, how we got it). The lead's zone, never the caller's.

    Precedence, most specific first:

      1. A SPLIT STATE plus a known area code — the area code wins,
         because "TX" spans Central and Mountain and the phone number is
         the only thing in the row that says which. (BY_AREA_CODE)
      2. The state's dominant zone. (BY_STATE)
      3. No usable state: the area code alone. (BY_AREA_CODE)
      4. Nothing usable: DEFAULT_TZ. (BY_DEFAULT)

    Rung 4 is why this function returns a source at all. `lead_timezone`
    has always fallen back to America/New_York and returned it
    indistinguishably from a lead that really is in New York — fine for
    an email, which lands whenever it lands, and NOT fine for a dialer:
    8am "Eastern" for a lead who is actually in California is a 5am
    phone call. The caller decides what to do about that; this function's
    job is to stop the guess from looking like a fact.
    """
    st = (state or "").strip().upper()
    ac = _area_code(phone)
    if st in STATE_TZ:
        if st in SPLIT_STATES and ac and ac in AREA_CODE_TZ:
            candidate = AREA_CODE_TZ[ac]
            # Only between the zones this state actually spans — see
            # SPLIT_STATE_ZONES for the Texas-lead-with-a-Seattle-number
            # case that bound this.
            if candidate in SPLIT_STATE_ZONES.get(st, frozenset()):
                return candidate, BY_AREA_CODE
        return STATE_TZ[st], BY_STATE
    if ac and ac in AREA_CODE_TZ:
        return AREA_CODE_TZ[ac], BY_AREA_CODE
    return DEFAULT_TZ, BY_DEFAULT


def timezone_is_known(state, phone):
    # type: (Optional[str], Optional[str]) -> bool
    """False when the zone is the fallback guess rather than derived."""
    return derive_timezone(state, phone)[1] != BY_DEFAULT


def lead_timezone(state, phone):
    # type: (Optional[str], Optional[str]) -> str
    """Infer a lead's IANA timezone. The zone only — see
    `derive_timezone` when it matters HOW the zone was reached."""
    return derive_timezone(state, phone)[0]


def _zone(tz_name):
    try:
        return ZoneInfo(tz_name)
    except Exception:
        logger.warning("unknown timezone %r; falling back to %s", tz_name, DEFAULT_TZ)
        return ZoneInfo(DEFAULT_TZ)


def local_clock(tz_name, at=None):
    # type: (Optional[str], Optional[datetime.datetime]) -> str
    """The wall clock in `tz_name` at `at` (UTC; default now), e.g.
    '3:42 PM CDT'.

    ONE FUNCTION, TWO CALLERS, ON PURPOSE. The VA work console shows the
    lead's clock beside the number an assistant is about to dial, and
    B11's leads card shows it on every lead. Those two readings have to
    agree — an assistant told "3:42 PM CDT" and an agent told something
    else about the same person is a support ticket — and the only way
    that stays true is for there to be one sentence.

    A blank or unknown zone falls back to DEFAULT_TZ through `_zone`,
    which logs it. A clock is never omitted: "we do not know what time
    it is there" is not a state the caller can render usefully, and
    Eastern is the app's stated default everywhere else.
    """
    at = _ensure_aware_utc(at)
    local = at.astimezone(_zone(tz_name or DEFAULT_TZ))
    return "%d:%02d %s %s" % (local.hour % 12 or 12, local.minute,
                              "AM" if local.hour < 12 else "PM",
                              local.tzname() or "")


def _parse_hhmm(value):
    # type: (str) -> int
    """'HH:MM' -> minutes since local midnight."""
    parts = str(value).strip().split(":")
    hour = int(parts[0])
    minute = int(parts[1]) if len(parts) > 1 else 0
    return hour * 60 + minute


def _ensure_aware_utc(at):
    # type: (Optional[datetime.datetime]) -> datetime.datetime
    if at is None:
        return datetime.datetime.now(datetime.timezone.utc)
    if at.tzinfo is None:
        return at.replace(tzinfo=datetime.timezone.utc)
    return at.astimezone(datetime.timezone.utc)


def is_quiet_ok(tz_name, quiet_start, quiet_end, at=None):
    # type: (str, str, str, Optional[datetime.datetime]) -> bool
    """True if `at` (UTC; default now) falls inside the lead-local send window.

    Window is [quiet_start, quiet_end). Windows that cross midnight
    (start > end, e.g. 22:00-06:00) are handled. start == end means the
    window never closes (always ok) - defensive, not expected in practice.
    """
    at = _ensure_aware_utc(at)
    local = at.astimezone(_zone(tz_name))
    minutes = local.hour * 60 + local.minute
    start = _parse_hhmm(quiet_start)
    end = _parse_hhmm(quiet_end)
    if start == end:
        return True
    if start < end:
        return start <= minutes < end
    # window crosses midnight
    return minutes >= start or minutes < end


def next_window_open(tz_name, quiet_start, at=None):
    # type: (str, str, Optional[datetime.datetime]) -> datetime.datetime
    """Next moment (UTC aware) the lead-local window opens at quiet_start.

    Returns today's opening if it is still ahead of `at` lead-local,
    otherwise tomorrow's opening.
    """
    at = _ensure_aware_utc(at)
    zone = _zone(tz_name)
    local = at.astimezone(zone)
    start = _parse_hhmm(quiet_start)
    candidate = local.replace(
        hour=start // 60, minute=start % 60, second=0, microsecond=0
    )
    if candidate <= local:
        candidate = candidate + datetime.timedelta(days=1)
        # re-anchor wall-clock time after crossing a possible DST transition
        candidate = candidate.replace(hour=start // 60, minute=start % 60)
    return candidate.astimezone(datetime.timezone.utc)
