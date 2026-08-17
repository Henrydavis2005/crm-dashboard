"""A minimal PDF writer. Standard library only.

WHY THIS EXISTS RATHER THAN A DEPENDENCY. CLAUDE.md's rule is stdlib
first, and B10 needs one thing from a PDF: a page of headed text with
money in aligned columns. That is a few hundred bytes of a format whose
text-only subset is genuinely simple — a catalogue, a pages node, one
content stream per page, two built-in fonts, and an xref table. Pulling in
reportlab (a C-adjacent, ~4MB library with its own font machinery) to draw
left-aligned labels and right-aligned figures would be the larger risk,
not the smaller one, and it would be the first dependency in this repo
added for a single screen.

WHAT IT DOES NOT DO, and what would change the calculation: no images, no
embedded fonts, no vector graphics, no tables with rules, no wrapping of
arbitrary long prose, no non-Latin text. If a later block needs a chart or
a logo in a statement, that is the moment to reconsider — this module is
deliberately not the beginning of a rendering engine.

THE FOURTEEN STANDARD FONTS need no embedding: every conforming reader
has Helvetica and Courier. That is the single fact that makes a stdlib
writer reasonable, and it is why `FONTS` is exactly two entries.

ALIGNMENT WITHOUT FONT METRICS. Figures are drawn in Courier, which is
monospaced at 0.6 em per glyph, so a column of money right-aligns by
counting characters. Helvetica is proportional and its widths are not
carried here — so proportional text is never used for anything that has
to line up. That is the same discipline `--font-mono` and `tabular-nums`
enforce in the app's own CSS.
"""
import logging

logger = logging.getLogger("leadflow.pdf")

# US Letter, in points, which is what MediaBox speaks.
PAGE_W = 612
PAGE_H = 792
MARGIN = 54

# The two of the fourteen standard fonts this module uses. Both are
# guaranteed present in any conforming reader, which is what lets the
# file carry no font programs at all.
FONTS = (("F1", "Helvetica"), ("F2", "Helvetica-Bold"), ("F3", "Courier"))

# Courier advances 0.6 em per character, exactly. This is the only metric
# in the file and the reason figures are drawn in Courier.
COURIER_ADVANCE = 0.6


def _escape(text):
    """PDF string escaping, and the transliteration that keeps it honest.

    A literal string is delimited by parentheses, so `(`, `)` and `\\` must
    be escaped or the content stream stops parsing where the text does —
    and a username or a note is user-supplied, so this is not theoretical.

    Non-ASCII is transliterated rather than dropped: a statement carrying
    a name spelled `Jose` when the person is `José` is wrong but legible,
    whereas emitting the raw byte would produce a mojibake glyph or an
    unparseable stream. WinAnsi covers most Latin text and is what the
    standard fonts assume; anything outside it becomes `?` so the failure
    is visible rather than silent.
    """
    out = []
    for ch in str(text):
        if ch in ("\\", "(", ")"):
            out.append("\\" + ch)
        elif ord(ch) < 32:
            out.append(" ")
        elif ord(ch) < 127:
            out.append(ch)
        else:
            try:
                ch.encode("cp1252")
                out.append(ch)
            except (UnicodeEncodeError, LookupError):
                out.append("?")
    return "".join(out)


class Page(object):
    """One page's content stream, built as drawing operators."""

    def __init__(self):
        self.ops = []
        self.y = PAGE_H - MARGIN

    # --------------------------------------------------------- primitives

    def text(self, x, y, value, font="F1", size=10):
        self.ops.append("BT /%s %g Tf %g %g Td (%s) Tj ET"
                        % (font, size, x, y, _escape(value)))

    def right_text(self, right_x, y, value, size=10):
        """Right-aligned, in Courier, by counting characters.

        Only Courier is offered here on purpose: right-aligning
        proportional text needs a width table this module deliberately
        does not carry, and guessing would produce columns that are
        almost aligned, which is worse than obviously not.
        """
        value = _escape(value)
        width = len(value) * COURIER_ADVANCE * size
        self.ops.append("BT /F3 %g Tf %g %g Td (%s) Tj ET"
                        % (size, right_x - width, y, value))

    def line(self, x0, y0, x1, y1, width=0.5, grey=0.75):
        self.ops.append("%g w %g G %g %g m %g %g l S"
                        % (width, grey, x0, y0, x1, y1))

    def stream(self):
        return "\n".join(self.ops)


class Document(object):
    """A sequence of pages, serialised to bytes.

    Flow helpers (`heading`, `row`, `rule`) track a cursor and start a new
    page when one runs out, so a caller writes a statement top to bottom
    without doing pagination arithmetic — which is the part of hand-rolling
    a PDF that actually goes wrong.
    """

    def __init__(self, title="Statement"):
        self.title = title
        self.pages = [Page()]

    # ------------------------------------------------------------- layout

    @property
    def page(self):
        return self.pages[-1]

    def _space(self, needed):
        if self.page.y - needed < MARGIN:
            self.pages.append(Page())
        return self.page

    def heading(self, value, size=16):
        page = self._space(size + 10)
        page.y -= size + 4
        page.text(MARGIN, page.y, value, font="F2", size=size)
        page.y -= 6

    def subheading(self, value, size=11):
        page = self._space(size + 14)
        page.y -= size + 8
        page.text(MARGIN, page.y, value, font="F2", size=size)
        page.y -= 4

    def row(self, label, value=None, size=10, indent=0, bold=False):
        """A label on the left, an optional figure right-aligned on the
        right. The figure is Courier so a column of them lines up."""
        page = self._space(size + 6)
        page.y -= size + 3
        page.text(MARGIN + indent, page.y, label,
                  font="F2" if bold else "F1", size=size)
        if value is not None:
            page.right_text(PAGE_W - MARGIN, page.y, value, size=size)

    def note(self, value, size=8.5):
        page = self._space(size + 6)
        page.y -= size + 3
        page.text(MARGIN, page.y, value, font="F1", size=size)

    def rule(self):
        page = self._space(10)
        page.y -= 6
        page.line(MARGIN, page.y, PAGE_W - MARGIN, page.y)
        page.y -= 2

    def gap(self, points=8):
        self._space(points).y -= points

    # -------------------------------------------------------- serialising

    def build(self):
        # type: () -> bytes
        """The file itself: objects, then an xref table whose byte offsets
        must be exact, then the trailer. Offsets are measured as the file
        is assembled rather than computed, because a computed offset that
        is one byte out produces a file every reader rejects with no clue
        which number was wrong.
        """
        objects = []          # 1-based; index i is object i+1

        font_ids = {}
        n_fixed = 3 + len(FONTS)          # catalog, pages, + fonts
        for i, (alias, base) in enumerate(FONTS):
            font_ids[alias] = 3 + i + 1   # objects 4.. are the fonts

        page_obj_start = n_fixed + 1
        page_ids = []
        content_ids = []
        for i in range(len(self.pages)):
            page_ids.append(page_obj_start + i * 2)
            content_ids.append(page_obj_start + i * 2 + 1)

        resources = "<< /Font << %s >> >>" % " ".join(
            "/%s %d 0 R" % (alias, font_ids[alias]) for alias, _b in FONTS)

        objects.append("<< /Type /Catalog /Pages 2 0 R >>")
        objects.append("<< /Type /Pages /Kids [%s] /Count %d >>"
                       % (" ".join("%d 0 R" % p for p in page_ids),
                          len(page_ids)))
        objects.append("<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica "
                       "/Encoding /WinAnsiEncoding >>")
        for _alias, base in FONTS[1:]:
            objects.append("<< /Type /Font /Subtype /Type1 /BaseFont /%s "
                           "/Encoding /WinAnsiEncoding >>" % base)

        for i, page in enumerate(self.pages):
            objects.append(
                "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 %d %d] "
                "/Resources %s /Contents %d 0 R >>"
                % (PAGE_W, PAGE_H, resources, content_ids[i]))
            objects.append(("stream", page.stream()))

        out = bytearray(b"%PDF-1.4\n")
        offsets = []
        for number, body in enumerate(objects, start=1):
            offsets.append(len(out))
            if isinstance(body, tuple):
                data = body[1].encode("cp1252", "replace")
                out += ("%d 0 obj\n<< /Length %d >>\nstream\n"
                        % (number, len(data))).encode("ascii")
                out += data
                out += b"\nendstream\nendobj\n"
            else:
                out += ("%d 0 obj\n%s\nendobj\n"
                        % (number, body)).encode("cp1252", "replace")

        xref_at = len(out)
        out += ("xref\n0 %d\n" % (len(objects) + 1)).encode("ascii")
        out += b"0000000000 65535 f \n"
        for offset in offsets:
            out += ("%010d 00000 n \n" % offset).encode("ascii")
        out += ("trailer\n<< /Size %d /Root 1 0 R /Info << /Title (%s) "
                "/Producer (Ancora) >> >>\nstartxref\n%d\n%%%%EOF\n"
                % (len(objects) + 1, _escape(self.title),
                   xref_at)).encode("cp1252", "replace")
        return bytes(out)
