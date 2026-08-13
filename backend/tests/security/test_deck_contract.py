"""Contract checks over the Rule 2 executive presentation.

``blitzy-deck/executive-summary.html`` is delivered to satisfy Rule 2
(Executive Presentation). The Rule fixes a great deal about the file
exactly -- the pinned dependency versions, the framework configuration,
the theme's custom properties, the slide types and component classes, the
section count, and a hard cap on how much text a content slide may carry
-- and none of it is checked by anything else in this suite. Editing the
deck for accuracy is precisely when one of those constraints is easiest
to break, so this module asserts them. What is asserted:

* the structural limits: 12 to 18 sections, four slide types, at most
  four bullets and forty body words on a content slide, one non-text
  visual on every slide, no emoji, no fenced code block
* the delivery contract: three exactly-pinned content-delivery-network
  versions, the framework's five configuration values, the diagram
  library's five theme variables, and a render cycle wired to both the
  ready and the slide-changed events
* the theme: every custom property the Rule enumerates, every slide-type
  class, all ten component classes and the diagram container
* accessibility semantics: an accessible name and description on each
  diagram, a caption and column scopes on each table, and every
  decorative icon hidden from assistive technology
* contrast: that no text rule uses the muted grey the Rule declares but
  which measures 2.85:1 on white, and that the title slide carries the
  scrim that lifts white and teal text over its gradient
* the claims the deck makes about this work, which a reader cannot check
  against the code and which were previously overstated

Word counting follows the review's method: every text node in a section
except headings, with diagram source excluded. Speaker notes are
excluded because reveal.js does not render them onto the slide, and the
review's own guidance names them as the destination for detail.
"""

import re

import pytest
from conftest import REPO_ROOT

#: The Rule 2 deliverable.
DECK = REPO_ROOT / "blitzy-deck" / "executive-summary.html"

#: Section-count bounds the Rule fixes.
MIN_SECTIONS = 12
MAX_SECTIONS = 18

#: Per-content-slide caps the Rule fixes.
MAX_BULLETS = 4
MAX_BODY_WORDS = 40

#: Exact dependency pins, as the Rule states them.
PINNED_ASSETS = (
    "reveal.js@5.1.0/dist/reveal.css",
    "reveal.js@5.1.0/dist/reveal.js",
    "mermaid@11.4.0",
    "lucide@0.460.0",
)

#: Framework configuration values the Rule fixes.
FRAMEWORK_CONFIG = (
    "hash: true",
    "transition: 'slide'",
    "controlsTutorial: false",
    "width: 1920",
    "height: 1080",
)

#: Diagram theme variables the Rule fixes.
DIAGRAM_THEME = (
    "primaryColor: '#F2F0FE'",
    "primaryTextColor: '#333333'",
    "primaryBorderColor: '#5B39F3'",
    "lineColor: '#999999'",
    "secondaryColor: '#F4EFF6'",
)

#: Custom properties the Rule requires the inline theme to declare.
THEME_TOKENS = (
    "--blitzy-primary",
    "--blitzy-primary-dark",
    "--blitzy-primary-navy",
    "--blitzy-primary-light",
    "--blitzy-primary-deep",
    "--blitzy-accent-teal",
    "--blitzy-surface-0",
    "--blitzy-surface-1",
    "--blitzy-surface-2",
    "--blitzy-surface-3",
    "--blitzy-border",
    "--blitzy-text",
    "--blitzy-text-muted",
    "--blitzy-text-invert",
    "--ff-body",
    "--ff-display",
    "--ff-mono",
    "--gradient-hero",
    "--gradient-divider",
    "--gradient-accent-bar",
)

#: Slide-type and component classes the Rule enumerates.
THEME_CLASSES = (
    "slide-title",
    "slide-divider",
    "slide-closing",
    "kpi-card",
    "kpi-grid",
    "kpi-value",
    "kpi-label",
    "kpi-icon",
    "eyebrow",
    "accent-bar",
    "brand-lockup",
    "hero-icon",
    "icon-row",
    "mermaid",
)

#: Gradient the Rule fixes for the title slide.
HERO_GRADIENT = (
    "linear-gradient(68deg, #7A6DEC 15.56%, #5B39F3 62.74%, #4101DB 84.44%)"
)

#: Typefaces the Rule fixes, as requested from the font service.
TYPEFACES = ("Inter:wght", "Space+Grotesk:wght", "Fira+Code:wght")

#: Colour the Rule declares as a token and that measures 2.85:1 on
#: white. It may style a line or a diagram edge; it may not style text.
UNDERCONTRAST_GREY = "#999999"

#: Declarations allowed to name that colour.
GREY_ALLOWED_IN = ("--blitzy-text-muted:", "lineColor:", "stroke:")

#: Claims the deck must not make, each one previously made and wrong.
WITHDRAWN_CLAIMS = (
    "findings closed",
    "no patched release existed",
    "every setting ships documented with a safe local default",
    "every setting has a safe local default",
    "a control ever stops holding",
    "no browser client calls it",
)

#: Claims the deck must make, each one a correction.
REQUIRED_CLAIMS = (
    "remediated in code",
    "items awaiting an operator",
    "delivery still pending",
    "not operational",
    "Needs a component nobody will fix",
    "Unmaintained; had stopped working",
    "Archived; cannot verify notifications",
)


def _text():
    """Returns the deck as text with normalised line endings."""
    return DECK.read_text(encoding="utf-8").replace("\r\n", "\n")


def _slides(text):
    """Returns the markup of every section, in document order."""
    body = text[text.index('<div class="slides">'):]
    return re.findall(r"<section\b[^>]*>.*?</section>", body, re.S)


def _kind(section):
    """Returns one section's slide type."""
    opening = re.match(r"<section\b[^>]*>", section).group(0)
    for name in ("slide-title", "slide-divider", "slide-closing"):
        if name in opening:
            return name
    return "content"


#: Components removed before body text is counted: the heading block, the
#: metric-card grid, the styled table, the icon row, the brand lockup and
#: screen-reader-only text. None of them is body prose an audience reads off
#: the slide, and the first four are the non-text visuals Rule 2 requires a
#: slide to carry. ``docs/security/DECISION_LOG.md`` row 96.5.1 holds why
#: the model is drawn here rather than one element wider.
VISUAL_COMPONENTS = (
    ("div", "slide-head"),
    ("div", "kpi-grid"),
    ("table", "data-table"),
    ("div", "icon-row"),
    ("div", "brand-lockup"),
    ("span", "sr-only"),
)


def _without_component(markup, tag, class_name):
    """Returns ``markup`` without each ``tag`` element carrying ``class_name``.

    Nesting is followed, so a component holding more of the same tag is
    removed whole rather than only as far as its first closing tag.
    """
    opening = re.compile(
        r'<%s\b[^>]*class="[^"]*\b%s\b[^"]*"[^>]*>' % (tag, class_name)
    )
    boundary = re.compile(r"<(/?)%s\b[^>]*>" % tag)
    while True:
        found = opening.search(markup)
        if found is None:
            return markup
        depth = 0
        for edge in boundary.finditer(markup, found.start()):
            depth += -1 if edge.group(1) else 1
            if depth == 0:
                markup = markup[: found.start()] + " " + markup[edge.end():]
                break
        else:
            return markup[: found.start()] + " "


def _without_visual_components(markup):
    """Returns ``markup`` without every declared visual component."""
    for tag, class_name in VISUAL_COMPONENTS:
        markup = _without_component(markup, tag, class_name)
    return markup


def _rendered(section):
    """Returns one section's markup without unrendered text.

    Diagram source is layout, not prose, and speaker notes are not shown
    on the slide, so neither is part of what an audience reads.
    """
    without = re.sub(
        r"<pre class=\"mermaid\">.*?</pre>", " ", section, flags=re.S
    )
    return re.sub(
        r"<aside class=\"notes\">.*?</aside>", " ", without, flags=re.S
    )


def _prose(section):
    """Returns one section's body prose, without its visual components."""
    return _without_visual_components(_rendered(section))


def _body_words(section):
    """Returns the words a content slide's body carries."""
    visible = re.sub(
        r"<h[1-4]\b[^>]*>.*?</h[1-4]>", " ", _prose(section), flags=re.S
    )
    visible = re.sub(r"<[^>]+>", " ", visible)
    visible = visible.replace("&rarr;", "\u2192")
    visible = re.sub(r"&[a-z]+;", " ", visible)
    return [word for word in visible.split() if re.search(r"[\w\u2192]", word)]


def _visuals(section):
    """Returns how many non-text visuals one section carries."""
    return sum(
        len(re.findall(pattern, section))
        for pattern in (
            r"data-lucide=",
            r"<pre class=\"mermaid\">",
            r"class=\"kpi-card\"",
            r"class=\"data-table\"",
        )
    )


def test_the_deck_is_present_and_self_contained():
    """Asserts one file with no local dependency, as the Rule requires."""
    text = _text()

    assert DECK.is_file()
    assert text.lstrip().startswith("<!DOCTYPE html>")
    assert text.rstrip().endswith("</html>")

    local = [
        reference
        for reference in re.findall(r'(?:href|src)="([^"]+)"', text)
        if not reference.startswith(("https://", "data:", "#"))
    ]
    assert local == [], local


def test_the_section_count_is_within_the_fixed_bounds():
    """Asserts the deck neither shrinks below nor grows past the range."""
    count = len(_slides(_text()))

    assert MIN_SECTIONS <= count <= MAX_SECTIONS, count


def test_all_four_slide_types_are_present():
    """Asserts the title, divider, content and closing types all appear."""
    kinds = {_kind(section) for section in _slides(_text())}

    assert kinds == {
        "slide-title",
        "slide-divider",
        "content",
        "slide-closing",
    }, sorted(kinds)


def test_no_content_slide_exceeds_its_text_budget():
    """Asserts the Rule's four-bullet and forty-word caps hold.

    Reported per slide rather than as a single failure, because the cap
    is the constraint most easily broken by an edit for accuracy and the
    slide number is what a fixer needs.
    """
    over = []
    for index, section in enumerate(_slides(_text()), start=1):
        if _kind(section) != "content":
            continue
        words = len(_body_words(section))
        bullets = len(re.findall(r"<li\b", _rendered(section)))
        if words > MAX_BODY_WORDS or bullets > MAX_BULLETS:
            over.append((index, words, bullets))

    assert over == [], over


def test_every_slide_carries_a_non_text_visual():
    """Asserts the Rule's prohibition on a text-only slide."""
    bare = [
        index
        for index, section in enumerate(_slides(_text()), start=1)
        if _visuals(section) == 0
    ]

    assert bare == [], bare


def test_the_closing_slide_keeps_its_own_limits():
    """Asserts a 3-6 word takeaway, at most 3 bullets, and its fixtures."""
    closing = [
        section
        for section in _slides(_text())
        if _kind(section) == "slide-closing"
    ]
    assert len(closing) == 1
    section = closing[0]

    heading = re.search(r"<h2\b[^>]*>(.*?)</h2>", section, re.S)
    assert heading is not None
    words = re.sub(r"<[^>]+>", " ", heading.group(1)).split()

    assert 3 <= len(words) <= 6, words
    assert len(re.findall(r"<li\b", _rendered(section))) <= 3
    assert 'class="brand-lockup"' in section
    assert 'class="accent-bar"' in section


def test_the_brand_lockup_separates_its_two_lines_by_a_margin():
    """Asserts the lockup's spacing does not rest on font metrics.

    Rendered-pixel measurement showed the two lines of the lockup
    touching, with no background row between the descender of the word
    and the cap-height of the line beneath it, because the inherited
    unitless line-height leaves no leading. A line-height large enough
    to help would depend on the display face's own ascent and descent,
    which a font substitution changes; an explicit margin does not. The
    delivered margin measures six empty pixel rows at this deck's scale.
    """
    lockup = re.search(
        r"\.brand-lockup \.brand-sub \{(.*?)\}", _text(), re.S
    )
    assert lockup is not None
    assert re.search(r"margin-top:\s*8px", lockup.group(1))


def test_the_deck_carries_no_emoji_and_no_fenced_code():
    """Asserts iconography is Lucide only and code stays inline."""
    text = _text()
    body = text[text.index('<div class="slides">'):]

    assert not re.search(
        r"[\U0001F300-\U0001FAFF\u2600-\u27BF\uFE0F]", text
    )
    assert "```" not in body
    assert "<code" not in body
    assert 'class="mono"' in body


@pytest.mark.parametrize("asset", PINNED_ASSETS)
def test_every_dependency_stays_pinned(asset):
    """Asserts the three exact versions the Rule names."""
    assert asset in _text(), asset


@pytest.mark.parametrize("setting", FRAMEWORK_CONFIG)
def test_the_framework_configuration_is_unchanged(setting):
    """Asserts each fixed configuration value survives."""
    assert setting in _text(), setting


@pytest.mark.parametrize("variable", DIAGRAM_THEME)
def test_the_diagram_theme_is_unchanged(variable):
    """Asserts each fixed diagram theme variable survives."""
    assert variable in _text(), variable


#: Window of source, in characters, a handler's body is looked for in
#: after its registration. Long enough to hold either handler as
#: written and short enough that a match cannot come from the next one.
HANDLER_WINDOW = 240


def _after(text, marker):
    """Returns the source following ``marker``, bounded to one handler."""
    assert marker in text, marker
    start = text.index(marker) + len(marker)
    return text[start:start + HANDLER_WINDOW]


def test_the_render_cycle_is_wired_to_both_events():
    """Asserts diagrams and icons are drawn on ready and on every change.

    A diagram on a slide the framework has not laid out yet has no
    layout box, so a single draw at load time leaves later diagrams
    blank. Each library is therefore invoked from the ready handler and
    again from the slide-changed handler. The invocations are located
    inside those handlers, so moving one out of a handler fails here
    even when the number of call sites is unchanged.
    """
    text = _text()

    assert "startOnLoad: false" in text
    assert "Reveal.on('ready'" in text
    assert "Reveal.on('slidechanged'" in text

    assert "lucide.createIcons()" in _after(text, "Reveal.on('ready'")

    changes = text.split("Reveal.on('slidechanged'")[1:]
    assert len(changes) == 2, len(changes)
    bodies = [change[:HANDLER_WINDOW] for change in changes]
    assert any("lucide.createIcons()" in body for body in bodies), bodies
    assert any("mermaid.run(" in body for body in bodies), bodies

    # Two call sites: the pass that draws every diagram once the library
    # arrives, and the pass a slide change runs.
    assert text.count("mermaid.run(") == 2


def test_the_presentation_starts_outside_the_diagram_module():
    """Asserts a diagram-library fetch failure cannot stop the deck.

    A failed static import discards the whole module it appears in.
    While the framework start-up, the icon fallback and the diagram
    recovery notice all lived in the module that imported the diagram
    library, losing that one file left every slide hidden, no fallback
    drawn and nothing on the console: the presentation never started.
    Start-up therefore lives in a script that imports nothing, and the
    library is fetched by a guarded dynamic import.
    """
    text = _text()

    scripts = re.findall(
        r"<script(?P<attrs>[^>]*)>(?P<body>.*?)</script>", text, re.S
    )
    starters = [
        body for attrs, body in scripts if "Reveal.initialize(" in body
    ]
    assert len(starters) == 1, len(starters)
    starter = starters[0]

    assert "import " not in starter
    assert "import(" not in starter

    importers = [body for attrs, body in scripts if "import(" in body]
    assert len(importers) == 1, len(importers)
    importer = importers[0]

    assert "import('mermaid')" in importer
    assert ".catch(" in importer
    assert "Reveal.initialize(" not in importer

    # No static import of the library survives anywhere.
    assert not re.search(r"^\s*import\s+\w+\s+from", text, re.M)


@pytest.mark.parametrize("token", THEME_TOKENS)
def test_every_theme_token_is_declared(token):
    """Asserts the inline theme still declares each custom property."""
    assert re.search(re.escape(token) + r"\s*:", _text()), token


@pytest.mark.parametrize("name", THEME_CLASSES)
def test_every_theme_class_is_defined(name):
    """Asserts each slide-type, component and container class survives."""
    assert re.search(r"\." + re.escape(name) + r"\b", _text()), name


def test_the_brand_fixtures_are_unchanged():
    """Asserts the hero gradient and the three typefaces survive."""
    text = _text()

    assert HERO_GRADIENT in text
    for typeface in TYPEFACES:
        assert typeface in text, typeface


def test_no_text_rule_uses_the_undercontrast_grey():
    """Asserts the 2.85:1 grey styles no text.

    The Rule requires the token to be declared, so it stays declared and
    stays available to a line or a diagram edge. What it may not do is
    colour text, which is what the review measured.
    """
    # A comment names the colour in order to explain why it is not used
    # for text, and styles nothing, so comments are removed before the
    # scan rather than allow-listed line by line.
    uncommented = re.sub(r"/\*.*?\*/", " ", _text(), flags=re.S)

    offenders = []
    for line in uncommented.splitlines():
        if UNDERCONTRAST_GREY not in line:
            continue
        if any(allowed in line for allowed in GREY_ALLOWED_IN):
            continue
        offenders.append(line.strip())

    assert offenders == [], offenders


def test_the_closing_slide_overrides_the_lede_colour():
    """Asserts the navy closing slide's lede is not the dark body ink.

    ``.lede`` declares its own colour, and a class declaration on the
    paragraph beats the inverted colour the closing slide sets for its
    subtree to inherit. Without an override the closing takeaway renders
    the theme's body ink on the navy, measuring 1.30:1 against a 4.5:1
    threshold -- rendered, unclipped and unreadable, which no other
    assertion here would notice.
    """
    text = _text()

    override = re.search(r"\.slide-closing \.lede \{(.*?)\}", text, re.S)
    assert override is not None
    body = override.group(1)

    assert "var(--blitzy-text)" not in body
    assert "#333333" not in body
    assert "rgba(255, 255, 255, 0.9)" in body


def test_the_dark_closing_slide_recolours_every_text_element_it_carries():
    """Asserts no text on the navy slide keeps the light-surface colour.

    The closing slide sets a navy background and overrode its heading and
    its bullets, but not its lead line, which kept ``--blitzy-text`` at
    #333333 and rendered at 1.30:1 against #1A105F -- charcoal on navy,
    measured in a browser and sampled from the rendered pixels. The
    heading and bullets on the same slide measured 16.36:1, so the fault
    was one missing selector rather than a theme-wide one. This case reads
    which text elements the slide actually carries and requires a rule for
    each, so adding a fifth element without recolouring it fails here.
    """
    text = _text()
    closing = [
        section
        for section in _slides(text)
        if _kind(section) == "slide-closing"
    ][0]
    style = re.search(r"<style>(.*?)</style>", text, re.S).group(1)

    selectors = []
    if re.search(r"<h2\b", closing):
        selectors.append(".slide-closing h2")
    if 'class="lede"' in closing:
        selectors.append(".slide-closing .lede")
    if re.search(r"<li\b", _rendered(closing)):
        selectors.append(".slide-closing li")

    assert selectors, "the closing slide carries no text element"
    for selector in selectors:
        assert selector in style, selector
        declarations = style.split(selector, 1)[1].split("}", 1)[0]
        assert "color:" in declarations, selector
        assert "var(--blitzy-text)" not in declarations, selector


def test_the_title_slide_carries_its_contrast_scrim():
    """Asserts the measured scrim over the mandated gradient survives.

    White text on the gradient's light stop measures 4.02:1 and the teal
    eyebrow 3.23:1, both under the 4.5:1 normal-text threshold. The scrim
    is what lifts them, so its removal would silently reintroduce the
    finding while leaving every other assertion here green.
    """
    text = _text()
    scrim = re.search(
        r"\.slide-title \.slide-body \{(.*?)\}", text, re.S
    )
    assert scrim is not None
    body = scrim.group(1)

    assert "rgba(26, 16, 95, 0.55)" in body
    assert "rgba(26, 16, 95, 0.30)" in body
    assert "rgba(255, 255, 255, 0.86)" in text


def test_every_diagram_carries_an_accessible_name_and_description():
    """Asserts each diagram is described for assistive technology."""
    text = _text()
    diagrams = re.findall(
        r"<pre class=\"mermaid\">(.*?)</pre>", text, re.S
    )

    assert len(diagrams) == 2
    for source in diagrams:
        assert re.search(r"^\s*accTitle:\s*\S", source, re.M)
        assert re.search(r"^\s*accDescr \{\s*$", source, re.M)


def test_every_table_carries_a_caption_and_column_scopes():
    """Asserts table semantics, which the review found absent."""
    text = _text()
    tables = re.findall(r"<table\b.*?</table>", text, re.S)

    assert tables
    for table in tables:
        assert "<caption" in table
        headers = re.findall(r"<th\b[^>]*>", table)
        assert headers
        for header in headers:
            assert 'scope="col"' in header, header


def test_every_icon_is_hidden_from_assistive_technology():
    """Asserts each icon is marked decorative.

    Every icon in this deck sits beside its own text, so none carries
    meaning alone and each should be skipped rather than announced.
    """
    text = _text()
    placeholders = re.findall(r"<i\b[^>]*data-lucide=[^>]*>", text)

    assert placeholders
    for placeholder in placeholders:
        assert 'aria-hidden="true"' in placeholder, placeholder


def test_the_deck_declares_responsive_behaviour():
    """Asserts the breakpoints and overflow handling are present."""
    text = _text()

    for query in ("max-width: 1400px", "max-width: 1024px",
                  "max-width: 720px", "max-height: 820px"):
        assert query in text, query
    assert "prefers-reduced-motion" in text
    assert text.count("overflow-y: auto") >= 2


@pytest.mark.parametrize("claim", WITHDRAWN_CLAIMS)
def test_the_deck_repeats_no_withdrawn_claim(claim):
    """Asserts a corrected overstatement does not return.

    Each string below was on a slide and was wrong or overstated. The
    audience for this file cannot check any of them against the code,
    which is what makes an inaccuracy here costly.
    """
    assert claim not in _text(), claim


@pytest.mark.parametrize("claim", REQUIRED_CLAIMS)
def test_the_deck_states_each_correction(claim):
    """Asserts the accurate replacement statement is present."""
    assert claim in _text(), claim


def test_the_deck_reports_the_open_items_explicitly():
    """Asserts completion is qualified rather than implied.

    The deck previously described the work as finished. Three kinds of
    work cannot be done from this repository, so the deck names them.

    The third item read "Enable private reporting" until that step was
    observed already done on the repository's Security and quality tab.
    What is open is narrower and is what the item now names: nothing
    inside this repository can establish that a filed report is read.
    ``docs/security/DECISION_LOG.md`` row 104.6.1 owns the restatement,
    and the superseded label is asserted absent so the deck cannot drift
    back to asking an operator for work that is finished.
    """
    text = _text()

    assert "What still needs an owner" in text
    assert "Rotate the exposed credentials" in text
    assert "Mount the provisioned secrets" in text
    assert "Confirm reports are read" in text
    assert "Enable private reporting" not in text


def test_the_architecture_diagram_draws_no_absent_flow():
    """Asserts the diagram claims no data flow that does not exist.

    The browser client and object storage carry no flow, so each is an
    unconnected node rather than an arrow. Secret delivery is the one that
    changed: the delivered manifests mount every value into the workloads,
    so its chain is drawn as the definitions carry it, and
    ``test_the_architecture_diagram_draws_secret_delivery_as_delivered``
    in ``test_operator_documentation.py`` asserts each of its edges. An
    earlier revision of this case required that chain to be unconnected
    and named two node identifiers the diagram no longer uses.
    """
    text = _text()
    diagram = re.search(
        r"<pre class=\"mermaid\">(.*?)</pre>", text, re.S
    ).group(1)

    for absent in (
        "CLIENT --",
        "&gt; CLIENT",
        "PLATFORM --",
        "&gt; PLATFORM",
        "STREAM",
        "BROWSER",
    ):
        assert absent not in diagram, absent
    for node in ("VAULT[", "PLATFORM[", "CLIENT["):
        assert node in diagram, node
    assert "stroke-dasharray" in diagram


# ---------------------------------------------------------------------
# Readability of the rendered slide.
#
# The body-word cap above counts prose and excludes each declared visual,
# which is the model row 96.5.1 of the decision log settles. A review of
# the rendered deck counted every visible word instead, including each
# cell of a table and each label of a metric card, and reported eight
# slides between 44 and 290 words on that count. Both models measure
# something real: the first is what Rule 2's forty-word cap governs, and
# the second is how much text a reader actually faces. The cases below
# bound the second one, so density is held by test on the same terms it
# was measured on. Row 104.8.1 of the decision log holds the two models
# and why the strictest slides cannot reach forty on the wider count.

#: Ceiling on the words a content slide renders in total, counting every
#: visible word including each table cell and metric label. Measured at 78
#: on the densest slide after the reduction, from 290 before it.
MAX_VISIBLE_WORDS = 80

#: Ceiling on the words one cell or one bullet may carry. A cell above this
#: is prose sitting inside a table, which is the shape the review found at
#: forty words. Running prose is bounded by the body-word cap above
#: instead, which is the measure Rule 2 states.
MAX_UNIT_WORDS = 13

#: The units that cap holds: table cells, table headers and bullets.
TEXT_UNITS = re.compile(r"<(td|th|li)\b[^>]*>(.*?)</\1>", re.S)

#: A screen-reader-only unit, which no sighted reader faces.
SCREEN_READER_ONLY = re.compile(r'class="[^"]*\bsr-only\b')


def _rendered_words(section):
    """Returns every word a slide renders, on the review's own model.

    Headings, diagram source, speaker notes and screen-reader-only text
    are excluded; every other visible word is counted, whichever element
    carries it.
    """
    without_diagram = re.sub(
        r'<pre class="mermaid">.*?</pre>', " ", section, flags=re.S
    )
    without_notes = re.sub(
        r'<aside class="notes">.*?</aside>', " ", without_diagram, flags=re.S
    )
    without_headings = re.sub(
        r"<h[1-4][^>]*>.*?</h[1-4]>", " ", without_notes, flags=re.S
    )
    without_hidden = re.sub(
        r'<(span|caption)\b[^>]*class="[^"]*\bsr-only\b[^"]*"[^>]*>'
        r".*?</\1>",
        " ",
        without_headings,
        flags=re.S,
    )
    return re.sub(r"<[^>]+>", " ", without_hidden).split()


def test_every_content_slide_is_within_the_rendered_word_ceiling():
    """No content slide faces a reader with more than the ceiling."""
    over = {}
    for number, section in enumerate(_slides(_text()), 1):
        if _kind(section) != "content":
            continue
        count = len(_rendered_words(section))
        if count > MAX_VISIBLE_WORDS:
            over[number] = count

    assert not over, over


def test_no_rendered_text_unit_carries_a_paragraph():
    """No cell, bullet, label or line exceeds the per-unit ceiling.

    The slide-level ceiling can be met by many short units or by one long
    one, and one long one is what the review found: a single table cell
    carrying forty words. This bounds the unit.
    """
    over = []
    for number, section in enumerate(_slides(_text()), 1):
        without_diagram = re.sub(
            r'<pre class="mermaid">.*?</pre>', " ", section, flags=re.S
        )
        without_notes = re.sub(
            r'<aside class="notes">.*?</aside>',
            " ",
            without_diagram,
            flags=re.S,
        )
        for match in TEXT_UNITS.finditer(without_notes):
            opening = match.group(0)[: match.group(0).find(">") + 1]
            if SCREEN_READER_ONLY.search(opening):
                continue
            body = re.sub(r"<[^>]+>", " ", match.group(2))
            words = body.split()
            if len(words) > MAX_UNIT_WORDS:
                over.append((number, len(words), " ".join(words)[:60]))

    assert not over, over


# ---------------------------------------------------------------------
# The authored type scale, the layout mode boundary and the navigation
# chrome.
#
# The stage the framework paints is a fixed 1920x1080 box scaled to the
# viewport, so every authored size is multiplied by that scale. A review
# of the rendered deck measured 6.23px text at 1025px wide and a 1.0 to
# 0.5125 step across a one-pixel change of width. The floor and the
# boundary below are what hold both.

#: Smallest authored size, as a fraction of the 32px root. At the lowest
#: stage scale the stylesheet still uses, 0.729, this renders at 11.7px.
#: Every rule is measured, including the two that size against their own
#: parent: a fraction of an em inside an already-fractional parent
#: compounds, and both of those landed under the floor at 0.92em and 0.94em
#: inside a 0.5em cell before they were carried to 1em.
MIN_ROOT_RELATIVE_EM = 0.5

#: Width at and below which the stage is released and the slide flows.
FLOW_BOUNDARY = "1400px"

#: Bottom padding the flowing slide reserves for the pinned chrome.
MIN_CHROME_RESERVE = 140


def _stylesheet():
    """Returns the deck's inline stylesheet."""
    return re.search(r"<style>(.*?)</style>", _text(), re.S).group(1)


def test_no_authored_type_tier_sits_below_the_legible_floor():
    """Every root-relative size is at or above the floor.

    A tier below the floor renders in single digits of pixels once the
    stage is scaled, which is what the review measured.
    """
    sheet = _stylesheet()
    low = []
    for block in re.finditer(r"([^{}]+)\{([^{}]*)\}", sheet):
        selector = " ".join(block.group(1).split())
        for size in re.finditer(
            r"font-size:\s*(?:min\()?([0-9.]+)em", block.group(2)
        ):
            if float(size.group(1)) < MIN_ROOT_RELATIVE_EM:
                low.append((selector, size.group(1)))

    assert not low, low


def test_the_stage_fills_the_viewport():
    """The framework's own inset is not applied.

    It defaults to four percent, which multiplies into every authored size
    through the stage scale and took the smallest tier under the floor at
    the layout-mode boundary.
    """
    assert "margin: 0," in _text()


def test_the_layout_mode_boundary_is_declared_once_everywhere():
    """The stylesheet and both scripts name the same boundary.

    The stylesheet releases the stage, one script re-shapes the diagram
    text when the mode changes and the other sizes the drawings for the
    mode it finds. A boundary that differed between them would leave one
    of the three in the wrong mode.
    """
    text = _text()
    sheet = _stylesheet()

    #: The flow-mode block, identified by the declaration only it makes.
    flow = re.search(
        r"@media \(max-width: ([0-9]+px)\) \{[^@]*?"
        r"\.reveal \.slides > section:not\(\.present\)",
        sheet,
        re.S,
    )
    assert flow is not None
    assert flow.group(1) == FLOW_BOUNDARY, flow.group(1)

    assert (
        "window.matchMedia('(max-width: %s)')" % FLOW_BOUNDARY
    ) in text
    assert ("FLOW_QUERY = '(max-width: %s)'" % FLOW_BOUNDARY) in text


def test_the_flowing_slide_reserves_room_for_the_pinned_chrome():
    """The chrome stands on its own ground and masks what passes beneath.

    Pinned to the viewport over a slide taller than it, the chrome has
    content pass under it at every intermediate scroll offset, which
    padding cannot prevent; what padding does guarantee is that no slide
    ends underneath it. The backdrop is what covers the rest, and it sits
    on the button rather than on the cluster element, whose own box is
    empty: the framework positions every button absolutely inside it, so a
    backdrop there measured 20px square while the buttons that paint
    measure 44px each.
    """
    sheet = _stylesheet()
    reserves = [
        int(value)
        for value in re.findall(
            r"\.slide-body \{ padding: [0-9]+px [0-9]+px ([0-9]+)px",
            sheet,
        )
    ]

    assert reserves, "no flowing slide padding found"
    for reserve in reserves:
        assert reserve >= MIN_CHROME_RESERVE, reserve

    #: The backdrop is on the painting box, in both slide tones, and is
    #: fully opaque: a token, never a colour with an alpha channel.
    light = re.search(
        r"\.reveal \.controls button \{([^}]*)\}", sheet, re.S
    )
    dark = re.search(
        r"\.reveal\.has-dark-background \.controls button \{([^}]*)\}",
        sheet,
        re.S,
    )

    assert light is not None
    assert dark is not None
    assert "background: var(--blitzy-surface-0);" in light.group(1)
    assert "background: var(--blitzy-primary-navy);" in dark.group(1)
    assert "rgba" not in light.group(1).split("box-shadow")[0]

    #: And the framework's own dimmed back arrow is returned to full
    #: opacity, which the backdrop depends on.
    assert ".reveal .controls button.enabled { opacity: 1; }" in sheet


def test_the_slide_heading_occludes_nothing():
    """The heading scrolls with its slide.

    It was pinned to the top of the scrollport with an offset shadow that
    painted its opaque box over the 60px above it, which stood over the
    lede, the callout or the first table header beneath it.
    """
    sheet = _stylesheet()
    head = re.search(
        r"\.slide-head \{[^}]*position: static;[^}]*\}", sheet, re.S
    )

    assert head is not None
    assert "position: sticky" not in sheet
    assert "box-shadow: 0 -60px" not in sheet


# ---------------------------------------------------------------------
# The diagram pan region, the control gesture and the remaining
# accessibility affordances.

def test_each_diagram_is_a_named_focusable_pan_region():
    """Both diagrams sit in a labelled region a keyboard can reach.

    A drawing wider than the slide pans, and the review found the pan
    region unreachable without a pointer and unmarked by a scrollbar.
    """
    text = _text()
    frames = re.findall(r'<div class="diagram-container"[^>]*>', text)
    sheet = _stylesheet()

    assert len(frames) == 2, frames
    for frame in frames:
        assert 'role="region"' in frame, frame
        assert 'tabindex="0"' in frame, frame
        assert 'aria-label="' in frame, frame
        assert "arrow keys" in frame, frame

    #: The frame is the scrollport, it draws a marked scrollbar, and it
    #: shows a focus ring.
    assert re.search(
        r"\.diagram-container \{[^}]*overflow-x: auto;", sheet, re.S
    )
    assert "scrollbar-width: thin" in sheet
    assert "scrollbar-color: var(--blitzy-primary)" in sheet
    assert ".diagram-container::-webkit-scrollbar {" in sheet
    assert ".reveal .diagram-container:focus-visible {" in sheet

    #: A stable gutter is not declared. It reserves an inline-end strip for
    #: a vertical scrollbar the frame can never show, since its vertical
    #: overflow is hidden, and that strip left the horizontal extent 10px
    #: short of the drawing's own end.
    assert "scrollbar-gutter" not in sheet


def test_the_pan_region_answers_the_keyboard_without_changing_slide():
    """Arrow, Home and End pan the frame and go no further.

    The framework binds the same keys to slide navigation on the
    document, so a key the frame handles is stopped before it arrives
    there. Each frame also opens at its left edge.
    """
    text = _text()
    handler = re.search(
        r"function panFrame\(event\) \{(.*?)\n  \}", text, re.S
    )

    assert handler is not None
    body = handler.group(1)
    for key in ("'ArrowRight'", "'ArrowLeft'", "'Home'", "'End'"):
        assert key in body, key
    assert "event.stopPropagation();" in body
    assert "event.preventDefault();" in body
    assert "frame.addEventListener('keydown', panFrame);" in text
    assert "frame.scrollLeft = 0;" in text
    assert "resetDiagramFrames();" in text


def test_a_gesture_on_a_control_never_reaches_the_swipe_handler():
    """A drag that starts on a control drives that control alone.

    One trusted drag on a chevron advanced two slides: the control acted
    and the framework's swipe acted on the same gesture.
    """
    text = _text()
    hold = re.search(
        r"function holdGesture\(event\) \{(.*?)\n  \}", text, re.S
    )

    assert hold is not None
    assert "closest('.reveal .controls')" in hold.group(1)
    assert "event.stopPropagation();" in hold.group(1)
    assert "event.preventDefault()" not in hold.group(1)
    assert (
        "document.addEventListener(GESTURE_EVENTS[gesture], holdGesture, true)"
        in text
    )

    #: Both gesture families are covered. The framework reads pointer
    #: events wherever the browser provides them, which every current
    #: browser does, and touch events otherwise; stopping only the touch
    #: family left the swipe reachable on the pointer one.
    guarded = re.search(r"var GESTURE_EVENTS = \[(.*?)\];", text, re.S)
    assert guarded is not None
    for event in (
        "'touchstart'", "'touchmove'", "'touchend'", "'touchcancel'",
        "'pointerdown'", "'pointermove'", "'pointerup'", "'pointercancel'",
    ):
        assert event in guarded.group(1), event


def test_the_landmark_role_survives_the_framework():
    """The landmark role is re-asserted after initialization.

    The framework stamps ``role="application"`` on the presentation
    element while it sets the document up, which replaces the landmark
    role a ``main`` element carries and left the accessibility tree with
    no main landmark at all.
    """
    text = _text()
    restore = re.search(
        r"function restoreLandmarkRole\(\) \{(.*?)\n  \}", text, re.S
    )

    assert restore is not None
    assert "querySelector('main.reveal')" in restore.group(1)
    assert "setAttribute('role', 'main')" in restore.group(1)
    assert "restoreLandmarkRole();" in text

    #: Called from the ready handler, which runs after that assignment.
    ready = re.search(
        r"Reveal\.on\('ready', function \(\) \{(.*?)\n  \}\);", text, re.S
    )
    assert ready is not None
    assert "restoreLandmarkRole();" in ready.group(1)


def test_the_presentation_is_a_landmark_with_a_name():
    """The slides sit in one named landmark."""
    text = _text()

    assert '<main class="reveal" aria-label="' in text
    assert '<div class="reveal">' not in text


def test_the_resume_control_carries_a_full_size_target():
    """The framework's resume control reaches 44px."""
    sheet = _stylesheet()
    rule = re.search(
        r"\.pause-overlay \.resume-button \{([^}]*)\}", sheet, re.S
    )

    assert rule is not None
    assert "min-height: 44px" in rule.group(1)
    assert "min-width: 44px" in rule.group(1)


def test_the_drawn_diagram_edges_clear_the_contrast_floor():
    """The drawn edge is darker than the theme value the Rule fixes.

    Rule 2 fixes ``lineColor: '#999999'`` as the library's theme value,
    and that value measures 2.85:1 against the slide surface. The theme
    value is unchanged and the drawn stroke is carried to #6B6B6B, which
    measures 5.3:1.
    """
    text = _text()
    sheet = _stylesheet()

    assert "lineColor: '#999999'" in text
    assert ".flowchart-link" in sheet
    for rule in re.findall(
        r"\.reveal \.mermaid svg [^{]*\{([^}]*)\}", sheet, re.S
    ):
        assert UNDERCONTRAST_GREY not in rule, rule
    assert "stroke: #6B6B6B !important" in sheet
    assert "fill: #6B6B6B !important" in sheet


def test_the_progress_fill_survives_a_forced_palette():
    """The fill names a system colour and clears its gradient.

    The gradient is a background image, which paints over any background
    colour a forced palette substitutes.
    """
    sheet = _stylesheet()
    forced = sheet.split("@media (forced-colors: active) {", 1)[1]
    fill = re.search(
        r"\.reveal \.progress span \{([^}]*)\}", forced, re.S
    )

    assert fill is not None
    assert "background-image: none" in fill.group(1)
    assert "background-color: Highlight" in fill.group(1)


def test_every_mono_rule_names_a_weight_the_font_request_loads():
    """No mono declaration asks for a weight with no file behind it.

    ``.row-mark`` asked for 600 while the request loads 400 and 500, and
    the browser drew a synthesized face.
    """
    sheet = _stylesheet()
    request = re.search(r"Fira\+Code:wght@([0-9;]+)", _text()).group(1)
    loaded = set(request.split(";"))

    for block in re.finditer(r"([^{}]+)\{([^{}]*)\}", sheet):
        declarations = block.group(2)
        if "var(--ff-mono)" not in declarations:
            continue
        for weight in re.findall(r"font-weight:\s*([0-9]+)", declarations):
            assert weight in loaded, (block.group(1).strip(), weight)


def test_every_content_slide_declares_its_type():
    """Rule 2 names four slide types, and each slide carries its own."""
    for number, section in enumerate(_slides(_text()), 1):
        opening = re.match(r"<section\b[^>]*>", section).group(0)
        assert 'class="slide-' in opening, (number, opening)
