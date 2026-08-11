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
    """
    text = _text()

    assert "What still needs an owner" in text
    assert "Rotate the exposed credentials" in text
    assert "Mount the provisioned secrets" in text
    assert "Enable private reporting" in text


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
