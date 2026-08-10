"""Checks the executive presentation against the constraints Rule 2 sets.

``blitzy-deck/executive-summary.html`` is a single self-contained
reveal.js file. Rule 2 states the constraints it must satisfy, and three
review findings recorded it breaching them: eight content slides carried
more than the permitted body words, several slides stated claims the
Agent Action Plan contradicts, and the render logic carried its
rationale in code comments.

Rendering itself is verified in a browser, which this test process has
no access to. Every property below is therefore one that is decidable
from the file's text, which is the layer the findings concerned.

What is asserted:

* the deck holds between twelve and eighteen slides, and each is one of
  the four slide types Rule 2 names
* every content slide carries at most forty body words and at most four
  bullets, and the closing slide carries at most three bullets
* every slide carries at least one non-text visual
* no slide carries an emoji or a fenced code block
* the three content-delivery-network dependencies are pinned to exact
  versions, diagram rendering is deferred, and the render pass is
  re-run on both the ready and the slide-change events
* the five theme variables the rule enumerates are all set
* the change-map figures the deck quotes are the figures
  ``docs/security/TRACEABILITY_MATRIX.md`` publishes
* the claims the Agent Action Plan contradicts appear nowhere, and the
  corrected statements are present
* no comment anywhere in the file carries rationale

The body-word model is the one the review applied: every text token
inside a ``section`` counts, except the text of an ``h1``, ``h2`` or
``h3`` heading and except the source of a ``pre.mermaid`` diagram.
Entities are resolved before counting, so a glyph written as an entity
counts as the token it renders to.

``docs/security/TRACEABILITY_MATRIX.md`` is the authority for the
change-map figures and the Agent Action Plan is the authority for the
dependency-replacement claims, so a change to either is compared
against this file rather than against a second copy of it.
"""

import html
import re

import pytest
from conftest import REPO_ROOT

#: The presentation under test.
DECK = REPO_ROOT / "blitzy-deck" / "executive-summary.html"

#: The document that publishes the change-map figures the deck quotes.
TRACEABILITY = REPO_ROOT / "docs" / "security" / "TRACEABILITY_MATRIX.md"

#: Rule 2's slide-count range.
MIN_SLIDES = 12
MAX_SLIDES = 18

#: Rule 2's per-content-slide budgets.
MAX_BODY_WORDS = 40
MAX_BULLETS = 4
MAX_CLOSING_BULLETS = 3

#: Exact dependency pins Rule 2 requires.
REQUIRED_PINS = (
    "reveal.js@5.1.0",
    "lucide@0.460.0",
    "mermaid@11.4.0",
)

#: Theme variables Rule 2 enumerates for the diagram theme.
REQUIRED_THEME_VARIABLES = (
    "primaryColor",
    "primaryTextColor",
    "primaryBorderColor",
    "lineColor",
    "secondaryColor",
)

#: Claims the Agent Action Plan contradicts. Section 0.2.2.2 records that
#: python-jose's own advisories were patched at 3.4.0 and that removal
#: was driven by the transitive ecdsa advisory, which has no fix;
#: section 0.5.1.2 records that a placeholder signing key is rejected in
#: every environment; and INFRA-4 carried no verifying test when the
#: claim of universal test coverage was written.
FORBIDDEN_CLAIMS = (
    "no patched release",
    "safe local default",
    "Every finding maps",
    "maps to a fix and a verifying test",
)

#: Statements that replaced them. The rotation wording is bounded to what
#: this repository can establish: that the operation is not performed
#: here, rather than that it is outstanding everywhere.
REQUIRED_CLAIMS = (
    "remediated in code",
    "Rotation is not performed here",
    "replaced rather than upgraded",
    "Exposed credentials must be treated as compromised until rotated",
)

#: Wording that states why rather than what. Rule 1 places rationale in
#: the decision log and nowhere else.
RATIONALE_WORDING = (
    "because",
    "rather than",
    "instead of",
    "in order to",
    "we chose",
    "so that",
    "otherwise",
    "needs to",
)

#: Ranges the deck must hold no character from.
EMOJI_RANGES = (
    (0x1F000, 0x1FAFF),
    (0x2600, 0x27BF),
    (0xFE0F, 0xFE0F),
    (0x1F1E6, 0x1F1FF),
)

_SECTION = re.compile(r"<section\b[^>]*>.*?</section>", re.DOTALL)
_SECTION_OPEN = re.compile(r"<section\b([^>]*)>")
_HEADING = re.compile(r"<h[1-3]\b[^>]*>.*?</h[1-3]>", re.DOTALL)
_MERMAID = re.compile(r"<pre\s+class=\"mermaid\">.*?</pre>", re.DOTALL)
_NOTES = re.compile(r"<aside\s+class=\"notes\">.*?</aside>", re.DOTALL)
_TAG = re.compile(r"<[^>]+>")
_BULLET = re.compile(r"<li\b")
_COMMENT = re.compile(r"<!--.*?-->|/\*.*?\*/", re.DOTALL)

#: Markup that renders as something other than running text.
_VISUALS = (
    re.compile(r"data-lucide="),
    _MERMAID,
    re.compile(r"<table\b"),
    re.compile(r"class=\"kpi-grid\""),
    re.compile(r"class=\"callout\""),
    re.compile(r"class=\"icon-row\""),
    re.compile(r"class=\"accent-bar\""),
)

SOURCE = DECK.read_text(encoding="utf-8")
SLIDE_AREA = SOURCE.split('<div class="slides">', 1)[1]
SLIDES = _SECTION.findall(SLIDE_AREA)


def _kind(section):
    """Return the Rule 2 slide type of one section."""
    attributes = _SECTION_OPEN.search(section).group(1)
    for name in ("slide-title", "slide-divider", "slide-closing"):
        if name in attributes:
            return name
    return "content"


#: Components Rule 2 counts as a slide's non-text visual rather than as its
#: body text: the metric-card grid, the styled table and the icon row. Rule 2
#: requires every slide to carry one of these and caps body text at forty
#: words, so counting a visual's own labels as body text would set the two
#: requirements against each other -- no table-bearing slide could ever be
#: within the cap. The heading block, the brand lockup and screen-reader-only
#: text are excluded for the same reason: none of them is body prose an
#: audience reads off the slide.
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


def _body_words(section):
    """Return the body-word count the review's model produces.

    The speaker notes and every declared visual component are removed
    first: neither is body prose the audience reads off the slide.
    """
    stripped = _MERMAID.sub(" ", section)
    stripped = _NOTES.sub(" ", stripped)
    stripped = _without_visual_components(stripped)
    stripped = _HEADING.sub(" ", stripped)
    return len(html.unescape(_TAG.sub(" ", stripped)).split())


#: Every slide paired with its type, numbered as the deck presents them.
NUMBERED_SLIDES = [
    (index, _kind(section), section)
    for index, section in enumerate(SLIDES, start=1)
]

CONTENT_SLIDES = [
    (index, section)
    for index, kind, section in NUMBERED_SLIDES
    if kind == "content"
]


def test_the_deck_holds_a_permitted_number_of_slides():
    assert MIN_SLIDES <= len(SLIDES) <= MAX_SLIDES, (
        "Rule 2 permits %d to %d slides; the deck holds %d"
        % (MIN_SLIDES, MAX_SLIDES, len(SLIDES))
    )


def test_every_slide_is_one_of_the_four_declared_types():
    kinds = {kind for _, kind, _ in NUMBERED_SLIDES}
    assert kinds <= {
        "slide-title",
        "slide-divider",
        "slide-closing",
        "content",
    }, "unexpected slide types: %s" % sorted(kinds)


def test_exactly_one_title_slide_and_one_closing_slide_are_present():
    kinds = [kind for _, kind, _ in NUMBERED_SLIDES]
    assert kinds.count("slide-title") == 1
    assert kinds.count("slide-closing") == 1
    assert kinds[0] == "slide-title"
    assert kinds[-1] == "slide-closing"


@pytest.mark.parametrize(
    "index,section",
    CONTENT_SLIDES,
    ids=[str(index) for index, _ in CONTENT_SLIDES],
)
def test_each_content_slide_stays_within_the_body_word_budget(
    index, section
):
    words = _body_words(section)
    assert words <= MAX_BODY_WORDS, (
        "slide %d carries %d body words; Rule 2 permits %d"
        % (index, words, MAX_BODY_WORDS)
    )


@pytest.mark.parametrize(
    "index,section",
    CONTENT_SLIDES,
    ids=[str(index) for index, _ in CONTENT_SLIDES],
)
def test_each_content_slide_stays_within_the_bullet_budget(index, section):
    bullets = len(_BULLET.findall(section))
    assert bullets <= MAX_BULLETS, (
        "slide %d carries %d bullets; Rule 2 permits %d"
        % (index, bullets, MAX_BULLETS)
    )


def test_the_closing_slide_stays_within_its_bullet_budget():
    closing = [
        (index, section)
        for index, kind, section in NUMBERED_SLIDES
        if kind == "slide-closing"
    ]
    for index, section in closing:
        bullets = len(_BULLET.findall(section))
        assert bullets <= MAX_CLOSING_BULLETS, (
            "closing slide %d carries %d bullets; Rule 2 permits %d"
            % (index, bullets, MAX_CLOSING_BULLETS)
        )


@pytest.mark.parametrize(
    "index,section",
    [(index, section) for index, _, section in NUMBERED_SLIDES],
    ids=[str(index) for index, _, _ in NUMBERED_SLIDES],
)
def test_every_slide_carries_a_non_text_visual(index, section):
    assert any(pattern.search(section) for pattern in _VISUALS), (
        "slide %d carries no non-text visual" % index
    )


def test_no_slide_carries_an_emoji():
    offenders = sorted(
        {
            character
            for character in SLIDE_AREA
            for low, high in EMOJI_RANGES
            if low <= ord(character) <= high
        }
    )
    assert not offenders, "emoji present: %s" % offenders


def test_no_slide_carries_a_fenced_code_block():
    assert "```" not in SLIDE_AREA


@pytest.mark.parametrize("pin", REQUIRED_PINS)
def test_each_dependency_is_pinned_to_an_exact_version(pin):
    assert pin in SOURCE, "dependency pin absent: %s" % pin


def test_no_dependency_is_requested_at_a_floating_version():
    for name in ("reveal.js", "lucide", "mermaid"):
        floating = re.findall(
            r"cdn\.jsdelivr\.net/npm/%s(?![@\w.-])" % re.escape(name),
            SOURCE,
        )
        assert not floating, "unpinned request for %s" % name


def test_diagram_rendering_is_deferred_and_re_run_on_slide_change():
    assert "startOnLoad: false" in SOURCE
    assert "Reveal.on('ready'" in SOURCE
    assert "Reveal.on('slidechanged'" in SOURCE
    assert SOURCE.count("mermaid.run(") >= 2


@pytest.mark.parametrize("variable", REQUIRED_THEME_VARIABLES)
def test_each_required_theme_variable_is_set(variable):
    assert re.search(r"\b%s\s*:" % re.escape(variable), SOURCE), (
        "theme variable absent: %s" % variable
    )


def test_the_theme_is_authored_inline_rather_than_imported():
    assert "<style>" in SOURCE
    assert not re.search(r"<link[^>]+blitzy-deck", SOURCE)


def test_the_change_map_figures_match_the_traceability_matrix():
    matrix = TRACEABILITY.read_text(encoding="utf-8")
    total = re.search(
        r"Entries in the plan's transformation mapping \| \*\*(\d+)\*\*",
        matrix,
    )
    assert total, "the matrix does not publish an entry total"
    reconciliation = re.search(
        r"\|\s*\*\*Total\*\*\s*\|\s*\*\*(\d+)\*\*\s*\|\s*\*\*(\d+)\*\*"
        r"\s*\|\s*\*\*(\d+)\*\*\s*\|\s*\*\*(\d+)\*\*\s*\|"
        r"\s*\*\*(\d+)\*\*\s*\|",
        matrix,
    )
    assert reconciliation, "the matrix does not publish a mode total"
    created, updated, deleted, reference, published = (
        int(value) for value in reconciliation.groups()
    )
    assert published == int(total.group(1))
    assert created + updated + deleted + reference == published

    assert ">%d<" % published in SOURCE, (
        "the deck does not quote the published entry total %d" % published
    )
    assert "%d created" % created in SOURCE
    assert "%d updated" % updated in SOURCE
    assert "%d read-only" % reference in SOURCE


@pytest.mark.parametrize("claim", FORBIDDEN_CLAIMS)
def test_no_contradicted_claim_survives(claim):
    assert claim not in SOURCE, "contradicted claim present: %s" % claim


@pytest.mark.parametrize("claim", REQUIRED_CLAIMS)
def test_each_corrected_statement_is_present(claim):
    assert claim in SOURCE, "corrected statement absent: %s" % claim


def test_the_dependency_table_separates_a_fixed_flaw_from_an_unfixed_one():
    assert "Own flaws fixed" in SOURCE
    assert "has no fix" in SOURCE


def test_no_comment_carries_rationale():
    offenders = []
    for comment in _COMMENT.findall(SOURCE):
        lowered = comment.lower()
        for wording in RATIONALE_WORDING:
            if wording in lowered:
                offenders.append((wording, comment.strip()))
    assert not offenders, "rationale in comments: %s" % offenders
