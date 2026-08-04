"""Regression cases for the generated documentation shells.

The acceptance gate loaded ``/docs`` and ``/redoc`` at four widths and
found both served from framework templates that omit a document
language, provide no main or navigation landmark and no skip link, skip a
heading level, and leave controls without an id, a name or an accessible
name. ReDoc additionally emitted thirteen ``label`` elements associated
with no field.

Both paths are now served from application-owned shells. The cases below
assert the markup those shells emit, that the paths and verbs the
framework served did not move, and that the runtime attribute pass the
shells carry is complete for every defect the gate named. What only a
browser can settle - that each bundle still renders under the shell, and
what the accessibility tree computes - is verified at runtime and
recorded in ``documentation/security/decision-log.md`` section 48.10.

Rationale is indexed in that log at DL-446 and DL-447.
"""
import re

import pytest

from backend.app.main import (
    DOCS_PATH,
    DOCUMENTATION_PATHS,
    FAVICON_URL,
    GOOGLE_FONTS_URL,
    REDOC_JS_URL,
    REDOC_PATH,
    SWAGGER_CSS_URL,
    SWAGGER_JS_URL,
    SWAGGER_OAUTH2_REDIRECT_PATH,
    app,
    redoc_documentation_html,
    swagger_documentation_html,
)


# The id the skip link targets on every shell
MAIN_LANDMARK_ID = "api-documentation"

# The verbs the framework served each documentation route on
DOCUMENTATION_METHODS = frozenset({"GET", "HEAD"})

# The three paths, in the order a reader meets them
SHELL_PATHS = (DOCS_PATH, REDOC_PATH, SWAGGER_OAUTH2_REDIRECT_PATH)

# The assets each shell is expected to load
SHELL_ASSETS = {
    DOCS_PATH: (SWAGGER_CSS_URL, SWAGGER_JS_URL, FAVICON_URL),
    REDOC_PATH: (GOOGLE_FONTS_URL, REDOC_JS_URL, FAVICON_URL),
}

# The framework template markers that must not reappear
_FRAMEWORK_OAUTH2_MARKER = "swaggerUIRedirectOauth2"

# What the runtime pass sets on the field-labelling side
_PARAMETER_LABEL_TEMPLATE = 'parameter + " (" + location + " parameter)"'

# The two heading levels the runtime pass supplies
_SWAGGER_TITLE_LEVEL = '"2"'
_REDOC_SECTION_LEVEL = '"3"'


def _served(client, path):
    """Return one shell's body, asserting it was served as a document."""
    response = client.get(path)

    assert response.status_code == 200, response.text
    assert response.headers["content-type"].startswith("text/html")
    return response.text


def _routes_for(path):
    """Return every registered route serving one path."""
    return [
        route
        for route in app.routes
        if getattr(route, "path", None) == path
    ]


# QA-07: the document language, which no framework parameter could supply
@pytest.mark.parametrize("path", SHELL_PATHS)
def test_every_shell_declares_the_document_language(client, path):
    """Each shell opens an html element carrying a language."""
    body = _served(client, path)

    assert '<html lang="en">' in body


# QA-07: the landmark structure the framework templates omit
@pytest.mark.parametrize("path", SHELL_PATHS)
def test_every_shell_carries_a_banner_navigation_and_main_landmark(
    client, path
):
    """Each shell emits one header, one nav and one main element."""
    body = _served(client, path)

    assert body.count("<header ") == 1
    assert body.count("<nav ") == 1
    assert body.count("<main ") == 1
    assert 'aria-label="API documentation"' in body


# QA-07: the skip link is the first element in the body, so it is the
# first focusable element on the page
@pytest.mark.parametrize("path", SHELL_PATHS)
def test_the_skip_link_opens_the_body_of_every_shell(client, path):
    """The first element after body is the skip link, and it targets main."""
    body = _served(client, path)
    opened = body.index("<body>") + len("<body>")

    assert body[opened:].lstrip().startswith(
        '<a class="doc-skip-link" href="#{0}">'.format(MAIN_LANDMARK_ID)
    )


# QA-07: a skip link that cannot move the keyboard caret leaves the
# caller in the header the link exists to bypass
@pytest.mark.parametrize("path", SHELL_PATHS)
def test_the_skip_target_can_take_focus(client, path):
    """The main landmark the link targets carries tabindex minus one."""
    body = _served(client, path)

    assert '<main id="{0}" tabindex="-1"'.format(MAIN_LANDMARK_ID) in body


# QA-07: the off-screen-until-focused rule, without which the link is
# either always visible or never reachable
@pytest.mark.parametrize("path", SHELL_PATHS)
def test_the_skip_link_is_offscreen_until_focused(client, path):
    """The stylesheet hides the link and reveals it on focus."""
    body = _served(client, path)

    assert ".doc-skip-link {" in body
    assert "left: -10000px;" in body
    assert ".doc-skip-link:focus { left: 0; }" in body


# QA-07: the level-one heading the framework templates never emit
@pytest.mark.parametrize("path", SHELL_PATHS)
def test_every_shell_carries_one_level_one_heading(client, path):
    """Each shell emits exactly one h1, inside the banner."""
    body = _served(client, path)
    headings = re.findall(r"<h1>(.*?)</h1>", body)

    assert len(headings) == 1
    assert app.title in headings[0]
    assert body.index("<h1>") < body.index("</header>")


# QA-07: the runtime pass levels the one heading rank Swagger skips
def test_the_swagger_shell_levels_the_api_title():
    """The interactive shell sets the API title to level two."""
    body = swagger_documentation_html()

    assert 'querySelector("h1.title")' in body
    assert 'setAttribute("aria-level", {0})'.format(
        _SWAGGER_TITLE_LEVEL
    ) in body


# QA-07: the runtime pass levels the ranks ReDoc skips, in both places
def test_the_redoc_shell_levels_its_title_and_section_headings():
    """The reference shell levels the ReDoc title and every h5."""
    body = redoc_documentation_html()

    assert 'querySelectorAll("h5")' in body
    assert 'setAttribute("aria-level", {0})'.format(
        _REDOC_SECTION_LEVEL
    ) in body
    assert 'setAttribute("aria-level", {0})'.format(
        _SWAGGER_TITLE_LEVEL
    ) in body


# QA-07: every field the bundles render gets an id and a name, which is
# what the gate's control finding asked for
@pytest.mark.parametrize(
    "path", [DOCS_PATH, REDOC_PATH]
)
def test_every_shell_identifies_every_field_the_bundle_renders(client, path):
    """Each shell assigns a missing id and name to every field."""
    body = _served(client, path)

    assert 'querySelectorAll("input, select, textarea")' in body
    assert 'setAttribute("id"' in body
    assert 'setAttribute("name"' in body


# QA-07: the two query-parameter fields the gate named by name are given
# an accessible name built from the row that describes them
def test_the_swagger_shell_names_every_parameter_field():
    """Parameter fields take a name from their own table row."""
    body = swagger_documentation_html()

    assert 'querySelectorAll("tr[data-param-name]")' in body
    assert 'getAttribute("data-param-name")' in body
    assert 'getAttribute("data-param-in")' in body
    assert _PARAMETER_LABEL_TEMPLATE in body


# QA-07: the request-body editor is a control too, and nothing in the
# bundle names it
def test_the_swagger_shell_names_the_request_body_editor():
    """Every textarea the bundle renders is given an accessible name."""
    body = swagger_documentation_html()

    assert 'querySelectorAll("textarea")' in body
    assert '"Request body"' in body


# QA-07: the thirteen control-less label elements are marked
# presentational, so none claims to label a field it does not label
def test_the_redoc_shell_releases_control_less_labels():
    """A label with no target and no nested control is presentational."""
    body = redoc_documentation_html()

    assert 'querySelectorAll("label")' in body
    assert 'getAttribute("for")' in body
    assert 'setAttribute("role", "presentation")' in body


# QA-07: a label that does label something is left alone, so the pass
# cannot strip a working association
def test_the_redoc_shell_leaves_a_working_label_alone():
    """The pass skips a label with a target or a nested control."""
    body = redoc_documentation_html()

    assert 'if (label.getAttribute("for")) { continue; }' in body
    assert "if (label.querySelector(LABELABLE)) { continue; }" in body


# QA-07: a bundle that manages the fragment pre-empts the browser's own
# move-focus-to-the-target step, so the shells carrying a bundle move the
# caret themselves. Measured: without this the interactive page leaves the
# caret in the header the link exists to bypass.
@pytest.mark.parametrize("path", [DOCS_PATH, REDOC_PATH])
def test_the_bundle_shells_move_the_caret_to_the_skip_target(client, path):
    """Activating the skip link focuses the landmark it targets."""
    body = _served(client, path)

    assert 'querySelector(".doc-skip-link")' in body
    assert 'getElementById("{0}")'.format(MAIN_LANDMARK_ID) in body
    assert 'addEventListener("click", function () { target.focus(); })' in body


# QA-07: the callback page needs no handler, which is what lets it stay
# free of script entirely
def test_the_callback_page_needs_no_focus_handler(client):
    """The scriptless page moves the caret without any code of its own."""
    body = _served(client, SWAGGER_OAUTH2_REDIRECT_PATH)

    assert "addEventListener" not in body


# QA-07: an id and a name are supplied independently, so a field the
# bundle already identified still receives the name it lacks
@pytest.mark.parametrize("path", [DOCS_PATH, REDOC_PATH])
def test_a_field_carrying_an_id_still_receives_a_name(client, path):
    """Neither pass returns early on a field that already has an id."""
    body = _served(client, path)

    assert 'if (field.getAttribute("id")) { return; }' not in body
    assert 'if (fields[i].getAttribute("id")) { continue; }' not in body
    assert '!field.getAttribute("name")' in body or (
        '!fields[i].getAttribute("name")' in body
    )


# QA-07: both bundles re-render, so the pass has to run again afterwards
@pytest.mark.parametrize("path", [DOCS_PATH, REDOC_PATH])
def test_every_shell_reapplies_its_pass_after_a_rerender(client, path):
    """Each shell observes its mount point for further renders."""
    body = _served(client, path)

    assert "new MutationObserver(apply)" in body
    assert "childList: true, subtree: true" in body


# QA-07: the pass adds an attribute only where one is absent, so no
# bundle behaviour is replaced
@pytest.mark.parametrize("path", [DOCS_PATH, REDOC_PATH])
def test_the_pass_only_supplies_an_absent_attribute(client, path):
    """No branch overwrites an attribute the bundle already set."""
    body = _served(client, path)
    opened = body.index("<script>", body.index("</main>"))
    script = body[opened:]

    assert "removeAttribute" not in script
    assert "innerHTML" not in script
    assert "replaceChild" not in script
    assert "outerHTML" not in script


# QA-07: the paths the framework served are the paths the shells serve
def test_the_documentation_paths_did_not_move():
    """Each shell is registered on the path the framework used."""
    assert set(DOCUMENTATION_PATHS) == set(SHELL_PATHS)
    for path in SHELL_PATHS:
        assert len(_routes_for(path)) == 1, path


# QA-07: the verbs did not move either
@pytest.mark.parametrize("path", SHELL_PATHS)
def test_every_documentation_route_serves_the_verbs_it_served_before(path):
    """Each documentation route answers GET and HEAD, and nothing else."""
    route = _routes_for(path)[0]

    assert set(route.methods) == DOCUMENTATION_METHODS


# QA-07: a documentation route is not part of the published API surface
@pytest.mark.parametrize("path", SHELL_PATHS)
def test_no_documentation_route_enters_the_schema(client, path):
    """The schema document names no documentation path."""
    document = client.get(app.openapi_url).json()

    assert path not in document["paths"]


# QA-07: the assets are the ones the framework's templates named, so
# owning the markup did not silently change a bundle version
@pytest.mark.parametrize("path", sorted(SHELL_ASSETS))
def test_every_shell_loads_the_assets_the_framework_named(client, path):
    """Each shell references the pinned bundle, style and icon URLs."""
    body = _served(client, path)

    for asset in SHELL_ASSETS[path]:
        assert asset in body, asset


# QA-07: the framework's opener-dereferencing callback script threw on
# every direct visit, and the replacement carries no script at all
def test_the_oauth2_callback_carries_no_script(client):
    """The callback page runs nothing and explains itself instead."""
    body = _served(client, SWAGGER_OAUTH2_REDIRECT_PATH)

    assert "<script" not in body
    assert _FRAMEWORK_OAUTH2_MARKER not in body
    assert "No OAuth2 flow is published" in body


# QA-07: the callback page's heading ladder needs no correction, so it
# is asserted directly rather than through an attribute pass
def test_the_oauth2_callback_headings_are_already_ordered(client):
    """The callback page runs level one to level two and stops."""
    body = _served(client, SWAGGER_OAUTH2_REDIRECT_PATH)
    levels = [
        int(level) for level in re.findall(r"<h([1-6])[ >]", body)
    ]

    assert levels == [1, 2]


# QA-07: the framework must not be able to serve a template of its own
# on any of the three paths
def test_the_framework_documentation_routes_are_switched_off():
    """No framework documentation URL is configured."""
    assert app.docs_url is None
    assert app.redoc_url is None
    assert app.swagger_ui_oauth2_redirect_url is None


# QA-07: each shell points at the other one and at the schema, so the
# navigation landmark carries real navigation
@pytest.mark.parametrize(
    "path, expected",
    [
        (DOCS_PATH, REDOC_PATH),
        (REDOC_PATH, DOCS_PATH),
        (SWAGGER_OAUTH2_REDIRECT_PATH, DOCS_PATH),
    ],
)
def test_the_navigation_landmark_links_the_other_documentation(
    client, path, expected
):
    """Each nav names the alternative page and the schema document."""
    body = _served(client, path)
    opened = body.index("<nav ")
    navigation = body[opened:body.index("</nav>")]

    assert 'href="{0}"'.format(expected) in navigation
    assert 'href="{0}"'.format(app.openapi_url) in navigation


# QA-07: the reference shell keeps a route for a caller with no
# scripting, since the bundle renders entirely in the browser
def test_the_reference_shell_keeps_a_scriptless_fallback(client):
    """The no-script path names the machine-readable schema."""
    body = _served(client, REDOC_PATH)

    assert "<noscript>" in body
    assert app.openapi_url in body[body.index("<noscript>"):]


# QA-07: the shells are documents, so the content policy served on them
# is the documentation one rather than the closed API one
@pytest.mark.parametrize("path", SHELL_PATHS)
def test_every_shell_is_served_the_document_content_policy(client, path):
    """Each shell's policy permits the bundle origin it loads from."""
    response = client.get(path)

    policy = response.headers["Content-Security-Policy"]
    assert "https://cdn.jsdelivr.net" in policy
    assert "frame-ancestors 'none'" in policy


# QA-07: the shells emit no inline event handler, so the content policy
# never needs to permit one
@pytest.mark.parametrize("path", SHELL_PATHS)
def test_no_shell_emits_an_inline_event_handler(client, path):
    """No element carries an on-event attribute."""
    body = _served(client, path)

    assert not re.search(r"\son[a-z]+\s*=", body), path
