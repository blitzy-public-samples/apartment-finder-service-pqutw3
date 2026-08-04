import logging
import os
import re
import sys
import threading
import time
import traceback
import uuid
from http import HTTPStatus
from urllib.parse import urlsplit

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError, StarletteHTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware
from starlette.datastructures import MutableHeaders
from starlette.middleware.trustedhost import TrustedHostMiddleware
from sqlalchemy.exc import SQLAlchemyError
from backend.app.api.endpoints.auth import (
    RETRY_AFTER_HEADER,
    limiter,
    retry_after_seconds,
)
from backend.app.api.router import api_router
from backend.app.core.config import settings
from backend.app.db.database import engine
from backend.app.db.models import Base

logger = logging.getLogger(__name__)

# SEC-08: the package logger every application record propagates through
_APPLICATION_LOGGER_NAME = "backend.app"

# SEC-08: the level and the shape of a record on the diagnostic channel
_LOG_LEVEL = logging.INFO
_LOG_FORMAT = "%(asctime)s %(levelname)s %(name)s %(message)s"

# SEC-08: what replaces a newline inside one record
_JOINED_LINE_MARKER = "\\n"


# SEC-08: control characters a record may not carry into any sink. Every
# C0 code point and DEL is replaced, the newline included. DL-364
_CONTROL_CHARACTER_TRANSLATION = {
    code: _JOINED_LINE_MARKER
    for code in range(0x20)
    if code != 0x20
}
_CONTROL_CHARACTER_TRANSLATION[0x7F] = _JOINED_LINE_MARKER


def _single_line(text: str) -> str:
    # SEC-08: one record occupies one line (CWE-117, CWE-778)
    return text.translate(_CONTROL_CHARACTER_TRANSLATION)


def _fold_record(record: logging.LogRecord) -> logging.LogRecord:
    # SEC-08: renders one record's whole text - message, exception and stack
    # - and folds it onto a single line, in place
    rendered = record.getMessage()
    if record.exc_info:
        rendered = "%s\n%s" % (
            rendered,
            "".join(traceback.format_exception(*record.exc_info)),
        )
    if record.stack_info:
        rendered = "%s\n%s" % (rendered, record.stack_info)
    record.msg = _single_line(rendered)
    record.args = ()
    # SEC-08: the folded text is the message; the record carries no
    # separate diagnostics for a formatter to append. DL-364
    record.exc_info = None
    record.exc_text = None
    record.stack_info = None
    return record


def _owns_record(name: str) -> bool:
    # SEC-08: this package's records, and no other library's
    return name == _APPLICATION_LOGGER_NAME or name.startswith(
        "{0}.".format(_APPLICATION_LOGGER_NAME)
    )


def _install_single_line_records() -> None:
    # SEC-08: folds every record this package creates at creation, ahead
    # of Logger.handle, every handler and propagation to an ancestor sink
    # (CWE-117, CWE-778). DL-364
    previous = logging.getLogRecordFactory()
    if getattr(previous, "_folds_application_records", False):
        return

    def factory(name, level, fn, lno, msg, args, exc_info, func=None,
                sinfo=None, **kwargs):
        record = previous(
            name, level, fn, lno, msg, args, exc_info, func, sinfo, **kwargs
        )
        if _owns_record(record.name):
            _fold_record(record)
        return record

    factory._folds_application_records = True
    logging.setLogRecordFactory(factory)


class _SingleLineFormatter(logging.Formatter):
    # SEC-08: the sink this module owns re-applies the same normalization
    # to the record and to the text the format string contributes
    # (CWE-778). DL-364
    def format(self, record: logging.LogRecord) -> str:
        return _single_line(super().format(record))


class _ApplicationLogHandler(logging.StreamHandler):
    # SEC-08: the diagnostic-channel handler this module owns
    pass


def _configure_application_logging() -> None:
    # SEC-08: gives this package a level, a timestamp and a logger name
    # on its own handler (CWE-778). DL-364
    application_logger = logging.getLogger(_APPLICATION_LOGGER_NAME)
    application_logger.setLevel(_LOG_LEVEL)
    _install_single_line_records()
    for handler in application_logger.handlers:
        if isinstance(handler, _ApplicationLogHandler):
            return
    handler = _ApplicationLogHandler(stream=sys.stderr)
    handler.setLevel(_LOG_LEVEL)
    handler.setFormatter(_SingleLineFormatter(_LOG_FORMAT))
    application_logger.addHandler(handler)


_configure_application_logging()

# QA-07: the framework's own documentation routes are switched off and
# replaced below. Their templates emit an html element with no lang, no
# landmark, no skip link and a heading level jump, none of which any
# parameter can correct (WCAG 3.1.1, 1.3.1, 2.4.1). DL-446
app = FastAPI(
    docs_url=None,
    redoc_url=None,
    swagger_ui_oauth2_redirect_url=None,
)

# QA-07: the paths the replacements are served on, unchanged from the
# framework defaults so no route path or verb moves. DL-446
DOCS_PATH = "/docs"
REDOC_PATH = "/redoc"
SWAGGER_OAUTH2_REDIRECT_PATH = "/docs/oauth2-redirect"

# QA-07: the assets the replacement shells load, at the versions the
# framework's own templates named. The content policy below derives its
# permitted origins from these, so an asset and its policy cannot drift.
SWAGGER_CSS_URL = (
    "https://cdn.jsdelivr.net/npm/swagger-ui-dist@5/swagger-ui.css"
)
SWAGGER_JS_URL = (
    "https://cdn.jsdelivr.net/npm/swagger-ui-dist@5/swagger-ui-bundle.js"
)
REDOC_JS_URL = (
    "https://cdn.jsdelivr.net/npm/redoc@2/bundles/redoc.standalone.js"
)
FAVICON_URL = "https://fastapi.tiangolo.com/img/favicon.png"
GOOGLE_FONTS_URL = (
    "https://fonts.googleapis.com/css?family="
    "Montserrat:300,400,700|Roboto:300,400,700"
)

# QA-07: the ReDoc bundle requests its attribution glyph from this origin
# at runtime. No served markup names it, so a browser is what found it.
REDOC_IMAGE_ORIGIN = "https://cdn.redoc.ly"

# QA-07: the origin the Google Fonts stylesheet fetches its font files
# from, named by that stylesheet rather than by any markup here
GOOGLE_FONT_FILE_ORIGIN = "https://fonts.gstatic.com"

# SEC-07: registers the single login throttle limiter defined in auth.py
app.state.limiter = limiter
app.add_middleware(SlowAPIMiddleware)

def create_tables():
    # SEC-11: DDL for absent tables only (CWE-250). DL-364
    Base.metadata.create_all(bind=engine, checkfirst=True)


class SanitizedServerErrorMiddleware:
    # SEC-08: answers an unhandled exception with the sanitized envelope from
    # inside the CORS layer (CWE-209)
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        started = False

        async def send_started(message):
            nonlocal started
            if message["type"] == "http.response.start":
                started = True
            await send(message)

        try:
            await self.app(scope, receive, send_started)
        except Exception as exc:
            # SEC-08: a partially sent response cannot be replaced
            if started:
                raise
            response = handle_unhandled_exception(
                Request(scope, receive), exc
            )
            await response(scope, receive, send)


# QA-09: response headers every browser-facing answer carries. Each is a
# defence-in-depth instruction to the browser, and none was present before.
# Two headers are absent from this mapping because they are conditional:
# the content policy varies by path and HSTS by scheme. DL-444
BASELINE_SECURITY_HEADERS = (
    # CWE-430: no content-type sniffing, so a JSON body is never executed
    ("X-Content-Type-Options", "nosniff"),
    # CWE-1021: no framing, for a browser predating frame-ancestors
    ("X-Frame-Options", "DENY"),
    # CWE-200: no path or query reaches another origin through Referer
    ("Referrer-Policy", "no-referrer"),
    # CWE-1021: every powerful browser feature denied
    (
        "Permissions-Policy",
        "accelerometer=(), autoplay=(), camera=(), display-capture=(), "
        "encrypted-media=(), fullscreen=(), geolocation=(), gyroscope=(), "
        "magnetometer=(), microphone=(), midi=(), payment=(), "
        "picture-in-picture=(), usb=(), xr-spatial-tracking=()",
    ),
    # CWE-1021: no cross-origin window keeps a handle on a document served
    # from this origin. Cross-Origin-Resource-Policy is deliberately absent:
    # it is consulted for no-cors loads and the SPA reads this API in cors
    # mode with credentials, which SEC-03 already bounds by origin. DL-444
    ("Cross-Origin-Opener-Policy", "same-origin"),
)

CONTENT_SECURITY_POLICY_HEADER = "Content-Security-Policy"

# QA-09: the policy for the API surface. Every response on it is JSON or
# empty, so a document rendered from one needs no script, style, image or
# frame, may not be framed, may not rebase its relative URLs and may not
# submit a form (CWE-79, CWE-1021). DL-444
API_CONTENT_SECURITY_POLICY = (
    "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; "
    "form-action 'none'"
)


def origin_of(url: str) -> str:
    # QA-09: the scheme-and-host prefix one asset URL is fetched from,
    # so a permitted source is read from the asset rather than restated
    # beside it (CWE-79). DL-444
    parts = urlsplit(url)
    return "{0}://{1}".format(parts.scheme, parts.netloc)


# QA-09: every origin the documentation shells load from, each derived
# from the asset that needs it. The last two are named by a bundle or by
# a stylesheet rather than by any markup, so a browser found them. DL-444
_BUNDLE_ORIGIN = origin_of(SWAGGER_JS_URL)
_BUNDLE_IMAGE_ORIGIN = REDOC_IMAGE_ORIGIN
_FAVICON_ORIGIN = origin_of(FAVICON_URL)
_FONT_STYLE_ORIGIN = origin_of(GOOGLE_FONTS_URL)
_FONT_FILE_ORIGIN = GOOGLE_FONT_FILE_ORIGIN

# QA-09: the policy for the generated documentation pages, which are HTML
# documents loading their bundles from a CDN. Every source is named, and
# the framing, base-URI and form-action denials are the API policy's
# (CWE-79, CWE-1021). connect-src names the bundle origin because
# script-src already trusts it to execute: a fetch destination cannot be
# meaningfully narrower than a code source for the same origin, and
# withholding it only suppresses the source maps a browser's own
# developer tools request. DL-444
DOCUMENTATION_CONTENT_SECURITY_POLICY = (
    "default-src 'none'; "
    "script-src 'self' {bundle} 'unsafe-inline'; "
    "style-src 'self' {bundle} {font_style} 'unsafe-inline'; "
    "font-src 'self' {bundle} {font_file}; "
    "img-src 'self' data: {bundle} {bundle_image} {favicon}; "
    "connect-src 'self' {bundle}; "
    "worker-src 'self' blob:; "
    "frame-ancestors 'none'; base-uri 'none'; form-action 'none'"
).format(
    bundle=_BUNDLE_ORIGIN,
    bundle_image=_BUNDLE_IMAGE_ORIGIN,
    favicon=_FAVICON_ORIGIN,
    font_style=_FONT_STYLE_ORIGIN,
    font_file=_FONT_FILE_ORIGIN,
)

# QA-09: the paths answered with an HTML document. QA-07 replaced the
# framework's documentation routes with the shells below, so the set is
# read from the paths those shells are registered on. DL-444, DL-446
DOCUMENTATION_PATHS = frozenset(
    {DOCS_PATH, REDOC_PATH, SWAGGER_OAUTH2_REDIRECT_PATH}
)

# QA-09: sent only over TLS. Over plain HTTP a compliant browser ignores
# it, and asserting it there would be a false claim in a local or
# plaintext-proxied deployment, so the header follows the scheme the
# request arrived on (CWE-319). The TLS edge stays authoritative. DL-444
STRICT_TRANSPORT_SECURITY_HEADER = "Strict-Transport-Security"
STRICT_TRANSPORT_SECURITY = "max-age=31536000; includeSubDomains"

# QA-09: the schemes that make a connection secure enough for HSTS
_SECURE_SCHEMES = frozenset({"https", "wss"})


def content_security_policy_for(path: str) -> str:
    # QA-09: the policy one path is answered under (CWE-79). DL-444
    if path in DOCUMENTATION_PATHS:
        return DOCUMENTATION_CONTENT_SECURITY_POLICY
    return API_CONTENT_SECURITY_POLICY


class SecurityHeadersMiddleware:
    # QA-09: adds the baseline headers to every response, the refusals the
    # layers above produce included. A header a response already carries is
    # left alone, so a route may narrow its own policy further
    # (CWE-693). DL-444
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        secure = scope.get("scheme") in _SECURE_SCHEMES
        policy = content_security_policy_for(scope.get("path", ""))

        async def send_with_headers(message):
            if message["type"] == "http.response.start":
                headers = MutableHeaders(scope=message)
                for name, value in BASELINE_SECURITY_HEADERS:
                    if name not in headers:
                        headers[name] = value
                if CONTENT_SECURITY_POLICY_HEADER not in headers:
                    headers[CONTENT_SECURITY_POLICY_HEADER] = policy
                if secure and STRICT_TRANSPORT_SECURITY_HEADER not in headers:
                    headers[STRICT_TRANSPORT_SECURITY_HEADER] = (
                        STRICT_TRANSPORT_SECURITY
                    )
            await send(message)

        await self.app(scope, receive, send_with_headers)


# SEC-08: registered before CORSMiddleware, which places this layer inside it
app.add_middleware(SanitizedServerErrorMiddleware)

# Application setup and configuration
# SEC-03: explicit method/header allow-list; closes the
# wildcard-with-credentials CORS policy (CWE-942, CWE-346)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Accept", "Authorization", "Content-Type"],
    # SEC-07: a cross-origin caller cannot read a response header that is
    # not exposed, so the throttle recovery hint would be unreadable
    expose_headers=[RETRY_AFTER_HEADER],
    max_age=600,
)

# QA-03: exact Host allow-list, registered outside every layer above so an
# untrusted or malformed Host value is refused before routing reconstructs a
# URL from it. Closes the reachable half of PYSEC-2026-161 (CWE-20, CWE-350).
# www_redirect is off, so no refusal answers with a redirect. DL-439
app.add_middleware(
    TrustedHostMiddleware,
    allowed_hosts=settings.ALLOWED_HOSTS,
    www_redirect=False,
)

# QA-09: registered last, therefore the outermost layer, so the baseline
# headers reach every response - the Host refusal above, a CORS preflight,
# a throttle refusal and a sanitized error included (CWE-693). DL-444
app.add_middleware(SecurityHeadersMiddleware)

# QA-07: the id the skip link targets. The landmark carrying it also
# carries tabindex="-1", without which the link moves the scroll position
# but not the keyboard caret, so the next key press returns to the header
# the link exists to bypass (WCAG 2.4.1). DL-446
_DOCUMENTATION_MAIN_ID = "api-documentation"

# QA-07: the mount point each bundle renders into, kept inside the main
# landmark so the landmark survives the bundle replacing its contents
_SWAGGER_MOUNT_ID = "swagger-ui"

# QA-07: the skip link is the first focusable element on the page and is
# off-screen until focused, so a keyboard caller reaches the documentation
# without traversing the header (WCAG 2.4.1). The header rule keeps the
# stock zero body margin both framework templates set. DL-446
_DOCUMENTATION_STYLES = """
    html { color-scheme: light; }
    body { margin: 0; padding: 0; }
    .doc-skip-link {
      position: absolute;
      left: -10000px;
      top: 0;
      z-index: 1000;
      padding: 0.5rem 1rem;
      background: #ffffff;
      color: #12263f;
      border: 2px solid #12263f;
      font: 700 1rem/1.4 system-ui, -apple-system, sans-serif;
      text-decoration: none;
    }
    .doc-skip-link:focus { left: 0; }
    .doc-header {
      display: flex;
      flex-wrap: wrap;
      align-items: baseline;
      gap: 0.25rem 1.5rem;
      padding: 0.5rem 1rem;
      border-bottom: 1px solid #d8dde6;
      background: #ffffff;
      font: 400 1rem/1.4 system-ui, -apple-system, sans-serif;
    }
    .doc-header h1 {
      margin: 0;
      font-size: 1.0625rem;
      font-weight: 700;
      color: #12263f;
    }
    .doc-header ul {
      display: flex;
      flex-wrap: wrap;
      gap: 0 1rem;
      margin: 0;
      padding: 0;
      list-style: none;
    }
    .doc-header a {
      color: #1f6feb;
      font-size: 0.9375rem;
    }
    .doc-copy {
      max-width: 42rem;
      padding: 1rem;
      font: 400 1rem/1.5 system-ui, -apple-system, sans-serif;
      color: #12263f;
    }
    .doc-copy h2 { font-size: 1.25rem; margin: 0 0 0.5rem; }
    .doc-copy p { margin: 0; }
    .doc-copy a { color: #1f6feb; }
"""

# QA-07: moves the keyboard caret to the landmark the skip link targets.
# A bundle that manages the fragment itself - the interactive one does, to
# deep-link an operation - pre-empts the browser's own move-focus-to-the
# -target step, so the link would scroll and leave the caret in the header
# it exists to bypass. Measured on all three shells: without this the
# interactive page fails and the other two pass (WCAG 2.4.1). DL-446
_SKIP_LINK_FOCUS_SCRIPT = """
    (function () {
      var link = document.querySelector(".doc-skip-link");
      var target = document.getElementById("__MAIN__");
      if (!link || !target) { return; }
      link.addEventListener("click", function () { target.focus(); });
    })();
"""

# QA-07: names the two controls the Swagger bundle renders without an id
# or a name, levels the API title so no heading level is skipped, and
# reapplies both after the bundle re-renders. Only attributes are added,
# and only where one is absent, so no bundle behaviour is replaced
# (WCAG 1.3.1, 3.3.2, 4.1.2). DL-447
_SWAGGER_ACCESSIBILITY_SCRIPT = """
    (function () {
      var root = document.getElementById("__MOUNT__");
      if (!root) { return; }
      var generated = 0;
      function identify(field) {
        if (!field.getAttribute("id")) {
          generated += 1;
          field.setAttribute("id", "swagger-field-" + generated);
        }
        if (!field.getAttribute("name")) {
          field.setAttribute("name", field.getAttribute("id"));
        }
      }
      function levelApiTitle() {
        var title = root.querySelector("h1.title");
        if (title && !title.getAttribute("aria-level")) {
          title.setAttribute("aria-level", "2");
        }
      }
      function nameParameterFields() {
        var rows = root.querySelectorAll("tr[data-param-name]");
        for (var i = 0; i < rows.length; i += 1) {
          var field = rows[i].querySelector("input, select, textarea");
          if (!field) { continue; }
          var parameter = rows[i].getAttribute("data-param-name");
          var location = rows[i].getAttribute("data-param-in") || "query";
          identify(field);
          if (!field.getAttribute("aria-label")) {
            field.setAttribute(
              "aria-label", parameter + " (" + location + " parameter)"
            );
          }
        }
      }
      function nameRequestBodyFields() {
        var fields = root.querySelectorAll("textarea");
        for (var i = 0; i < fields.length; i += 1) {
          identify(fields[i]);
          if (!fields[i].getAttribute("aria-label")) {
            fields[i].setAttribute("aria-label", "Request body");
          }
        }
      }
      function identifyEveryField() {
        var fields = root.querySelectorAll("input, select, textarea");
        for (var i = 0; i < fields.length; i += 1) { identify(fields[i]); }
      }
      function apply() {
        levelApiTitle();
        nameParameterFields();
        nameRequestBodyFields();
        identifyEveryField();
      }
      apply();
      if (window.MutationObserver) {
        new MutationObserver(apply).observe(
          root, { childList: true, subtree: true }
        );
      }
    })();
"""

# QA-07: levels the two heading ranks the ReDoc bundle skips, marks its
# control-less row wrappers presentational so none claims to label a
# field it does not label, and names its search field. Attributes only,
# and only where absent (WCAG 1.3.1, 4.1.2). DL-447
_REDOC_ACCESSIBILITY_SCRIPT = """
    (function () {
      var root = document.querySelector("redoc");
      if (!root) { return; }
      var LABELABLE = "input, select, textarea, button, meter, output," +
        " progress";
      var generated = 0;
      function levelHeadings() {
        var title = root.querySelector("h1");
        if (title && !title.getAttribute("aria-level")) {
          title.setAttribute("aria-level", "2");
        }
        var sections = root.querySelectorAll("h5");
        for (var i = 0; i < sections.length; i += 1) {
          if (!sections[i].getAttribute("aria-level")) {
            sections[i].setAttribute("aria-level", "3");
          }
        }
      }
      function releaseControlLessLabels() {
        var labels = root.querySelectorAll("label");
        for (var i = 0; i < labels.length; i += 1) {
          var label = labels[i];
          if (label.getAttribute("for")) { continue; }
          if (label.querySelector(LABELABLE)) { continue; }
          if (label.getAttribute("role")) { continue; }
          label.setAttribute("role", "presentation");
        }
      }
      function identifyEveryField() {
        var fields = root.querySelectorAll("input, select, textarea");
        for (var i = 0; i < fields.length; i += 1) {
          if (!fields[i].getAttribute("id")) {
            generated += 1;
            fields[i].setAttribute("id", "redoc-field-" + generated);
          }
          if (!fields[i].getAttribute("name")) {
            fields[i].setAttribute("name", fields[i].getAttribute("id"));
          }
        }
      }
      function apply() {
        levelHeadings();
        releaseControlLessLabels();
        identifyEveryField();
      }
      apply();
      if (window.MutationObserver) {
        new MutationObserver(apply).observe(
          root, { childList: true, subtree: true }
        );
      }
    })();
"""


def _documentation_head(title: str, stylesheets) -> str:
    # QA-07: the head every documentation shell shares. The lang
    # attribute is the whole point of owning this markup: no framework
    # parameter can add it (WCAG 3.1.1). DL-446
    links = [
        '<link rel="stylesheet" href="{0}">'.format(href)
        for href in stylesheets
    ]
    links.append('<link rel="icon" href="{0}">'.format(FAVICON_URL))
    return "\n".join(
        [
            "<!DOCTYPE html>",
            '<html lang="en">',
            "<head>",
            '<meta charset="utf-8">',
            '<meta name="viewport" content="width=device-width, '
            'initial-scale=1">',
            "<title>{0}</title>".format(title),
        ]
        + links
        + [
            "<style>{0}</style>".format(_DOCUMENTATION_STYLES),
            "</head>",
        ]
    )


def _documentation_header(heading: str, alternative_path: str,
                          alternative_label: str) -> str:
    # QA-07: the banner and navigation landmarks, the level-one heading
    # the framework templates omit, and the skip link, in the order a
    # keyboard caller meets them (WCAG 1.3.1, 2.4.1). DL-446
    return "\n".join(
        [
            '<a class="doc-skip-link" href="#{0}">'
            "Skip to API documentation</a>".format(_DOCUMENTATION_MAIN_ID),
            '<header class="doc-header">',
            "<h1>{0}</h1>".format(heading),
            '<nav aria-label="API documentation">',
            "<ul>",
            '<li><a href="{0}">{1}</a></li>'.format(
                alternative_path, alternative_label
            ),
            '<li><a href="{0}">OpenAPI schema</a></li>'.format(
                app.openapi_url
            ),
            "</ul>",
            "</nav>",
            "</header>",
        ]
    )


def swagger_documentation_html() -> str:
    # QA-07: the interactive documentation shell. Replaces the framework
    # template, which emits no lang, no landmark, no skip link and a
    # heading level jump. DL-446
    bootstrap = "\n".join(
        [
            "const ui = SwaggerUIBundle({",
            "  url: {0!r},".format(app.openapi_url),
            '  dom_id: "#{0}",'.format(_SWAGGER_MOUNT_ID),
            '  layout: "BaseLayout",',
            "  deepLinking: true,",
            "  showExtensions: true,",
            "  showCommonExtensions: true,",
            "  presets: [",
            "    SwaggerUIBundle.presets.apis,",
            "    SwaggerUIBundle.SwaggerUIStandalonePreset",
            "  ]",
            "});",
        ]
    )
    return "\n".join(
        [
            _documentation_head(
                "{0} - Swagger UI".format(app.title), [SWAGGER_CSS_URL]
            ),
            "<body>",
            _documentation_header(
                "{0} interactive API documentation".format(app.title),
                REDOC_PATH,
                "Reference documentation",
            ),
            '<main id="{0}" tabindex="-1">'.format(_DOCUMENTATION_MAIN_ID),
            '<div id="{0}"></div>'.format(_SWAGGER_MOUNT_ID),
            "</main>",
            '<script src="{0}"></script>'.format(SWAGGER_JS_URL),
            "<script>",
            bootstrap,
            _SWAGGER_ACCESSIBILITY_SCRIPT.replace(
                "__MOUNT__", _SWAGGER_MOUNT_ID
            ),
            _SKIP_LINK_FOCUS_SCRIPT.replace(
                "__MAIN__", _DOCUMENTATION_MAIN_ID
            ),
            "</script>",
            "</body>",
            "</html>",
        ]
    )


def redoc_documentation_html() -> str:
    # QA-07: the reference documentation shell, with the same landmarks,
    # heading and skip link as the interactive one. DL-446
    return "\n".join(
        [
            _documentation_head(
                "{0} - ReDoc".format(app.title),
                [GOOGLE_FONTS_URL],
            ),
            "<body>",
            _documentation_header(
                "{0} API reference documentation".format(app.title),
                DOCS_PATH,
                "Interactive documentation",
            ),
            '<main id="{0}" tabindex="-1">'.format(_DOCUMENTATION_MAIN_ID),
            "<noscript>This reference documentation is rendered in the "
            "browser and needs JavaScript. The machine-readable schema at "
            '<a href="{0}">{0}</a> needs none.</noscript>'.format(
                app.openapi_url
            ),
            '<redoc spec-url="{0}"></redoc>'.format(app.openapi_url),
            "</main>",
            '<script src="{0}"></script>'.format(REDOC_JS_URL),
            "<script>",
            _REDOC_ACCESSIBILITY_SCRIPT,
            _SKIP_LINK_FOCUS_SCRIPT.replace(
                "__MAIN__", _DOCUMENTATION_MAIN_ID
            ),
            "</script>",
            "</body>",
            "</html>",
        ]
    )


def interactive_documentation(request: Request) -> HTMLResponse:
    # QA-07: serves the accessible interactive shell on the path the
    # framework served its own template on. DL-446
    return HTMLResponse(swagger_documentation_html())


def reference_documentation(request: Request) -> HTMLResponse:
    # QA-07: serves the accessible reference shell on the path the
    # framework served its own template on. DL-446
    return HTMLResponse(redoc_documentation_html())


def swagger_oauth2_redirect(request: Request) -> HTMLResponse:
    # QA-07: the callback path the framework registered stays registered,
    # so no route path or verb moves. QA-04 removed the only flow that
    # could reach it, so it answers a static explanation rather than the
    # framework's opener-dereferencing script, which threw on any direct
    # visit. DL-446
    return HTMLResponse(
        "\n".join(
            [
                _documentation_head(
                    "{0} - OAuth2 redirect".format(app.title), []
                ),
                "<body>",
                _documentation_header(
                    "{0} OAuth2 redirect".format(app.title),
                    DOCS_PATH,
                    "Interactive documentation",
                ),
                '<main id="{0}" tabindex="-1" class="doc-copy">'.format(
                    _DOCUMENTATION_MAIN_ID
                ),
                "<h2>No OAuth2 flow is published</h2>",
                "<p>This API authenticates with a session cookie or a "
                "bearer token, so no authorization redirect is used. Open "
                '<a href="{0}">the interactive documentation</a> and use '
                "its Authorize control.</p>".format(DOCS_PATH),
                "</main>",
                "</body>",
                "</html>",
            ]
        )
    )


# QA-07: registered through the same call the framework used for its own
# templates, so each documentation route keeps the type, the GET and HEAD
# verbs and the schema exclusion it had before. DL-446
app.add_route(DOCS_PATH, interactive_documentation, include_in_schema=False)
app.add_route(REDOC_PATH, reference_documentation, include_in_schema=False)
app.add_route(
    SWAGGER_OAUTH2_REDIRECT_PATH,
    swagger_oauth2_redirect,
    include_in_schema=False,
)

app.include_router(api_router)

create_tables()

# SEC-08: uniform sanitized error envelope; keeps tracebacks, driver text,
# SQL and file paths out of every error response (CWE-209, CWE-497)
_REQUEST_LOCATIONS = ("body", "query", "path", "header", "cookie")
_GENERIC_SERVER_DETAIL = "Internal server error"

# SEC-08: substitutes the values a record carries for the client-supplied
# request path and method (CWE-532). DL-364
_UNMATCHED_ROUTE = "<unmatched>"
_UNSERVED_METHOD = "<method>"
_SERVED_METHODS = frozenset({"GET", "HEAD", "POST", "OPTIONS"})

# SEC-08: a record names an undeclared key by position and withholds the
# submitted name (CWE-532). DL-364
_UNDECLARED_ERROR_TYPES = ("value_error.extra", "extra_forbidden")
_UNDECLARED_FIELD = "<undeclared>"
_MAX_LOGGED_FIELDS = 8
_MAX_LOGGED_NAME_LENGTH = 40

# SEC-08: bounds on the type chain and the frame summary a record carries
_MAX_LOGGED_CAUSES = 4
_MAX_LOGGED_FRAMES = 6
_APPLICATION_ROOT = os.path.dirname(os.path.abspath(__file__))

# SEC-08: bounds on the cause chain a formatted report is scrubbed
# against, and the shortest provider text worth removing from it
_MAX_RENDERED_MEMBERS = 16
_MIN_DRIVER_TEXT_LENGTH = 4

# SEC-08: bounds on one diagnostic record. The rendered report keeps the
# innermost frames, which carry the fault, and stops at a byte ceiling. An
# unbounded record lets a client-reachable failure fill the log volume the
# process shares with everything else on the host (CWE-770, CWE-779).
_MAX_RENDERED_FRAMES = 8
_MAX_DIAGNOSTIC_BYTES = 4096
_TRUNCATION_MARKER = "...[truncated]"

# SEC-08: the diagnostic budget. One route and one exception type may
# render the full report a bounded number of times per window; every
# further occurrence is still recorded under its own correlation
# identifier, in the compact form, with the number it stands for. Without
# the budget a client that can reach any failing route writes an unbounded
# volume of diagnostics on the request path (CWE-770).
_DIAGNOSTIC_BURST = 5
_DIAGNOSTIC_WINDOW_SECONDS = 60.0
_DIAGNOSTIC_TRACKING_CAP = 512
_SUPPRESSED_DIAGNOSTICS = "suppressed"
_diagnostic_budget = {}
_diagnostic_budget_lock = threading.Lock()

# SEC-08: a diagnostic record carries the formatted traceback, which
# quotes exception messages. Held secrets and secret-shaped text are
# removed from it before it reaches a log handler (CWE-209, CWE-532).
_REDACTED = "[redacted]"
_MIN_SECRET_LENGTH = 8
_SECRET_SETTING_NAMES = (
    "SECRET_KEY",
    "PAYPAL_CLIENT_SECRET",
    "SENDGRID_API_KEY",
    "ZILLOW_API_KEY",
)
_SECRET_SHAPES = (
    # a JSON Web Token in compact serialization
    (
        re.compile(
            r"eyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]*"
        ),
        _REDACTED,
    ),
    # the password component of a URL or a database connection string
    (
        re.compile(r"(://[^\s:/@]+:)[^\s@]+(@)"),
        r"\g<1>" + _REDACTED + r"\g<2>",
    ),
    # the credential carried by an HTTP bearer authorization scheme
    (
        re.compile(r"(?i)(bearer\s+)[A-Za-z0-9._~+/=-]{8,}"),
        r"\g<1>" + _REDACTED,
    ),
    # a credential named in assignment, keyword or mapping syntax. The
    # name match starts at the keyword and any identifier prefix before it
    # is left in place, so signing_key, client_secret and api-token are
    # covered alongside key, secret and token. The lookahead skips a value
    # a previous pattern already replaced; one marker per value.
    (
        re.compile(
            r"(?i)((?:pass(?:word|wd|phrase)?|secret"
            r"|token|key|credential|auth(?:orization)?|cookie)"
            r"[\"']?\s*[:=]\s*)"
            r"(?!\[redacted\])"
            r"('[^']*'|\"[^\"]*\"|[^\s,;)}\]]+)"
        ),
        r"\g<1>" + _REDACTED,
    ),
)


def _error_envelope(detail: str, error_id: str, fields=()) -> dict:
    return {"detail": detail, "error_id": error_id, "fields": list(fields)}


def _status_phrase(status_code: int) -> str:
    try:
        return HTTPStatus(status_code).phrase
    except ValueError:
        return "Request failed"


def _route_label(request: Request) -> str:
    # SEC-08: the template of the matched route, never the request path
    # the caller supplied (CWE-532)
    route = request.scope.get("route")
    template = getattr(route, "path", None)
    if isinstance(template, str) and template:
        return template
    return _UNMATCHED_ROUTE


def _method_label(request: Request) -> str:
    # SEC-08: a served verb; an unserved method is caller-supplied text
    method = request.method
    if method in _SERVED_METHODS:
        return method
    return _UNSERVED_METHOD


def _exception_type(exc: BaseException) -> str:
    # SEC-08: the qualified type name, never str(exc)
    exc_type = type(exc)
    module = getattr(exc_type, "__module__", "") or ""
    if module in ("", "builtins"):
        return exc_type.__name__
    return "%s.%s" % (module, exc_type.__name__)


def _exception_chain(exc: BaseException) -> str:
    # SEC-08: type names along the cause chain, including a DBAPI driver
    # error reached through SQLAlchemy's orig attribute
    names = []
    seen = set()
    current = exc
    while (
        isinstance(current, BaseException)
        and id(current) not in seen
        and len(names) < _MAX_LOGGED_CAUSES
    ):
        seen.add(id(current))
        names.append(_exception_type(current))
        current = (
            getattr(current, "orig", None)
            or current.__cause__
            or current.__context__
        )
    return "<-".join(names)


def _exception_origin(exc: BaseException) -> str:
    # SEC-08: a single-line frame summary with source lookup disabled,
    # keeping the innermost application frame
    frames = traceback.StackSummary.extract(
        traceback.walk_tb(exc.__traceback__), lookup_lines=False
    )
    selected = frames[-_MAX_LOGGED_FRAMES:]
    application = [
        frame for frame in frames
        if os.path.abspath(frame.filename).startswith(_APPLICATION_ROOT)
    ]
    if application and application[-1] not in selected:
        selected = [application[-1]] + selected
    return ";".join(
        "%s:%s:%s" % (frame.filename, frame.lineno, frame.name)
        for frame in selected
    )


def _dsn_password(url: str) -> str:
    # SEC-08: the credential a connection string carries inline
    try:
        return urlsplit(url).password or ""
    except ValueError:
        return ""


def _secret_literals() -> tuple:
    # SEC-08: the values this process holds that no record may quote,
    # ordered longest first (CWE-532). DL-364
    values = [
        getattr(settings, name, None) for name in _SECRET_SETTING_NAMES
    ]
    values.append(_dsn_password(str(settings.DATABASE_URL or "")))
    literals = {
        str(value)
        for value in values
        if value and len(str(value)) >= _MIN_SECRET_LENGTH
    }
    return tuple(sorted(literals, key=len, reverse=True))


def _redact(text: str) -> str:
    # SEC-08: removes held secrets and secret-shaped text (CWE-532)
    for literal in _secret_literals():
        text = text.replace(literal, _REDACTED)
    for pattern, replacement in _SECRET_SHAPES:
        text = pattern.sub(replacement, text)
    return text


def _exception_members(exc: BaseException) -> list:
    # SEC-08: every exception a formatted report renders
    members = []
    seen = set()
    pending = [exc]
    while pending and len(members) < _MAX_RENDERED_MEMBERS:
        current = pending.pop(0)
        if not isinstance(current, BaseException) or id(current) in seen:
            continue
        seen.add(id(current))
        members.append(current)
        pending.extend(
            [
                getattr(current, "orig", None),
                current.__cause__,
                current.__context__,
            ]
        )
    return members


def _driver_literals(exc: BaseException) -> tuple:
    # SEC-08: provider text a database exception renders, which quotes the
    # failing column value and the statement that carried it (CWE-532)
    literals = set()
    for member in _exception_members(exc):
        if not isinstance(member, SQLAlchemyError):
            continue
        origin = getattr(member, "orig", None)
        if isinstance(origin, BaseException):
            message = str(origin)
            literals.add(message)
            literals.update(message.splitlines())
        statement = getattr(member, "statement", None)
        if isinstance(statement, str):
            literals.add(statement)
    return tuple(
        sorted(
            (
                literal.strip()
                for literal in literals
                if len(literal.strip()) >= _MIN_DRIVER_TEXT_LENGTH
            ),
            key=len,
            reverse=True,
        )
    )


def _suppress_bound_parameters(exc: BaseException) -> None:
    # SEC-08: suppresses the caller-submitted row values on every chain
    # member, the raised exception included (CWE-532). DL-364
    for member in _exception_members(exc):
        if hasattr(member, "hide_parameters"):
            member.hide_parameters = True


def _bounded_report(exc: BaseException) -> str:
    # SEC-08: the formatted traceback, bounded before it is scrubbed. The
    # negative frame limit keeps the innermost frames of every exception in
    # the chain, which is where the fault is raised; the outer frames are
    # the same server stack on every request. The byte ceiling bounds an
    # exception whose own message is long (CWE-770).
    report = "".join(
        traceback.format_exception(
            type(exc), exc, exc.__traceback__, limit=-_MAX_RENDERED_FRAMES
        )
    )
    if len(report) > _MAX_DIAGNOSTIC_BYTES:
        report = report[:_MAX_DIAGNOSTIC_BYTES] + _TRUNCATION_MARKER
    return report


def _diagnostics(exc: BaseException) -> str:
    # SEC-08: the bounded formatted traceback, including the innermost
    # stack, the exception messages and the cause chain, with held
    # secrets, bound parameters and provider message text removed
    _suppress_bound_parameters(exc)
    report = _bounded_report(exc)
    for literal in _driver_literals(exc):
        report = report.replace(literal, _REDACTED)
    return _redact(report)


def _diagnostic_allowance(route: str, chain: str) -> tuple:
    # SEC-08: counts one failure and decides whether it renders the full
    # report. Returns (render_full, occurrence_in_window); an occurrence of
    # zero reports a tracking map at capacity, which renders nothing new
    # rather than evicting a live window and repeating its budget.
    # Counting and deciding happen in one critical section, so a
    # concurrent burst shares one budget (CWE-367).
    key = (route, chain)
    now = time.monotonic()
    with _diagnostic_budget_lock:
        for spent in [
            held for held, entry in _diagnostic_budget.items()
            if entry[1] <= now
        ]:
            del _diagnostic_budget[spent]
        seen, expires_at = _diagnostic_budget.get(
            key, (0, now + _DIAGNOSTIC_WINDOW_SECONDS)
        )
        if seen == 0 and len(_diagnostic_budget) >= _DIAGNOSTIC_TRACKING_CAP:
            return False, 0
        seen += 1
        _diagnostic_budget[key] = (seen, expires_at)
        return seen <= _DIAGNOSTIC_BURST, seen


def reset_error_diagnostics() -> None:
    # SEC-08: empties the diagnostic budget. The test harness calls this
    # between cases so one case's failures decide nothing for the next.
    with _diagnostic_budget_lock:
        _diagnostic_budget.clear()


def _audit_context(exc: BaseException) -> str:
    # SEC-08: appends the markers an exception publishes on audit_context;
    # raised detail and exception text are never promoted (CWE-209)
    context = getattr(exc, "audit_context", None)
    if not isinstance(context, dict):
        return ""
    return "".join(
        " %s=%s" % (key, context[key]) for key in sorted(context)
    )


def _error_location(error) -> tuple:
    # SEC-08: the field path one rejection names, with the request
    # location prefix removed
    location = tuple(error.get("loc", ()))
    if len(location) > 1 and location[0] in _REQUEST_LOCATIONS:
        location = location[1:]
    return location


def _measures_the_body(location) -> bool:
    # SEC-08: a byte offset measures the submitted content (CWE-209)
    return len(location) == 1 and isinstance(location[0], int)


def _validation_field_names(errors) -> list:
    # SEC-08: field paths only; withholds the values msg, ctx and input
    # carry (CWE-209)
    names = []
    for error in errors:
        location = _error_location(error)
        if _measures_the_body(location):
            continue
        name = ".".join(str(part) for part in location)
        if name and name not in names:
            names.append(name)
    return names


def _loggable_field_names(errors) -> str:
    # SEC-08: schema-declared names only, bounded in count and in length;
    # an undeclared key is named by position (CWE-532)
    names = []
    for error in errors:
        location = _error_location(error)
        if _measures_the_body(location):
            continue
        parts = [str(part)[:_MAX_LOGGED_NAME_LENGTH] for part in location]
        if parts and str(error.get("type", "")) in _UNDECLARED_ERROR_TYPES:
            parts[-1] = _UNDECLARED_FIELD
        name = ".".join(parts)
        if name and name not in names:
            names.append(name)
    kept = names[:_MAX_LOGGED_FIELDS]
    rendered = ",".join(kept)
    withheld = len(names) - len(kept)
    if withheld > 0:
        rendered = "{0},+{1}".format(rendered, withheld)
    return rendered


def handle_validation_error(
    request: Request, exc: RequestValidationError
) -> JSONResponse:
    # SEC-08: the rendered name list passes through the same redaction the
    # diagnostic channel applies (CWE-532)
    error_id = uuid.uuid4().hex
    errors = exc.errors()
    fields = _validation_field_names(errors)
    logger.warning(
        "error_id=%s validation rejected %s %s fields=%s count=%s",
        error_id, _method_label(request), _route_label(request),
        _redact(_loggable_field_names(errors)), len(errors),
    )
    return JSONResponse(
        status_code=422,
        content=_error_envelope(
            "Request validation failed", error_id, fields
        ),
    )


def _budgeted_diagnostics(request: Request, exc: BaseException) -> str:
    # SEC-08: the diagnostic suffix one record carries. Inside the window's
    # budget the record renders the bounded report; past it the record
    # names the occurrence it stands for and renders nothing, so a
    # client-reachable failure costs a bounded record and a bounded amount
    # of work on the request path (CWE-770).
    render, occurrence = _diagnostic_allowance(
        _route_label(request), _exception_chain(exc)
    )
    if render:
        return " occurrence=%s origin=%s\ndiagnostics:\n%s" % (
            occurrence, _exception_origin(exc), _diagnostics(exc)
        )
    return " occurrence=%s diagnostics=%s" % (
        occurrence, _SUPPRESSED_DIAGNOSTICS
    )


def handle_http_exception(
    request: Request, exc: StarletteHTTPException
) -> JSONResponse:
    # SEC-08: preserves the raised status, replaces the raised detail, and
    # opens the diagnostic channel at 500 only (CWE-209)
    error_id = uuid.uuid4().hex
    server_fault = exc.status_code >= 500
    diagnostics = (
        _budgeted_diagnostics(request, exc) if server_fault else ""
    )
    emit = logger.error if server_fault else logger.warning
    emit(
        "error_id=%s http_exception status=%s on %s %s detail=%s%s%s",
        error_id, exc.status_code, _method_label(request),
        _route_label(request), _redact(repr(exc.detail)),
        _audit_context(exc), diagnostics,
    )
    return JSONResponse(
        status_code=exc.status_code,
        content=_error_envelope(_status_phrase(exc.status_code), error_id),
        headers=exc.headers,
    )


def _address_layer_retry_after(request: Request) -> int:
    # SEC-07: seconds until the address-keyed window admits another
    # attempt, read from the limiter's own storage. The limiter records
    # the refused limit on the request before it raises; when that record
    # or the storage is unavailable the configured window is the answer,
    # so the hint is always present and never understated.
    current_limit = getattr(request.state, "view_rate_limit", None)
    if current_limit:
        try:
            reset_at, _remaining = limiter.limiter.get_window_stats(
                current_limit[0], *current_limit[1]
            )
            return retry_after_seconds(reset_at - time.time())
        except Exception:
            logger.warning("rate limit window stats unavailable")
    return retry_after_seconds(0)


def handle_rate_limit_exceeded(
    request: Request, exc: RateLimitExceeded
) -> JSONResponse:
    # SEC-07: throttled attempts are logged, not silently dropped
    error_id = uuid.uuid4().hex
    logger.warning(
        "error_id=%s rate limit exceeded status=429 limit=%s on %s %s",
        error_id, _redact(str(exc.detail)), _method_label(request),
        _route_label(request),
    )
    return JSONResponse(
        status_code=429,
        content=_error_envelope(_status_phrase(429), error_id),
        headers={RETRY_AFTER_HEADER: str(_address_layer_retry_after(request))},
    )


def _driver_error_code(exc: SQLAlchemyError) -> str:
    # SEC-08: SQLSTATE identifies the failure without carrying a column value
    origin = getattr(exc, "orig", None)
    code = getattr(origin, "pgcode", None) or getattr(origin, "sqlstate", None)
    return str(code) if code else "none"


def handle_database_error(
    request: Request, exc: SQLAlchemyError
) -> JSONResponse:
    # SEC-08: records the type chain, SQLSTATE, frame locations, the
    # matched route and the correlation id, and no provider text or bound
    # parameter (CWE-532)
    error_id = uuid.uuid4().hex
    _suppress_bound_parameters(exc)
    chain = _exception_chain(exc)
    render, occurrence = _diagnostic_allowance(_route_label(request), chain)
    # SEC-08: the frame summary is the expensive part of this record, and a
    # repeat of one route's one failure adds no location the first record
    # does not already carry (CWE-770)
    origin = _exception_origin(exc) if render else _SUPPRESSED_DIAGNOSTICS
    logger.error(
        "error_id=%s database error on %s %s exception=%s sqlstate=%s"
        " occurrence=%s origin=%s",
        error_id, _method_label(request), _route_label(request),
        chain, _driver_error_code(exc), occurrence, origin,
    )
    return JSONResponse(
        status_code=500,
        content=_error_envelope(_GENERIC_SERVER_DETAIL, error_id),
    )


def handle_unhandled_exception(
    request: Request, exc: Exception
) -> JSONResponse:
    # SEC-08: the caller receives a reference; this record carries the
    # diagnostics that reference resolves to - the type chain, the frame
    # locations and the redacted traceback with its exception messages.
    # Every occurrence is recorded; the report itself is rendered within
    # the window's budget (CWE-770).
    error_id = uuid.uuid4().hex
    logger.error(
        "error_id=%s unhandled exception on %s %s exception=%s%s",
        error_id, _method_label(request), _route_label(request),
        _exception_chain(exc), _budgeted_diagnostics(request, exc),
    )
    return JSONResponse(
        status_code=500,
        content=_error_envelope(_GENERIC_SERVER_DETAIL, error_id),
    )


app.add_exception_handler(RequestValidationError, handle_validation_error)
app.add_exception_handler(StarletteHTTPException, handle_http_exception)
app.add_exception_handler(RateLimitExceeded, handle_rate_limit_exceeded)
app.add_exception_handler(SQLAlchemyError, handle_database_error)
app.add_exception_handler(Exception, handle_unhandled_exception)