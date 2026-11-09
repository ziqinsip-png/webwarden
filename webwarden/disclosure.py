"""Read-only detection of verbose errors and unauthenticated JSON data.

Both detectors work on responses the scan already fetched with GET. They never
submit a payload, replay a credential, or trigger a state change: the only
extra request is re-fetching the same URL to confirm the match.
"""

from __future__ import annotations

import json
import re

_IGNORECASE = re.IGNORECASE | re.MULTILINE


def _rx(pattern: str) -> re.Pattern:
    return re.compile(pattern, _IGNORECASE)


ERROR_SIGNATURES = (
    {
        "kind": "werkzeug",
        "title": "Werkzeug interactive debugger is reachable",
        "severity": "critical",
        "all": (_rx(r"werkzeug"), _rx(r"debugger")),
        "any": (_rx(r"console mode"), _rx(r"debugger pin"), _rx(r"interactive")),
        "description": (
            "The response contains the Werkzeug debugger console. When the PIN "
            "is guessed or disclosed, that console executes Python on the "
            "server, so this is treated as remote code execution surface."
        ),
        "remediation": (
            "Never run Flask/Werkzeug with debug=True in production; set "
            "debug=False and remove the debugger middleware."
        ),
    },
    {
        "kind": "django",
        "title": "Django DEBUG=True page exposes internals",
        "severity": "high",
        "all": (
            _rx(r"you(?:&#39;|'|\u2019)re seeing this error because you have"),
            _rx(r"debug\s*=\s*true"),
        ),
        "any": (),
        "description": (
            "Django is rendering its technical 500 page, which lists settings, "
            "SQL queries, request data, and source excerpts to any visitor."
        ),
        "remediation": (
            "Set DEBUG=False, restrict ALLOWED_HOSTS, and route 500s through a "
            "generic error page."
        ),
    },
    {
        "kind": "sql_error",
        "title": "SQL error message discloses query details",
        "severity": "high",
        "all": (),
        "any": (
            _rx(r"you have an error in your sql syntax"),
            _rx(r"sqlstate\[\w{5}\]"),
            _rx(r"mysqli_sql_exception"),
            _rx(r"pg_query\(\)\s*:"),
            _rx(r"\bora-\d{5}\b"),
            _rx(r"sqlite3?::(?:query|prepare)"),
            _rx(r"unclosed quotation mark after the character string"),
        ),
        "description": (
            "A database driver error is rendered to the client. These messages "
            "name the engine, the failing statement, and often the schema, "
            "which is the starting point for SQL injection work."
        ),
        "remediation": (
            "Catch database exceptions, log them server-side, and return a "
            "generic error page; parameterise every query."
        ),
    },
    {
        "kind": "php_fatal",
        "title": "PHP error message discloses server paths",
        "severity": "medium",
        "all": (
            _rx(r"(?:fatal error|parse error|uncaught\s+[\w\\]*error)\s*"
                r"(?:</?b>|</?strong>)?\s*:"),
            _rx(r"\bon line\s*<?b?>?\s*\d+"),
            _rx(r"\.php\b"),
        ),
        "any": (),
        "description": (
            "PHP is printing an uncaught error with the absolute script path "
            "and line number, which maps the docroot and the application code."
        ),
        "remediation": (
            "Set display_errors=Off, log errors to a private file, and enable "
            "a generic error handler in production."
        ),
    },
    {
        "kind": "php_notice",
        "title": "PHP warning or notice discloses server paths",
        "severity": "low",
        "all": (
            _rx(r"(?:warning|notice|deprecated|strict standards)\s*"
                r"(?:</?b>|</?strong>)?\s*:"),
            _rx(r"\bon line\s*<?b?>?\s*\d+"),
            _rx(r"\.php\b"),
        ),
        "any": (),
        "description": (
            "PHP notices are displayed with file paths and line numbers. "
            "Individually minor, they confirm the exact application path."
        ),
        "remediation": (
            "Set display_errors=Off and error_reporting to log-only in "
            "production."
        ),
    },
    {
        "kind": "python_traceback",
        "title": "Python traceback discloses source paths",
        "severity": "medium",
        "all": (
            _rx(r"traceback \(most recent call last\)"),
            _rx(r"file \"[^\"]+\.py\", line \d+"),
        ),
        "any": (),
        "description": (
            "An unhandled Python exception rendered its traceback, exposing "
            "module paths, function names, and sometimes local values."
        ),
        "remediation": (
            "Run the app behind a generic error handler; disable debug mode "
            "and never echo tracebacks to clients."
        ),
    },
    {
        "kind": "rails",
        "title": "Rails error page discloses application internals",
        "severity": "medium",
        "all": (),
        "any": (
            _rx(r"no route matches \[[a-z]+\]"),
            _rx(r"actioncontroller::\w+"),
            _rx(r"activerecord::\w+notfound"),
            _rx(r"<h1>\s*actionview::template::error"),
        ),
        "description": (
            "The Rails exception page exposes controller names, routes, and "
            "sometimes request parameters and source lines."
        ),
        "remediation": (
            "Set config.consider_all_requests_local = false and serve a static "
            "error page in production."
        ),
    },
    {
        "kind": "spring",
        "title": "Spring error page discloses application internals",
        "severity": "medium",
        "all": (),
        "any": (
            _rx(r"whitelabel error page"),
            _rx(r"org\.springframework\.(?:web|boot)\.[\w.]+exception"),
        ),
        "description": (
            "Spring is rendering its default error page, including exception "
            "classes and package names."
        ),
        "remediation": (
            "Disable server.error.include-stacktrace and include-message, and "
            "register a custom error controller."
        ),
    },
    {
        "kind": "laravel",
        "title": "Laravel error page discloses application internals",
        "severity": "medium",
        "all": (),
        "any": (
            _rx(r"whoops[!,. ]+looks like something went wrong"),
            _rx(r"<title>\s*whoops"),
            _rx(r"ignition\s*·\s*laravel"),
        ),
        "description": (
            "Laravel's Whoops/Ignition page lists environment variables, "
            "queries, and source excerpts."
        ),
        "remediation": (
            "Set APP_DEBUG=false and APP_ENV=production; never expose "
            "Ignition outside local development."
        ),
    },
    {
        "kind": "aspnet",
        "title": "ASP.NET error page discloses stack trace",
        "severity": "medium",
        "all": (),
        "any": (
            _rx(r"server error in ['\u2018\"]/\"? application"),
            _rx(r"system\.(?:nullreference|invalidoperation|argument)\w*exception"),
            _rx(r"yellow screen of death"),
        ),
        "description": (
            "The ASP.NET error page rendered a managed stack trace with "
            "assembly names and source lines."
        ),
        "remediation": (
            "Set customErrors/UseDeveloperExceptionPage off in production and "
            "log exceptions privately."
        ),
    },
    {
        "kind": "node_stack",
        "title": "Node.js stack trace discloses source paths",
        "severity": "low",
        "all": (
            _rx(r"^\s+at\s+\S+.*:\d+:\d+\)?$"),
            _rx(r"(?:/var/www|/home/|/srv/|/app/|c:\\|node_modules)"),
        ),
        "any": (),
        "description": (
            "A Node.js stack trace is returned to the client, naming internal "
            "files, line numbers, and module layout."
        ),
        "remediation": (
            "Return a generic 500 body and log the stack trace server-side "
            "only."
        ),
    },
)

COLLECTION_KEYS = (
    "items", "data", "results", "records", "rows", "list", "entries", "docs",
    "content", "payload", "response", "value",
)

RECORD_KEYS = {
    "id", "uuid", "guid", "user_id", "userid", "email", "mail", "username",
    "user", "name", "nama", "full_name", "fullname", "phone", "no_hp",
    "whatsapp", "telephone", "nik", "npwp", "address", "alamat", "role",
    "roles", "status", "active", "created_at", "createdat", "updated_at",
    "updatedat", "last_login", "token", "password", "password_hash",
    "hash", "salt", "api_key", "apikey", "secret", "balance", "saldo",
    "amount", "total", "price", "invoice", "order_id", "orderid",
}

SENSITIVE_KEYS = {
    "password", "password_hash", "hash", "salt", "token", "api_key", "apikey",
    "secret", "nik", "npwp", "no_hp", "phone", "telephone", "whatsapp",
    "email", "mail", "address", "alamat", "balance", "saldo", "invoice",
    "order_id", "orderid", "last_login",
}


def match_error(body: bytes, status: int | None = None) -> dict | None:
    """Return the first matching error signature for a response body."""
    if not body or len(body) > 2_000_000:
        return None
    text = body[:200_000].decode("utf-8", "ignore")
    if not text:
        return None
    for signature in ERROR_SIGNATURES:
        required = signature["all"]
        if required and not all(pattern.search(text) for pattern in required):
            continue
        options = signature["any"]
        if options and not any(pattern.search(text) for pattern in options):
            continue
        if not required and not options:
            continue
        return signature
    return None


def error_excerpt(body: bytes, signature: dict, limit: int = 240) -> str:
    """One matching line from the body, trimmed for the finding evidence."""
    text = body[:200_000].decode("utf-8", "ignore")
    patterns = list(signature["all"]) + list(signature["any"])
    for pattern in patterns:
        match = pattern.search(text)
        if not match:
            continue
        start = text.rfind("\n", 0, match.start()) + 1
        end = text.find("\n", match.end())
        line = " ".join(text[start:end if end > 0 else len(text)].split())
        if line:
            return line[:limit]
    return signature["title"]


def json_collection(
    body: bytes, headers: dict[str, str]
) -> dict | None:
    """Describe a JSON collection of records, or None when it is not one."""
    if not body or len(body) > 1_500_000:
        return None
    content_type = (headers.get("content-type") or "").lower()
    stripped = body.lstrip()[:1]
    if "json" not in content_type and stripped not in (b"{", b"["):
        return None
    sample = body[:300_000]
    try:
        data = json.loads(sample.decode("utf-8", "ignore"))
    except (ValueError, UnicodeDecodeError):
        return None

    records: list[dict] = []
    shape = ""
    if isinstance(data, list):
        records = [item for item in data if isinstance(item, dict)]
        shape = "array"
    elif isinstance(data, dict):
        for key in COLLECTION_KEYS:
            value = data.get(key)
            if isinstance(value, list) and len(value) >= 2:
                records = [item for item in value if isinstance(item, dict)]
                shape = key
                break
    if len(records) < 2:
        return None

    keys: set[str] = set()
    for record in records[:3]:
        keys.update(str(key) for key in record.keys())
    lowered = {key.lower() for key in keys}
    if len(lowered & RECORD_KEYS) < 2:
        return None
    return {
        "count": len(records),
        "shape": shape,
        "keys": sorted(keys)[:12],
        "sensitive": sorted(lowered & SENSITIVE_KEYS),
    }
