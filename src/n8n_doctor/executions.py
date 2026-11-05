"""``n8n-doctor executions``: recent failed executions grouped by workflow, node and error."""

from __future__ import annotations

import base64
import functools
import json
import re
import sys
import urllib.parse
from collections import OrderedDict
from collections.abc import Callable
from typing import Any
from urllib.parse import unquote

from .api import Client, PaginationStalled, RunTimeout
from .limits import DEFAULT as DEFAULT_LIMITS
from .report import Style, safe_text
from .rules import SENSITIVE_KEY, SENSITIVE_NAME, display_name, password_named, redact, secret_masker
from .workflow import WorkflowError, from_data, is_workflow

# `Basic <token>`: the token is checked by _mask_basic; scanned by _mask_basic_all, which finds each run of token
# characters once (a regex with a bounded run and a lookahead would rescan the run from every `Basic+` inside it)
_BASIC_START = re.compile(r"\b(Basic)([ \t]+|%20|\+)", re.IGNORECASE)
_TOKEN_CHARS = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/_%-")
_TOKEN_RUN = re.compile(r"[A-Za-z0-9+/_%-]*")
_TOKEN_MAX = 4096
_SCHEME_TOKEN = re.compile(r"\b(Bearer|Token)([ \t]+|%20|\+)([^\s\"',;]{1,4096})", re.IGNORECASE)
# "key": "value" in JSON (also escaped inside another JSON string, at any depth) and 'key': 'value' in a
# Python repr; the key may spell letters as \u escapes. The value (quoted, a list or bare) is scanned by _mask_quoted_pairs.
_QUOTED_KEY = re.compile(r"""(\\{0,16})(["'])((?:[A-Za-z0-9_-]|\\{1,16}u[0-9a-fA-F]{4}){2,60})\1\2[ \t]{0,64}:[ \t]{0,64}""")
_QUOTE_AT = re.compile(r"""(\\{0,16})(["'])""")
_BARE_VALUE = re.compile(r"""[^\s,}\]"'\\]{1,1024}""")
_UNICODE_ESCAPE = re.compile(r"\\+u([0-9a-fA-F]{4})")
_VALUE_LIMIT = 4096
_ENCODED_FIELD = re.compile(r"(?i)(?<![A-Za-z0-9_-])([A-Za-z0-9_-]{2,40})(%3D)((?:(?!%26)[^&\s'\"<>]){1,1024})")
_ONE_TOKEN_SCHEMES = r"basic|bearer|token|apikey|api-key|key|ssws|jwt|dpop|negotiate|ntlm|otp|client-id|privatetoken|splunk"
_PARAM_SCHEMES = (
    r"digest|oauth|hawk|hoba|mutual|signature|aws4-hmac-sha256|aws|sharedkey|sharedkeylite|sharedaccesssignature|"
    r"googlelogin|session|mac|gnap|vapid|scram-sha-1|scram-sha-256|concealed"
)
# `password = "x"`, `token: 'x'` (the closing quote may be missing)
_QUOTED_FIELD = re.compile(r"""(?<![A-Za-z0-9_-])([A-Za-z0-9_-]{2,40})([ \t]{0,64}[=:][ \t]{0,64})(?:"([^"\r\n]{1,1024})"?|'([^'\r\n]{1,1024})'?)""")
# `password: x`, `token: Bearer x` (a scheme word is kept, the value after it masked)
# Both also take the next word (groups 4 and 5): `password=abc <token>` (a value with a space in it) masks the
# token too when it looks generated.
_COLON_FIELD = re.compile(
    rf"(?<![A-Za-z0-9_-])([A-Za-z0-9_-]{{2,40}})([ \t]{{0,64}}:[ \t]{{0,64}}(?:(?i:{_ONE_TOKEN_SCHEMES}|{_PARAM_SCHEMES})[ \t]{{1,64}})?)"
    r"([^\s\"',;&<>{}\[\]]{1,1024})(?:([ \t]{1,64})([^\s\"',;&<>{}\[\]]{8,1024}))?"
)
_FORM_FIELD = re.compile(r"(?<![A-Za-z0-9_-])([A-Za-z0-9_-]{2,40})(=)([^&\s'\"<>]{1,1024})(?:([ \t]{1,64})([^&\s'\"<>]{8,1024}))?")
# <password>value</password>, <ns:ApiKey attr="x">value</ns:ApiKey>: XML elements named like credentials
_XML_FIELD = re.compile(r"<((?:[A-Za-z][\w.-]{0,40}:)?([A-Za-z][\w.-]{0,40}))(\s[^<>]{0,256})?>([^<]{1,1024})</\1\s{0,16}>")
_HEADER = re.compile(r"(?i)\b(x-api-key|api-key|apikey|x-auth-token|x-access-token)([ \t]{0,64}:[ \t]{0,64})([^\s\"',;]{1,4096})")
# Authorization and Cookie headers (also `Authorization=...` in a logged form or query). A known scheme word is
# kept: after a one-token scheme the token is masked (`Authorization: ApiKey ***, retrying`), after any other scheme
# (Digest, OAuth, AWS4-HMAC-SHA256: parameters with commas and quotes) the rest of the line. An unknown first word
# may itself be the credential, and a Cookie header holds several, so then the whole value to the end of the line
# is masked.
_AUTH_FIELD = re.compile(r"(?i)(?<![A-Za-z0-9_-])((?:proxy-)?authorization|(?:set-)?cookie)([ \t]{0,64}[:=][ \t]{0,64})([^\r\n]{1,1024})")
_AUTH_SCHEME = re.compile(rf"(?i)(?:({_ONE_TOKEN_SCHEMES})|({_PARAM_SCHEMES}))[ \t]{{1,64}}(?=\S)")
_AUTH_TOKEN = re.compile(r"[^\s\"',;]{1,4096}")
# More names whose values are credentials (on top of N8D101's SENSITIVE_NAME and SENSITIVE_KEY)
_MORE_SENSITIVE = re.compile(
    r"(?i)(?:^|[-_])(?:(?:api|private|session|id|refresh|security|csrf|xsrf|bot|app|user|client)[-_]?token|"
    r"secret[-_]?access[-_]?key|access[-_]?key[-_]?secret|(?:set-)?cookie|credentials?|passphrase|"
    r"(?:subscription|api|access|secret|private|master|account|app|client|auth|signing|encryption|license|primary|secondary)[-_]?key|"
    r"access[-_]?key[-_]?id)$"
)
# `Invalid API key: X`, `api key X`, `secret key=X`: a credential named in prose, then its value (a single token that
# looks generated, so "api key is invalid" is left alone)
_PROSE_KEY = re.compile(
    r"(?i)(?<![A-Za-z0-9_-])((?:api|access|secret|private|subscription|auth|client)[ _-]?(?:key|token|secret)|apikey|password|passwd|token|secret|key)"
    r"([ \t]{0,64}[:=]?[ \t]{1,64}|[ \t]{0,64}[:=])([^\s\"',;]{1,1024})"
)
# `secret 'x' is wrong`, `password "x" rejected`: a quoted value right after a credential word
_QUOTED_PROSE = re.compile(
    r"(?i)(?<![A-Za-z0-9_-])((?:api|access|secret|private|subscription|auth|client)[ _-]?(?:key|token|secret)|apikey|password|passwd|passphrase"
    r"|pwd|token|secret|credentials?)(s?[ \t]{1,64}(?:(?:is|was|of|value)[ \t]{1,64})?)(['\"`])([^'\"`\r\n]{1,1024})\3"
)
# `Invalid API key provided: <token>`: a credential word and a participle before the value
_PROSE_PARTICIPLE = re.compile(
    r"(?i)(?<![A-Za-z0-9_-])((?:api|access|secret|private|subscription|auth|client)[ _-]?(?:key|token|secret)|apikey|password|token|secret|key)"
    r"([ \t]{1,64}(?:provided|given|supplied|passed|sent|used|specified|received)[ \t]{0,64}[:=]?[ \t]{1,64})([^\s\"',;]{1,1024})"
)
# `The provided key '<token>' is invalid`: a quoted value after the word "key" alone (masked when it looks generated)
_QUOTED_KEY_PROSE = re.compile(r"(?i)(?<![A-Za-z0-9_-])(keys?)([ \t]{1,64}(?:(?:is|was|of|value)[ \t]{1,64})?)(['\"`])([^'\"`\r\n]{1,1024})\3")
# `user@example.com:<token>`: an e-mail address and a token, as Basic auth and API logins take them. The match
# starts at the last character before the "@" (the rest of the address is kept as it is anyway), so a long run of
# address characters is not rescanned from every position in it.
_EMAIL_TOKEN = re.compile(r"([\w.+-]@[\w-]{1,63}(?:\.[\w-]{1,63}){1,8}):([^\s\"',;<>@]{8,1024})")
# `sha256=<hex>`: a webhook signature
_SIGNATURE = re.compile(r"(?i)(?<![A-Za-z0-9_-])(sha1|sha256|sha512|md5|v0|v1)=([0-9a-f]{16,1024})(?![0-9a-z])")
# a Mailgun API key: `key-` and 32 letters and digits
_MAILGUN_KEY = re.compile(r"(?<![A-Za-z0-9_-])key-[0-9A-Za-z]{32}(?![0-9A-Za-z])")
# user info in a URL, to the last @ before the host: a password can hold "@" (postgres://u:p@ss@db)
_URL_USERINFO = re.compile(r"(://)[^/\s]{1,256}@(?=[\w.\[-])")
_URL_RUN = re.compile(r"https?://[^\s?#'\"]+")
_QUERY_RUN = re.compile(r"[^\s'\"]*")


def _mask_basic(scheme: str, sep: str, token: str, whole: str) -> str:
    """Hide ``Basic <base64 user:password>``; leave prose such as "Basic authentication" alone."""
    if sep == "%20":  # URL-encoded: never prose
        return scheme + sep + "***"
    plain = unquote(token)
    try:
        decoded = base64.b64decode(plain + "=" * (-len(plain) % 4), altchars=b"-_" if "-" in plain or "_" in plain else None, validate=True)
    except ValueError:  # binascii.Error is a ValueError
        return whole
    return scheme + sep + "***" if b":" in decoded else whole


def _mask_basic_all(text: str) -> str:
    """``Basic`` followed by 4 to 4096 token characters, up to two ``=`` (or ``%3D``, a token character) and
    then no token character or ``=``; each run of token characters is measured once, so this is linear."""
    out: list[str] = []
    pos = 0  # text[:pos] is in out
    search = 0
    run_end = -1  # end of the token run measured last; a later start inside it ends there too
    while (m := _BASIC_START.search(text, search)) is not None:
        start = m.end()
        if start >= run_end:
            run_end = _TOKEN_RUN.match(text, start).end()  # type: ignore[union-attr]  # matches the empty string
        end = run_end
        while end < len(text) and text[end] == "=" and end - run_end < 2:
            end += 1
        if 4 <= run_end - start <= _TOKEN_MAX and (end == len(text) or (text[end] != "=" and text[end] not in _TOKEN_CHARS)):
            out.append(text[pos : m.start()])
            out.append(_mask_basic(m.group(1), m.group(2), text[start:end], text[m.start() : end]))
            pos = search = end
        else:
            search = m.end()
    out.append(text[pos:])
    return "".join(out)


def _mask_query_strings(text: str, replacement: str) -> str:
    """``https://host/path?query`` -> ``https://host/path?<replacement>`` in one pass: a URL whose path ends
    at ``#`` or a space has no query, and no URL starting inside it can have one either."""
    out: list[str] = []
    pos = 0
    search = 0
    while (m := _URL_RUN.search(text, search)) is not None:
        end = m.end()
        if end < len(text) and text[end] == "?":
            query_end = _QUERY_RUN.match(text, end + 1).end()  # type: ignore[union-attr]  # matches the empty string
            out.append(text[pos : end + 1])
            out.append(replacement)
            pos = query_end
            search = query_end
        else:
            search = end
    out.append(text[pos:])
    return "".join(out)


def _key_name(raw: str) -> str:
    if "\\" not in raw:
        return raw
    return _UNICODE_ESCAPE.sub(lambda m: chr(int(m.group(1), 16)), raw)


def _closing_quote(text: str, start: int, quote: str, level: int) -> int:
    """Where the string value opened before ``start`` ends: the next ``quote`` with ``level`` backslashes
    before it (escaped quotes inside it, and deeper levels, are skipped); ``start + _VALUE_LIMIT`` without one."""
    j = start
    limit = min(len(text), start + _VALUE_LIMIT)
    while (j := text.find(quote, j, limit)) >= 0:
        k = j
        while k > start and text[k - 1] == "\\":
            k -= 1
        if j - k == level:
            return k
        j += 1
    return limit


def _mask_quoted_pairs(text: str) -> str:
    """Mask the values of sensitive quoted keys: a string (to its closing quote, see :func:`_closing_quote`),
    a list (to its first ``]``) or a bare value (``"password":x``); a nested object is scanned as it is.
    Linear: each scan resumes after what it read."""
    out: list[str] = []
    pos = 0  # text[:pos] is in out
    search = 0
    while (m := _QUOTED_KEY.search(text, search)) is not None:
        start = m.end()
        if not _sensitive(_key_name(m.group(3))) or text.startswith("{", start):
            search = start  # the value may hold nested pairs
            continue
        if text.startswith("[", start):
            close = text.find("]", start, start + _VALUE_LIMIT)
            start, end = start + 1, close if close >= 0 else min(len(text), start + _VALUE_LIMIT)
        elif (q := _QUOTE_AT.match(text, start)) is not None:
            start = q.end()
            end = _closing_quote(text, start, q.group(2), len(q.group(1)))
        elif (bare := _BARE_VALUE.match(text, start)) is not None:
            end = bare.end()
        else:
            search = start
            continue
        out.append(text[pos:start])
        out.append("***")
        pos = search = max(end, start)
    out.append(text[pos:])
    return "".join(out)


def _mask_auth_field(m: re.Match[str]) -> str:
    value = m.group(3)
    scheme = _AUTH_SCHEME.match(value)
    if scheme is None or m.group(1).lower().endswith("cookie"):
        return m.group(1) + m.group(2) + "***"
    rest = ""
    if scheme.group(1) and (token := _AUTH_TOKEN.match(value, scheme.end())) is not None:
        rest = value[token.end() :]
    return m.group(1) + m.group(2) + scheme.group(0) + "***" + rest


def _tokenish(value: str) -> bool:
    """A value after ``Bearer``/``Token`` that is a credential, not the next word of a sentence."""
    return any(c.isdigit() or c in "._~+/=-" for c in value) or len(value) >= 12


@functools.lru_cache(maxsize=4096)  # the same few key names repeat in every message
def _sensitive(name: str) -> bool:
    return bool(SENSITIVE_NAME.match(name) or SENSITIVE_KEY.search(name) or _MORE_SENSITIVE.search(name) or password_named(name)) or name.lower() in (
        "token",
        "auth",
        "key",
    )


_SCHEME_WORDS = frozenset(_ONE_TOKEN_SCHEMES.split("|")) | frozenset(_PARAM_SCHEMES.split("|"))


def _generated(value: str) -> bool:
    """Letters and digits mixed, at least 8 characters: a token, not a word of the sentence."""
    return len(value) >= 8 and any(c.isdigit() for c in value) and any(c.isalpha() for c in value)


def _mask_prose_key(m: re.Match[str]) -> str:
    value = m.group(3)
    if "***" in value or not value[0].isalnum() or value.lower() in _SCHEME_WORDS:
        return m.group(0)  # already masked, punctuation, or a scheme word that the token after it follows
    if not (_tokenish(value) or ":" in m.group(2) or "=" in m.group(2)):
        return m.group(0)
    if m.group(1).lower() == "key" and not (":" in m.group(2) or "=" in m.group(2) or _generated(value)):
        return m.group(0)  # "key" alone is a common word: "key value is missing"
    return m.group(1) + m.group(2) + "***"


def _mask_field(m: re.Match[str]) -> str:
    if not _sensitive(m.group(1)) or m.group(3).lower() in _SCHEME_WORDS:
        return m.group(0)  # `Authorization=Bearer ***`: the token after the scheme word is masked on its own
    after = ""
    if m.re.groups >= 5 and m.group(5):  # the next word: masked too when it looks generated
        after = m.group(4) + ("***" if _generated(m.group(5)) else m.group(5))
    return m.group(1) + m.group(2) + "***" + after


def _mask_xml(m: re.Match[str]) -> str:
    if not _sensitive(m.group(2)):
        return m.group(0)
    return m.group(0)[: m.start(4) - m.start()] + "***" + m.group(0)[m.end(4) - m.start() :]


def mask_message(message: str) -> str:
    """An error message with credentials removed: the N8D101 patterns (private keys included), sensitive
    JSON fields and form fields, ``Authorization``/``Cookie`` values, ``Bearer``/``Token``/``Basic`` values
    (also URL-encoded), API key headers, XML elements named like credentials, URL user info and query strings.
    Every step is linear in the text."""
    text = redact(message)
    text = _mask_quoted_pairs(text)
    text = _AUTH_FIELD.sub(_mask_auth_field, text)
    text = _XML_FIELD.sub(_mask_xml, text)
    text = _QUOTED_FIELD.sub(lambda m: m.group(1) + m.group(2) + ('"***"' if m.group(3) else "'***'") if _sensitive(m.group(1)) else m.group(0), text)
    text = _QUOTED_PROSE.sub(lambda m: m.group(0) if m.group(4) == "***" else f"{m.group(1)}{m.group(2)}{m.group(3)}***{m.group(3)}", text)
    # before the field patterns: in `Authorization=Bearer <token>` they would take "Bearer" for the value
    text = _SCHEME_TOKEN.sub(lambda m: m.group(1) + m.group(2) + "***" if _tokenish(m.group(3)) else m.group(0), text)
    for field in (_FORM_FIELD, _ENCODED_FIELD, _COLON_FIELD):
        text = field.sub(_mask_field, text)
    text = _MAILGUN_KEY.sub("key-***", text)
    text = _SIGNATURE.sub(lambda m: m.group(1) + "=***", text)
    text = _EMAIL_TOKEN.sub(lambda m: m.group(1) + ":***" if _generated(m.group(2)) or len(m.group(2)) >= 16 else m.group(0), text)
    text = _PROSE_PARTICIPLE.sub(lambda m: m.group(1) + m.group(2) + "***" if _tokenish(m.group(3)) or _generated(m.group(3)) else m.group(0), text)
    text = _QUOTED_KEY_PROSE.sub(lambda m: f"{m.group(1)}{m.group(2)}{m.group(3)}***{m.group(3)}" if _generated(m.group(4)) else m.group(0), text)
    text = _PROSE_KEY.sub(_mask_prose_key, text)
    text = _HEADER.sub(lambda m: m.group(1) + m.group(2) + "***", text)
    text = _URL_USERINFO.sub(r"\1***@", text)  # messages quote URLs and headers
    text = _mask_query_strings(text, "...")
    return _mask_basic_all(text)


_VOLATILE = [
    (re.compile(r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b", re.IGNORECASE), "<uuid>"),
    (re.compile(r"\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}(?::\d{2}(?:\.\d+)?)?(?:Z|[+-]\d{2}:?\d{2})?\b"), "<time>"),
    (re.compile(r"\b[0-9a-f]{16,}\b", re.IGNORECASE), "<hex>"),
    (re.compile(r"\b\d{5,}\b"), "<n>"),
]


def normalize(message: str) -> str:
    """Make messages that differ only in ids, timestamps or long numbers group together. Short numbers (HTTP status codes) stay."""
    text = " ".join(message.split())[:300]
    for pattern, repl in _VOLATILE:
        text = pattern.sub(repl, text)
    return _mask_query_strings(text, "<query>")


NO_DETAILS = "(no error details: the execution data was not returned or was pruned)"
NO_MESSAGE = "(no error message)"
# an error class name such as NodeApiError: any other name (it could be text from the error, a token) shows as "Error"
_ERROR_TYPE = re.compile(r"[A-Z][A-Za-z0-9]{0,60}(?:Error|Exception)")
GENERIC_ERROR_TYPE = "Error"
# Characters of a message that are masked: the start of it is all that is shown (``MESSAGE_SHOWN``), so the rest is
# dropped before masking, which keeps the work per message bounded whatever the API returns
MESSAGE_MASKED = 16 * 1024
MESSAGE_SHOWN = 2000
_NODE_TYPE = re.compile(r"[A-Za-z][A-Za-z0-9]{0,60}")


def _error_of(execution: dict[str, Any]) -> tuple[str, str, str | None]:
    """(node name, error message, error class) from an execution fetched with includeData=true."""
    data = execution.get("data")
    result = data.get("resultData") if isinstance(data, dict) else None
    if not isinstance(result, dict):
        return "", NO_DETAILS, None
    err = result.get("error")
    node = ""
    message = ""
    error_type = None
    if isinstance(err, dict):
        message = str(err.get("message") or err.get("description") or "")
        name = err.get("name")
        if name is not None:
            error_type = name if isinstance(name, str) and _ERROR_TYPE.fullmatch(name) else GENERIC_ERROR_TYPE
        err_node = err.get("node")
        if isinstance(err_node, dict):
            node = str(err_node.get("name") or "")
    if not node:
        last = result.get("lastNodeExecuted")
        node = str(last) if isinstance(last, str) else ""
    if not message:
        run_data = result.get("runData")
        runs = run_data.get(node) if isinstance(run_data, dict) and node else None
        if isinstance(runs, list):
            for run in reversed(runs):
                run_err = run.get("error") if isinstance(run, dict) else None
                if isinstance(run_err, dict) and run_err.get("message"):
                    message = str(run_err["message"])
                    break
    return node, message or NO_MESSAGE, error_type


Masker = Callable[[str], str]


def _node_ref(wf_data: Any, node: str) -> str:
    """A node as a group without a workflow masker names it: by its position in the workflow copy and its type,
    never by its name (a name can repeat a secret that only the workflow knows)."""
    nodes = wf_data.get("nodes") if isinstance(wf_data, dict) else None
    if node and isinstance(nodes, list):
        for i, item in enumerate(nodes[:100_000]):
            if isinstance(item, dict) and item.get("name") == node:
                kind = str(item.get("type") or "").rsplit(".", 1)[-1]
                return f"node #{i} ({kind})" if _NODE_TYPE.fullmatch(kind) else f"node #{i}"
    return "node (name hidden)" if node else ""


MASKER_CACHE_SIZE = 4  # workflow versions whose maskers are kept: executions of one version usually come together
# Characters of workflow copies (as JSON) turned into maskers in one run (``max-masker-mb``); past it, messages
# are hidden. Building a masker is linear in the workflow, so this bounds the run's work and memory.
MASKER_BUDGET_CHARS = DEFAULT_LIMITS.max_masker_chars
# What replaces a message whose workflow secrets could not be checked (fail closed; --pattern-masking-only opts out)
HIDDEN_BUDGET = "message hidden (workflow secrets could not be checked; rerun with --max-masker-mb N or fewer executions)"
HIDDEN_UNREADABLE = "message hidden (workflow secrets could not be checked: the workflow could not be read)"


class _Maskers:
    """:func:`rules.secret_masker` of the workflow copies executions carry, so a secret written into a workflow
    (a header value) is masked in its error messages and names too. The last ``MASKER_CACHE_SIZE`` are kept,
    by (workflow id, version); building them stops after ``budget`` characters of workflow JSON."""

    def __init__(self, budget: int, pattern_only: bool) -> None:
        self.budget = budget
        self.pattern_only = pattern_only
        self.cache: OrderedDict[tuple[str, str], Masker | None] = OrderedDict()
        self.spent = 0
        self.over = False  # the budget ran out: a workflow copy was left unread

    def cached(self, key: tuple[str, str]) -> Masker | None:
        self.cache.move_to_end(key)
        return self.cache[key]

    def of(self, wid: str, wf_data: Any, version: str | None = None) -> Masker | None:
        """The masker of one workflow copy (``version``: its versionId by default), or None without a usable one."""
        if not isinstance(wf_data, dict) or not is_workflow(wf_data):
            return None
        version = version or str(wf_data.get("versionId") or wf_data.get("updatedAt") or "")
        key = (wid, version)
        if version and key in self.cache:
            return self.cached(key)
        if self.over:
            return None
        try:
            size = len(json.dumps(wf_data, ensure_ascii=False, check_circular=False, default=str))
        except (ValueError, RecursionError):
            size = 0
        if self.spent + size > self.budget:
            self.over = True
            if self.pattern_only:
                note = "the rest of the messages are masked by the secret patterns only (secrets written into those workflows are not looked up)"
            else:
                note = "the error messages of the rest are hidden, since secrets written into those workflows could not be checked"
            sys.stderr.write(
                f"n8n-doctor: note: the workflow copies of these executions are larger than --max-masker-mb ({self.budget // (1024 * 1024)} MB "
                f"in all); {note}\n"
            )
            return None
        self.spent += size
        try:
            masker: Masker | None = secret_masker(from_data(wf_data, "<execution>")[0])
        except (WorkflowError, RecursionError):
            masker = None
        if version:
            self.cache[key] = masker
            if len(self.cache) > MASKER_CACHE_SIZE:
                self.cache.popitem(last=False)
        return masker


_BASE64_RUN = re.compile(r"[A-Za-z0-9+/_-]{8,}={0,2}")


def _key_masker(key: str) -> Callable[[str], str]:
    """A function that masks the API key wherever a text repeats it: as it is, in any letter case, URL-encoded,
    and inside base64 (standard or URL-safe, padded or not, alone or with text around it such as ``user:key``)."""
    if len(key) < 4:
        return lambda text: text
    forms = {key, urllib.parse.quote(key, safe=""), urllib.parse.quote_plus(key)}
    exact = re.compile("|".join(re.escape(f) for f in sorted(forms, key=len, reverse=True)), re.IGNORECASE)
    shortest = len(key) * 4 // 3  # base64 of the key alone is at least this long

    def in_base64(m: re.Match[str]) -> str:
        run = m.group(0)
        if len(run) >= shortest:
            for alphabet in (b"+/", b"-_"):
                for skip in range(4):  # the run can start inside a base64 quantum of the text around the key
                    body = run[skip:].rstrip("=")
                    try:
                        decoded = base64.b64decode(body + "=" * (-len(body) % 4), altchars=alphabet, validate=False)
                    except ValueError:
                        continue
                    if key.lower().encode() in decoded.lower():
                        return "***"
        return run

    def mask(text: str) -> str:
        return _BASE64_RUN.sub(in_base64, exact.sub("***", text))

    return mask


def summarize(
    client: Client, workflow_id: str | None, limit: int, status: str = "error", *, masker_budget: int | None = None, pattern_only: bool = False
) -> dict[str, Any]:
    """Failed executions grouped by workflow, node and error.

    A message is masked with its workflow's secrets as well as the patterns. When that workflow's masker is
    unavailable (``masker_budget`` characters of workflow JSON already read, or no usable copy of the
    workflow), the message is hidden, and so are the workflow and node names (the group names the workflow by id and
    the node by position and type); ``pattern_only`` shows them masked by the patterns only instead (less safe).
    Only the first ``MESSAGE_MASKED`` characters of a message are masked and kept.
    """
    names: dict[str, str] = {}  # workflow names by id, masked with the workflow's own masker when there was one
    named_by_masker: set[str] = set()
    unreadable: set[str] = set()  # workflows the API did not return as a workflow (deleted, no access)
    maskers = _Maskers(MASKER_BUDGET_CHARS if masker_budget is None else masker_budget, pattern_only)
    hidden = 0
    groups: dict[tuple[str, str, str, str, bool], dict[str, Any]] = {}
    total = 0
    seen_ids: set[str] = set()
    unkeyed = _key_masker(getattr(client, "_key", "") or "")

    def _add_execution(ex: dict[str, Any]) -> int:
        """Adds one execution to its group; 0 for a repeat of one already counted."""
        nonlocal hidden
        ex_id = safe_text(str(ex.get("id", "")))[:40]
        if ex_id and ex_id in seen_ids:  # a page boundary can repeat an execution
            return 0
        seen_ids.add(ex_id)
        wid = str(ex.get("workflowId", ""))
        wf_data = ex.get("workflowData")
        name = str(wf_data["name"]) if isinstance(wf_data, dict) and wf_data.get("name") else None
        node, message, error_type = _error_of(ex)
        node, message = unkeyed(node), unkeyed(message[:MESSAGE_MASKED])
        known = maskers.of(wid, wf_data)
        if known is None and wid and wid not in unreadable:
            # no usable copy in the execution: the workflow as the API returns it now (read again if its masker was evicted)
            if (wid, "<current>") in maskers.cache:
                known = maskers.cached((wid, "<current>"))
            elif not maskers.over:
                try:
                    current = client.workflow(wid)
                except RunTimeout:
                    raise
                except Exception:  # a deleted workflow or a key without access
                    current = None
                known = maskers.of(wid, current, "<current>")
                if known is None:
                    unreadable.add(wid)
                if isinstance(current, dict) and current.get("name"):
                    name = name or str(current["name"])
        if known is not None:
            message, node = known(message), known(node)
            if error_type is not None and redact(known(unkeyed(error_type))) != error_type:
                error_type = GENERIC_ERROR_TYPE
        elif error_type is not None and redact(unkeyed(error_type)) != error_type:
            error_type = GENERIC_ERROR_TYPE
        names_hidden = known is None and not pattern_only  # fail closed: names can repeat a secret only the workflow knows
        if names_hidden:
            node = _node_ref(wf_data, node)
        if wid and name and not names_hidden and (wid not in names or (known is not None and wid not in named_by_masker)):
            names[wid] = known(name) if known is not None else name
            if known is not None:
                named_by_masker.add(wid)
        message_hidden = known is None and not pattern_only and message not in (NO_DETAILS, NO_MESSAGE)
        if message_hidden:  # fail closed: a secret only the workflow knows could be in it
            hidden += 1
            message = HIDDEN_BUDGET if maskers.over else HIDDEN_UNREADABLE
        else:
            # masked before it is shortened, so a cut cannot leave half a key that no pattern recognises
            message = mask_message(message)[:MESSAGE_SHOWN]
        node = display_name(node)
        key = (wid, node, message if message_hidden else normalize(message), (error_type or "") if message_hidden else "", names_hidden)
        started = safe_text(str(ex.get("startedAt") or ""))[:40]
        g = groups.setdefault(
            key,
            {
                "workflow_id": wid,
                "node": node or None,
                "error": key[2],
                "error_type": error_type,
                "message_hidden": message_hidden,
                "names_hidden": names_hidden,
                "example": message[:500],
                "count": 0,
                "execution_ids": [],
                "first_seen": started,
                "last_seen": started,
            },
        )
        g["count"] += 1
        if len(g["execution_ids"]) < 5:
            g["execution_ids"].append(ex_id)
        if started:
            g["first_seen"] = min(g["first_seen"] or started, started)
            g["last_seen"] = max(g["last_seen"], started)
        return 1

    incomplete: str | None = None
    try:
        for ex in client.executions(status, workflow_id, limit, include_data=True):
            total += _add_execution(ex)
    except RunTimeout as exc:  # --timeout ran out: what was read so far is kept
        if not total:
            raise
        incomplete = f"stopped after {total:,} executions: {exc}"
    except PaginationStalled as exc:  # also with nothing read: "no failed executions" would not be known
        incomplete = f"stopped after {total:,} executions: {exc}"
    ordered = sorted(groups.values(), key=lambda g: (-g["count"], g["workflow_id"], g["node"] or ""))
    for g in ordered:
        if g["names_hidden"]:
            g["workflow"] = f"workflow {display_name(unkeyed(g['workflow_id']))}"
        else:
            g["workflow"] = display_name(unkeyed(names.get(g["workflow_id"], g["workflow_id"])))
    result = {"instance": client.base, "status": status, "executions": total, "hidden_messages": hidden, "groups": ordered}
    if incomplete is not None:
        result["incomplete"] = incomplete
    return result


def render_text(result: dict[str, Any], style: Style) -> str:
    total = result["executions"]
    groups = result["groups"]
    if not total and result.get("incomplete"):
        return style.yellow(f"Incomplete: {safe_text(result['incomplete'])}.") + "\n"
    if not total:
        return style.green(f"No {result['status']} executions in the recent history of {result['instance']}.") + "\n"
    lines = [
        style.bold(f"{total} {result['status']} execution{'s' if total != 1 else ''}, {len(groups)} distinct problem{'s' if len(groups) != 1 else ''}"),
        "",
    ]
    for g in groups:
        where = f"{safe_text(g['workflow'])} > {safe_text(g['node'] or '(unknown node)')}"
        lines.append(f"{style.red(str(g['count']).rjust(4) + 'x')}  {style.bold(where)}")
        example = safe_text(g["example"])
        if g.get("message_hidden") and g.get("error_type"):  # what is left to tell hidden messages apart
            example = f"{style.dim(safe_text(g['error_type']) + ':')} {example}"
        lines.append(f"       {example}")
        span = g["last_seen"] if g["first_seen"] == g["last_seen"] else f"{g['first_seen'] or '?'} .. {g['last_seen']}"
        ids = f"executions {', '.join(g['execution_ids'])}{' ...' if g['count'] > len(g['execution_ids']) else ''}"
        lines.append(style.dim(f"       {ids}; {span}" if span else f"       {ids}"))
        lines.append("")
    if result.get("incomplete"):
        lines += [style.yellow(f"Incomplete: {safe_text(result['incomplete'])}."), ""]
    return "\n".join(lines)
