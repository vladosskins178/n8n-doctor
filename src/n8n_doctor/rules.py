"""The lint rules.

Every rule has a stable id (``N8D1xx`` security, ``N8D2xx`` structure, ``N8D3xx``
reliability, ``N8D4xx`` code) and a stable name. Ids never change meaning; a retired
rule's id is not reused. Documentation for each rule is in ``docs/rules.md``.
"""

from __future__ import annotations

import base64
import bisect
import collections
import functools
import heapq
import json
import math
import re
import unicodedata
import weakref
from array import array
from collections.abc import Callable, Iterable, Iterator
from dataclasses import dataclass
from typing import Any
from urllib.parse import quote

from . import nodes as nk
from .config import ALLOW_MAX_INPUT, compile_allow
from .expressions import (
    Key,
    KeyPath,
    code_language,
    code_part,
    expression_spans,
    format_path,
    iter_leaves,
    node_refs_with_keys,
    strip_js_comments,
    strip_python_comments,
)
from .files import json_copy, json_dumps
from .limits import DEFAULT, MB, Limits
from .model import Finding, Rule, Severity, plural
from .workflow import FileBudget, LimitError, Node, Workflow, WorkflowError, build, from_data

# Rules whose fixes address a node by its name: `fix` leaves alone the nodes that share a name.
NODE_FIXES = frozenset({"N8D207", "N8D212", "N8D302", "N8D303"})


@dataclass
class Context:
    wf: Workflow
    options: dict[str, dict[str, Any]]
    # True while the findings a rule yields next will only be counted (lint.run sets it once a limit is reached):
    # a rule may then skip what only a listed finding needs (messages, typo suggestions). Such findings count as
    # not fixable.
    counting: bool = False

    def option(self, rule_id: str, key: str, default: Any = None) -> Any:
        return self.options.get(rule_id, {}).get(key, default)


CheckFn = Callable[[Context, Rule], Iterator[Finding]]


def counted_findings(meta: Rule, count: int, severity: Severity | None = None) -> Finding:
    """``count`` findings at once, yielded while ``ctx.counting`` is set: lint.run counts them (not fixable, no node)."""
    finding = Finding(rule=meta, message="", severity=severity or meta.severity, autofix=False)
    finding.extra["count"] = count
    return finding


@dataclass(frozen=True)
class RegisteredRule:
    meta: Rule
    func: CheckFn

    @property
    def id(self) -> str:
        return self.meta.id

    def check(self, ctx: Context) -> Iterator[Finding]:
        """The rule's findings, one at a time: lint keeps only as many as it lists and counts the rest."""
        return self.func(ctx, self.meta)


RULES: list[RegisteredRule] = []


def rule(rule_id: str, name: str, severity: Severity, summary: str, fix: str, fixable: bool = False) -> Callable[[CheckFn], CheckFn]:
    def register(func: CheckFn) -> CheckFn:
        RULES.append(RegisteredRule(Rule(rule_id, name, severity, summary, fix, fixable), func))
        return func

    return register


def resolve(ref: str) -> Rule:
    """A rule by id (``N8D101``, any case) or name (``hardcoded-secret``)."""
    key = ref.strip().lower()
    for r in RULES:
        if r.meta.id.lower() == key or r.meta.name == key:
            return r.meta
    raise KeyError(f"unknown rule {shorten(ref, 40)!r}")


def _f(
    meta: Rule,
    message: str,
    node: Node | None = None,
    parameter: str | None = None,
    fix: str | None = None,
    severity: Severity | None = None,
) -> Finding:
    # Text is masked where it is shown (lint.run masks every finding it lists, names and paths included), so a
    # finding that is only counted costs no masking.
    return Finding(
        rule=meta,
        message=message,
        severity=severity or meta.severity,
        node=node.name if node else None,
        parameter=parameter,
        fix_hint=fix,
        node_index=node.index if node else None,
    )


def _shown(text: str, wf: Workflow) -> str:
    """A name or value quoted in a message: as it is up to the name length limit, otherwise only its length
    (cutting it could leave part of a secret that masking no longer recognises)."""
    return text if len(text) <= wf.limits.max_name_chars else f"<{len(text):,} characters>"


def _active_nodes(wf: Workflow) -> list[Node]:
    return [n for n in wf.real_nodes if not n.disabled]


def _is_expr(value: Any) -> bool:
    return isinstance(value, str) and value.startswith("=")


CHAT_TRIGGER = "@n8n/n8n-nodes-langchain.chatTrigger"
TOOL_WORKFLOW = "@n8n/n8n-nodes-langchain.toolWorkflow"
MCP_TRIGGER = "@n8n/n8n-nodes-langchain.mcpTrigger"
_AI_SUB_PREFIXES = ("lmChat", "lm", "tool", "memory", "embeddings", "outputParser", "textSplitter", "document", "retriever", "vectorStore", "reranker")

# ============================================================================================
# Input
# ============================================================================================


@rule(
    "N8D001",
    "incomplete-check",
    Severity.INFO,
    "Part of the workflow was checked only in part because it is over a resource limit (Code longer than "
    "--max-code-kb), or more findings than --max-findings (per workflow) or --max-findings-total (per run) were found and the rest are only counted.",
    "Check that part by hand, or raise the limit (see README, Resource limits).",
)
def _incomplete_check(ctx: Context, meta: Rule) -> Iterator[Finding]:
    for index, what in ctx.wf.partial:
        node = ctx.wf.node_at.get(index) if index is not None else None
        size = ctx.wf.limits.max_code_chars // 1024
        yield _f(meta, what, node, fix=f"Check the rest by hand, or raise the limit with --max-code-kb (max-code-kb in [limits]); it is {size:,} KB.")


# ============================================================================================
# Security
# ============================================================================================

# Private keys are found by their header, then masked through the matching END line even when the key is split
# over several string literals (Code nodes build PEMs with + and .join("\n")), or to the end of the value when
# there is no END line (encrypted headers, truncated keys): see _pem_spans.
_PEM_HEADER = re.compile(
    r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?|---- BEGIN SSH2 ENCRYPTED PRIVATE KEY|PuTTY-User-Key-File-\d{1,2}:"
)
_PEM_END = re.compile(r"-{4,5} ?END [A-Z0-9 ]{0,30}PRIVATE KEY(?: BLOCK)? ?-{4,5}")
_BASE64_RUN = re.compile(r"[A-Za-z0-9+/=]{40,}")
_PEM_WHAT = "a private key"

_SECRET_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("an AWS access key", re.compile(r"(?<![A-Za-z0-9])(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("a GitHub token", re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{36,4096}|github_pat_[A-Za-z0-9_]{40,4096})")),
    ("a Slack token", re.compile(r"(?<![A-Za-z0-9_-])xox[abposr]-[A-Za-z0-9-]{10,4096}")),
    ("a Slack webhook URL", re.compile(r"https://hooks\.slack\.com/services/T[A-Za-z0-9]+/B[A-Za-z0-9]+/[A-Za-z0-9]{8,4096}")),
    ("a Discord webhook URL", re.compile(r"https://(?:canary\.|ptb\.)?discord(?:app)?\.com/api/webhooks/\d+/[\w-]{20,4096}")),
    ("a Stripe live key", re.compile(r"\b[rs]k_live_[A-Za-z0-9]{20,4096}")),
    ("a Stripe test key", re.compile(r"\b[rs]k_test_[A-Za-z0-9]{20,4096}")),
    ("a GitLab token", re.compile(r"(?<![A-Za-z0-9_-])glpat-[A-Za-z0-9_-]{20,4096}")),
    ("a Hugging Face token", re.compile(r"(?<![A-Za-z0-9_-])hf_[A-Za-z0-9]{30,4096}")),
    ("a Shopify token", re.compile(r"(?<![A-Za-z0-9_-])shpat_[a-fA-F0-9]{32}(?![A-Za-z0-9])")),
    ("an npm token", re.compile(r"(?<![A-Za-z0-9_-])npm_[A-Za-z0-9]{30,4096}")),
    ("a Google OAuth token", re.compile(r"(?<![A-Za-z0-9_-])ya29\.[A-Za-z0-9_-]{20,4096}")),
    ("a Perplexity API key", re.compile(r"(?<![A-Za-z0-9_-])pplx-[A-Za-z0-9]{30,4096}")),
    ("a Replicate token", re.compile(r"(?<![A-Za-z0-9_-])r8_[A-Za-z0-9]{30,4096}")),
    ("an xAI API key", re.compile(r"(?<![A-Za-z0-9_-])xai-[A-Za-z0-9]{30,4096}")),
    ("an Anthropic API key", re.compile(r"(?<![A-Za-z0-9_-])sk-ant-[A-Za-z0-9_-]{20,4096}")),
    ("an OpenAI API key", re.compile(r"(?<![A-Za-z0-9_-])sk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{32,4096}")),
    ("a Google API key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    ("a Telegram bot token", re.compile(r"(?<![0-9])\d{8,10}:AA[0-9A-Za-z_-]{33}(?![0-9A-Za-z_-])")),
    ("a SendGrid API key", re.compile(r"\bSG\.[\w-]{22}\.[\w-]{43}\b")),
    ("a Groq API key", re.compile(r"(?<![A-Za-z0-9_-])gsk_[A-Za-z0-9]{40,4096}")),
    ("a Notion token", re.compile(r"(?<![A-Za-z0-9_-])(?:ntn_[A-Za-z0-9]{40,4096}|secret_[A-Za-z0-9]{43}(?![A-Za-z0-9_-]))")),
    ("a Stripe webhook secret", re.compile(r"(?<![A-Za-z0-9_-])whsec_[A-Za-z0-9+/=]{24,4096}")),
    ("a DigitalOcean token", re.compile(r"(?<![A-Za-z0-9_-])do[opr]_v1_[a-f0-9]{64}(?![A-Za-z0-9])")),
    ("a Linear API key", re.compile(r"(?<![A-Za-z0-9_-])lin_api_[A-Za-z0-9]{32,4096}")),
    ("a Tavily API key", re.compile(r"(?<![A-Za-z0-9_-])tvly-(?:dev-|prod-)?[A-Za-z0-9]{24,4096}")),
    ("a Supabase token", re.compile(r"(?<![A-Za-z0-9_-])sbp_[a-f0-9]{40}(?![A-Za-z0-9])")),
    ("a Pinecone API key", re.compile(r"(?<![A-Za-z0-9_-])pcsk_[A-Za-z0-9_]{40,4096}")),
    ("an Atlassian API token", re.compile(r"(?<![A-Za-z0-9_-])ATATT[A-Za-z0-9_=-]{50,4096}")),
    ("an Apify token", re.compile(r"(?<![A-Za-z0-9_-])apify_api_[A-Za-z0-9]{30,4096}")),
    ("a Brevo API key", re.compile(r"(?<![A-Za-z0-9_-])xkeysib-[a-f0-9]{64}-[A-Za-z0-9]{16}(?![A-Za-z0-9])")),
    ("a Google OAuth client secret", re.compile(r"(?<![A-Za-z0-9_-])GOCSPX-[A-Za-z0-9_-]{28}(?![A-Za-z0-9_-])")),
    ("a Bitbucket app password", re.compile(r"(?<![A-Za-z0-9_-])ATBB[A-Za-z0-9]{24,64}(?![A-Za-z0-9_-])")),
    ("a Supabase secret key", re.compile(r"(?<![A-Za-z0-9_-])sb_secret_[A-Za-z0-9_-]{20,4096}")),
    (
        "a Microsoft Teams webhook URL",
        re.compile(r"https://(?:[A-Za-z0-9-]{1,63}\.webhook\.office\.com/webhookb2|outlook\.office(?:365)?\.com/webhook)/[A-Za-z0-9@/_-]{20,1024}"),
    ),
    ("a Facebook access token", re.compile(r"(?<![A-Za-z0-9_-])EAA[BG][A-Za-z0-9]{80,4096}")),
    ("a Sentry token", re.compile(r"(?<![A-Za-z0-9_-])sntry[su]_[A-Za-z0-9_+/=-]{40,4096}")),
    ("a Slack app token", re.compile(r"(?<![A-Za-z0-9_-])xapp-\d-[A-Za-z0-9-]{20,4096}")),
    ("a HubSpot token", re.compile(r"(?<![A-Za-z0-9_-])pat-(?:na|eu|ap)\d{1,2}-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b")),
    ("an Airtable token", re.compile(r"(?<![A-Za-z0-9_-])pat[A-Za-z0-9]{14}\.[A-Za-z0-9]{40,128}\b")),
    ("a JSON Web Token", re.compile(r"(?<![A-Za-z0-9_.-])eyJ[A-Za-z0-9_-]{10,4096}\.eyJ[A-Za-z0-9_-]{10,4096}\.[A-Za-z0-9_-]{10,4096}")),
    (  # the password runs to the last @ before the host: it can hold one (postgres://u:p@ss@db)
        "a password in a URL",
        re.compile(r"(?<![a-z0-9+.-])[a-z][a-z0-9+.-]{0,30}://[^\s/:@{}'\"]{0,256}:([^\s/{}'\"]{3,256})@(?!example\.(?:com|org|net)\b)[\w.-]", re.IGNORECASE),
    ),
    (  # a name that can only mean a secret: any literal value counts (placeholders and {{ }} aside)
        # the value stops at a backtick, and punctuation or markdown only counts inside it: `...?token=abc`, *...?token=abc*, ...?token=abc.
        "a secret in a URL query string",
        re.compile(
            r"(?:^|[?&])(?:[a-z0-9_-]{0,40}(?:api[_-]?key|secret)|hapikey|api[_-]?token|access[_-]?token|auth[_-]?token|auth[_-]?key|private[_-]?token|"
            r"refresh[_-]?token|session[_-]?token|secret[_-]?token|oauth[_-]?token|bot[_-]?token|token|access[_-]?key|user[_-]?key|client[_-]?key|app[_-]?key|"
            r"license[_-]?key|secret[_-]?key|subscription-key)"
            r"=((?:[^&#\s'\"{}<>`.,;:!)*]|[.,;:!)*](?=[^&#\s'\"{}<>`.,;:!)*])){8,1024})",
            re.IGNORECASE,
        ),
    ),
    (  # a password can hold any punctuation, so it runs to the next delimiter; from 4 characters, and a short start of an expression is no value
        "a password in a URL query string",
        re.compile(
            r"(?:^|[?&])(?:pass|[a-z0-9_-]{0,40}(?:password|passwd|passphrase)|[a-z0-9_-]{0,40}pwd(?!=/)|[a-z0-9_-]{0,40}[_-]pass)="
            r"([^&#\s'\"{}<>`]{8,1024}|[^&#\s'\"{}<>`]{4,7}(?=[&#\s'\"}<>`]|$))",
            re.IGNORECASE,
        ),
    ),
    (  # ?key=, ?sig= and ?sort_key= also name fields and timestamps: only a generated-looking value counts, and paging tokens are no secrets
        "a key in a URL query string",
        re.compile(
            r"[?&](?!(?:(?:next|prev(?:ious)?|continuation|sync|cursor)[_-]?(?:page[_-]?)?|page[_-]?)token=)"
            r"(?:[a-z0-9_-]{0,40}(?:key|token|auth)|signature|sig|x-amz-signature|appid)=((?:[^&#\s'\"{}<>`.,;:!)*]|[.,;:!)*](?=[^&#\s'\"{}<>`.,;:!)*])){8,1024})",
            re.IGNORECASE,
        ),
    ),
    (  # Server=db;User Id=sa;Password=...; (ADO.NET, ODBC, JDBC property strings)
        "a password in a connection string",
        re.compile(r"(?i)(?:^|(?<=[;'\"]))[ \t]*(?:password|pwd)[ \t]*=[ \t]*([^;'\"\s{}&]{4,256})(?=;|['\"]|$)"),
    ),
    (  # DefaultEndpointsProtocol=https;AccountName=a;AccountKey=...; (Azure storage and Service Bus)
        "a key in a connection string",
        re.compile(r"(?i)(?<![A-Za-z0-9])(?:AccountKey|SharedAccessKey)[ \t]*=[ \t]*([A-Za-z0-9+/]{16,1024}={0,2})"),
    ),
    (  # curl -u user:password, curl --user=user:password (see _in_curl: other tools take -u for a URL or a user)
        "a password in a curl command",
        re.compile(r"(?<![\w-])(?:-u|--user)(?:[ \t]+|=)['\"]?[^\s:'\"]{1,256}:([^\s'\"]{4,256})"),
    ),
    (  # from 4 characters: docker run -u node:node, sudo -u a:b are no passwords
        "a short password in a curl command",
        re.compile(r"(?<![\w-])(?:-u|--user)(?:[ \t]+|=)['\"]?[^\s:'\"]{1,256}:([^\s'\"]{4,7})(?=[\s'\"]|$)"),
    ),
    ("a bearer token", re.compile(r"\bBearer[ \t]+([A-Za-z0-9._~+/-]{20,1024}=*)(?![A-Za-z0-9._~+/=-])(?![^\s]{0,256}\{\{)")),
]

# A text without any of these substrings cannot match the pattern, so the scan is skipped (a fast `in` test).
_HINTS: dict[str, tuple[str, ...]] = {
    "an AWS access key": ("AKIA", "ASIA"),
    "a GitHub token": ("ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github_pat_"),
    "a Slack token": ("xox",),
    "a Slack webhook URL": ("hooks.slack.com",),
    "a Discord webhook URL": ("discord",),
    "a Stripe live key": ("k_live_",),
    "a Stripe test key": ("k_test_",),
    "a GitLab token": ("glpat-",),
    "a Hugging Face token": ("hf_",),
    "a Shopify token": ("shpat_",),
    "an npm token": ("npm_",),
    "a Google OAuth token": ("ya29.",),
    "a Perplexity API key": ("pplx-",),
    "a Replicate token": ("r8_",),
    "an xAI API key": ("xai-",),
    "a key in a connection string": ("ccountKey", "ccountkey", "CCOUNTKEY", "ccessKey", "ccesskey", "CCESSKEY"),
    "an Anthropic API key": ("sk-ant-",),
    "an OpenAI API key": ("sk-",),
    "a Google API key": ("AIza",),
    "a Telegram bot token": (":AA",),
    "a SendGrid API key": ("SG.",),
    "a Groq API key": ("gsk_",),
    "a Notion token": ("ntn_", "secret_"),
    "a Stripe webhook secret": ("whsec_",),
    "a DigitalOcean token": ("_v1_",),
    "a Linear API key": ("lin_api_",),
    "a Tavily API key": ("tvly-",),
    "a Supabase token": ("sbp_",),
    "a Pinecone API key": ("pcsk_",),
    "an Atlassian API token": ("ATATT",),
    "an Apify token": ("apify_api_",),
    "a Brevo API key": ("xkeysib-",),
    "a Google OAuth client secret": ("GOCSPX-",),
    "a Bitbucket app password": ("ATBB",),
    "a Supabase secret key": ("sb_secret_",),
    "a Microsoft Teams webhook URL": ("office",),
    "a Facebook access token": ("EAA",),
    "a Sentry token": ("sntry",),
    "a Slack app token": ("xapp-",),
    "a HubSpot token": ("pat-",),
    "an Airtable token": ("pat",),
    "a JSON Web Token": ("eyJ",),
    "a password in a URL": ("://",),
    "a secret in a URL query string": ("=",),
    "a password in a URL query string": ("=",),
    "a key in a URL query string": ("=",),
    "a password in a connection string": ("assword", "ASSWORD", "wd", "WD"),
    "a password in a curl command": ("-u", "--user"),
    "a short password in a curl command": ("-u", "--user"),
    "a bearer token": ("Bearer",),
}


_HINT_FINDER = re.compile("|".join(sorted({re.escape(h) for hints in _HINTS.values() for h in hints}, key=len, reverse=True)))


def _patterns_for(text: str) -> list[tuple[str, re.Pattern[str]]]:
    """The N8D101 patterns that can match somewhere in ``text`` (one scan for all their hints)."""
    found = set(_HINT_FINDER.findall(text))
    if not found:
        return []
    if "sk-ant-" in found:  # the longer hint was taken where both start; the OpenAI pattern also applies there
        found.add("sk-")
    if "pat-" in found:
        found.add("pat")
    if "--user" in found:
        found.add("-u")
    return [(what, pattern) for what, pattern in _SECRET_PATTERNS if any(hint in found for hint in _HINTS[what])]


SENSITIVE_NAME = re.compile(
    r"^(?:authorization|proxy-authorization|x-api[-_]?key|api[-_ ]?key|apikey|hapikey|x-auth-token|auth[-_]?token|access[-_]?token|"
    r"refresh[-_]?token|token|secret|client[-_]?secret|app[-_]?secret|password|passwd|pwd|pass|passphrase|private[-_]?key|x-access-token|x-authorization|authentication|"
    r"x-[a-z0-9-]*-(?:key|token|secret)|[a-z0-9_ -]{0,80}[-_ ](?:apikey|apitoken|authtoken|passphrase))$",
    re.IGNORECASE,
)
SENSITIVE_KEY = re.compile(r"(?:password|passwd|secret|api_?key|apikey|access_?token|auth_?token|private_?key)$", re.IGNORECASE)
# A name that holds a password wherever the word stands in it (db_password, userPassword, X-Db-Password, password_old),
# or that ends in the word pass (ftp_pass, dbPass; not bypass, compass, ByPass). Words around it can say the name is
# about the password rather than holding it: passwordField, password_policy, reset_password_url, boarding_pass.
_PASSWORD_IN = re.compile(r"(?i)pass(?:word|wd)(?!less)|pwd")
_PASS_AT_END = re.compile(r"(?i:(?<![a-z])pass)$|(?<=[a-z0-9])(?<![Bb]y)Pass$")
_NAME_WORD = re.compile(r"[A-Z]?[a-z0-9]+|[A-Z]+(?![a-z])")
_NOT_PASSWORD_AFTER = frozenset(
    "field input url uri link path file policy rule rules min max minimum maximum length len size hint label placeholder selector "  # noqa: SIM905
    "expiry expires expired expiration reset required strength prompt title text message column attr attribute name type changed change "
    "updated age enabled disabled flow regex pattern mask algorithm id".split()
)
_NOT_PASSWORD_BEFORE = frozenset(
    "forgot reset change update require requires required has show hide no is need needs use uses with without generate enable disable "  # noqa: SIM905
    "send sent min max minimum maximum".split()
)
_NOT_PASS_BEFORE = frozenset(
    "boarding season hall day week month year annual mountain gift ticket gate free test tests did can must should by all first second third final".split()  # noqa: SIM905
)


@functools.lru_cache(maxsize=4096)
def password_named(name: str) -> bool:
    """``name`` (of a header, field, variable or key) says it holds a password (see above)."""
    if not _PASSWORD_IN.search(name) and not _PASS_AT_END.search(name.strip()):
        return False
    words = [w.lower() for w in _NAME_WORD.findall(name)]
    for i, word in enumerate(words):
        if _PASSWORD_IN.search(word):
            return not _NOT_PASSWORD_BEFORE.intersection(words[:i]) and not _NOT_PASSWORD_AFTER.intersection(words[i + 1 :])
    return not _NOT_PASS_BEFORE.intersection(words[:-1])


def _secret_name(name: str) -> bool:
    """A header or entry name whose literal value is a secret, whatever the value looks like."""
    return SENSITIVE_NAME.match(name.strip()) is not None or password_named(name)


def _secret_key(key: str) -> bool:
    """The same for a plain parameter; pwd alone can be a folder and pass a flag (see _PLAIN_SECRET_KEY)."""
    return SENSITIVE_KEY.search(key) is not None or (password_named(key) and key.lower() not in ("pwd", "pass"))


# Plain parameters whose name says less: pwd can be a folder, pass a flag, token a word. Only a generated-looking value
# counts (see _generated). Exact names, since pageToken and nextToken hold generated values that are no secrets.
_PLAIN_SECRET_KEY = re.compile(r"(?i)token|pwd|pass|passphrase|cookie|x[-_]api[-_]key|(?:refresh|bot|session)[-_]?token|(?:encryption|license)[-_]?key")
_COOKIE_PAIR = re.compile(r"(?:^|;)\s*[^=;\s]+=([^;\s]+)")
# A label and its value in a sticky note ("password: hunter2", "**API key:** `abc123`"). The value must end the line or
# a list item: "password: see the vault" is prose. Quotes and markdown around either are left out of the match.
# Each scan takes the whole run of value characters at once (nothing after it can make the regex back up over the run,
# and the next match starts after it); only then is the end of the value checked, once. So the work is linear in the
# text however many labels it repeats.
_NOTE_RUN = r"""([^\s*`"']{4,257})"""
_NOTE_RUN_ROW = r"""([^\s|*`"']{4,257})"""
_NOTE_NAMES = r"password|passwd|pwd|pass|passphrase|secret|token|api[-_ ]?key|access[-_ ]?key|private[-_ ]?key"
_NOTE_HEADERS = r"authorization|proxy-authorization|x-authorization|x-[a-z0-9-]{0,40}(?:key|token|secret|auth)"
_NOTE_LABEL = re.compile(rf"""(?i)(?<![\w-])(?:{_NOTE_NAMES})[*_`]{{0,4}}[ \t]{{0,8}}[:=][*_`"' \t]{{0,16}}{_NOTE_RUN}""")
_NOTE_VALUE = re.compile(r"""(?im)([^\s*`"']{4,256}?)[*_`"']{0,4}(?:[,;|][ \t]|[.,;!]?[ \t]*$|[ \t]+\()""")
# What the name of a setting ends in: OPENAI_API_KEY=..., client_secret: ..., accessToken: ... (see _note_secrets)
_NOTE_SETTING = re.compile(
    r"""(?<![\w-])(?P<name>(?:[A-Za-z0-9]{1,40}[-_]){1,7}(?i:password|passwd|pwd|pass|passphrase|secret|token|api[-_]?key|access[-_]?key|secret[-_]?key|private[-_]?key)"""
    r"""|[A-Z]?[a-z0-9]{1,40}(?:[A-Z][a-z0-9]{1,40}){0,4}(?:Password|Passwd|Pwd|Passphrase|Secret|Token|Api[Kk]ey|API[Kk]ey|Access[Kk]ey|Secret[Kk]ey|Private[Kk]ey))"""
    rf"""[*_`]{{0,4}}[ \t]{{0,8}}[:=][*_`"' \t]{{0,16}}{_NOTE_RUN}"""
)
# Limits of a language model, not secrets: max_tokens=4096
_NOTE_NOT_SETTING = re.compile(r"(?i)(?:max|min|num|total|input|output|prompt|completion|context|default)[-_]?(?:new[-_]?)?tokens?")
# Where the label says less about the value, the value must not be a plain word (see _note_value_like): a header
# ("X-Api-Key: ...", "Authorization: Bearer ..."), "password is ...", and a table row ("| password | ... |").
_NOTE_SCHEMES = "bearer|basic|token|bot|oauth|ssws|geniekey|klaviyo-api-key|zoho-oauthtoken"
_NOTE_HEADER = re.compile(rf"""(?i)(?<![\w-])(?:{_NOTE_HEADERS})[*_`]{{0,4}}[ \t]{{0,8}}:[*_`"' \t]{{0,16}}(?:(?:{_NOTE_SCHEMES})[ \t]+)?{_NOTE_RUN}""")
_NOTE_IS = re.compile(rf"""(?i)(?<![\w-])(?:{_NOTE_NAMES}|{_NOTE_HEADERS})[*_`]{{0,4}}[ \t]+is[ \t]+[*_`"']{{0,4}}{_NOTE_RUN}""")
_NOTE_ROW = re.compile(rf"""(?im)^[ \t]*(?:\|[ \t]*)?[*_`]{{0,4}}(?:{_NOTE_NAMES}|{_NOTE_HEADERS})[*_`]{{0,4}}[ \t]*\|[ \t]*[*_`"']{{0,4}}{_NOTE_RUN_ROW}""")
_NOTE_ROW_VALUE = re.compile(r"""(?im)([^\s|*`"']{4,256}?)[*_`"']{0,4}[ \t]*(?:\||$)""")
# Words with digits that name a product or a method rather than hold a secret; other capitalised words are told by
# their shape (see _note_product).
_NOTE_PRODUCTS = frozenset(
    {"oauth1", "oauth2", "1password", "auth0", "base64", "base32", "md5", "sha1", "sha256", "sha512", "aes256", "s3", "k8s", "web3", "int32", "int64", "uuid4"}
)
_NOTE_WORDS = frozenset(
    {"none", "null", "nil", "empty", "required", "optional", "unknown", "unset", "hidden", "masked", "redacted"}
    | {"secret", "password", "token", "credential", "credentials", "vault", "tbd", "todo", "true", "false", "here", "below", "above"}
    | {"string", "str", "text", "number", "integer", "int", "float", "boolean", "bool", "object", "array"}
)
# what a note says about tokens of a language model: "Token: gpt-4o", "token: claude-3"
_NOTE_MODEL = re.compile(r"(?i)(?:gpt|chatgpt|claude|gemini|llama|mistral|deepseek|qwen|o[134])(?:-[a-z0-9.]{1,20}){0,5}")
# name = 'value' or name: 'value', the name bare or quoted ('X-Api-Key': '...', "password": "..."), the value
# after an optional auth scheme ("Basic ...")
_CODE_NAME = r"""(?:(?<![\w$])([A-Za-z_$][\w$]{0,80})|(['"])([A-Za-z_$][\w$-]{0,80})\2)"""
_CODE_VALUE = r"""\s*[:=]\s*(['"`])(?:(?:Basic|Bearer|Token)[ \t]+)?"""
_ASSIGN_HINT = re.compile(r"""[:=]\s*['"`]""")
_CODE_ASSIGN = re.compile(_CODE_NAME + _CODE_VALUE + r"""([^'"`\s{}$]{4,1024})\4""")
# headers["x-api-key"] = '...' (JavaScript and Python)
_CODE_INDEX = re.compile(r"""\[\s*(['"])([A-Za-z_$][\w$-]{0,80})\1\s*\]\s*=\s*(['"`])(?:(?:Basic|Bearer|Token)[ \t]+)?([^'"`\n{}$]{4,1024})\3""")
# params.set('token', '...'), headers.append("X-Api-Key", "...")
_CODE_SET = re.compile(r"""\.(?:set|append)\(\s*(['"])([A-Za-z_$][\w$-]{0,80})\1\s*,\s*(['"`])(?:(?:Basic|Bearer|Token)[ \t]+)?([^'"`\n{}$]{4,1024})\3\s*\)""")
# the variable name must end in the secret word: apiKey, BOT_TOKEN, dbPassword (not tokenUrl, passwordField)
_SECRETISH_NAME = re.compile(
    r"(?i:api[-_]?key|apikey|secret|secret_?key|token|password|passwd|pwd|bearer|private_?key|access_?key|signing_?key|"
    r"client_?secret|master_?key|encryption_?key|auth_?key|authorization)$|" + _PASS_AT_END.pattern
)
_JSON_PAIR = re.compile(r'(?<![A-Za-z0-9_-])"((?:[A-Za-z0-9_-]|\\u[0-9a-fA-F]{4}){2,40})"\s*:\s*"(?:(?:Basic|Token|Bearer)[ \t]+)?([^"{}\s]{4,1024})"')
_JSON_ESCAPE = re.compile(r"\\u([0-9a-fA-F]{4})")
# Authorization under any scheme word: Bot, OAuth, SSWS, GenieKey, Klaviyo-API-Key, Zoho-oauthtoken, ...
_AUTH_NAME = re.compile(r"(?i)(?:proxy-|x-)?authorization|authentication")
_AUTH_SCHEME = re.compile(r"[A-Za-z][A-Za-z0-9_.-]{0,40}\s+(?=\S+$)")
_JSON_AUTH = re.compile(r'"((?i:(?:proxy-|x-)?authorization|authentication))"\s*:\s*"[A-Za-z][A-Za-z0-9_.-]{0,40}[ \t]+([^"{}\s]{1,1024})"')
_CODE_AUTH = re.compile(r"""(?i)authorization['"]?\s*(?:[:=,]|\]\s*=)\s*(['"`])[a-z][a-z0-9_.-]{0,40}[ \t]+([^'"`\s{}$]{1,1024})\1""")
# What a template or the docs put where the secret goes; only these clear forms, so a real password that holds
# such a word (Enter-The-Dragon-99, addMe2024!, Prod-Example-77) or is written in capitals (ADMINPASS) is a secret.
# A value in a secret-named field is masked in every output whether or not it is one of these (:func:`_leaf_secrets`).
_PLACEHOLDER_PHRASE = re.compile(
    r"(?i)^[<\[{%]?\s*(?:your|enter|add|insert|replace|put)[-_ ]?(?:your[-_ ]?)?[a-z_ -]*"
    r"(?:api[-_ ]?key|token|secret|password|key|id|api|credentials?)(?:[-_ ]?(?:add[-_ ]?)?here)?\s*[>\]}%]?$"
)
# your_api_key_here, YourAPIKeyHere, <<API_KEY>>, Bearer YOUR_ACCESS_TOKEN_HERE, test-api-key, paste-your-key-here
_KEY_PHRASE = r"(?:api|access|secret|auth)?[-_ ]?(?:key|token|secret|password|pass)"
_PLACEHOLDER_TEMPLATE = re.compile(
    r"(?i)^(?:bearer\s+)?(?:<<?|\{\{?|\[|%)?\s*(?:"
    r"(?:your|my|the|test|example|sample|dummy|fake)?[-_ ]?" + _KEY_PHRASE + r"[-_ ]?(?:goes[-_ ]?)?(?:here)?"
    r"|(?:paste|put|add|insert|enter|replace)[-_ ]?(?:your[-_ ]?)?" + _KEY_PHRASE + r"[-_ ]?(?:goes[-_ ]?)?here"
    r")\s*(?:>>?|\}\}?|\]|%)?$"
)
# YOUR_N8N_API_KEY_HERE, your-s3-secret-key, Bearer YOUR_S3_TOKEN: separate words, each with a letter, so your-2024-password
# and Your2024Key are passwords; YOU_API_KEY_HERE, the typo, only with its "here"
_PLACEHOLDER_WORDS = r"(?:(?=[a-z0-9]*[a-z])[a-z0-9]{1,24}[-_ ]){0,6}?(?:api[-_ ]?key|token|secret|password|key|id|api|credentials?)"
_PLACEHOLDER_NAMED = re.compile(
    r"(?i)^(?:bearer\s+)?[<\[{%]?\s*(?:(?:your|enter|add|insert|replace|put)[-_ ](?:your[-_ ])?" + _PLACEHOLDER_WORDS + r"(?:[-_ ](?:add[-_ ])?here)?"
    r"|you[-_ ]" + _PLACEHOLDER_WORDS + r"[-_ ]here)\s*[>\]}%]?$"
)
_PLACEHOLDER_REDACTED = re.compile(r"(?i)^(?:bearer\s+)?[\[<{(]\s*redacted[-_ a-z0-9]{0,60}[\]>})]$")  # [REDACTED_API_TOKEN]
_PLACEHOLDER_FILL = re.compile(r"(?i)^x{2,}(?:[-_ ]x{2,})+$|^0{8}-0{4}-0{4}-0{4}-0{12}$")  # xxx-xxx-xxx, the all-zero UUID
_PLACEHOLDER_WORD = re.compile(r"(?i)^(?:changeme|replace_?me|example|placeholder|redacted|undefined|required|x{3,}|\*{3,}|<[^>]+>|%[A-Z_]+%)$")
_PLACEHOLDER_REDACTED_NAME = re.compile(r"REDACTED(?:_[A-Z0-9]+)+")  # REDACTED_API_TOKEN
# PASTE_YOUR_NIXGUARD_API_KEY_HERE, enter your license number here: any "<verb> your ... here"
_PLACEHOLDER_YOUR_HERE = re.compile(r"(?i)^[<\[{(]?\s*(?:paste|enter|insert|put|add)[-_ ]+(?:in[-_ ]+)?your[-_ ][\w -]{0,80}?[-_ ]?here\s*[>\]})]?$")
# change-me forms: change_me, CHANGE-ME-app-secret, changeme-please, please-change-me (a separator before any rest,
# so changeme123 is a password); bracketed "your ..." text, also after a URL part: [your-api-key], {your_app_secret},
# bot[your-telegram-bot-token], [change-me]
_PLACEHOLDER_CHANGE_ME = re.compile(r"(?i)^(?:[a-z0-9]+[-_ .])*change[-_ ]?me(?:[-_ .][a-z0-9]+\+?)*$")
_PLACEHOLDER_MAX = 100  # longer text is no change-me placeholder (and the pattern backtracks on long word lists)
_PLACEHOLDER_BRACKETED = re.compile(
    r"(?i)^[a-z]{0,12}(?:\[\s*(?:your|change)[-_ ][^\[\]<>{}]{1,80}\]|<\s*(?:your|change)[-_ ][^\[\]<>{}]{1,80}>|"
    r"\{\s*(?:your|change)[-_ ][^\[\]<>{}]{1,80}\})$"
)
# the name of the environment variable or setting that holds the secret: POSTIZ_API_KEY, CLIENTSECRET
_SETTING_NAME = re.compile(r"[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)*_(?:KEY|TOKEN|SECRET|PASSWORD|ID|AUTH)")
_SETTING_WORDS = frozenset({"CLIENTSECRET", "APIKEY", "ACCESSTOKEN", "SECRETKEY"})
# the example keys of the providers' own documentation
_DOCUMENTED_KEYS = frozenset({"AKIAIOSFODNN7EXAMPLE", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"})
_KNOWN_PREFIX = re.compile(
    r"(?:sk-(?:ant-|proj-|svcacct-|admin-)?|[rs]k_(?:live|test)_|glpat-|hf_|shpat_|npm_|ya29\.|pplx-|r8_|xai-|gh[pousr]_|github_pat_|AKIA|ASIA|xox[abposr]-|AIza|SG\.|gsk_|ntn_|secret_|whsec_|do[opr]_v1_|lin_api_|tvly-(?:dev-|prod-)?|sbp_|pcsk_|ATATT|apify_api_|xkeysib-|GOCSPX-|ATBB|sb_secret_|EAA[BG]|sntry[su]_|xapp-\d-|"
    r"pat-(?:na|eu|ap)\d{1,2}-|pat(?=[A-Za-z0-9]{14}\.))"
)
# filler after a known prefix: sk-xxxx..., ghp_0000..., xoxb-your-token-here; separators count with it
_FILLER = re.compile(r"(?i:x{2,}|your|my|enter|insert|replace|put|add|api|key|token|secret|here|goes|example|placeholder|value)|0{2,}|\*{2,}|[-_.]")
_WEBHOOK_HEAD = re.compile(r"https://[^/]+/(?:services|api/webhooks|webhookb2|webhook)/")
_WEBHOOK_YOUR = re.compile(r"(?i)(?:your|my)[-_]")  # .../webhook/your-teams-incoming-webhook: real paths hold ids


def _placeholder_token(value: str) -> bool:
    """A provider token that a template or the docs show: filler makes up at least 60% of what follows the known
    prefix (sk-xxxx, xoxb-your-token-here, AKIAXXXXXXXXXXXXXXXX), or one of the providers' documented examples."""
    if value in _DOCUMENTED_KEYS:
        return True
    webhook = _WEBHOOK_HEAD.match(value)
    if webhook and _WEBHOOK_YOUR.match(value, webhook.end()):
        return True
    head = _KNOWN_PREFIX.match(value) or webhook
    rest = value[head.end() :] if head else value
    if not rest:
        return False
    filler = sum(m.end() - m.start() for m in _FILLER.finditer(rest))
    return filler >= 0.6 * len(rest)


_BASE64_PAIR = re.compile(r"(?:[A-Za-z0-9+/]{4}){2,256}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?")


def _encoded_placeholder(value: str) -> bool:
    """Base64 of ``user:password`` whose password part stands for one: a template's Basic header."""
    if not _BASE64_PAIR.fullmatch(value):
        return False
    try:
        text = base64.b64decode(value, validate=True).decode("utf-8")
    except ValueError:
        return False
    if not text.isprintable():
        return False
    secret = text.rpartition(":")[2].strip()
    return bool(secret) and (secret.lower() in _NON_VALUES or _placeholder(secret))


def _placeholder(value: str) -> bool:
    """A value that stands for a secret rather than being one, or the name of the setting that holds it."""
    if _encoded_placeholder(value):
        return True
    if len(value) > 2 and value[0] == value[-1] and value[0] in "\"'":  # "your_api_key", the quotes in the value
        value = value[1:-1]
    return (
        _PLACEHOLDER_PHRASE.match(value) is not None
        or _PLACEHOLDER_TEMPLATE.match(value) is not None
        or _PLACEHOLDER_NAMED.match(value) is not None
        or _pem_placeholder(value)
        or _PLACEHOLDER_FILL.match(value) is not None
        or _PLACEHOLDER_REDACTED.match(value) is not None
        or _PLACEHOLDER_WORD.match(value) is not None
        or _PLACEHOLDER_REDACTED_NAME.fullmatch(value) is not None
        or (len(value) <= _PLACEHOLDER_MAX and _PLACEHOLDER_YOUR_HERE.match(value) is not None)
        or (len(value) <= _PLACEHOLDER_MAX and _PLACEHOLDER_CHANGE_ME.match(value) is not None)
        or _PLACEHOLDER_BRACKETED.match(value) is not None
        or _SETTING_NAME.fullmatch(value) is not None
        or value in _SETTING_WORDS
        or (_KNOWN_PREFIX.match(value) is not None and _placeholder_token(value))
        or value in _DOCUMENTED_KEYS
    )


_PEM_LINE_BREAK = re.compile(r"\\+[nr]")  # a line break written as text, in JSON text once more


def _pem_placeholder(value: str) -> bool:
    """A private key block whose body only shows where the key goes: ``...``, ``[INSERT YOUR KEY HERE]``."""
    head = _PEM_HEADER.match(value.lstrip())
    if head is None:
        return False
    rest = value.lstrip()[head.end() :]
    end = _PEM_END.search(rest)
    if end is not None and _PEM_LINE_BREAK.sub("", rest[end.end() :]).strip():
        return False
    body = _PEM_LINE_BREAK.sub("\n", rest[: end.start()] if end else rest).replace("\\u2026", "\u2026").strip("-").strip()
    return len(body) <= _PLACEHOLDER_MAX and bool(body) and (not body.strip(".\u2026") or _placeholder(body))


def _pem_spans(text: str, stop_at_quote: bool) -> tuple[list[tuple[int, int]], int | None]:
    """(start, end) of every private key in ``text``, and where the first key without an END line starts.

    A key runs from its header through the next END line, across quotes and string literals; without
    one it runs to the next ``"`` (``stop_at_quote``, for JSON text such as diff lines) or to the end of
    ``text`` (a single parameter value). Linear: the next END and quote positions are found once and reused.
    """
    spans: list[tuple[int, int]] = []
    open_from: int | None = None
    if "PRIVATE KEY" not in text and "PuTTY-User-Key-File-" not in text:
        return spans, open_from
    end_match: re.Match[str] | None = None
    end_from = -1  # end_match is the first END at or after this position (None: there is none)
    quote = -1
    for h in _PEM_HEADER.finditer(text):
        if spans and h.start() < spans[-1][1]:
            continue  # inside the previous key
        if end_from < 0 or (end_match is not None and end_match.start() < h.end()):
            end_match = _PEM_END.search(text, h.end())
            end_from = h.end()
        if end_match is not None:
            spans.append((h.start(), end_match.end()))
            continue
        if open_from is None:
            open_from = h.start()
        if stop_at_quote:
            if quote < h.end():
                quote = text.find('"', h.end())
                quote = len(text) if quote < 0 else quote
            spans.append((h.start(), quote))
        else:
            spans.append((h.start(), len(text)))
    return spans, open_from


def _pem_secrets(text: str) -> Iterator[tuple[str, int]]:
    """(secret, offset) for every private key in one value, and every long base64 run after a key header."""
    spans, open_from = _pem_spans(text, stop_at_quote=False)
    for start, end in spans:
        yield text[start:end], start
    if open_from is not None:  # masked on their own too: a fix can change the text around them
        for m in _BASE64_RUN.finditer(text, open_from):
            yield m.group(0), m.start()


def _mask_pem(text: str) -> str:
    """``text`` with private keys masked (keeping 4 characters of the header), and long base64 runs after a
    key with no END line (its body may continue in the next string literal)."""
    spans, open_from = _pem_spans(text, stop_at_quote=True)
    if not spans:
        return text
    marks = [(s, e, True) for s, e in spans]
    if open_from is not None:
        marks += [(m.start(), m.end(), False) for m in _BASE64_RUN.finditer(text, open_from)]
        marks.sort()
    out: list[str] = []
    pos = 0
    for start, end, header in marks:
        if end <= pos:
            continue
        start = max(start, pos)
        out.append(text[pos:start])
        out.append((text[start : start + 4] if header else "") + "***")
        pos = end
    out.append(text[pos:])
    return "".join(out)


_PASSWORD_LABEL = re.compile(r"(?i)pass(?:word|wd|phrase)|pwd|(?<![a-z])pass(?![a-z])")
_LITERAL_LABEL = re.compile(r'a literal "(.*)" value')


def _password_label(what: str) -> bool:
    """A label from :func:`text_secrets` says the value is a password, by its own words or the name of its field."""
    literal = _LITERAL_LABEL.fullmatch(what)
    return _PASSWORD_LABEL.search(what) is not None or (literal is not None and _PASS_AT_END.search(literal.group(1).strip()) is not None)


def _mask(value: str, what: str = "") -> str:
    """Show a long token's first 4 characters (usually its well-known prefix), nothing of shorter ones or of passwords (``what``: the label)."""
    value = value.strip()
    return (value[:4] + "..." if len(value) >= 20 and not _password_label(what) else "***") + f" ({len(value)} chars)"


def redact(text: str) -> str:
    """``text`` with every secret the N8D101 patterns recognise replaced by a masked form."""

    def masker(what: str) -> Callable[[re.Match[str]], str]:
        def mask(m: re.Match[str]) -> str:
            if m.lastindex:
                if not _match_counts(what, m):
                    return m.group(0)  # a field name or a placeholder, as for N8D101 (known secrets are masked anyway)
                start, end = m.span(1)
                return m.group(0)[: start - m.start()] + "***" + m.group(0)[end - m.start() :]
            return m.group(0)[:4] + "***"

        return mask

    text = _mask_pem(text)
    for what, pattern in _patterns_for(text):
        text = pattern.sub(masker(what), text)
    return text


_CURL = re.compile(r"(?<![\w-])curl(?![\w-])")
_SHELL_QUOTED = re.compile(r"'[^']*'|\"[^\"]*\"")  # a ; or & in a header or URL does not end the command
_SHELL_SPLIT = re.compile(r"[;|]|&&|&(?=\s)")
_CURL_PASSWORDS = frozenset(("a password in a curl command", "a short password in a curl command"))


def _match_counts(what: str, m: re.Match[str]) -> bool:
    """A match of an N8D101 pattern is a secret: its value by :func:`_passes_filter`, and where it stands."""
    if not _passes_filter(what, m.group(m.lastindex or 0)):
        return False
    return what not in _CURL_PASSWORDS or _in_curl(m.string, m.start())


def _in_curl(text: str, start: int) -> bool:
    """The simple command around the flag at ``start`` runs curl, looking back a bounded way."""
    head = text[max(start - 512, 0) : start]
    return _CURL.search(_SHELL_SPLIT.split(_SHELL_QUOTED.sub("", head))[-1]) is not None


@functools.lru_cache(maxsize=1 << 16)  # lint, known_secrets and redact see the same matches
def _passes_filter(what: str, secret: str) -> bool:
    """The N8D101 checks on what a pattern's group captured: placeholders and field names are not secrets."""
    if what == "a bearer token":
        return _looks_secret_value(secret)
    if what in _CURL_PASSWORDS and secret.startswith("//"):  # the rest of a URL: -u https://example.com
        return False
    if what in ("a password in a URL", "a short password in a curl command"):
        return len(secret.strip()) >= 4 and _literal_secret(secret) and secret.strip().lower() not in ("user", "username")
    if what in ("a secret in a URL query string", "a password in a connection string", "a password in a curl command"):
        return _looks_secret_value(secret)
    if what == "a password in a URL query string":  # your_password. and <...>) in a sentence are placeholders still
        return _literal_secret(secret.rstrip(".,;:!)*"))
    if what == "a key in a URL query string":  # ?key=customer_id names a field, ?sig=2024-01-01T00 a time
        return _looks_secret_value(secret) and _random_looking(secret) and _varied(secret)
    return not _placeholder_token(secret)


def display_name(name: str) -> str:
    """A node, workflow or connection name as any output shows it: what the N8D101 patterns match is masked.

    The one helper every reporter (lint findings, fix changes, explain) passes names through.
    """
    return redact(name)


SHORTEN_MAX_INPUT = 64 * 1024  # longer text is not shown at all: masking it first would cost more than it shows


def shorten(text: str, limit: int = 80) -> str:
    """A name, key or path as an error or warning message shows it: masked first (:func:`redact`), then cut
    to ``limit`` characters at a space, ending in "…". A cut never falls inside a word, so a token is shown
    whole (masked) or not at all, never in part. Control characters become "?"."""
    if len(text) > SHORTEN_MAX_INPUT:
        return f"({len(text):,} characters)"
    shown = "".join(ch if ch.isprintable() or ch == " " else "?" for ch in redact(text))
    if len(shown) <= limit:
        return shown
    cut = shown[:limit]
    if not shown[limit].isspace():  # the cut falls inside a word: drop the word
        cut = cut[: cut.rfind(" ") + 1]
    return cut.rstrip() + "…"


def _random_looking(value: str) -> bool:
    """Letters and digits mixed, and not a URL, path, host or plain word: what generated keys look like."""
    if any(c in value for c in ".:@ "):
        return False
    if "/" in value:
        return _slashed_base64(value)
    value = value.replace("n8n", "")  # n8n-hiring-watch: the digit of the product's name
    return any(c.isdigit() for c in value) and any(c.isalpha() for c in value)


_BASE64_TEXT = re.compile(r"[A-Za-z0-9+/]{20,}={0,2}")
_VALUE_TOKEN = re.compile(r"[A-Z]?[a-z]+|[A-Z]+|\d+|[-_]+|.")


def _dictionary_like(value: str) -> bool:
    """One or a few words in camelCase, snake_case or kebab-case, perhaps with a number: imagePrompt2, country_code_2."""
    words = short = digits = 0
    for token in _VALUE_TOKEN.findall(value):
        if token.isdigit():
            digits += len(token)
        elif token.isalpha():
            words += 1
            short += len(token) < 3
            if len(token) >= 5 and 8 * sum(c in "aeiouyAEIOUY" for c in token) < len(token):  # xkqzjvbnwpt: no word
                return False
        elif token[0] not in "-_":
            return False
    return 1 <= words <= 6 and digits <= 4 and short <= 1


def _slashed_base64(value: str) -> bool:
    """A long mix of capitals, small letters and digits with ``/`` in it, not a path: no part between slashes is a small-letter word,
    and not all of them are words. wJalrXUtnFEMI/K7MDENG..., not /usr/local/bin, image/png or Reports2024/FinalDraft2."""
    if not _BASE64_TEXT.fullmatch(value) or not (any(c.isupper() for c in value) and any(c.islower() for c in value) and any(c.isdigit() for c in value)):
        return False
    parts = [part for part in value.rstrip("=").split("/") if part]
    if max(map(len, parts), default=0) < 10 or all(map(_dictionary_like, parts)):
        return False
    return not any(len(part) >= 3 and part.isalpha() and part.islower() for part in parts)


_DATE_LIKE = re.compile(r"\d{4}-?\d{2}-?\d{2}(?:[T ]|$)")


_C_LOG_C = [0.0] + [c * math.log2(c) for c in range(1, 4097)]  # c * log2(c) for the character counts of one value


def _varied(value: str) -> bool:
    """At least 12 characters, not a date, and at least 3 bits of entropy per character (generated keys have ~4-6)."""
    n = len(value)
    if n < 12 or n > 4096 or _DATE_LIKE.match(value):
        return n > 4096 and _varied(value[:4096])
    counts = collections.Counter(value).values()
    if len(counts) < 8:  # fewer than 8 distinct characters cannot reach 3 bits
        return False
    # entropy = log2(n) - sum(c * log2(c)) / n, with the products looked up rather than computed per character
    return math.log2(n) - sum(map(_C_LOG_C.__getitem__, counts)) / n >= 3.0


# a reference to an environment variable, not its value: $API_TOKEN, ${API_TOKEN}, $env.X, process.env.X
_ENV_REFERENCE = re.compile(r"(?:\$\{?[A-Z_][A-Z0-9_]*\}?|\$env(?:\.[A-Za-z_]\w*|\[['\"][^'\"]+['\"]\])|process\.env(?:\.[A-Za-z_]\w*|\[['\"][^'\"]+['\"]\]))")


# What a field holds when it describes a secret or its slot rather than holding it: a type, a state, a hash or a product
_NON_VALUES = frozenset(
    {"none", "null", "nil", "undefined", "empty", "unset", "unknown", "required", "optional", "true", "false", "hidden", "masked", "redacted"}
    | {"string", "str", "text", "number", "integer", "int", "float", "boolean", "bool", "object", "array", "plaintext", "cleartext", "plain"}
    | {"password", "passwd", "passphrase", "pass", "credential", "credentials", "tbd", "todo", "default", "generated"}
    | {"bcrypt", "scrypt", "argon2", "md5", "sha1", "sha256", "sha512", "1password", "bitwarden", "lastpass", "dashlane", "keepass", "keeper", "vault"}
    | {"approved", "rejected", "passed", "failed", "pending", "success"}
)


def _literal_secret(value: str) -> bool:
    """``value`` can be a secret by its form, whatever its length: no expression, reference, placeholder or non-value."""
    v = value.strip()
    return (
        bool(v)
        and " " not in v
        and "{{" not in v
        and not v.startswith("=")
        and v.lower() not in _NON_VALUES
        and not _placeholder(v)
        and not _ENV_REFERENCE.fullmatch(v)
    )


def _looks_secret_value(value: str) -> bool:
    return len(value.strip()) >= 8 and _literal_secret(value)


# After the word password, these say the field is about the password (when it was made, how it is kept): password_created_at,
# password_format, password_manager. Only a generated-looking value counts there.
_DESCRIBES_PASSWORD = frozenset(
    "created at date time timestamp last format manager provider store storage version encoding scheme method mode status source tool "  # noqa: SIM905
    "app set auth authentication protected protection valid validated validation invalid count ok check checked match matches matched attempts retries".split()
)


@functools.lru_cache(maxsize=4096)
def _describes_password(name: str) -> bool:
    words = [w.lower() for w in _NAME_WORD.findall(name)]
    for i, word in enumerate(words):
        if _PASSWORD_IN.search(word):
            return not _DESCRIBES_PASSWORD.isdisjoint(words[i + 1 :])
    return False


def _password_literal(name: str, value: str) -> bool:
    """A literal in a field that :func:`password_named` accepts is a password from 4 characters: such a field has no other use."""
    v = value.strip()
    if _describes_password(name):
        return _random_looking(v) and _varied(v) and _literal_secret(v)
    if name.strip().lower() == "pwd" and "/" in v:  # a working folder
        return False
    return len(v) >= 4 and _literal_secret(v) and _DOLLAR_NAME.match(v) is None


# Passwords everyone tries: lowercase words like the words below, but a literal of one in code is a real credential
_WEAK_PASSWORDS = frozenset(
    "admin administrator root toor test guest demo qwerty letmein welcome monkey dragon master shadow sunshine princess football baseball "  # noqa: SIM905
    "superman iloveyou freedom whatever abcd asdf".split()
)
_CSS_COLOUR = re.compile(r"#(?:[0-9a-fA-F]{3,4}){1,2}")
_WORD_VALUE = re.compile(r"[A-Za-z]?[a-z]{3,11}")  # green, Invalid, missing: a status or a label
_VALIDATION_WORD = (
    r"(?:required|nullable|sometimes|confirmed|bail|string|min|max|between|size|regex|"
    r"email|alpha|alpha_num|alpha_dash|numeric|digits|same|different|in|not_in|unique|exists)"
)
_VALIDATION_RULE = re.compile(rf"{_VALIDATION_WORD}(?::[\w,.-]{{0,64}})?(?:\|{_VALIDATION_WORD}(?::[\w,.-]{{0,64}})?){{0,16}}")


def _code_label(value: str) -> bool:
    """What a password-named key of an object in code holds when it is a form's setup rather than a password: a CSS
    selector (#pwd), a validation rule (required|min:8), a message or label word (Invalid, Пароль)."""
    if _CSS_COLOUR.fullmatch(value):
        return True
    if _css_selector(value):
        return not (any(c.isdigit() for c in value) and any(c.isupper() for c in value))  # #Hunter2
    if _VALIDATION_RULE.fullmatch(value):
        return True
    if value.lower() in _WEAK_PASSWORDS:
        return False
    return _WORD_VALUE.fullmatch(value) is not None or (not value.isascii() and value.isalpha())


def _code_password(name: str, value: str) -> bool:
    """:func:`_password_literal` for a pair in code, which also holds form setups; a key called just ``pass`` is mostly a test status."""
    if not _password_literal(name, value):
        return False
    v = value.strip()
    if _code_label(v):
        return False
    if name.strip().lower() != "pass":
        return True
    return (len(v) >= 6 and _random_looking(v)) or (len(v) >= 12 and any(c.isupper() for c in v) and any(c.islower() for c in v))


def _after_ternary(text: str, start: int) -> bool:
    """A question mark comes before ``start``, spaces aside: ``ok ? 'pass' : 'fail'``."""
    i = start - 1
    floor = max(start - 64, 0)
    while i >= floor and text[i].isspace():
        i -= 1
    return i >= 0 and text[i] == "?"


# The token a swap or price call is about: a contract or mint address on a public chain, nothing to hide. Any other value still counts.
_TOKEN_SIDE_NAME = re.compile(r"(?i)(?:from|to|base|quote)[-_ ]?token")
_TOKEN_ADDRESS = re.compile(r"0x[0-9a-fA-F]{40,64}|[1-9A-HJ-NP-Za-km-z]{32,44}")


def _token_address(name: str, value: str) -> bool:
    return _TOKEN_SIDE_NAME.fullmatch(name.strip()) is not None and _TOKEN_ADDRESS.fullmatch(value.strip()) is not None


def _named_literal(name: str, value: str, secretish: Callable[[str], bool]) -> bool:
    """``value`` counts as the secret of a field called ``name``. ``secretish`` is what any other name asks of it."""
    if _token_address(name, value):
        return False
    if secretish is _looks_secret_value and password_named(name):
        return _password_literal(name, value)
    if secretish is _looks_secret_value and name.strip().lower() == "authentication" and not (_random_looking(value) and _varied(value)):
        return False  # n8n's own field: genericCredentialType, headerAuth
    return secretish(value)


_SIGNED_PARAM = re.compile(r"(?i)[?&](?:sig|signature|x-amz-signature)=\Z")


@rule(
    "N8D101",
    "hardcoded-secret",
    Severity.ERROR,
    "An API key, token, password or private key is written into a node parameter or Code node.",
    "Store it in an n8n credential (Header Auth, Basic Auth, the service's own credential type) and select that "
    "credential on the node; then rotate the exposed value, it is in every export and version of this workflow.",
)
def _hardcoded_secret(ctx: Context, meta: Rule) -> Iterator[Finding]:
    allow = [compile_allow(a) for a in ctx.option(meta.id, "allow", [])]

    def allowed(value: str) -> bool:
        return len(value) <= ALLOW_MAX_INPUT and any(a.search(value) for a in allow)

    wf = ctx.wf
    limit = wf.limits.max_value_chars

    def partly(where: str, size: int, node: Node | None, parameter: str | None = None) -> Finding:
        return _f(
            meta,
            f"{where} is {size:,} characters long, too large to check in full: only its first and last {limit // 2048:,} KB "
            "were checked for secrets (the rest is not shown in explain and fix output)",
            node,
            parameter,
            f"Check the value by hand, or raise the limit with --max-value-kb (max-value-kb in [limits]); it is {limit // 1024:,} KB.",
            severity=Severity.INFO,
        )

    def in_name(text: str, where: str, node: Node | None = None) -> Iterator[Finding]:
        # names are shown masked everywhere, but the secret is still in every export of the workflow
        if len(text) > limit:
            yield partly(where, len(text), node)
        shown: set[str] = set()
        for what, secret in text_secrets(text, limit):
            if secret not in shown and not allowed(secret):
                shown.add(secret)
                yield _f(meta, f"{where} contains {what}: {_mask(secret, what)}", node)

    yield from in_name(wf.name, "the workflow name")
    for node in wf.nodes:
        yield from in_name(node.name, "the node name", node)
    missing = {e.source for e in wf.edges if e.source not in wf.by_name} | {e.target for e in wf.edges if e.target not in wf.by_name}
    for name in sorted(missing):
        yield from in_name(name, "a connection's missing node name")
    for name in wf.pin_data:
        if name not in wf.by_name:
            yield from in_name(name, "a node name in the pinned data")
    for name, items in wf.pin_data.items():
        pinned: set[str] = set()
        signed: set[str] = set()
        for _, value in iter_leaves(items):
            for what, secret, start in _pattern_secrets(value, False, limit):
                if len(secret) < 4 or allowed(secret):
                    continue
                if what == "a key in a URL query string" and _SIGNED_PARAM.search(value, max(start - 20, 0), start):
                    signed.add(secret)
                elif secret not in pinned:
                    pinned.add(secret)
                    yield _f(meta, f"the pinned data contains {what}: {_mask(secret, what)}", wf.by_name.get(name), "pinData")
        if signed - pinned:
            yield _f(
                meta,
                f"the pinned data holds {plural(len(signed - pinned), 'signed URL')}: each gives access to its file until it expires",
                wf.by_name.get(name),
                "pinData",
                "Empty the pinned data: N8D211's fix does it (n8n-doctor fix), or unpin the node in the editor.",
                severity=Severity.WARNING,
            )

    def in_parameters(current: Node, owner: Node, prefix: str, shared: set[str]) -> Iterator[Finding]:
        """The secrets of one node, reported on ``owner``. ``shared``: the secrets said so far of an embedded workflow,
        whose text or object the outer node's values also hold, so that each is reported once."""
        field = _EMBEDDED_WORKFLOWS.get(current.type)
        flows = _embedded(current, wf)
        params = _own_parameters(current, flows)
        if current.cache.get("embedded_over"):
            over = f"{prefix}{field}"
            yield _f(
                meta,
                f"{over} was only scanned as text, not read as a workflow: the file holds more than {wf.limits.max_file_nodes:,} nodes and embedded workflows",
                owner,
                over,
                f"Check it by hand, or raise the limit with --max-file-nodes (max-file-nodes in [limits]); it is {wf.limits.max_file_nodes:,}.",
                severity=Severity.INFO,
            )
        for what, secret in _key_secrets(params, limit):
            if not allowed(secret) and (not prefix or secret not in shared):
                shared.add(secret)
                yield _f(meta, f"{prefix}a parameter name contains {what}: {_mask(secret, what)}", owner)
        notes = current.notes
        if notes:
            if len(notes) > limit:
                yield partly(f"{prefix}notes", len(notes), owner, f"{prefix}notes")
            said: set[str] = set()
            for what, secret, _ in _notes_secrets(notes, limit):
                if secret not in said and not allowed(secret) and (not prefix or secret not in shared):
                    said.add(secret)
                    shared.add(secret)
                    yield _f(meta, f"{prefix}notes contains {what}: {_mask(secret, what)}", owner, f"{prefix}notes")
        for keys, value in iter_leaves(params):
            embedded = bool(prefix) or (field is not None and keys.first == field)
            path = ""  # formatted when there is something to report
            if len(value) > limit and not (flows and keys.first == field):  # read in full when parsed (see _embedded)
                path = prefix + keys.text()
                yield partly(path, len(value), owner, path)
            reported: set[str] = set()
            covered = -1  # end of the furthest reported match: a match inside it is the same secret
            # leftmost first, longest first at one position: a match inside a reported one counts once, but an
            # allowed match does not hide a longer secret around it or a different one inside it
            for what, secret, start in sorted(_leaf_secrets(current, keys, value, limit=limit, budget=wf.budget), key=lambda t: (t[2], -len(t[1]))):
                end = start + len(secret)
                if end <= covered or secret in reported or allowed(secret) or (embedded and secret in shared):
                    continue
                reported.add(secret)
                if embedded:
                    shared.add(secret)
                covered = max(covered, end)
                path = path or prefix + keys.text()
                yield _f(meta, f"{path} contains {what}: {_mask(secret, what)}", owner, path)
            if current.cache.pop("raw_cut", False):
                path = path or prefix + keys.text()
                yield _f(
                    meta,
                    f"{path} does not parse as a workflow and was only partly scanned as text for secrets: its escapes go deep, or the file "
                    "holds more such text than "
                    f"{wf.limits.max_raw_scan_bytes // MB:,} MB (the value is not shown in explain output)",
                    owner,
                    path,
                    "Check it by hand, or raise the limit with --max-raw-scan-mb (max-raw-scan-mb in [limits]).",
                    severity=Severity.INFO,
                )
        for name, flow in flows:
            beside = _beside_parameters(flow)
            for what, secret in _key_secrets(beside, limit):
                if secret not in shared and not allowed(secret):
                    shared.add(secret)
                    yield _f(meta, f"{prefix}{name}: a name contains {what}: {_mask(secret, what)}", owner)
            for keys, value in iter_leaves(beside):
                for what, secret in text_secrets(value, limit):
                    if secret not in shared and not allowed(secret):
                        shared.add(secret)
                        path = f"{prefix}{name}.{keys.text()}"
                        yield _f(meta, f"{path} contains {what}: {_mask(secret, what)}", owner, path)
            for inner in flow.nodes:
                yield from in_parameters(inner, owner, f"{prefix}{name}.nodes[{inner.index}].parameters.", shared)

    for node in wf.nodes:
        yield from in_parameters(node, node, "", set())


def _notes_secrets(notes: str, limit: int) -> Iterator[tuple[str, str, int]]:
    """What the notes of a node hold, read like a sticky note, and any token the N8D101 patterns match."""
    for part, base in _parts(notes, limit):
        yield from ((what, secret, base + start) for what, secret, start in _note_secrets(part))
        yield from ((what, secret, base + start) for what, secret, start in _pattern_secrets(part, False, limit))


def text_secrets(text: str, limit: int = DEFAULT.max_value_chars) -> Iterator[tuple[str, str]]:
    """(what, secret) for every N8D101 pattern match in a free text: a parameter name, a node or workflow name.

    The same filters as for parameter values apply: ``GET /search?key=customer_id`` names a field, and
    ``https://user:password@host`` shows where credentials go; neither is a secret.
    """
    for what, secret, _ in _pattern_secrets(text, False, limit):
        if len(secret) >= 4:
            yield what, secret


def _key_secrets(params: dict[str, Any], limit: int = DEFAULT.max_value_chars) -> Iterator[tuple[str, str]]:
    """(what, secret) for N8D101 patterns matched by dict keys inside ``params`` (they are shown in paths)."""
    seen: set[str] = set()
    stack: list[Any] = [params]
    while stack:
        current = stack.pop()
        if isinstance(current, dict):
            for k, v in current.items():
                if isinstance(k, str) and k not in seen:
                    seen.add(k)
                    yield from text_secrets(k, limit)
                stack.append(v)
        elif isinstance(current, list):
            stack.extend(current)


def path_of(keys: Key) -> str:
    """:func:`format_path` with token-like keys masked: paths are printed in findings and fix summaries."""
    return redact(format_path(keys))


def _blank_spans(value: str) -> str:
    """``value`` with the inside of every ``{{ ... }}`` blanked out, offsets unchanged."""
    out: list[str] = []
    pos = 0
    for start, end in expression_spans(value):
        out.append(value[pos:start])
        out.append(" " * (end - start))
        pos = end
    out.append(value[pos:])
    return "".join(out)


def _parts(text: str, limit: int) -> list[tuple[str, int]]:
    """(part, offset) of ``text`` to check for secrets: all of it, or its first and last ``limit // 2``
    characters when it is longer than ``limit``."""
    if len(text) <= limit:
        return [(text, 0)]
    half = limit // 2
    return [(text[:half], 0), (text[len(text) - half :], len(text) - half)]


@functools.lru_cache(maxsize=16)
def _pattern_secrets(text: str, is_code: bool, limit: int = DEFAULT.max_value_chars) -> tuple[tuple[str, str, int], ...]:
    """The part of :func:`_leaf_secrets` that depends on the text alone; cached, since lint, every fix round
    and the masking of fix and explain output all scan the same parameter values. A text longer than
    ``limit`` is checked at its start and end only (see :func:`_parts`)."""
    if len(text) > limit:
        return tuple((what, secret, offset + start) for part, offset in _parts(text, limit) for what, secret, start in _pattern_secrets(part, is_code, limit))
    found: list[tuple[str, str, int]] = [(_PEM_WHAT, secret, start) for secret, start in _pem_secrets(text) if not _pem_placeholder(secret)]
    for what, pattern in _patterns_for(text):
        for m in pattern.finditer(text):
            group = m.lastindex or 0
            secret = m.group(group)
            if _match_counts(what, m):
                found.append((what, secret, m.start(group)))
    if is_code:
        if "uthorization" in text or "UTHORIZATION" in text:
            found += [("what looks like a hardcoded secret", m.group(2), m.start(2)) for m in _CODE_AUTH.finditer(text) if _auth_literal(m.group(2))]
        found += _basic_credentials(text)
        for name, value, start in _code_pairs(text, _CODE_ASSIGN):
            if _key_named(name):
                if _generated(value) and not _dictionary_like(value):
                    found.append(("what looks like a hardcoded secret", value, start))
            elif password_named(name) and _code_secret_name(name):
                if _code_password(name, value):
                    found.append(("what looks like a hardcoded password", value, start))
            elif _code_secret_name(name) and _looks_secret_value(value) and _random_looking(value) and not _token_address(name, value):
                found.append(("what looks like a hardcoded secret", value, start))
    return tuple(found)


# Buffer.from('admin:SuperSecret9'), btoa("admin:SuperSecret9"): the password of a literal user:password being encoded
_ENCODED_PAIR = re.compile(r"""(?:\bBuffer\.from|\bbtoa)\(\s*(['"`])([^'"`\s{}$:]{0,128}):([^'"`\s{}$]{4,256})\1""")
_BASIC_HEADER = re.compile(r"""(['"`])Basic[ \t]+([A-Za-z0-9+/]{8,1024}={0,2})\1""")
_BASIC_WHAT = "Basic auth credentials"
_LOGIN_WORDS = frozenset({"admin", "administrator", "root", "user", "username", "login"})
_URI_SCHEMES = frozenset("http https ftp ftps sftp ws wss file data blob mailto tel urn s3 gs".split())  # noqa: SIM905


def _credentials_pair(user: str, password: str) -> bool:
    """The two sides of ``user:password`` read as credentials: no URL, time or ``status:active``-style label."""
    if user.lower() in _URI_SCHEMES or user.isdigit() or _DATE_LIKE.match(user) or not _literal_secret(password) or _placeholder(user):
        return False
    if "/" in password and not _random_looking(password):
        return False
    return user.lower() in _LOGIN_WORDS or (any(c.isalpha() for c in password) and not password.isalpha())


def _encoded_basic(value: str) -> bool:
    """Base64 of ``user:password``, a real one (see :func:`_encoded_placeholder`)."""
    try:
        text = base64.b64decode(value, validate=True).decode("utf-8")
    except ValueError:
        return False
    return text.isprintable() and bool(text.partition(":")[2]) and not _placeholder(value)


def _basic_credentials(code: str) -> list[tuple[str, str, int]]:
    """Basic auth credentials in code, encoded or about to be, whatever variable holds them."""
    found: list[tuple[str, str, int]] = []
    if "Buffer.from(" in code or "btoa(" in code:
        found += [(_BASIC_WHAT, m.group(3), m.start(3)) for m in _ENCODED_PAIR.finditer(code) if _credentials_pair(m.group(2), m.group(3))]
    if "Basic" in code:
        found += [(_BASIC_WHAT, m.group(2), m.start(2)) for m in _BASIC_HEADER.finditer(code) if _encoded_basic(m.group(2))]
    return found


# The word before KEY in names that hold no secret, whatever the value looks like: sortKey, CACHE_KEY, publicKey
_NOT_SECRET_KEY_WORD = frozenset(
    "sort cache primary public publishable foreign partition composite unique object file s3 bucket storage map row item group record table sheet "  # noqa: SIM905
    "spreadsheet product price base site "
    "session idempotency dedup dedupe lookup hash index routing shard event message state translation locale data meta field column entry user".split()
)


def _key_named(name: str) -> bool:
    """A variable named for a key, OPENAI_KEY or consumerKey, that counts with a generated-looking value (:func:`_generated`)."""
    if not (name.endswith("Key") and name[0].islower()) and not (name.endswith("_KEY") and name.isupper()):
        return False
    words = _NAME_WORD.findall(name)
    return len(words) >= 2 and words[-2].lower() not in _NOT_SECRET_KEY_WORD and not _code_secret_name(name)


def _code_secret_name(name: str) -> bool:
    """A variable, key or header name in code that holds a secret: apiKey, 'X-Api-Key', "Authorization", pass."""
    return (_SECRETISH_NAME.search(name) is not None or _secret_name(name)) and _PAGING_NAME.fullmatch(name) is None


def _code_pairs(text: str, assign: re.Pattern[str]) -> Iterator[tuple[str, str, int]]:
    """(name, value, offset of the value) for every ``name = 'value'``, ``name: 'value'`` (``assign``),
    ``x.set('name', 'value')`` / ``x.append(...)`` and ``x['name'] = 'value'`` in ``text``."""
    if _ASSIGN_HINT.search(text):  # a quick scan for "= '" / ": '": code without one has no name = 'value'
        for m in assign.finditer(text):
            # the ternary's branches, for what N8D101 reports; output masks them anyway
            if assign is _CODE_ASSIGN and ":" in text[m.start() : m.start(4)] and _after_ternary(text, m.start()):
                continue
            yield m.group(1) or m.group(3), m.group(5), m.start(5)
    if ".set(" in text or ".append(" in text:
        for m in _CODE_SET.finditer(text):
            yield m.group(2), m.group(4), m.start(4)
    if "[" in text:
        for m in _CODE_INDEX.finditer(text):
            yield m.group(2), m.group(4), m.start(4)


def _json_like(value: str) -> bool:
    """``value`` starts like a JSON object or array, after an optional leading ``=``."""
    head = value[:64].lstrip()
    if head.startswith("="):
        head = head[1:].lstrip()
    return head.startswith(("{", "[")) and not head.startswith("{{")


def _literal(value: str) -> tuple[str, int] | None:
    """The text n8n uses for a parameter value and where it starts in ``value``, when that is fixed: the value
    itself, or what follows a leading ``=`` with no ``{{ }}`` (an expression with nothing to evaluate)."""
    if not value.startswith("="):
        return value, 0
    return (value[1:], 1) if "{{" not in value else None


def _maskable(value: str) -> bool:
    """A literal value in a secret-named field, whatever it looks like: output masks it (placeholders included)."""
    v = value.strip()
    return len(v) >= 4 and "{{" not in v and not v.startswith("=") and not _ENV_REFERENCE.fullmatch(v)


_CODE_ASSIGN_ANY = re.compile(_CODE_NAME + _CODE_VALUE + r"""([^'"`\n{}$]{4,1024})\4""")
_SCHEMES = frozenset(
    {
        "basic",
        "bearer",
        "token",
        "bot",
        "oauth",
        "ssws",
        "geniekey",
        "klaviyo-api-key",
        "zoho-oauthtoken",
        "apikey",
        "key",
        "digest",
        "negotiate",
        "ntlm",
        "jwt",
    }
)


def _auth_literal(value: str) -> bool:
    """A literal Authorization value, however short and in whatever words: only expressions and placeholders are not."""
    v = value.strip()
    if len(v) < 4 or v.lower() in _SCHEMES or v.lower() in ("none", "null") or "{{" in v or v.startswith("="):
        return False
    if _ENV_REFERENCE.fullmatch(v) or _placeholder(v):
        return False
    if " " in v and _placeholder(v.split(None, 1)[1]):
        return False
    return not v.startswith("$(") and not any(_placeholder(word) or word.startswith("$(") for word in v.split()[:8])  # Bearer <token> //move this up


def _generated(value: str) -> bool:
    """A value that looks made by a generator or a password manager, not a word, path, address or flag."""
    v = value.strip()
    if not _looks_secret_value(v) or any(c in v for c in ".:") or ("/" in v and not _slashed_base64(v)):
        return False
    return any(c.isdigit() for c in v) and any(c.isalpha() for c in v) and _varied(v)


def _note_product(value: str, label: str) -> bool:
    """What a note names rather than holds: ``API key: OpenAI``, ``Token: OAuth2``, ``Password: 1Password``. A word in
    capitals only counts when the label is not a password's (``Token: AWS``, but ``Password: ADMINPASS``)."""
    if value.lower() in _NOTE_PRODUCTS:
        return True
    return value.isalpha() and value[0].isupper() and not (value.isupper() and label.lower().startswith(("pass", "pwd")))


def _note_value_like(value: str) -> bool:
    """Not a word, as a type or a yes/no column would be: it has digits, symbols, or capitals inside (dXNlcjpwYXNz)."""
    letters = any(c.isalpha() for c in value)
    if any(c.isdigit() for c in value):
        return letters or len(value) >= 6
    if not value.isalnum():
        return letters and any(not c.isalnum() and c not in "-_()" for c in value)
    return len(value) >= 8 and value[0].islower() and any(c.isupper() for c in value)


def _note_value(secret: str, label: str, slash: bool = False) -> bool:
    # "Token: 4096" and "Token: gpt-4o" say which tokens; a password can be anything
    if not label.lower().startswith(("pass", "pwd")) and ((secret.isdecimal() and len(secret) < 8) or _NOTE_MODEL.fullmatch(secret)):
        return False
    return (
        secret.strip("()[]").lower() not in _NOTE_WORDS
        and "{{" not in secret
        and ("/" not in secret or (slash and "://" not in secret and not secret.startswith("/") and _varied(secret)))
        and not _placeholder(secret)
        and not _ENV_REFERENCE.fullmatch(secret)
        and not _note_product(secret, label)
    )


_NOTE_SCANS = (
    (_NOTE_LABEL, _NOTE_VALUE, False),
    (_NOTE_SETTING, _NOTE_VALUE, True),
    (_NOTE_HEADER, _NOTE_VALUE, True),
    (_NOTE_IS, _NOTE_VALUE, True),
    (_NOTE_ROW, _NOTE_ROW_VALUE, True),
)


def _note_secrets(text: str) -> Iterator[tuple[str, str, int]]:
    """(what, secret, offset) for each label with a value in the text of a sticky note or a node's notes. Each value is
    judged and reported once: only its first place matters, and a note can repeat it a hundred thousand times."""
    reported: set[str] = set()
    for finder, ending, strict in _NOTE_SCANS:
        judged: set[tuple[str, str]] = set()
        setting = finder is _NOTE_SETTING
        for m in finder.finditer(text):
            start = m.start(m.lastindex or 0)
            value = ending.match(text, start)
            if value is None:
                continue
            secret = value.group(1)
            if "&" in secret and "=" in secret.partition("&")[2]:  # apiKey=abc&pageSize=3: the next parameter of a URL
                secret = secret.partition("&")[0]
                if len(secret) < 4:
                    continue
            if secret.endswith(")") and "(" not in secret:  # (password: hunter2): the bracket closes around the label
                secret = secret.rstrip(")")
                if len(secret) < 4:
                    continue
            key = (secret, text[m.start() : m.start() + 4])  # the label's start is all the checks below read of it
            if key in judged or secret in reported:
                continue
            judged.add(key)
            name = m.group("name") if setting else None
            if name is not None:
                if _NOTE_NOT_SETTING.fullmatch(name) or _PAGING_NAME.fullmatch(name):
                    continue
                label = "pass" if password_named(name) else name
            else:
                label = m.group(0).lstrip("| \t*_`")
            if _note_value(secret, label, setting) and (not strict or _note_value_like(secret)):
                reported.add(secret)
                yield ("a labelled password" if label == "pass" or _password_label(label) else "a labelled secret"), secret, start


def _cookie_secrets(text: str, start: int, mask: bool) -> Iterator[tuple[str, str, int]]:
    """A Cookie value (at ``start``) with a generated-looking value in it: the whole of it and those values."""
    values = [m for m in _COOKIE_PAIR.finditer(text) if _generated(m.group(1))]
    if values or _generated(text) or (mask and _maskable(text)):
        yield 'a literal "cookie" value', text.strip(), start + len(text) - len(text.lstrip())
    yield from (('a literal "cookie" value', m.group(1), start + m.start(1)) for m in values)


# Tokens of JSON text that does not parse, or of a JavaScript object in an expression: with any indent (a run of
# white space is measured once per token, so this stays linear), other keys between name and value, and quotes of
# either kind or none around the keys.
_RAW_WS = r"\s{0,512}"
_RAW_NAME_TEXT = r"""(?:"((?:[^"\\]|\\u[0-9a-fA-F]{4}){1,200})"|'([^'\\]{1,200})')"""
_RAW_VALUE_TEXT = r"""(?:"((?:[^"\\]|\\.){4,1024})"|'((?:[^'\\]|\\.){4,1024})')"""


def _raw_key(word: str) -> str:
    return rf"""(?<![\w$-])["']?{word}["']?{_RAW_WS}:{_RAW_WS}"""


_RAW_BETWEEN = (
    rf"""{_RAW_WS},{_RAW_WS}(?:(?!["']?(?:name|value)["']?{_RAW_WS}:)["']?[\w-]{{1,40}}["']?{_RAW_WS}:{_RAW_WS}"""
    rf"""(?:"[^"\\]{{0,200}}"|'[^'\\]{{0,200}}'|true|false|null|-?\d{{1,20}}(?:\.\d{{1,20}})?){_RAW_WS},{_RAW_WS}){{0,4}}"""
)
_RAW_ENTRY = re.compile(
    _raw_key("name")
    + _RAW_NAME_TEXT
    + _RAW_BETWEEN
    + _raw_key("value")
    + _RAW_VALUE_TEXT
    + "|"
    + _raw_key("value")
    + _RAW_VALUE_TEXT
    + _RAW_BETWEEN
    + _raw_key("name")
    + _RAW_NAME_TEXT
)
_RAW_COOKIE = re.compile(rf"""(?i)["'](?:set-)?cookie["']{_RAW_WS}:{_RAW_WS}{_RAW_VALUE_TEXT}""")
_RAW_BEARER = re.compile(r"\bBearer[ \t]+([A-Za-z0-9._~+/-]{4,19}=*)(?![A-Za-z0-9._~+/=-])")
_RAW_NOTE = re.compile(rf""""content"{_RAW_WS}:{_RAW_WS}"((?:[^"\\]|\\.){{4,65536}})\"""")
_RAW_SCHEME = re.compile(r"(?i)(?:basic|token|bearer|apikey|key)\s+(?=\S{4,}$)")
_RAW_ESCAPED_LETTER = re.compile(r"\\u00(?:2[1-9a-fA-F]|[3-4][0-9a-fA-F]|5[0-9abd-fABD-F]|6[0-9a-fA-F]|7[0-9a-eA-E])")  # not " or \


def _raw_unescape(text: str) -> str:
    """One level of JSON string escapes less: quotes, backslashes and line ends, the ones tokens depend on."""
    return text.replace("\\\\", "\0").replace('\\"', '"').replace("\\n", "\n").replace("\0", "\\")


_RAW_DEEP_TEXT = 64 * 1024  # a longer text has its escapes taken off only _RAW_LARGE_LEVELS times
_RAW_LARGE_LEVELS = 2


def _raw_levels(part: str) -> Iterator[tuple[str, bool, bool]]:
    """``part`` and what it reads as with the escapes of the texts it is inside taken off, one at a time: (text, whether
    to scan it as code, whether to read its tokens). Tokens only change where a quote was escaped."""
    if "\\" not in part:
        yield part, True, True
        return
    yield part, False, True
    for _ in range(_EMBEDDED_DEPTH if len(part) <= _RAW_DEEP_TEXT else _RAW_LARGE_LEVELS):
        unescaped = _raw_unescape(part)
        tokens = '\\"' in part
        yield unescaped, True, tokens
        if '\\"' not in unescaped:
            return
        part = unescaped


def _raw_entries(text: str, base: int, mask: bool) -> Iterator[tuple[str, str, int]]:
    """What the name/value entries, Cookie keys, short Bearer tokens and sticky notes in ``text`` hold."""
    secretish = _maskable if mask else _looks_secret_value
    if "alue" in text:
        for m in _RAW_ENTRY.finditer(text):
            name = _JSON_ESCAPE.sub(
                lambda u: chr(int(u.group(1), 16)), next(g for g in (m.group(1), m.group(2), m.group(7), m.group(8)) if g is not None)
            ).strip()
            group = next(g for g in (3, 4, 5, 6) if m.group(g) is not None)
            found = m.group(group)
            start = base + m.start(group)
            if _not_secret_header(name):
                continue
            if name.lower() in ("cookie", "set-cookie"):
                yield from _cookie_secrets(found, start, mask)
                continue
            scheme = (_AUTH_SCHEME if _AUTH_NAME.fullmatch(name) else _RAW_SCHEME).match(found.strip())
            bare = found.strip()[scheme.end() :] if scheme else found
            if _named_literal(name, bare, secretish) and (_secret_name(name) or (_CUSTOM_SECRET_NAME.search(name) and _generated_or_masked(bare, secretish))):
                yield f'a literal "{name}" value', bare, start
    if "ookie" in text or "OOKIE" in text:
        for m in _RAW_COOKIE.finditer(text):
            group = 1 if m.group(1) is not None else 2
            yield from _cookie_secrets(m.group(group), base + m.start(group), mask)
    if "Bearer" in text:
        for m in _RAW_BEARER.finditer(text):
            if secretish(m.group(1)) and _random_looking(m.group(1)):
                yield "a bearer token", m.group(1), base + m.start(1)
    if "stickyNote" in text:
        for m in _RAW_NOTE.finditer(text):
            yield from ((what, secret, base + m.start(1) + start) for what, secret, start in _note_secrets(_raw_unescape(m.group(1))))


def _raw_embedded_secrets(value: str, limit: int, mask: bool, node: Node | None = None, budget: FileBudget | None = None) -> Iterator[tuple[str, str, int]]:
    """What can still be told from an embedded workflow that could not be parsed: its Code, with the quotes unescaped
    (``const password = \\"x\\"``), and its entries and labels (see :func:`_raw_entries`), at every level of text
    in text. Names spelled with \\u escapes are read too. Offsets are approximate.

    All of it is scanned many times, so the characters read per file are bounded (``budget``) and a large text has
    fewer levels. What that leaves unread is noted: on the node for a finding, on the budget for the output."""

    def cut_short() -> None:
        if node is not None and not mask:
            node.cache["raw_cut"] = True
        if budget is not None and mask:
            budget.raw_cut = True

    seen: set[str] = set()  # one spelling of a secret is enough to report; masking wants them all
    for part, base in _parts(value, limit):
        text = part
        for text, code, tokens in _raw_levels(part):
            spellings = [text]
            if "\\u" in text and (plain := _RAW_ESCAPED_LETTER.sub(lambda u: chr(int(u.group(0)[2:], 16)), text)) != text:
                spellings.append(plain)
            for spelled in spellings:
                if budget is not None and not budget.raw_charge(len(spelled), mask):
                    cut_short()
                    return
                for found in _raw_text_secrets(spelled, base, limit, mask, code, tokens):
                    decoded = _JSON_ESCAPE.sub(lambda u: chr(int(u.group(1), 16)), found[1])
                    if mask or decoded not in seen:
                        seen.add(decoded)
                        yield found
        if len(part) > _RAW_DEEP_TEXT and '\\"' in text:  # more levels than a text of this size has read
            cut_short()


def _raw_text_secrets(text: str, base: int, limit: int, mask: bool, code: bool, tokens: bool) -> Iterator[tuple[str, str, int]]:
    if code:
        yield from ((what, secret, base + start) for what, secret, start in _pattern_secrets(text, True, limit))
        if mask:
            for name, found, start in _code_pairs(text, _CODE_ASSIGN_ANY):
                if _code_secret_name(name) and _maskable(found) and found.strip().lower() not in _SCHEMES:
                    yield "what looks like a hardcoded secret", found.strip(), base + start
    if tokens:
        yield from _raw_entries(text, base, mask)


# Edit Fields v3.0-3.2 writes fields.values[] as {name, type, <type>Value} (nodes/Set/v2/manual.mode.ts)
_TYPED_VALUES = frozenset({"stringValue", "numberValue", "booleanValue", "arrayValue", "objectValue"})
_FORM_BODY_KEYS = frozenset({"body", "rawBody", "bodyParametersJson"})
_FORM_BODY = re.compile(r"[\w.\[\]%-]{1,80}=[^\s&]*(?:&[\w.\[\]%-]{1,80}=[^\s&]*)*")


def _form_secrets(text: str, start: int, secretish: Callable[[str], bool]) -> Iterator[tuple[str, str, int]]:
    """The values named for a secret in a raw form body (password=abc&x=1), the first parameter included."""
    pos = start
    for pair in text.split("&"):
        name, _, found = pair.partition("=")
        named_password = password_named(name) and name.lower() != "pwd"
        if (named_password or _code_secret_name(name)) and (
            secretish(found) or (named_password and found and secretish is _looks_secret_value and _short_password(found))
        ):
            yield f'a literal "{name}" value', found, pos + len(name) + 1
        pos += len(pair) + 1


def _short_password(value: str) -> bool:
    return _literal_secret(value)


def _leaf_secrets(
    node: Node,
    keys: KeyPath,
    value: str,
    keep_comments: bool = False,
    limit: int = DEFAULT.max_value_chars,
    mask: bool = False,
    budget: FileBudget | None = None,
) -> Iterator[tuple[str, str, int]]:
    """(what, secret, offset in ``value``) for every secret in one parameter value, overlapping matches included.

    A value longer than ``limit`` is checked at its start and end only (see :func:`_parts`). With ``mask`` (what
    output masks) every literal value of a secret-named field counts, placeholders and short values included.
    """
    key = str(keys.last) if keys.depth else ""
    if key in _TYPED_VALUES:
        key = "value"
    language = code_language(node.type, keys)
    secretish = _maskable if mask else _looks_secret_value
    if keys.depth == 1 and key == _EMBEDDED_WORKFLOWS.get(node.type) and (not node.cache.get("embedded") or node.cache.get("embedded_duplicates")):
        yield from _raw_embedded_secrets(value, limit, mask, node, budget)
    if key == "content" and node.type == nk.BASE + "stickyNote":
        notes: dict[int, list[tuple[str, str, int]]] = node.cache.setdefault("note_secrets", {})  # lint and the masker both ask
        if id(value) not in notes:
            notes[id(value)] = [(what, secret, base + start) for part, base in _parts(value, limit) for what, secret, start in _note_secrets(part)]
        yield from notes[id(value)]
    if language is not None:
        strip = strip_python_comments if language == "python" else strip_js_comments
        for part, base in _parts(value, limit):
            text = part if keep_comments else strip(part)  # same offsets
            yield from ((what, secret, base + start) for what, secret, start in _pattern_secrets(text, True, limit))
            if mask:
                for name, found_value, start in _code_pairs(text, _CODE_ASSIGN_ANY):
                    if _code_secret_name(name) and _maskable(found_value) and found_value.strip().lower() not in _SCHEMES:
                        yield "what looks like a hardcoded secret", found_value.strip(), base + start
        return
    # by value: lint, known_secrets (masking) and fix rounds all scan the node's values; the value lives in the node
    cache: dict[int, tuple[tuple[str, str, int], ...]] = node.cache.setdefault("pattern_secrets", {})
    found = cache.get(id(value))
    if found is None:
        found = cache[id(value)] = _pattern_secrets(value, False, limit)
    yield from found
    if key == "command" and node.type in _COMMAND_NODES:
        yield from _command_secrets(value, secretish)
    if "{{" in value and key != "content":  # ={{ {'api_key': '...'} }}: an object literal in an expression
        for part, base in _parts(value, limit):
            for start, end in expression_spans(part):
                for name, literal, offset in _code_pairs(part[start:end], _CODE_ASSIGN_ANY if mask else _CODE_ASSIGN):
                    if (
                        _code_secret_name(name)
                        and _named_literal(name, literal, secretish)
                        and (mask or _random_looking(literal) or (password_named(name) and _code_password(name, literal)))
                    ):
                        yield "what looks like a hardcoded secret", literal.strip() if mask else literal, base + start + offset
    json_field = key in ("jsonHeaders", "jsonQuery", "jsonBody", "headerParametersJson", "queryParametersJson")
    if json_field or _json_like(value):  # JSON text in any field: a Set node's jsonOutput, a raw body
        for part, base in _parts(value, limit):
            literal = _blank_spans(part)  # expression parts are not literals
            for m3 in _JSON_PAIR.finditer(literal):
                name = _JSON_ESCAPE.sub(lambda u: chr(int(u.group(1), 16)), m3.group(1))  # "X-Api-\u004bey" is X-Api-Key
                found_value = m3.group(2)
                if (
                    name.lower() not in ("cookie", "set-cookie")
                    and not _not_secret_header(name)
                    and _named_literal(name, found_value, secretish)
                    and (_secret_name(name) or (_CUSTOM_SECRET_NAME.search(name) and _generated_or_masked(found_value, secretish)))
                ):
                    yield f'a literal "{name}" value', found_value, base + m3.start(2)
            if "ookie" in literal or "OOKIE" in literal:
                for m3 in _RAW_COOKIE.finditer(literal):
                    group = 1 if m3.group(1) is not None else 2
                    yield from _cookie_secrets(m3.group(group), base + m3.start(group), mask)
            for m3 in _JSON_AUTH.finditer(literal):
                if (_maskable if mask else _auth_literal)(m3.group(2)):
                    yield f'a literal "{m3.group(1)}" value', m3.group(2), base + m3.start(2)
        if json_field:
            return
    fixed = _literal(value)
    if fixed is not None:
        yield from _named_secret(node, keys, key, *fixed, secretish, mask)
        if key in _FORM_BODY_KEYS and "=" in fixed[0] and len(fixed[0]) <= limit and _FORM_BODY.fullmatch(fixed[0]):
            yield from _form_secrets(*fixed, secretish)
    elif key == "value" or SENSITIVE_KEY.search(key) or _PLAIN_SECRET_KEY.fullmatch(key):
        # ={{ 'Bearer ' + 'abc...' }}: the string literals of the expression are sent as they are; in an expression
        # a literal can be anything ('yes', a fallback text), so only generated-looking ones count unless masking
        def generated(text: str) -> bool:
            return secretish(text) and (mask or (_random_looking(text) and _varied(text)))

        for start, end in expression_spans(value):
            described = [c.end() for c in _FROM_AI.finditer(value, start, end)] if "from" in value else []
            begun = [c.start() for c in _FROM_AI.finditer(value, start, end)] if described else []
            for m in _EXPRESSION_STRING.finditer(value, start, end):
                group = 1 if m.group(1) is not None else 2
                text = m.group(group)
                at = bisect.bisect_right(begun, m.start()) - 1
                if _REFERENCE_HEAD.search(value, max(start, m.start() - _REFERENCE_WINDOW), m.start()) or (at >= 0 and m.start() < described[at]):
                    continue  # $('Login'), $json['field'], $fromAI('name', 'what it is'): they name something, the value is elsewhere
                if text.strip().lower() not in _SCHEMES and not text.endswith((" ", "\t")):  # 'OAuth ' + $json.token
                    yield from _named_secret(node, keys, key, m.group(group), m.start(group), generated, mask)


_COMMAND_NODES = frozenset({nk.BASE + "executeCommand", nk.BASE + "ssh"})
# curl -H "X-Api-Key: ...", --header 'Authorization: Bearer ...'
_COMMAND_HEADER = re.compile(r"""(?:-H|--header)(?:[ \t]+|=)(['"])[ \t]*([A-Za-z][\w-]{0,80})[ \t]*:[ \t]*(?:[A-Za-z][\w.-]{0,40}[ \t]+)?([^'"\s]{4,1024})\1""")
# API_KEY=... ./run.sh, export API_KEY='...'
_COMMAND_ENV = re.compile(r"""(?m)(?:^|(?<=[\s;&|]))(?:export[ \t]+)?([A-Za-z_][A-Za-z0-9_]{0,80})=(['"]?)([^\s'"$`(){};&|]{4,1024})\2(?=[\s;&|]|$)""")


def _command_secrets(value: str, secretish: Callable[[str], bool]) -> Iterator[tuple[str, str, int]]:
    """The header values and environment assignments named for a secret in a shell command."""
    if "-H" in value or "--header" in value:
        for m in _COMMAND_HEADER.finditer(value):
            name, found = m.group(2), m.group(3)
            if (
                not _not_secret_header(name)
                and _named_literal(name, found, secretish)
                and (_secret_name(name) or (_CUSTOM_SECRET_NAME.search(name) and _generated_or_masked(found, secretish)))
            ):
                yield f'a literal "{name}" value', found, m.start(3)
    if "=" in value:
        for m in _COMMAND_ENV.finditer(value):
            name, found = m.group(1), m.group(3)
            if (
                (_SECRETISH_NAME.search(name) or password_named(name))
                and not _NOTE_NOT_SETTING.fullmatch(name)
                and not _PAGING_NAME.fullmatch(name)
                and _named_literal(name, found, secretish)
            ):
                yield f'a literal "{name}" value', found, m.start(3)
    yield from _command_flags(value, secretish)


_SHELL_VALUE = r"""(?:'([^'\n]{1,1024})'|"([^"\n]{1,1024})"|([^\s'"`;&|()]{1,1024}))"""
_WORD_START = r"""(?<![^\s/;&|("'])"""
# --password=X, --password X, --http-password=X. Not --password-stdin or --password-file (they name no password)
_COMMAND_LONG_FLAG = re.compile(rf"""(?<![\w-])--((?:[a-z0-9]+-)*pass(?:word|wd)?)(?:=|[ \t]+(?!-)){_SHELL_VALUE}""")
_NOT_A_PASSWORD_FLAG = frozenset({"ask", "prompt", "read", "empty", "skip", "no"})
# sshpass takes -p before the command it runs (sshpass -e ssh -p 2222 is ssh's port), so only its own options may come first
_COMMAND_SSHPASS = re.compile(rf"""{_WORD_START}sshpass(?:[ \t]+(?:-v+|-[Pd][ \t]*\S{{1,256}}))*[ \t]+-p[ \t]*(?!-){_SHELL_VALUE}""")
# One pass over a command: which tool the current simple command runs, and the short flags that mean a password to it
_COMMAND_TOOL = re.compile(
    rf"""(?<!\\)\n|[;|&]|{_WORD_START}(?P<tool>mysql|mysqldump|mysqladmin|mysqlimport|mysqlshow|mysqlcheck|mysqlpump|mysqlbinlog|mariadb(?:-dump|-admin|-import|-show|-check)?|"""
    rf"""redis-cli|(?:docker|podman|nerdctl)[ \t]+login)(?=\s)|(?<=\s)-(?P<flag>[pa])(?P<gap>[ \t]*)(?!-){_SHELL_VALUE}"""
)
_COMMAND_TOOL_HINT = re.compile(r"mysql|mariadb|redis-cli|login")


# These take --password=X only: --password alone asks for it, and what follows is the next argument (mysql --password mydb)
_COMMAND_PROMPTS = re.compile(
    rf"""{_WORD_START}(?:mysql(?:dump|admin|import|show|check|pump|binlog)?|mariadb(?:-dump|-admin|-import|-show|-check)?|psql|pg_dump|pg_dumpall|pg_restore|pg_basebackup|createdb|dropdb)(?=\s)"""
)
_COMMAND_SPLIT = re.compile(r"(?<!\\)\n|[;|&]")


def _asks_for_password(text: str, flag: int) -> bool:
    """The simple command that the flag at ``flag`` belongs to runs a tool of :data:`_COMMAND_PROMPTS`."""
    head = text[max(flag - 512, 0) : flag]
    return _COMMAND_PROMPTS.search(_COMMAND_SPLIT.split(head)[-1]) is not None


def _flag_value(m: re.Match[str], first: int) -> tuple[str, int, bool]:
    """(value, offset, single-quoted) of a :data:`_SHELL_VALUE` whose first group is number ``first``."""
    group = next(g for g in range(first, first + 3) if m.group(g) is not None)
    return m.group(group), m.start(group), group == first


def _flag_secret(value: str, single_quoted: bool, secretish: Callable[[str], bool]) -> bool:
    """A password flag's value: a shell variable, a command substitution or an expression is no literal."""
    if not single_quoted and "$" in value:
        return False
    if secretish is _maskable:
        return _maskable(value)
    v = value.strip()
    return _spaced_password(v) if " " in v else len(v) >= 4 and _literal_secret(v)


def _command_flags(value: str, secretish: Callable[[str], bool]) -> Iterator[tuple[str, str, int]]:
    """The passwords given as flags in a shell command; the expressions in it are not literals."""
    text = value
    if "{{" in value:
        pieces: list[str] = []
        pos = 0
        for start, end in expression_spans(value):
            pieces += [value[pos:start], "$" * (end - start)]
            pos = end
        text = "".join([*pieces, value[pos:]])
    if "pass" in text:
        for m in _COMMAND_LONG_FLAG.finditer(text):
            name = m.group(1)
            found, start, single = _flag_value(m, 2)
            if text[m.end(1)] != "=" and name in ("password", "pass") and _asks_for_password(text, m.start()):
                continue
            if password_named(name) and _NOT_A_PASSWORD_FLAG.isdisjoint(name.split("-")) and _flag_secret(found, single, secretish):
                yield f'a literal "--{name}" value', found.strip(), start
    if "sshpass" in text:
        for m in _COMMAND_SSHPASS.finditer(text):
            found, start, single = _flag_value(m, 1)
            if _flag_secret(found, single, secretish):
                yield "a password in an sshpass -p flag", found.strip(), start
    if _COMMAND_TOOL_HINT.search(text):
        tool = ""
        for m in _COMMAND_TOOL.finditer(text):
            if m.group("tool"):
                tool = m.group("tool").split()[0]
            elif not m.group("flag"):
                tool = ""
            elif tool:
                redis = tool == "redis-cli"
                spaced = bool(m.group("gap"))
                docker = tool in ("docker", "podman", "nerdctl")
                # mysql -pX: "-p X" asks for the password and X is the database. redis-cli -a X. docker login -p X, -pX
                if m.group("flag") == ("a" if redis else "p") and (docker or spaced == redis):
                    found, start, single = _flag_value(m, m.re.groupindex["gap"] + 1)
                    if _flag_secret(found, single, secretish):
                        yield f"a password in a {tool} -{m.group('flag')} flag", found.strip(), start


def _generated_or_masked(value: str, secretish: Callable[[str], bool]) -> bool:
    return secretish is _maskable or (_random_looking(value) and _varied(value))


def _spaced_password(value: str) -> bool:
    """A value of a field named for a password that holds spaces: a pass phrase, not the setting's name or a template's text."""
    return 8 <= len(value) <= 128 and "{{" not in value and not value.startswith("=") and not _placeholder(value) and not _ENV_REFERENCE.search(value)


_EXPRESSION_STRING = re.compile(r"'([^'\\\n{}]{4,1024})'|\"([^\"\\\n{}]{4,1024})\"")
# What a string literal of an expression is the argument or index of when it names a node or a field
_REFERENCE_WINDOW = 32
_REFERENCE_HEAD = re.compile(r"(?:\$(?:items|getWorkflowStaticData)?\(|[\w$\])]\s{0,8}\[)\s{0,8}\Z")
_FROM_AI = re.compile(r"""(?i:\$fromai)\(\s{0,8}(?:(?:'[^'\\\n]{0,1024}'|"[^"\\\n]{0,1024}")\s{0,8},?\s{0,8}){1,3}""")


def _named_secret(node: Node, keys: KeyPath, key: str, text: str, start: int, secretish: Callable[[str], bool], mask: bool) -> Iterator[tuple[str, str, int]]:
    """``text`` (at ``start`` in its value) as a secret, when the field or the entry it is in is named for one."""
    stripped = text.strip()
    scheme = re.match(r"(?i)(?:basic|token|bearer|apikey|key)\s+(?=\S{4,}$)", stripped)
    bare, offset = (stripped[scheme.end() :], start + len(text) - len(text.lstrip()) + scheme.end()) if scheme else (text, start)
    if key == "value" and (sibling := _sibling_name(node.parameters, keys.keys())):
        if sibling.strip().lower() in ("cookie", "set-cookie"):
            yield from _cookie_secrets(text, start, mask)
            return
        if _AUTH_NAME.fullmatch(sibling.strip()):
            word = _AUTH_SCHEME.match(stripped)
            bare, offset = (
                (stripped[word.end() :], start + len(text) - len(text.lstrip()) + word.end()) if word else (stripped, start + len(text) - len(text.lstrip()))
            )
            # after a scheme word (or as several words) a literal counts however short; one short word alone can be anything
            if _auth_literal(bare) if secretish is _looks_secret_value and (word or " " in bare) else _named_literal(sibling, bare, secretish):
                yield f'a literal "{sibling.strip()}" value', bare, offset
            return
    spaced = " " in stripped and _spaced_password(stripped)
    if key == "value":
        sibling = _sibling_name(node.parameters, keys.keys())
        if not _named_literal(sibling or "", bare, secretish) and not (spaced and sibling and password_named(sibling)):
            return
        if sibling and not _not_secret_header(sibling):
            if _secret_name(sibling):
                yield f'a literal "{sibling.strip()}" value', bare, offset
            elif _CUSTOM_SECRET_NAME.search(sibling) and _generated_or_masked(bare, secretish):
                # X-Custom-Auth, X-Partner-Token: only a value that looks generated (a header value can be anything)
                yield f'a literal "{sibling.strip()}" value', bare, offset
        return
    if _secret_key(key) and (_named_literal(key, text, secretish) or (spaced and password_named(key))) and (mask or node.type != nk.BASE + "stickyNote"):
        yield f'a literal "{key}"', text.strip() if mask else text, start
    elif key.lower() == "cookie":
        yield from _cookie_secrets(text, start, False)
    elif _PLAIN_SECRET_KEY.fullmatch(key) and _generated(text):
        yield f'a literal "{key}"', text.strip(), start


def known_secrets(wf: Workflow) -> list[str]:
    """Every secret value in the workflow's parameters (and parameter names), longest first.

    Unlike N8D101 findings this ignores ``allow`` lists and inline suppressions, and also
    looks inside code comments: it is what output that may show parameter values masks.
    More than ``max_secrets`` of them raise :class:`LimitError` (every output masks them all).
    """
    return sorted(_known_secrets(wf), key=lambda s: (-len(s), s))


def _known_secrets(wf: Workflow) -> set[str]:
    """The secrets of ``wf``, read once (a masker can be dropped and built again: see :func:`secret_masker`)."""
    if wf.secrets is None:
        wf.secrets = _read_known_secrets(wf)
    return wf.secrets


def _read_known_secrets(wf: Workflow) -> set[str]:
    found: set[str] = set()
    limit = wf.limits.max_value_chars
    most = wf.limits.max_secrets
    texts: list[str] = []  # the embedded workflows written as text, as their spelling of a secret may differ
    pending: list[tuple[Workflow, int]] = [(wf, 0)]  # a workflow, and how many JSON texts it is inside
    while pending:
        current, escapes = pending.pop()
        here: set[str] = set()
        for node in current.nodes:
            flows = _embedded(node, current)  # before _leaf_secrets, which scans what could not be parsed
            params = _own_parameters(node, flows)
            here.update(s for _, s in _key_secrets(params, limit))
            if node.notes:
                here.update(s for _, s, _ in _notes_secrets(node.notes, limit) if len(s) >= 4)
            for keys, value in iter_leaves(params):
                code = code_language(node.type, keys) is not None  # comments matter in code only
                for keep in (False, True) if code else (False,):
                    here.update(s for _, s, _ in _leaf_secrets(node, keys, value, keep_comments=keep, limit=limit, mask=True, budget=wf.budget) if len(s) >= 4)
                if len(found) + len(here) > most:  # checked as they are found, so the work before the error is bounded too
                    where = wf.source + (f"[{wf.position}]" if wf.position else "")
                    what = f"more than {most:,} distinct secrets in node parameters"
                    raise LimitError(f"{where}: {what} (raise the limit with --max-secrets or max-secrets in [limits])")
            for _, sub in flows:
                beside = _beside_parameters(sub)
                here.update(s for _, s in _key_secrets(beside, limit))
                here.update(s for _, value in iter_leaves(beside) for _, s in text_secrets(value, limit))
                raw = node.parameters[_EMBEDDED_WORKFLOWS[node.type]]
                if isinstance(raw, str):
                    texts.append(raw)
                pending.append((sub, escapes + isinstance(raw, str)))
        for _ in range(escapes - 1):  # the masker adds one level of JSON escapes; a text inside a text has more
            here |= {json.dumps(s, ensure_ascii=False)[1:-1] for s in here}
        found |= here
    for text in texts:
        found.update(_raw_spellings(text, found))
    for secret in list(found):
        if "\\" in secret and (decoded := _json_unescape(secret)) and len(decoded) >= 4:
            found.add(decoded)  # "\u0067hp_..." in a JSON text is sent (and may be shown elsewhere) as "ghp_..."
    return found


_JSON_STRING_BODY = re.compile(r'"((?:[^"\\]|\\.)*)"')


def _raw_spellings(text: str, secrets: set[str]) -> Iterator[str]:
    """How the JSON ``text`` spells any of ``secrets`` with \\u escapes (``"\\u0067hp_..."``): the masker would miss it."""
    if "\\u" in text:
        for m in _JSON_STRING_BODY.finditer(text):
            body = m.group(1)
            if "\\u" in body and (decoded := _json_unescape(body)) and (decoded in secrets or not secrets.isdisjoint(decoded.split())):
                yield body


def _json_unescape(text: str) -> str | None:
    """``text`` with its JSON string escapes decoded, or None when it is not a valid JSON string body."""
    try:
        decoded = json.loads(f'"{text}"')
    except ValueError:
        decoded = _JSON_ESCAPE.sub(lambda u: chr(int(u.group(1), 16)), text)
    return decoded if isinstance(decoded, str) and decoded != text else None


_PREFIX = 4  # every known secret is at least this long
_MEMO_TEXT = 4096  # masked texts up to this long are remembered with their result (names, types, diff lines repeat)
_MEMO_SIZE = 100_000
_MEMO_CHARS = 16 * 1024 * 1024  # and at most this much of them
_MASK_WORK_PER_CHAR = 16  # see _MultiMasker._mask: the characters compared per character of the text
_MASK_WORK_STEP = 64  # what one comparison costs besides its characters, in the same unit
_URL_SPELLED_MAX = 256  # longer secrets are looked for as they are: a URL does not hold them, and each spelling costs memory
_LIVE_MASKERS = 4  # maskers kept per run: each holds an automaton of twelve bytes per character of the workflow's secrets
_live_maskers: collections.deque[weakref.ref[Workflow]] = collections.deque()


class _MultiMasker:
    """Replaces every occurrence of any of many strings in one pass (where several overlap, their union).

    An Aho-Corasick automaton over the strings, built once: reading the text it knows the longest
    string ending at each position, so the work is linear in the text whatever the number,
    length or overlap of the strings. Every string is at least 4 characters long, so a match can
    only start where the text's next 4 characters are the start of one of them (a candidate):
    those places are found first (with a regular expression for their first characters, or one
    set lookup per position when the strings start with many different characters), and the
    automaton runs from each one. States less than 4 characters deep are never kept: where a
    failure link leads to one, the scan restarts at the candidates among the last 3 characters,
    which finds the same matches. Along a run of trie nodes with one child each (the body of a
    long secret) the text is compared with the run with ``str.startswith`` and the strings that end
    inside it are found with ``bytearray.find``, so Python steps one character at a time only where
    the trie branches.

    The trie is stored compactly, since a secret can be megabytes long: the strings are
    inserted in sorted order, so the new nodes of each one are numbered consecutively and node
    ``s + 1`` is usually the child of ``s`` (``linked[s]``, by the character ``chars[s + 1]``);
    the other children, at most one per string, are in ``extra``. Building it takes time linear
    in the total length of the strings, about twelve bytes per character. Failure links are
    computed when the scan first reaches a node, once.
    """

    def __init__(self, forms: set[str], whole: frozenset[str] = frozenset()) -> None:
        # strings of ``whole`` are masked only where they are a whole token (see _bounded)
        self.whole = whole
        self.whole_lengths = {len(w) for w in whole}
        self.forms = forms
        self.lengths = sorted({len(f) for f in forms if len(f) >= _PREFIX})
        pieces = [" "]  # joined: the character on the edge into each node (a placeholder for the root)
        size = 1
        linked = bytearray(1)  # linked[s]: node s + 1 is a child of node s
        deep = bytearray(1)  # deep[s]: node s is at least _PREFIX characters deep
        extra: dict[int, dict[str, int]] = {}
        ends: dict[int, int] = {}  # node -> length of the string that ends there
        path: list[tuple[int, int]] = [(0, 0)]  # the previous string's nodes: (depth, node) where a numbered run starts
        prev = ""
        for form in sorted(f for f in forms if len(f) >= _PREFIX):
            common = 0
            limit = min(len(prev), len(form))
            while common < limit and prev[common] == form[common]:
                common += 1
            while path[-1][0] > common:
                path.pop()
            parent = path[-1][1] + common - path[-1][0]
            if common < len(form):
                if parent == size - 1 and not linked[parent]:
                    linked[parent] = 1
                else:
                    extra.setdefault(parent, {})[form[common]] = size
                path.append((common + 1, size))
                pieces.append(form[common:])
                added = len(form) - common
                linked.extend(b"\x01" * (added - 1) + b"\x00")
                shallow = max(0, min(added, _PREFIX - 1 - common))  # the new nodes are common + 1 ... len(form) deep
                deep.extend(b"\x00" * shallow + b"\x01" * (added - shallow))
                size += added
            ends[path[-1][1] + len(form) - path[-1][0]] = len(form)
            prev = form
        self.chars = "".join(pieces)
        self.linked, self.extra, self.deep = linked, extra, deep
        self.parents = {t: s for s, branch in extra.items() for t in branch.values()}  # other nodes: s + 1's parent is s
        self.fail = array("i", [-1]) * size  # -1: not computed yet
        self.longest = array("i", bytes(4 * size))  # length of the longest string that ends at this node
        self.done = bytearray(size)  # 1 where fail and longest are computed
        self.out = bytearray(size)  # 1 where a string ends (longest > 0), once computed
        for node, length in ends.items():
            self.longest[node] = length
        self.fail[0] = 0
        self.done[0] = 1
        self.prefixes = {form[:_PREFIX] for form in forms if len(form) >= _PREFIX}
        firsts = sorted({prefix[0] for prefix in self.prefixes})
        self.finder = re.compile("[" + "".join(re.escape(c) for c in firsts) + "]") if firsts else None
        self.broad = len(firsts) > 12  # then most characters start a prefix: look up the text's 4-grams instead
        # For the broad case: every 4-gram at offsets 0-3 of the strings of 7 or more characters, with its offsets
        # (bit o: at offset o). Each match of such a string covers a position divisible by 4 whose 4-gram is one of
        # these, so looking up every 4th position of the text finds them all. Shorter strings are found by a regex.
        self.grams: dict[str, int] = {}
        short = [form for form in forms if _PREFIX <= len(form) < 2 * _PREFIX - 1]
        for form in forms:
            if len(form) >= 2 * _PREFIX - 1:
                for o in range(_PREFIX):
                    gram = form[o : o + _PREFIX]
                    self.grams[gram] = self.grams.get(gram, 0) | 1 << o
        self.short = re.compile("(?=" + "|".join(map(re.escape, sorted(short))) + ")") if 0 < len(short) <= 256 else None
        self.sampled = len(short) <= 256

    def _candidates(self, text: str) -> list[int]:
        """Where a string can start: positions whose next 4 characters begin one of the strings, in order."""
        prefixes = self.prefixes
        if self.broad and self.sampled:
            grams = self.grams
            found = []
            for i in [i for i in range(0, len(text) - _PREFIX + 1, _PREFIX) if text[i : i + _PREFIX] in grams]:
                bits = grams[text[i : i + _PREFIX]]
                found += [i - o for o in (3, 2, 1, 0) if bits >> o & 1 and i >= o and text[i - o : i - o + _PREFIX] in prefixes]
            if self.short is not None:
                found = sorted({*found, *(m.start() for m in self.short.finditer(text))})
            return found
        if self.broad:
            return [i for i in range(len(text) - _PREFIX + 1) if text[i : i + _PREFIX] in prefixes]
        found = []
        m = self.finder.search(text) if self.finder is not None else None
        while m is not None:
            i = m.start()
            if text[i : i + _PREFIX] in prefixes:
                found.append(i)
            m = self.finder.search(text, i + 1)  # type: ignore[union-attr]  # set when there are strings
        return found

    def _child(self, s: int, c: str) -> int:
        if self.linked[s] and self.chars[s + 1] == c:
            return s + 1
        branch = self.extra.get(s)
        return branch.get(c, -1) if branch is not None else -1

    def _finish(self, u: int, target: int) -> None:
        self.fail[u] = target
        if not self.longest[u]:
            self.longest[u] = self.longest[target]
        self.done[u] = 1
        if self.longest[u]:
            self.out[u] = 1

    def _resolve(self, u: int) -> None:
        """Compute the failure link of node ``u`` (and ``longest[u]``), and first those of the nodes it needs.

        A link always points to a shallower node, which is computed first; every node is computed
        once, so the total work is at most that of building them all up front.
        """
        fail, stack = self.fail, [u]
        while stack:
            u = stack[-1]
            if fail[u] >= 0:
                stack.pop()
                continue
            parent = u - 1 if self.linked[u - 1] else self.parents[u]
            if fail[parent] < 0:
                stack.append(parent)
                continue
            c = self.chars[u]
            f = fail[parent] if parent else -1
            target = 0
            while f >= 0:
                g = self._child(f, c)
                if g >= 0:
                    target = g
                    break
                f = fail[f] if f else -1
            if fail[target] < 0:  # shallower than u: compute it first, then come back to u
                stack.append(target)
                continue
            self._finish(u, target)
            stack.pop()

    def _resolve_run(self, first: int, last: int) -> None:
        """:meth:`_resolve` for the nodes ``first`` to ``last`` of a run (each the only child of the one before)."""
        chars, linked, extra, fail, longest, done, out = self.chars, self.linked, self.extra, self.fail, self.longest, self.done, self.out
        for u in range(first, last + 1):
            if done[u]:
                continue
            c = chars[u]
            f = fail[u - 1] if u > 1 else -1
            target = 0
            while f >= 0:
                if linked[f] and chars[f + 1] == c:
                    target = f + 1
                    break
                branch = extra.get(f)
                if branch is not None and c in branch:
                    target = branch[c]
                    break
                f = fail[f] if f else -1
            if not done[target]:
                self._resolve(u)
                continue
            fail[u] = target
            if not longest[u]:
                longest[u] = longest[target]
            done[u] = 1
            if longest[u]:
                out[u] = 1

    def _run_length(self, text: str, p: int, first: int, most: int) -> int:
        """How many characters of ``text`` from ``p`` match ``chars`` from ``first`` (at least 1, at most ``most``):
        probes of doubling length with ``startswith``, then a binary search in the last step."""
        chars = self.chars
        good, step = 1, 16
        while good < most:
            probe = min(most, good + step)
            if not text.startswith(chars[first : first + probe], p):
                lo, hi = good, probe - 1
                while lo < hi:
                    mid = (lo + hi + 1) // 2
                    if text.startswith(chars[first : first + mid], p):
                        lo = mid
                    else:
                        hi = mid - 1
                return lo
            good, step = probe, step * 2
        return good

    def _bounded(self, text: str, start: int, end: int) -> bool:
        """False for a string of ``whole`` found inside a longer word: ``Pa55`` in ``Pa55word``."""
        inside = (_word_char(text[start]) and start > 0 and _word_char(text[start - 1])) or (
            _word_char(text[end - 1]) and end < len(text) and _word_char(text[end])
        )
        return not inside or text[start:end] not in self.whole

    def _shorter(self, text: str, start: int, end: int, left: list[int]) -> int:
        """Where the longest string that ends at ``end``, is shorter than ``end - start`` and may be masked there
        starts, or -1. ``left``: the work this text may still cost; when it runs out the match is masked as it is."""
        for i in range(bisect.bisect_left(self.lengths, end - start) - 1, -1, -1):
            length = self.lengths[i]
            left[0] -= length + _MASK_WORK_STEP
            if left[0] < 0:
                return start
            if text[end - length : end] in self.forms and self._bounded(text, end - length, end):
                return end - length
        return -1

    def __call__(self, text: str) -> str:
        if self.finder is None:
            return text
        return self._mask(text)

    def _mask(self, text: str) -> str:
        candidates = self._candidates(text)
        if not candidates:
            return text
        chars, linked, extra, fail, longest = self.chars, self.linked, self.extra, self.fail, self.longest
        done, out, deep = self.done, self.out, self.deep
        regions: list[list[int]] = []  # masked [start, end), merged where they overlap or touch
        # Telling whole tokens from parts of words takes work per match, and the matches can be many and long: this
        # much per text. Past it every match is masked, which can cut a word apart but shows nothing.
        left = [_MASK_WORK_PER_CHAR * len(text) + 4096]

        def add(start: int, end: int) -> None:
            if self.whole and left[0] >= 0 and end - start in self.whole_lengths:
                left[0] -= end - start + _MASK_WORK_STEP
                if not self._bounded(text, start, end):
                    start = self._shorter(text, start, end, left)  # a shorter string that also ends here, or none
                    if start < 0:
                        return
            while regions and regions[-1][1] >= start:
                start = min(start, regions.pop()[0])
            regions.append([start, end])

        s = 0
        p = 0
        size = len(text)
        while True:
            if s == 0:  # nothing read so far can be part of a match: go to the next candidate
                at = bisect.bisect_left(candidates, p)
                if at == len(candidates):
                    break
                p = candidates[at]
            elif p >= size:
                break
            c = text[p]
            if linked[s] and chars[s + 1] == c:
                # along the run of nodes with one child each that starts here: as far as the text follows it
                run_end = linked.find(0, s)
                k = self._run_length(text, p, s + 1, min(run_end - s, size - p)) if run_end - s > 1 and size - p > 1 else 1
                last = s + k
                if done.find(0, s + 1, last + 1) >= 0:
                    self._resolve_run(s + 1, last)
                u = out.find(1, s + 1, last + 1)
                while u >= 0:
                    end = p + (u - s)
                    add(end - longest[u], end)
                    u = out.find(1, u + 1, last + 1)
                p += k
                s = last
                continue
            parent = s
            while True:
                branch = extra.get(s)
                if branch is not None and c in branch:
                    s = branch[c]
                    break
                s = fail[s]  # s is at least _PREFIX deep here (a candidate's first characters never fail)
                if not deep[s]:
                    s = -1  # a shallow state: restart at the candidates among the last characters read
                    break
                parent = s
                if linked[s] and chars[s + 1] == c:
                    s += 1
                    break
            if s < 0:
                s = 0
                p -= _PREFIX - 1
                continue
            if not done[s]:
                f = fail[parent] if parent else -1  # first visit: the common case of _resolve, inlined
                target = 0
                while f >= 0:
                    if linked[f] and chars[f + 1] == c:
                        target = f + 1
                        break
                    branch = extra.get(f)
                    if branch is not None and c in branch:
                        target = branch[c]
                        break
                    f = fail[f] if f else -1
                if fail[target] < 0:
                    self._resolve(s)
                else:
                    self._finish(s, target)
            p += 1
            if out[s]:
                add(p - longest[s], p)
        pieces: list[str] = []
        last_end = 0
        for start, end in regions:
            pieces.append(text[last_end:start])
            pieces.append("***")
            last_end = end
        pieces.append(text[last_end:])
        return "".join(pieces)


def _word_char(ch: str) -> bool:
    return ch.isalnum() or ch == "_"


def _weak(secret: str) -> bool:
    """A secret short or plain enough to occur inside ordinary words (Pa55, hunter22, email): masked as a whole
    token only, so it does not cut other text apart."""
    return len(secret) < 8 or not _varied(secret)


def _without_number(name: str) -> str:
    """``re.sub(r"\\d+$", "", name)`` without its quadratic search on a long run of digits not at the end."""
    end = len(name) - 1 if name.endswith("\n") else len(name)
    start = end
    while start and name[start - 1].isdecimal():
        start -= 1
    return name[:start] + name[end:]


_PERCENT = re.compile(r"%[0-9A-F]{2}")


def _url_spellings(secret: str) -> set[str]:
    """How URLs write ``secret``: every reserved character encoded (``encodeURIComponent`` leaves ``!~*'()``, Python's
    ``quote`` leaves ``/``), or only what ``encodeURI`` encodes, or with ``:@`` left as they are in a query; spaces as
    ``%20`` or ``+``, in upper and lower case hexadecimal."""
    forms = {quote(secret, safe=safe, errors="replace") for safe in ("", "!~*'()", "/", ":@", ";,/?:@&=+$-_.!~*'()#")}
    forms |= {form.replace("%20", "+") for form in forms}
    return forms | {_PERCENT.sub(lambda m: m.group(0).lower(), form) for form in forms}


def secret_masker(wf: Workflow) -> Callable[[str], str]:
    """A function that masks every secret of ``wf`` (and anything the N8D101 patterns match) in a text.

    The one helper for output that shows anything from the workflow: names, finding messages, the
    ``fix`` diff and changes, ``explain`` (a value detected by its context, such as a header value,
    is masked wherever it appears, also in a node or workflow name). Built once per workflow.
    Values are masked as they are and in each way a JSON string can spell them (``json.dumps``
    with and without ``ensure_ascii``, and :func:`files.json_dumps`, which the diff uses).
    One pass over the text whatever the number of secrets.
    """
    if wf.masker is not None:
        return wf.masker  # type: ignore[no-any-return]
    # A file can hold a thousand workflows: only the last few maskers stay, and the automaton is only built for a text
    # long enough to hold a secret (the names a report lists often are not).
    forms: set[str] = set()
    weak: set[str] = set()
    strong: set[str] = set()
    for secret in _known_secrets(wf):
        spelled = {secret}
        if not (secret.isascii() and secret.isprintable() and '"' not in secret and "\\" not in secret):  # JSON writes plain ASCII as it is
            spelled.update((json.dumps(secret)[1:-1], json.dumps(secret, ensure_ascii=False)[1:-1], json_dumps(secret, None)[1:-1]))
        if not secret.isalnum() and len(secret) <= _URL_SPELLED_MAX:  # a URL in an error message
            spelled.update(_url_spellings(secret))
        forms |= spelled
        if _weak(secret):
            weak |= spelled
        else:
            strong |= spelled
    if (total := sum(map(len, forms))) > wf.limits.max_secret_chars:  # the masker's work grows with it
        where = wf.source + (f"[{wf.position}]" if wf.position else "")
        what = f"{total / 1024:,.0f} KB of distinct secrets in node parameters, more than {wf.limits.max_secret_chars // 1024:,} KB"
        raise LimitError(f"{where}: {what} (raise the limit with --max-secret-kb or max-secret-kb in [limits])")
    shortest = min(map(len, forms), default=0)
    automaton: list[Callable[[str], str]] = []
    memo: dict[str, str] = {}  # short texts repeat (names, types, diff lines): each is masked once
    memo_left = [_MEMO_CHARS]

    def unmemoized(text: str) -> str:
        if len(text) < shortest:
            return redact(text)
        if not automaton:
            automaton.append(_MultiMasker(forms, frozenset(weak - strong)))
        return redact(automaton[0](text))

    def mask(text: str) -> str:
        if len(text) > _MEMO_TEXT:
            return unmemoized(text)
        shown = memo.get(text)
        if shown is None:
            shown = unmemoized(text)
            if len(memo) < _MEMO_SIZE and memo_left[0] > 0:
                memo_left[0] -= len(text)
                memo[text] = shown
        return shown

    wf.masker = mask
    _live_maskers.append(weakref.ref(wf))
    while len(_live_maskers) > _LIVE_MASKERS:
        old = _live_maskers.popleft()()
        if old is not None:
            old.masker = None
    return mask


def too_large(value: str) -> str:
    """What output shows instead of a value too long to check for secrets in full."""
    return f"<{len(value):,} characters, too large to check for secrets: not shown>"


def shown_value(wf: Workflow) -> Callable[[str], str]:
    """:func:`secret_masker` for parameter values: a value over the scan limit is replaced as a whole, since
    a secret in its unchecked middle could not be masked."""
    mask = secret_masker(wf)  # reads every secret of the workflow, so the budget below is settled
    limit = wf.limits.max_value_chars
    budget: FileBudget = wf.budget
    unread = _raw_texts(budget.flows or [wf]) if budget.raw_cut else frozenset()

    def show(value: str) -> str:
        if len(value) > limit:
            return too_large(value)
        if value in unread:
            return f"<{len(value):,} characters of embedded text, only partly checked for secrets: not shown>"
        return mask(value)

    return show


def _raw_texts(flows: list[Workflow]) -> frozenset[str]:
    """What the embedded-workflow fields of ``flows`` and the workflows in them hold as text. The raw scan did not read
    all of it, and an outer text holds the inner ones."""
    found: set[str] = set()
    pending = list(flows)
    while pending:
        for node in pending.pop().nodes:
            raw = node.parameters.get(_EMBEDDED_WORKFLOWS.get(node.type, ""))
            if isinstance(raw, str):
                found.add(raw)
            pending.extend(sub for _, sub in node.cache.get("embedded", ()))
    return frozenset(found)


def masked_workflow(wf: Workflow) -> Workflow:
    """A copy of ``wf`` with every parameter string (values and keys) passed through :func:`shown_value`.

    Names are kept (connections refer to them); show them through ``secret_masker(wf)`` of the original.
    """
    show = shown_value(wf)
    data = json_copy(wf.data)
    for raw in data.get("nodes", []):
        params = raw.get("parameters") if isinstance(raw, dict) else None
        if isinstance(params, dict):
            raw["parameters"] = _map_strings(params, show)
    return build(data, wf.source, wf.position, limits=wf.limits)


def _map_strings(value: Any, func: Callable[[str], str]) -> Any:
    """``value`` with ``func`` applied to every string in it, dict keys included. Iterative (no recursion limit)."""
    root: list[Any] = [value]
    stack: list[tuple[Any, Any]] = [(root, 0)]
    while stack:
        container, key = stack.pop()
        current = container[key]
        if isinstance(current, str):
            container[key] = func(current)
        elif isinstance(current, dict):
            if any(isinstance(k, str) and func(k) != k for k in current):
                current = container[key] = {func(k) if isinstance(k, str) else k: v for k, v in current.items()}
            stack.extend((current, k) for k in current)
        elif isinstance(current, list):
            stack.extend((current, i) for i in range(len(current)))
    return root[0]


# Where the next page starts: generated, no secret. Exact names: webpage_token, page_token and PAGE_TOKEN (a Facebook
# page's access token) count as secrets; pageToken is the paging field of the Google APIs.
_PAGING_NAME = re.compile(r"(?i:(?:next|prev(?:ious)?|continuation)[-_]?(?:page[-_]?)?token)|[Pp]age(?:Token|-[Tt]oken)")
_NOT_SECRET_HEADER = re.compile(
    r"(?i)(?:x-)?(?:[a-z0-9]+-)?(?:idempotency[-_]?(?:key|token)|idempotent[-_]?key|(?:request|correlation|trace)[-_]?(?:id|key|token)|"
    r"session[-_]?id|public[-_ ]?key|(?:cache|partition|websocket|routing|sort|shard|dedup|object|file|bucket|sheet|spreadsheet|product|price)[-_ ]?key|"
    r"key[-_]?id|auth[-_]?scheme|secret[-_ ]?name|atlassian-token|"
    r"(?:(?:next|prev(?:ious)?|continuation)[-_ ]?(?:page[-_ ]?)?|page[-_]?)token)"
    r"|(?i:[a-z0-9 _-]{0,80}token[-_ ]?address)"  # a token's contract address is public
)


def _not_secret_header(name: str) -> bool:
    """A header or entry whose exact name says it holds an id or a place in a list: X-Request-Id, Idempotency-Key,
    X-Page-Token. Names that only contain those words are looked at: X-Requester-Api-Key, X-Public-Api-Token."""
    return _NOT_SECRET_HEADER.fullmatch(name.strip()) is not None


# a whole word of the header name (between separators, or capitalised: XApiKey, X-AuthToken), so X-Monkey-Id,
# X-Author-Id, X-Keyword and X-Tokenizer-Model do not count
_CUSTOM_SECRET_NAME = re.compile(
    r"(?i:(?<![a-z])(?:auth|tokens?|keys?|secrets?)(?![a-z]))|(?:Auth|Tokens?|Keys?|Secrets?)(?![a-z])|(?i:^(?:appid|sig|signature)$)"
)


def _sibling_name(params: dict[str, Any], keys: Key) -> str | None:
    """For the keys of ``a.b[0].value`` return the ``name`` of the same object, if any."""
    obj: Any = params
    for k in keys[:-1]:
        if isinstance(k, int):
            obj = obj[k] if isinstance(obj, list) and k < len(obj) else None
        else:
            obj = obj.get(k) if isinstance(obj, dict) else None
        if obj is None:
            return None
    name = obj.get("name") if isinstance(obj, dict) else None
    return name if isinstance(name, str) else None


@rule(
    "N8D102",
    "webhook-without-auth",
    Severity.WARNING,
    "A Webhook, MCP Server or public Chat trigger accepts requests from anyone who knows or guesses its URL.",
    "Set Authentication to Header Auth, Basic Auth or JWT Auth on the Webhook node, or verify a signature in the first "
    "node and mark this node with the note `n8n-doctor-disable webhook-without-auth`.",
)
def _webhook_without_auth(ctx: Context, meta: Rule) -> Iterator[Finding]:
    for node in _active_nodes(ctx.wf):
        if node.type == CHAT_TRIGGER and nk.p(node, "public") is True and nk.p(node, "authentication", default="none") in ("none", "", None):
            yield _f(
                meta,
                "public chat with no authentication: anyone with the URL can run the agent (and spend its model budget)",
                node,
                "authentication",
                "Set Authentication to Basic Auth or n8n User Auth on the Chat Trigger, or turn off 'Make Chat Publicly Available'.",
            )
            continue
        if node.type == MCP_TRIGGER and nk.p(node, "authentication", default="none") in ("none", "", None):
            yield _f(
                meta,
                f"MCP server /{redact(_shown(str(nk.p(node, 'path', default='')), ctx.wf))} has no authentication: "
                "anyone with the URL can list and call its tools",
                node,
                "authentication",
                "Set Authentication to Bearer Auth or Header Auth on the MCP Server Trigger (or n8n User Auth on v2+).",
            )
            continue
        if node.type == nk.WEBHOOK and nk.p(node, "authentication", default="none") in ("none", "", None):
            method = _shown(nk.webhook_methods(node), ctx.wf)
            yield _f(meta, f"{method} /{redact(_shown(str(nk.p(node, 'path', default='')), ctx.wf))} has no authentication", node, "authentication")


@rule(
    "N8D103",
    "webhook-test-url",
    Severity.ERROR,
    "A node calls an n8n test webhook URL (/webhook-test/), which only works while someone has the editor open and listening.",
    "Use the production URL (/webhook/...) of the target workflow and make sure that workflow is active.",
)
def _webhook_test_url(ctx: Context, meta: Rule) -> Iterator[Finding]:
    for node in _active_nodes(ctx.wf):
        for keys, value in iter_leaves(node.parameters):
            if "/webhook-test/" in value:
                path = keys.text()
                yield _f(meta, f"{path} points at a test webhook URL", node, path)
                break


@rule(
    "N8D104",
    "wait-resume-without-auth",
    Severity.INFO,
    "A Wait node resumes on a webhook call without authentication, so the resume URL alone is enough to continue the "
    "execution (and older n8n versions build that URL from the sequential execution id).",
    "Set Authentication on the Wait node (Basic, Header or JWT Auth) and keep $execution.resumeUrl out of public places.",
)
def _wait_resume_without_auth(ctx: Context, meta: Rule) -> Iterator[Finding]:
    for node in _active_nodes(ctx.wf):
        if node.type == nk.WAIT and nk.p(node, "resume") == "webhook" and nk.p(node, "incomingAuthentication", default="none") in ("none", "", None):
            yield _f(meta, "resumes on a webhook call without authentication", node, "incomingAuthentication")


@rule(
    "N8D105",
    "tls-verification-disabled",
    Severity.WARNING,
    "An HTTP Request ignores TLS certificate errors, so a man-in-the-middle can read or change the traffic.",
    "Turn off 'Ignore SSL Issues'. For an internal service with its own CA, install that CA for n8n (NODE_EXTRA_CA_CERTS) instead.",
)
def _tls_disabled(ctx: Context, meta: Rule) -> Iterator[Finding]:
    for node in _active_nodes(ctx.wf):
        if node.type != nk.HTTP:
            continue
        if nk.p(node, "options", "allowUnauthorizedCerts") is True or nk.p(node, "allowUnauthorizedCerts") is True:
            yield _f(meta, "'Ignore SSL Issues' is on", node, "options.allowUnauthorizedCerts")


# ============================================================================================
# Structure
# ============================================================================================


@rule(
    "N8D201",
    "unreachable-node",
    Severity.WARNING,
    "A node is not connected to any trigger, so it never runs.",
    "Connect it to the flow or delete it. Leftover nodes confuse the next person who edits the workflow.",
)
def _unreachable(ctx: Context, meta: Rule) -> Iterator[Finding]:
    wf = ctx.wf
    if not wf.triggers:
        return  # N8D202 covers it
    reachable = wf.reachable_from_triggers()
    for node in wf.real_nodes:
        if node.name in reachable:
            continue
        linked = bool(wf.outgoing(node.name, None) or wf.incoming(node.name, None))
        why = "is not reachable from any trigger" if linked else "is not connected to anything"
        sev = Severity.INFO if node.disabled else None
        hint = None
        if node.type.startswith(nk.LANGCHAIN) and node.short_type.startswith(_AI_SUB_PREFIXES):
            main_out = [e.target for e in wf.outgoing(node.name) if e.kind == "main"]
            hint = (
                "This is an AI sub-node: connect it from its own output to the agent or chain with the matching AI "
                "connection type (ai_languageModel, ai_tool, ai_memory, ...), not a main connection."
                + (f' It is wired with a main connection to "{main_out[0]}".' if main_out else "")
            )
        yield _f(meta, f"{why}{' (and is disabled)' if node.disabled else ''}", node, fix=hint, severity=sev)


@rule(
    "N8D202",
    "no-trigger",
    Severity.WARNING,
    "The workflow has no trigger (or no nodes at all), so it cannot start.",
    "Add a trigger (Webhook, Schedule, an app trigger, or 'When Executed by Another Workflow' for a sub-workflow).",
)
def _no_trigger(ctx: Context, meta: Rule) -> Iterator[Finding]:
    if not ctx.wf.real_nodes:
        yield _f(meta, "the workflow has no nodes" + (" (only sticky notes)" if ctx.wf.nodes else ""))
    elif not ctx.wf.triggers:
        yield _f(meta, "no trigger node")


def _condition_lists(node: Node) -> list[tuple[str, list[Any]]]:
    """(parameter path, conditions) for IF/Filter/Switch nodes in the v2+ condition format."""
    out: list[tuple[str, list[Any]]] = []
    if node.type in (nk.IF, nk.FILTER) and node.type_version >= 2:
        conds = nk.p(node, "conditions", "conditions")
        if isinstance(conds, list):
            out.append(("conditions", conds))
    elif node.type == nk.SWITCH and node.type_version >= 3 and nk.p(node, "mode", default="rules") == "rules":
        values = nk.p(node, "rules", "values", default=[])
        for i, v in enumerate(values if isinstance(values, list) else []):
            conds = v.get("conditions", {}).get("conditions") if isinstance(v, dict) and isinstance(v.get("conditions"), dict) else None
            if isinstance(conds, list):
                out.append((f"rules.values[{i}]", conds))
    elif node.type == nk.IF and node.type_version < 2:
        groups = nk.p(node, "conditions", default={})
        flat: list[Any] = []
        for kind in ("string", "number", "boolean", "dateTime"):
            items = groups.get(kind) if isinstance(groups, dict) else None
            for c in items if isinstance(items, list) else []:
                if isinstance(c, dict):
                    flat.append({"leftValue": c.get("value1", ""), "rightValue": c.get("value2", "")})
        if flat:
            out.append(("conditions", flat))
    return out


def _constant(cond: Any) -> bool:
    if not isinstance(cond, dict):
        return False
    left = cond.get("leftValue", "")
    right = cond.get("rightValue", "")
    op = cond.get("operator") if isinstance(cond.get("operator"), dict) else {}
    single = bool(op.get("singleValue")) if isinstance(op, dict) else False
    return not _is_expr(left) and (single or not _is_expr(right))


@rule(
    "N8D203",
    "constant-condition",
    Severity.WARNING,
    "An IF, Filter or Switch condition compares fixed values, so it always takes the same branch and the other branch is dead.",
    'Use an expression on at least one side, written with a leading = in the JSON ("={{ $json.status }}"); '
    "without the = the text is compared as it is, braces included.",
)
def _constant_condition(ctx: Context, meta: Rule) -> Iterator[Finding]:
    for node in _active_nodes(ctx.wf):
        for path, conds in _condition_lists(node):
            if conds and all(_constant(c) for c in conds):
                empty = all(isinstance(c, dict) and c.get("leftValue", "") in ("", None) for c in conds)
                braces = any(isinstance(c, dict) and "{{" in str(c.get("leftValue", "")) + str(c.get("rightValue", "")) for c in conds)
                if empty:
                    what = "is empty (not configured)"
                elif braces:
                    what = "has {{ }} but no leading =, so it compares the text literally"
                else:
                    what = "only compares fixed values"
                where = "the condition" if path == "conditions" else f"rule {int(path.split('[')[1].rstrip(']')) + 1}"
                yield _f(meta, f"{where} {what}", node, path)


@rule(
    "N8D204",
    "unconnected-switch-output",
    Severity.INFO,
    "A Switch output has no connection, so items that match its rule are silently dropped.",
    "Connect the output, remove the rule, or route it to a No Operation node to show the drop is intended.",
)
def _switch_outputs(ctx: Context, meta: Rule) -> Iterator[Finding]:
    wf = ctx.wf
    for node in _active_nodes(wf):
        if node.type != nk.SWITCH or nk.is_dynamic_outputs(node):
            continue
        labels = nk.output_labels(node)
        if nk.on_error_output(node):
            labels = labels[:-1]
        connected = wf.connected_outputs(node.name)
        if not connected:
            continue
        routed = nk.switch_routed_outputs(node)
        missing = [lab for i, lab in enumerate(labels) if i not in connected and (routed is None or i in routed)]
        if missing:
            shown = _listed([_shown(label, wf) for label in missing[: _LISTED + 1]])
            more = f" ({len(missing):,} in all)" if len(missing) > _LISTED else ""
            yield _f(meta, f"output{'s' if len(missing) != 1 else ''} {shown} not connected{more}", node, "rules")


_ID_LEFT = "n8n connects nodes by name: connect the node meant in the editor. n8n-doctor fix leaves this wiring in place."


def node_id_owners(wf: Workflow) -> dict[str, list[str]]:
    """The names of the nodes that have each id, what a connection written with ids instead of names can mean."""
    owners: dict[str, list[str]] = {}
    for node in wf.real_nodes:
        node_id = node.raw.get("id")
        if isinstance(node_id, str) and node_id:
            owners.setdefault(node_id, []).append(node.name)
    return owners


def _id_finding(meta: Rule, wf: Workflow, what: str, ids: dict[str, list[str]], node: Node | None) -> Finding:
    """A connection written with node ids: ``ids`` all of one node each, which fix rewrites, or all of several, which it leaves."""
    said = _listed([f'"{i}" ({"node" if len(names) == 1 else "shared by"} ' + _listed([f'"{_shown(n, wf)}"' for n in names]) + ")" for i, names in ids.items()])
    message = f"{what} node id{'s' if len(ids) > 1 else ''} {said}"
    if all(len(names) == 1 for names in ids.values()):
        return _f(meta, message, node, fix="n8n connects nodes by name; n8n-doctor fix rewrites the id to the name.")
    finding = _f(meta, message, node, fix=_ID_LEFT)
    finding.autofix = False
    return finding


@rule(
    "N8D205",
    "dangling-connection",
    Severity.ERROR,
    "A connection points from or to a node that does not exist (usually after hand-editing or merging workflow JSON).",
    "Remove the connection (n8n-doctor fix does this, and rewrites a node id to the name) or restore the missing node.",
    fixable=True,
)
def _dangling(ctx: Context, meta: Rule) -> Iterator[Finding]:
    """One finding per missing source node, and one per existing node for all its connections to missing nodes."""
    wf = ctx.wf
    missing_targets: dict[str, list[str]] = {}  # existing source -> missing targets, first seen first
    owners = node_id_owners(wf) if any(e.source not in wf.by_name or e.target not in wf.by_name for e in wf.edges) else {}
    missing_sources: dict[str, str | None] = {}  # missing source -> an existing node it connects to
    for e in wf.edges:
        if e.source not in wf.by_name:
            if missing_sources.get(e.source) is None:
                missing_sources[e.source] = e.target if e.target in wf.by_name else None
        elif e.target not in wf.by_name:
            targets = missing_targets.setdefault(e.source, [])
            if e.target not in targets[-1:]:
                targets.append(e.target)
    for name, other in missing_sources.items():
        names = owners.get(name)
        if names:
            finding = _id_finding(meta, wf, "connection from", {name: names}, wf.by_name[names[0]] if len(names) == 1 else None)
            if len(names) == 1 and names[0] in wf.data.get("connections", ()):  # listed under both: fix leaves it too
                finding.autofix, finding.fix_hint = False, _ID_LEFT
            yield finding
        else:
            yield _f(meta, f'connection from missing node "{name}"' + (f' (linked with "{other}")' if other else ""))
    for source, targets in missing_targets.items():
        unique = [t for t in dict.fromkeys(targets) if t not in owners]
        by_id = {t: owners[t] for t in dict.fromkeys(targets) if t in owners}
        for group in ({t: n for t, n in by_id.items() if len(n) == 1}, {t: n for t, n in by_id.items() if len(n) > 1}):
            if group:
                yield _id_finding(meta, wf, f"connection{'s' if len(group) > 1 else ''} to", group, wf.by_name[source])
        if not unique:
            continue
        if len(unique) == 1:
            message = f'connection to missing node "{unique[0]}"'
        else:
            message = f"connections to {len(unique):,} missing nodes: " + _listed([f'"{t}"' for t in unique])
        yield _f(meta, message, wf.by_name[source])


@rule(
    "N8D206",
    "duplicate-node-name",
    Severity.ERROR,
    "Two nodes share a name; connections and expressions identify nodes by name, so one of them is unreachable.",
    "Rename one of the nodes in the editor (n8n updates references when you rename there).",
)
def _duplicate_names(ctx: Context, meta: Rule) -> Iterator[Finding]:
    counts: dict[str, int] = {}
    first: dict[str, Node] = {}
    for node in ctx.wf.real_nodes:
        counts[node.name] = counts.get(node.name, 0) + 1
        first.setdefault(node.name, node)
    for name, n in counts.items():
        if n > 1:
            yield _f(meta, f'{n:,} nodes are named "{name}"', first[name])


_FUZZY_CANDIDATES = 300  # names compared with difflib for one reference, the closest in length first
_FUZZY_BUDGET = 4_000_000  # difflib work per run, in len(a) * len(b) cells (about a second at worst); past it, only the exact checks run
_FUZZY_REFS = 1_000  # distinct unknown references per run that get a typo suggestion; later ones get only the exact checks
_FUZZY_MAX_NAME = 64  # a longer reference gets no typo suggestion: the work grows with the square of the length
_TYPO_MIN_LETTERS = 5  # a shorter word changed by a letter is another word: Get and Set, Post and Port
_TYPO_TWO_EDITS_LETTERS = 7  # two edits turn shorter words into others: Filter and Folder, Parse and Purge, Trend and Treat
_COMPARE_COST = 64  # the fixed part of one comparison, in cells


class FuzzyBudget:
    """The difflib work left for one run (:func:`lint.run`, a fix), shared by all its workflows."""

    def __init__(self) -> None:
        self.cells = _FUZZY_BUDGET
        self.refs = _FUZZY_REFS
        self.typo_refs = _FUZZY_REFS


def share_fuzzy_budget(flows: Iterable[Workflow]) -> None:
    """Give the workflows of one run one typo-suggestion budget (those that have one keep it)."""
    budget = FuzzyBudget()
    for wf in flows:
        if wf.fuzzy_budget is None:
            wf.fuzzy_budget = budget


class _NameIndex:
    """Lookups over a workflow's node names for :func:`suggest_name`, built once per workflow."""

    def __init__(self, wf: Workflow) -> None:
        self.stem = {n.name: _without_number(n.name) for n in wf.real_nodes}
        self.by_stem: dict[str, list[str]] = {}
        for name, stem in self.stem.items():
            self.by_stem.setdefault(stem, []).append(name)
        self.by_lower: dict[str, list[str]] = {}
        self.by_spaced: dict[str, list[str]] = {}
        self.by_end: dict[str, list[tuple[int, str]]] = {}  # "^a" / "$z" (first / last letter) -> (length, name), sorted
        for name in self.stem:
            self.by_lower.setdefault(name.lower(), []).append(name)
            self.by_spaced.setdefault(name.replace("_", " "), []).append(name)
            if name:
                for end in ("^" + name[0].lower(), "$" + name[-1].lower()):
                    self.by_end.setdefault(end, []).append((len(name), name))
        for entries in self.by_end.values():
            entries.sort()
        self.max_len = max(map(len, self.stem), default=0)
        self.sorted_lower = sorted((name.lower(), name) for name in self.stem)
        self.cache: dict[str, str | None] = {}
        self.near_cache: dict[str, str | None] = {}
        self.by_key: dict[str, list[str]] = {}  # the name but for case, spaces and punctuation -> names (a few)
        self.by_words: dict[tuple[int, str], list[tuple[int, str]]] = {}  # (words, see _word_buckets) -> (length, name), sorted
        for name in self.stem:
            names = self.by_key.setdefault(_name_key(name), [])
            if len(names) < 3:
                names.append(name)
            if len(name) <= 2 * _FUZZY_MAX_NAME:
                words = _name_words(name)
                for end in _word_buckets(words):
                    self.by_words.setdefault((len(words), end), []).append((len(name), name))
        for sized in self.by_words.values():
            sized.sort()
        if wf.fuzzy_budget is None:
            wf.fuzzy_budget = FuzzyBudget()
        self.budget: FuzzyBudget = wf.fuzzy_budget


def _index(wf: Workflow) -> _NameIndex:
    if not isinstance(wf.name_index, _NameIndex):
        wf.name_index = _NameIndex(wf)
    return wf.name_index


def suggest_name(wf: Workflow, missing: str) -> str | None:
    """The one node name that ``missing`` can only mean, if any: fix rewrites to it, so this stays very conservative.

    Only a name that differs by case, spaces or punctuation, or by a typo (see :func:`_typo`). None where a node has
    the same name but for its number: n8n numbers copies, so ``missing`` is another copy or a deleted one (see
    :func:`same_stem_name`). A name with words added or removed, or another word, is at most a suggestion
    (see :func:`near_name`): a wrong rewrite gives wrong data without any error.

    Cached per reference (a fix reuses what its lint pass found). Typos are looked for among a bounded number of names,
    only for references up to 64 characters, for the first thousand references of a run, and on a fixed number of
    len(a) * len(b) cells per run (shared by every workflow of a file), so huge workflows and long names stay fast.
    """
    index = _index(wf)
    if missing not in index.cache:
        index.cache[missing] = _rename_target(index, missing)
    return index.cache[missing]


def near_name(wf: Workflow, missing: str) -> str | None:
    """A node that ``missing`` may have meant, for a report to point at and fix to leave alone: words added or removed
    (Get Customer for Get Customer Orders), or a name alike in most letters. The budgets of :func:`suggest_name` apply."""
    index = _index(wf)
    if missing not in index.near_cache:
        index.near_cache[missing] = _suggest(index, missing)
    return index.near_cache[missing]


def same_stem_name(wf: Workflow, missing: str) -> str | None:
    """The node that ``missing`` is a numbered copy of, or a copy of: what a report can point at, never a rename."""
    stem = _without_number(missing)
    names = _index(wf).by_stem.get(stem, [])
    if stem in names:
        return stem
    return names[0] if len(names) == 1 else None


# Symbols that change what a name says: Score > 5 and Score < 5, Profit + and Profit -. Other punctuation does not.
_NAME_SIGNS = frozenset("<>=+*%#$@&^")
_NAME_WORD_OR_SIGN = re.compile(r"[^\W_]+|[<>=+*%#$@&^]")


def _name_key(name: str) -> str:
    """``name`` without case, spaces and punctuation (emoji included). Numbers stay apart: Step 12 is not Step 1 2."""
    out: list[str] = []
    digits = False
    for ch in unicodedata.normalize("NFC", name).casefold():
        if ch.isdecimal():
            if not digits:
                out.append("\0")
                digits = True
            out.append(ch)
            continue
        digits = False
        if ch.isalpha() or ch in _NAME_SIGNS or (unicodedata.category(ch)[0] == "M" and ch not in "\ufe0e\ufe0f"):
            out.append(ch)
    return "".join(out)


def _name_words(name: str) -> list[str]:
    return _NAME_WORD_OR_SIGN.findall(unicodedata.normalize("NFC", name).casefold())


def _word_buckets(words: list[str]) -> tuple[str, ...]:
    """Where to find the names that differ from ``words`` in one word: the others are equal, so they share the first
    or the last word; a name of one word shares only its first letter."""
    if not words:
        return ()
    return ("^" + words[0], "$" + words[-1]) if len(words) > 1 else (words[0][0],)


def _edits(a: str, b: str, limit: int) -> int:
    """Edit distance with adjacent transpositions (optimal string alignment); ``limit`` + 1 once it is over ``limit``."""
    if abs(len(a) - len(b)) > limit:
        return limit + 1
    before: list[int] = []
    row = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        current = [i]
        for j, cb in enumerate(b, 1):
            cost = min(row[j] + 1, current[j - 1] + 1, row[j - 1] + (ca != cb))
            if i > 1 and j > 1 and ca == b[j - 2] and a[i - 2] == cb:
                cost = min(cost, before[j - 2] + 1)
            current.append(cost)
        if min(current) > limit:
            return limit + 1
        before, row = row, current
    return min(row[-1], limit + 1)


def _typo(a: str, b: str) -> int | None:
    """The edits between the word ``a`` of a reference and the word ``b`` of a node name, if ``a`` can be a typo of it:
    the same first letter and numbers, ``b`` of at least 5 letters, at most 2 edits (1 under 7 letters: two make Filter
    from Folder)."""
    letters = sum(c.isalpha() for c in b)
    if letters < _TYPO_MIN_LETTERS or a[0] != b[0] or [c for c in a if c.isdecimal()] != [c for c in b if c.isdecimal()]:
        return None
    limit = 2 if letters >= _TYPO_TWO_EDITS_LETTERS else 1
    edits = _edits(a, b, limit)
    return edits if edits <= limit else None


def _rename_target(index: _NameIndex, missing: str) -> str | None:
    if _without_number(missing) in index.by_stem:
        return None  # n8n names copies "HTTP Request1", "HTTP Request2": a different node, not a rename
    key = _name_key(missing)
    same = index.by_key.get(key, []) if key else []
    if same:
        return same[0] if len(same) == 1 else None
    budget = index.budget
    if len(missing) > _FUZZY_MAX_NAME or budget.typo_refs <= 0 or budget.cells <= 0:
        return None
    budget.typo_refs -= 1
    words = _name_words(missing)
    if not words:
        return None
    candidates: set[str] = set()
    for end in _word_buckets(words):
        sized = index.by_words.get((len(words), end), [])
        lo = bisect.bisect_left(sized, (len(missing) - 16, ""))
        hi = bisect.bisect_left(sized, (len(missing) + 17, ""))
        if hi - lo > _FUZZY_CANDIDATES:
            return None  # too many to tell one best name
        candidates.update(name for _, name in sized[lo:hi])
    scored: list[tuple[int, str]] = []
    for name in sorted(candidates):
        budget.cells -= _COMPARE_COST + 4 * len(name)
        if budget.cells <= 0:
            return None  # an answer from part of the candidates could be the wrong one
        others = _name_words(name)
        changed = [(a, b) for a, b in zip(words, others, strict=False) if a != b]
        if len(others) != len(words) or len(changed) != 1:
            continue
        budget.cells -= len(changed[0][0]) * len(changed[0][1])
        edits = _typo(*changed[0])
        if edits is not None:
            scored.append((edits, name))
    scored.sort()
    if scored and (len(scored) == 1 or scored[0][0] < scored[1][0]):
        return scored[0][1]
    return None


def _suggest(index: _NameIndex, missing: str) -> str | None:
    import difflib

    if _without_number(missing) in index.by_stem:
        return None  # n8n names copies "HTTP Request1", "HTTP Request2": a different node, not a rename

    low = missing.lower()
    # only "exactly one" matters, so each lookup is cut at a few names (case variants of one name can be many)
    lowered = {*index.by_lower.get(low, [])[:3], *index.by_spaced.get(missing.replace("_", " "), [])[:3]}
    if len(lowered) == 1:
        return lowered.pop()
    prefixed: set[str] = set()
    # names that start with "<missing> "
    i = bisect.bisect_left(index.sorted_lower, (low + " ", ""))
    while i < len(index.sorted_lower) and index.sorted_lower[i][0].startswith(low + " ") and len(prefixed) < 2:
        prefixed.add(index.sorted_lower[i][1])
        i += 1
    # names that "<name> ..." starts with
    for pos in (p for p, c in enumerate(low[: index.max_len + 1]) if c == " "):
        if len(prefixed) >= 2:
            break
        prefixed.update(index.by_lower.get(low[:pos], [])[:3])
    if len(prefixed) == 1:
        return prefixed.pop()
    budget = index.budget
    if budget.cells <= 0 or budget.refs <= 0 or len(missing) > _FUZZY_MAX_NAME:
        return None
    budget.refs -= 1
    # a typo keeps the first or the last letter, and a ratio of 0.7 (what a close second has) needs lengths within a factor of 13/7:
    # from the names sharing an end letter, take those closest in length, a bounded number
    size = len(missing)
    if not size:
        return None
    candidates: set[str] = set()
    for end in ("^" + missing[0].lower(), "$" + missing[-1].lower()):
        entries = index.by_end.get(end, [])
        lo = bisect.bisect_left(entries, (-(-7 * size // 13), ""))  # length >= 7/13 of size
        hi = bisect.bisect_left(entries, (13 * size // 7 + 1, ""))  # length <= 13/7 of size
        right = bisect.bisect_left(entries, (size, ""), lo, hi)
        left = right - 1
        steps = 0  # names looked at, skipped ones included, so the walk is bounded too
        while steps < _FUZZY_CANDIDATES // 2 and (left >= lo or right < hi):
            steps += 1
            if left < lo or (right < hi and entries[right][0] - size <= size - entries[left][0]):
                name = entries[right][1]
                right += 1
            else:
                name = entries[left][1]
                left -= 1
            candidates.add(name)
    # difflib.get_close_matches(missing, candidates, 2, 0.7), charging each full comparison by its cells: the best must
    # reach 0.8 and lead by more than 0.1, so a second name under 0.7 cannot matter
    matcher = difflib.SequenceMatcher()
    matcher.set_seq2(missing)
    scored: list[tuple[float, str]] = []
    for name in sorted(candidates):
        matcher.set_seq1(name)
        if matcher.real_quick_ratio() < 0.7 or matcher.quick_ratio() < 0.7:
            budget.cells -= _COMPARE_COST
            continue
        if budget.cells <= 0:
            return None  # an answer from part of the candidates could be the wrong one
        budget.cells -= _COMPARE_COST + size * len(name)
        ratio = matcher.ratio()
        if ratio >= 0.7:
            scored.append((ratio, name))
    close = sorted(scored, reverse=True)[:2]
    if close and close[0][0] >= 0.8 and (len(close) == 1 or close[0][0] - close[1][0] > 0.1):
        return close[0][1]
    return None


# jQuery in HTML that a node builds ($('#go'), $('.item'), $('div > p'), $('ul li.active')): not a node name. Only a
# name that is nothing but a selector counts: "[PROD] Get Lead", ".env loader" and "#1 Fetch" are node names.
_HTML_TAGS = frozenset(
    re.findall(
        r"\S+",
        "a abbr article aside audio b blockquote body br button canvas caption code col dd details dialog div dl dt em "
        "fieldset figure footer form h1 h2 h3 h4 h5 h6 head header hr html i iframe img input label legend li link "
        "main nav ol optgroup option p pre section select small span strong sub summary sup svg table tbody td "
        "template textarea tfoot th thead tr u ul video",
    )
)
_CSS_SIMPLE = r"(?:[#.]-?[A-Za-z_][\w-]*|\[[^\]\s]*\]|:{1,2}[a-z-]+(?:\([^)\s]*\))?)"
_CSS_COMPOUND = re.compile(rf"(\*|[a-z][a-z0-9]*)?{_CSS_SIMPLE}*")
_CSS_SPLIT = re.compile(r"\s*[>+~]\s*|\s+")


def _css_selector(name: str) -> bool:
    """A name that is a CSS selector and nothing else: compound selectors (an HTML tag, ``*``, ``#id``, ``.class``,
    ``[attr]``, ``:pseudo``) joined by spaces or ``>`` ``+`` ``~``, such as ``#go``, ``.item`` or ``ul li.active``."""
    name = name.strip()
    if not name:
        return False
    for part in _CSS_SPLIT.split(name):
        m = _CSS_COMPOUND.fullmatch(part)
        if not part or m is None or (m.group(1) not in (None, "*") and m.group(1) not in _HTML_TAGS):
            return False
    return True


@rule(
    "N8D207",
    "unknown-node-reference",
    Severity.ERROR,
    "An expression or Code node refers to a node name that is not in the workflow (often a node that was renamed or deleted).",
    "Point the reference at an existing node; renaming a node in the editor updates expressions, editing JSON does not.",
    fixable=True,
)
def _unknown_refs(ctx: Context, meta: Rule) -> Iterator[Finding]:
    wf = ctx.wf
    by_type: dict[str, list[str]] | None = None
    counted = 0  # findings past a limit (ctx.counting): no suggestion or message, reported together at the end
    for node in _active_nodes(wf):
        reported: set[str] = set()
        resolved = functools.partial(_self_resolved, node)
        for keys, ref in node_refs_with_keys(active_parameters(node), wf.limits.max_code_chars, resolved, node.type):
            # jQuery can only be meant in HTML a Code node builds (a template literal); every {{ }} of an HTML or
            # SQL template is an n8n expression, where $('table') names a node
            if ref.name in wf.by_name or ref.name in reported or (ref.in_literal and _css_selector(ref.name)):
                continue
            reported.add(ref.name)
            if ctx.counting:
                counted += 1
                continue
            path = format_path(keys)
            hint = suggest_name(wf, ref.name)
            fix = f'Did you mean "{hint}"? n8n-doctor fix can rewrite it.' if hint else None
            copy = same_stem_name(wf, ref.name) if hint is None else None
            near = near_name(wf, ref.name) if hint is None and copy is None else None
            if copy is not None:
                fix = f'Did you mean "{copy}"? n8n numbers copies of a node, so n8n-doctor fix leaves this to you: check that is the node meant.'
            elif near is not None:
                fix = f'Did you mean "{near}"? The names differ by more than a typo, so n8n-doctor fix leaves this to you: check that is the node meant.'
            elif hint is None:
                # "Webhook" is the default name of a webhook node: point at the one node of that type, without auto-fixing
                key = re.sub(r"[\s_\d]+", "", ref.name).lower()
                if by_type is None:
                    by_type = {}
                    for n in wf.real_nodes:
                        by_type.setdefault(n.short_type.lower(), []).append(n.name)
                same_type = by_type.get(key, [])
                if len(same_type) == 1:
                    fix = f'The only {_shown(ref.name.strip(), wf)} node here is "{same_type[0]}"; point the reference at it if that is the one meant.'

            finding = _f(meta, f'{path} references node "{_shown(ref.name, wf)}", which does not exist', node, path, fix)
            finding.autofix = hint is not None
            yield finding
    if counted:
        yield counted_findings(meta, counted)


@rule(
    "N8D208",
    "missing-credentials",
    Severity.ERROR,
    "A node is set to authenticate but has no credential selected, or its credential reference has no id.",
    "Open the node and select (or create) the credential; after importing a workflow on another instance, re-select every credential.",
)
def _missing_credentials(ctx: Context, meta: Rule) -> Iterator[Finding]:
    for node in _active_nodes(ctx.wf):
        creds = node.credentials
        for ctype, ref in creds.items():
            cid = ref.get("id") if isinstance(ref, dict) else None
            if cid in (None, ""):
                cname = ref.get("name") if isinstance(ref, dict) else None
                shown = _shown(str(ctype), ctx.wf)
                yield _f(
                    meta,
                    f"credential {shown}{f' ({_shown(str(cname), ctx.wf)})' if cname else ''} has no id; it must be selected again on this instance",
                    node,
                    f"credentials.{shown}",
                )
        auth = nk.p(node, "authentication")
        if node.type == nk.HTTP:
            if auth == "predefinedCredentialType":
                wanted = nk.p(node, "nodeCredentialType")
                if not creds or (isinstance(wanted, str) and wanted and wanted not in creds):
                    kind = _shown(str(wanted), ctx.wf) if wanted else "predefined"
                    yield _f(meta, f"authentication uses a {kind} credential but none is selected", node, "authentication")
            elif isinstance(auth, str) and auth in ("basicAuth", "digestAuth", "headerAuth", "queryAuth", "oAuth1", "oAuth2") and not creds:
                yield _f(meta, f"authentication is {_shown(auth, ctx.wf)} but no credential is selected", node, "authentication")
            elif auth == "genericCredentialType":
                wanted = nk.p(node, "genericAuthType")
                if not creds or (isinstance(wanted, str) and wanted and wanted not in creds):
                    kind = _shown(str(wanted), ctx.wf) if wanted else "generic"
                    yield _f(meta, f"authentication uses a {kind} credential but none is selected", node, "authentication")
        elif isinstance(auth, str) and auth not in ("", "none") and not _is_expr(auth) and not creds and node.type.startswith(nk.BASE):
            if node.type in (nk.WEBHOOK, nk.WAIT, nk.FORM_TRIGGER, nk.BASE + "respondToWebhook"):
                if node.type == nk.WEBHOOK and auth in ("basicAuth", "headerAuth", "jwtAuth"):
                    yield _f(meta, f"webhook authentication is {auth} but no credential is selected", node, "authentication")
                continue
            yield _f(meta, f"authentication is {_shown(auth, ctx.wf)} but no credential is selected", node, "authentication")


def _starts_new_request(node: Node) -> bool:
    """A Wait (on webhook/form) or Form node receives a new request; Respond nodes after it answer that one.
    A disabled one only passes its input on."""
    return not node.disabled and ((node.type == nk.WAIT and nk.p(node, "resume") in ("webhook", "form")) or node.type == nk.BASE + "form")


def _first_output_only(node: Node, shared: bool = False) -> bool:
    """n8n hands a disabled node's first input to its first output and to no other (handleDisabledNode, workflow-execute.ts)."""
    return node.disabled and not shared


def _main_graph(wf: Workflow, nodes: list[Node] | None = None, flow: bool = False) -> dict[int, list[int]]:
    """Successors along main connections between existing nodes (of ``nodes``, default all), by node index.

    Connections name their nodes, so where several nodes share a name (n8n does not allow it, but a hand-edited
    export can), a connection from that name leaves each of them and one to it reaches the first, as
    ``wf.by_name`` (and n8n's editor on import) has it. Graph rules work on indices so that one node is never
    taken for another of the same name.

    The successors of a shared name are stored once, on a vertex of their own with a negative key that each
    of those nodes leads to: the graph has at most one entry per connection and one per node, however many
    nodes share a name, so every walk over it is linear. Callers skip the negative keys. A node's successors
    are listed once each, in the order of their first connection. With ``flow``, only where items can go: a disabled
    node's other outputs are left out (a node of a shared name keeps all of them).
    """
    members = wf.nodes if nodes is None else nodes
    graph: dict[int, list[int]] = {n.index: [] for n in members}
    copies = collections.Counter(n.name for n in members)
    shared: dict[str, int] = {}
    for n in members:
        if n.name in shared:
            graph[n.index] = [shared[n.name]]
            continue
        first_only = flow and _first_output_only(n, copies[n.name] > 1)
        targets = dict.fromkeys(wf.by_name[e.target].index for e in wf.outgoing(n.name) if e.target in wf.by_name and not (first_only and e.output))
        successors = [t for t in targets if t in graph]
        if copies[n.name] > 1:
            vertex = shared[n.name] = -1 - len(shared)
            graph[vertex] = successors
            graph[n.index] = [vertex]
        else:
            graph[n.index] = successors
    return graph


def _sccs(graph: dict[int, list[int]]) -> list[list[int]]:
    """Strongly connected components (iterative Tarjan), each after every component it can reach.

    Every successor must be a key of ``graph``. Linear in nodes plus edges.
    """
    index: dict[int, int] = {}
    low: dict[int, int] = {}
    stack: list[int] = []
    on_stack: set[int] = set()
    out: list[list[int]] = []
    counter = 0
    for root in graph:
        if root in index:
            continue
        index[root] = low[root] = counter
        counter += 1
        stack.append(root)
        on_stack.add(root)
        work: list[tuple[int, int]] = [(root, 0)]
        while work:
            v, i = work[-1]
            if i < len(graph[v]):
                work[-1] = (v, i + 1)
                w = graph[v][i]
                if w not in index:
                    index[w] = low[w] = counter
                    counter += 1
                    stack.append(w)
                    on_stack.add(w)
                    work.append((w, 0))
                elif w in on_stack:
                    low[v] = min(low[v], index[w])
                continue
            work.pop()
            if work:
                parent = work[-1][0]
                low[parent] = min(low[parent], low[v])
            if low[v] == index[v]:
                comp: list[int] = []
                while True:
                    w = stack.pop()
                    on_stack.discard(w)
                    comp.append(w)
                    if w == v:
                        break
                out.append(comp)
    return out


def _reach_smallest(graph: dict[int, list[int]], own: dict[int, list[Any]], k: int) -> dict[int, list[Any]]:
    """For every node, the ``k`` smallest items ``own``ed by it or by any node reachable from it.

    One pass over the components in reverse topological order: O((nodes + edges) * k).
    """
    comp_of: dict[int, int] = {}
    best: list[list[Any]] = []
    for ci, comp in enumerate(_sccs(graph)):
        for v in comp:
            comp_of[v] = ci
        items: set[Any] = set()
        for v in comp:
            items.update(own.get(v, ()))
            for w in graph[v]:
                if comp_of[w] != ci:
                    items.update(best[comp_of[w]])
        best.append(heapq.nsmallest(k, items))
    return {v: best[c] for v, c in comp_of.items()}


_LISTED = 5  # names listed in one message; more are shown as "..."
_RESPONSE_WALK = 5_000_000  # connections walked per workflow for N8D209's unused Respond nodes, when Wait nodes own some


class _Responses:
    """For N8D209, computed once per workflow for all its Webhook nodes.

    ``responders[w]``: the first Respond to Webhook nodes after ``w`` (not past a node that
    starts a new request). ``gaps[w]``: where an execution can stop after ``w`` without having
    reached one: a dead end, or ``"<node>" [<branch>]`` for an IF/Switch/loop output with nothing
    connected. n8n runs every node connected to one output, and any output of a node can be the
    one taken, so a node "can end unanswered" when one of its outputs is open or leads only to
    nodes that can: Webhook -> [Respond, Log] is fine, and a loop's body coming back is no end.
    Paths into a Stop and Error node, or past a Wait/Form that starts a new request, are not
    counted. Both lists hold at most ``_LISTED + 1`` entries, in node order.

    :meth:`unused` is what n8n itself checks before a Webhook of version 2 or later answers.
    """

    def __init__(self, wf: Workflow) -> None:
        self.wf = wf
        self.raw: dict[int, list[int]] | None = None
        self.replies: set[int] = set()
        self.owners: set[int] = set()
        self.nearest: dict[int, list[Any]] = {}
        self.walk_budget = _RESPONSE_WALK
        graph = _main_graph(wf, flow=True)
        node_at = wf.node_at
        through: dict[int, list[int]] = {}
        resp_own: dict[int, list[Any]] = {}
        gap_own: dict[int, list[Any]] = {}
        outputs: dict[str, set[int]] = {}  # connected outputs by name (missing targets included), shared by nodes of one name

        def ends_path(t: int) -> bool:  # paths into a Respond to Webhook or Stop and Error node, or past one that starts a new request, are fine
            return t >= 0 and not node_at[t].disabled and (node_at[t].type in (nk.RESPOND, nk.BASE + "stopAndError") or _starts_new_request(node_at[t]))

        for i, targets in graph.items():
            through[i] = [] if i >= 0 and _starts_new_request(node_at[i]) else targets
        for node in wf.nodes:
            i = node.index
            if node.type == nk.RESPOND and not node.disabled:
                resp_own[i] = [(i, node.name)]
            edges = wf.outgoing(node.name)
            labels = nk.output_labels(node)
            if _first_output_only(node, graph[i][:1] != [] and graph[i][0] < 0):
                edges = [e for e in edges if not e.output]
                labels = labels[:1]
            local: list[str] = []
            if not edges:
                local.append(f'"{node.name}"')
            elif len(labels) > 1 and not nk.is_dynamic_outputs(node):
                connected = outputs.get(node.name)
                if connected is None:
                    connected = outputs[node.name] = {e.output for e in edges}
                routed = nk.switch_routed_outputs(node)
                local += [
                    f'"{node.name}" [{label or j}]'
                    for j, label in enumerate(labels)
                    # the editor gives a Filter one connector, so an open Discarded output is nothing to fix
                    if j not in connected and label != "error" and not (label == "discarded" and node.type == nk.FILTER) and (routed is None or j in routed)
                ]
            if local and not ends_path(i):
                gap_own[i] = [(i, j, text) for j, text in enumerate(local[: _LISTED + 1])]
        gap_graph = self._unanswered(wf, graph, gap_own, ends_path)
        self.responders = _reach_smallest(through, resp_own, _LISTED + 1)
        self.gaps = _reach_smallest(gap_graph, gap_own, _LISTED + 1)

    def unused(self, start: int) -> list[tuple[int, str]]:
        """The Respond to Webhook nodes n8n calls unused for the Webhook at ``start`` when it does not answer through one:
        checkResponseModeConfiguration (nodes-base/nodes/Webhook/utils.ts). Every Respond among its descendants, disabled
        or past a Wait, unless a parent of that Respond is an enabled Wait among those descendants that resumes on
        webhook or form with responseMode exactly responseNode. Connections count whatever is disabled.

        At most ``_LISTED + 1``, in node order. The walks of a workflow share a budget, past which nothing more is said."""
        if self.raw is None:
            self.raw = _main_graph(self.wf)
            self.replies = {n.index for n in self.wf.nodes if n.type == nk.RESPOND}
            self.owners = {
                n.index
                for n in self.wf.nodes
                if n.type == nk.WAIT and not n.disabled and nk.p(n, "resume") in ("webhook", "form") and nk.p(n, "responseMode") == "responseNode"
            }
            self.nearest = _reach_smallest(self.raw, {i: [(i, self.wf.node_at[i].name)] for i in self.replies}, _LISTED + 1)
        nearest = self.nearest[start]
        if not nearest or not self.owners:
            return list(nearest)
        after = self._after([start])
        owners = self.owners & after
        if not owners:
            return list(nearest)
        owned = self._after(list(owners))
        return [(i, self.wf.node_at[i].name) for i in sorted((self.replies & after) - owned)[: _LISTED + 1]]

    def _after(self, starts: list[int]) -> set[int]:
        """The vertices reachable from ``starts``, ``starts`` themselves only through a cycle."""
        assert self.raw is not None
        seen: set[int] = set()
        stack = list(starts)
        while stack and self.walk_budget > 0:
            targets = self.raw[stack.pop()]
            self.walk_budget -= len(targets) + 1
            for t in targets:
                if t not in seen:
                    seen.add(t)
                    stack.append(t)
        return seen if self.walk_budget > 0 else self.replies

    @staticmethod
    def _unanswered(wf: Workflow, graph: dict[int, list[int]], open_ends: dict[int, list[Any]], ends_path: Callable[[int], bool]) -> dict[int, list[int]]:
        """For every vertex of ``graph``, the successors that explain why it can end unanswered: those of its outputs
        all of whose targets can (none where it cannot). Linear in the connections: each target tells each output it
        is on once, when it turns out it can end unanswered. A connection to a missing node counts as answered: that
        finding is N8D205's."""
        groups: list[tuple[int, list[int]]] = []  # (owner, targets) of one output
        waiting: list[int] = []  # targets of that output not yet known to end unanswered
        on: dict[int, list[int]] = {}  # target -> the outputs it is on
        vertices: dict[str, int] = {}  # the vertex that holds the connections of a name
        for node in wf.nodes:
            first = graph[node.index]
            vertex = first[0] if len(first) == 1 and first[0] < 0 else node.index
            if vertex < 0:
                groups.append((node.index, [vertex]))
                on.setdefault(vertex, []).append(len(groups) - 1)
                waiting.append(1)
            if node.name in vertices and vertex < 0:
                continue
            vertices[node.name] = vertex
            by_output: dict[int, list[int]] = {}
            whole: set[int] = set()
            first_only = _first_output_only(node, vertex < 0)
            for e in wf.outgoing(node.name):
                if first_only and e.output:
                    continue
                target = wf.by_name.get(e.target)
                if target is None:
                    whole.add(e.output)
                else:
                    by_output.setdefault(e.output, []).append(target.index)
            for output, targets in by_output.items():
                if output in whole:
                    continue
                unique = list(dict.fromkeys(targets))
                groups.append((vertex, unique))
                waiting.append(len(unique))
                for t in unique:
                    on.setdefault(t, []).append(len(groups) - 1)
        bad = set(open_ends)
        stack = list(bad)
        while stack:
            for g in on.get(stack.pop(), ()):
                waiting[g] -= 1
                owner = groups[g][0]
                if waiting[g] == 0 and owner not in bad and not ends_path(owner):
                    bad.add(owner)
                    stack.append(owner)
        out: dict[int, list[int]] = {i: [] for i in graph}
        for g, (owner, targets) in enumerate(groups):
            if waiting[g] == 0 and owner in bad:
                out[owner].extend(targets)
        return out


def _listed(items: list[str]) -> str:
    return ", ".join(items[:_LISTED]) + (" ..." if len(items) > _LISTED else "")


@rule(
    "N8D209",
    "respond-to-webhook-mismatch",
    Severity.ERROR,
    "A Webhook set to answer from a 'Respond to Webhook' node has none after it (the caller waits, then gets an error), "
    "or a 'Respond to Webhook' node follows a Webhook that already answered.",
    "Set the Webhook's Respond option to 'Using Respond to Webhook Node' and add that node on every path, or remove the Respond to Webhook node.",
)
def _respond_mismatch(ctx: Context, meta: Rule) -> Iterator[Finding]:
    wf = ctx.wf
    graph: _Responses | None = None
    for node in _active_nodes(wf):
        if node.type != nk.WEBHOOK:
            continue
        mode = nk.p(node, "responseMode", default="onReceived")
        if mode == "streaming" or _is_expr(mode):
            continue
        graph = graph or _Responses(wf)
        responders = [name for _, name in graph.responders[node.index]]
        if mode == "responseNode" and not responders:
            yield _f(
                meta,
                "responds 'Using Respond to Webhook Node' but no Respond to Webhook node follows it",
                node,
                "responseMode",
                "Add a Respond to Webhook node at the end of the flow, or set Respond to 'Immediately' or 'When Last Node Finishes'.",
            )
        elif mode == "responseNode":
            gaps = [text for _, _, text in graph.gaps[node.index]]
            if gaps:
                yield _f(
                    meta,
                    "some paths end without a Respond to Webhook node: " + _listed(gaps),
                    node,
                    "responseMode",
                    "Add a Respond to Webhook node (for example a 4xx answer) at the end of each of these paths.",
                    severity=Severity.WARNING,
                )
        elif node.type_version >= 2:  # n8n only checks these (Webhook.node.ts)
            unused = graph.unused(node.index)
            if unused:
                names = _listed([f'"{name}"' + (" (disabled)" if wf.node_at[i].disabled else "") for i, name in unused])
                yield _f(
                    meta,
                    f"answers {('immediately' if mode == 'onReceived' else 'with the last node')}, but {names} after it expects to send the response: "
                    'n8n fails every request with "Unused Respond to Webhook node found in the workflow"',
                    node,
                    "responseMode",
                    "Set the Webhook's Respond option to 'Using Respond to Webhook Node', remove the Respond to Webhook node (a disabled one counts too), "
                    "or put it after a Wait that resumes on a webhook or form and responds 'Using Respond to Webhook Node'.",
                )
        elif responders:
            names = _listed([f'"{r}"' for r in responders])
            yield _f(
                meta,
                f"answers {('immediately' if mode == 'onReceived' else 'with the last node')}, but {names} after it expects to send the response",
                node,
                "responseMode",
                "Set the Webhook's Respond option to 'Using Respond to Webhook Node', or remove the Respond to Webhook node.",
            )


@rule(
    "N8D210",
    "disabled-node-in-path",
    Severity.WARNING,
    "A disabled node sits in the middle of a flow; n8n passes items straight through it, so the next nodes get unprocessed data.",
    "Re-enable the node, or remove it and connect its neighbours directly so the intent is explicit.",
)
def _disabled_in_path(ctx: Context, meta: Rule) -> Iterator[Finding]:
    wf = ctx.wf
    for node in wf.real_nodes:
        if node.disabled and wf.incoming(node.name) and wf.outgoing(node.name):
            yield _f(meta, "is disabled but has nodes before and after it", node)


@rule(
    "N8D211",
    "pinned-data",
    Severity.WARNING,
    "The workflow has pinned test data. Production runs ignore it, but it is saved and exported with the workflow (often "
    "real customer data), and manual test runs use it instead of live data.",
    "Unpin the data in the editor before saving or exporting (n8n-doctor fix removes it).",
    fixable=True,
)
def _pinned(ctx: Context, meta: Rule) -> Iterator[Finding]:
    for name, items in ctx.wf.pin_data.items():
        count = len(items) if isinstance(items, list) else 1
        node = ctx.wf.by_name.get(name)
        yield _f(meta, f"{count} pinned item{'s' if count != 1 else ''}" + ("" if node else f' on "{name}" (no such node)'), node, "pinData")


_DOLLAR_NAME = re.compile(r"\$[A-Za-z_(]")


def _has_n8n_expression(value: str) -> bool:
    """True when ``value`` has ``{{ ... }}`` containing ``$name`` or ``$(``; braces inside are allowed
    (``{{ JSON.stringify({a: $json.x}) }}``). Linear: each span is found with str.find."""
    return any(_DOLLAR_NAME.search(value, start, end) for start, end in expression_spans(value))


# Fields whose {{ }} the node resolves itself, with or without the leading = (n8n's getResolvables): node type ->
# (lowest typeVersion, parameter path) pairs. The SQL queries of the database nodes (Postgres v1 and the nodes built
# on its pgQueryV2 with resolveExpression: QuestDB, TimescaleDB, CrateDB), Postgres v2's query replacement (read raw
# from the node's parameters), the LDAP search fields (escapeResolvables), Merge's SQL mode and the HTML node's
# template. The Set node's JSON (raw) mode is not one: n8n resolves it only as an expression.
_SELF_RESOLVED: dict[str, tuple[tuple[float, tuple[str, ...]], ...]] = {
    nk.BASE + "postgres": ((1, ("query",)), (2, ("options", "queryReplacement"))),
    nk.BASE + "mySql": ((1, ("query",)),),
    nk.BASE + "microsoftSql": ((1, ("query",)),),
    nk.BASE + "snowflake": ((1, ("query",)),),
    nk.BASE + "googleBigQuery": ((2, ("sqlQuery",)),),
    nk.BASE + "oracleDatabase": ((1, ("query",)),),
    nk.BASE + "questDb": ((1, ("query",)),),
    nk.BASE + "timescaleDb": ((1, ("query",)),),
    nk.BASE + "crateDb": ((1, ("query",)),),
    nk.BASE + "ldap": ((1, ("searchFor",)), (1, ("customFilter",)), (1, ("searchText",))),
    nk.MERGE: ((3, ("query",)),),
    nk.BASE + "html": ((1, ("html",)),),
}
# The AI Agent tool variants of the nodes above (usableAsTool in their descriptions): the same node, type + "Tool"
_SELF_RESOLVED.update(
    {
        name + "Tool": entries
        for name, entries in list(_SELF_RESOLVED.items())
        if name.removeprefix(nk.BASE)
        in {"postgres", "mySql", "microsoftSql", "snowflake", "googleBigQuery", "oracleDatabase", "questDb", "timescaleDb", "crateDb", "ldap"}
    }
)
_SELF_RESOLVED_DEPTH = 2


# Form and Form Trigger: the HTML of a formFields entry of type html (resolved the same way when the form is shown)
_FORM_TYPES = frozenset({nk.BASE + "form", nk.FORM_TRIGGER})


def _self_resolved(node: Node, keys: KeyPath) -> bool:
    """A field whose {{ }} n8n resolves with or without the leading = (see _SELF_RESOLVED)."""
    if node.type in _FORM_TYPES:
        if keys.depth != 4 or keys.first != "formFields" or keys.last != "html":
            return False
        _, values, index, _ = keys.keys()
        entries = node.parameters.get("formFields", {}).get("values") if isinstance(node.parameters.get("formFields"), dict) else None
        if values != "values" or not isinstance(entries, list) or not isinstance(index, int) or index >= len(entries):
            return False
        entry = entries[index]
        return isinstance(entry, dict) and entry.get("fieldType") == "html"
    entries = _SELF_RESOLVED.get(node.type)
    if entries is None or keys.depth > _SELF_RESOLVED_DEPTH or keys.first not in {path[0] for _, path in entries}:
        return False
    path = keys.keys()
    if not any(path == fields and node.type_version >= lowest for lowest, fields in entries):
        return False
    return node.type != nk.MERGE or node.parameters.get("mode") == "combineBySql"


# Fields that hold a whole workflow as JSON (parameter type json): Execute Workflow and Tool Workflow with source
# 'Define below', and the n8n node's create/update. The {{ }} and node names inside belong to that workflow, which
# runs on its own; only a value written as an expression (leading =) is resolved in this one.
_EMBEDDED_WORKFLOWS = {
    nk.BASE + "executeWorkflow": "workflowJson",
    "@n8n/n8n-nodes-langchain.toolWorkflow": "workflowJson",
    nk.BASE + "n8n": "workflowObject",
}


_EMBEDDED_DEPTH = 8  # workflows embedded in embedded workflows; deeper text is only scanned as text


def _embedded(node: Node, wf: Workflow) -> tuple[tuple[str, Workflow], ...]:
    """The workflows embedded in ``node``, a node of ``wf`` or of a workflow embedded in it (see _EMBEDDED_WORKFLOWS),
    with the prefix findings show them under; none when the field holds no workflow that can be read."""
    budget: FileBudget = wf.budget
    if not budget.expanded:
        _read_embedded_workflows(budget)
    found: tuple[tuple[str, Workflow], ...] = node.cache.get("embedded", ())
    return found


def _read_embedded_workflows(budget: FileBudget) -> None:
    """Read every embedded workflow of a file, level by level and in document order, against its budget. All at once,
    so that which ones fit does not depend on what asks first (the rule and the masker walk them differently)."""
    budget.expanded = True
    pending = collections.deque((flow, 0) for flow in budget.flows)
    while pending:
        flow, level = pending.popleft()
        for node in flow.nodes:
            found = _read_embedded(node, flow.limits, budget) if level < _EMBEDDED_DEPTH and node.type in _EMBEDDED_WORKFLOWS else ()
            node.cache["embedded"] = found
            pending.extend((sub, level + 1) for _, sub in found)


def _read_embedded(node: Node, limits: Limits, budget: FileBudget) -> tuple[tuple[str, Workflow], ...]:
    """The workflows in one node's field. Text is parsed whole, however long: its size is bounded by the file's, and
    within it each value has the usual limit. What does not fit the budget is scanned as text (``embedded_over``)."""
    key = _EMBEDDED_WORKFLOWS[node.type]
    raw = node.parameters.get(key)
    if not isinstance(raw, (str, dict, list)):
        return ()
    text = raw.removeprefix("=") if isinstance(raw, str) else ""
    if isinstance(raw, str) and (not text.lstrip().startswith(("{", "[")) or text.lstrip().startswith("{{")):
        return ()
    if budget.spent:
        node.cache["embedded_over"] = True
        return ()
    duplicates: list[bool] = []

    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        obj = dict(items)
        if len(obj) != len(items):
            duplicates.append(True)
        return obj

    try:
        data = json.loads(text, object_pairs_hook=pairs) if isinstance(raw, str) else raw
        flows = from_data(data, "<embedded workflow>", limits=limits, budget=budget)
    except (ValueError, RecursionError, WorkflowError):  # LimitError included: the text is scanned as it is
        node.cache["embedded_over"] = budget.spent
        return ()
    node.cache["embedded_duplicates"] = bool(duplicates)  # the earlier values of a key are only in the text
    return tuple((key + (f"[{flow.position - 1}]" if flow.position else ""), flow) for flow in flows)


def _own_parameters(node: Node, flows: tuple[tuple[str, Workflow], ...]) -> dict[str, Any]:
    """``node.parameters`` without a workflow embedded as an object that was read: its values are walked at its own
    level, so that a value nested in many embedded workflows is scanned once (its text form is scanned at each level
    only up to the value limit, and each level holds less of it)."""
    field = _EMBEDDED_WORKFLOWS.get(node.type)
    if flows and field is not None and isinstance(node.parameters.get(field), (dict, list)):
        return {k: v for k, v in node.parameters.items() if k != field}
    return node.parameters


def _beside_parameters(flow: Workflow) -> dict[str, Any]:
    """An embedded workflow's data without its nodes' parameters: its name, node names, pinned data and the like."""
    nodes = [{k: v for k, v in raw.items() if k != "parameters"} if isinstance(raw, dict) else raw for raw in flow.data["nodes"]]
    return {**flow.data, "nodes": nodes}


# Nodes with a language option: the source of the other language is left over from before a switch, never run
_LANGUAGE_NODES = frozenset({nk.CODE, "@n8n/n8n-nodes-langchain.toolCode"})


def active_parameters(node: Node) -> dict[str, Any]:
    """``node.parameters`` as far as they belong to this workflow and run: without an embedded workflow (see
    _EMBEDDED_WORKFLOWS) unless it is an expression, and without the Code source of the language not selected
    (``jsCode`` of a Python Code node, ``pythonCode`` of a JavaScript one). For node references and expressions;
    secrets are looked for everywhere, leftover code included (it is in every export)."""
    params = node.parameters
    drop: set[str] = set()
    key = _EMBEDDED_WORKFLOWS.get(node.type)
    if key is not None and key in params and not (isinstance(params[key], str) and params[key].startswith("=")):
        drop.add(key)
    if node.type in _LANGUAGE_NODES:
        language = params.get("language", "javaScript")
        if language in ("python", "pythonNative"):
            drop.add("jsCode")
        elif language == "javaScript":
            drop.add("pythonCode")
    if not drop & params.keys():
        return params
    return {k: v for k, v in params.items() if k not in drop}


_PROMPT_FIELDS = frozenset({"prompt", "text", "message", "systemMessage", "content"})
_LONG_PROMPT = 1000


@rule(
    "N8D212",
    "expression-without-prefix",
    Severity.WARNING,
    "A parameter holds an n8n expression ({{ $json... }}) but does not start with =, so n8n sends the text literally, braces included.",
    'Start the value with = in the workflow JSON ("={{ $json.email }}"), or switch the field to Expression in the editor.',
    fixable=True,
)
def _expression_without_prefix(ctx: Context, meta: Rule) -> Iterator[Finding]:
    for node in _active_nodes(ctx.wf):
        if node.type in (nk.CODE, nk.FUNCTION, nk.FUNCTION_ITEM):
            continue
        for keys, value in iter_leaves(active_parameters(node)):
            if code_language(node.type, keys) is not None:  # code: n8n runs it, {{ }} in it is text
                continue
            if not value.startswith("=") and _has_n8n_expression(value) and not _self_resolved(node, keys):
                field = keys.keys()[-1]
                if isinstance(field, str) and field.startswith("cachedResult"):  # what the editor shows for a picked item; never evaluated
                    continue
                path = keys.text()
                other = next((value[start - 2 : end + 2] for start, end in expression_spans(value) if not _DOLLAR_NAME.search(value, start, end)), None)
                if other is None and field in _PROMPT_FIELDS and len(value) >= _LONG_PROMPT:
                    # free text: {{ }} in it can be examples for the model, and the = would evaluate them
                    hint = "Fix it by hand: a leading = makes n8n evaluate every {{ }} in the text, the examples in a prompt too."
                    finding = _f(meta, f"{path} contains {{{{ $... }}}} without the leading =", node, path, hint)
                    finding.autofix = False
                elif other is None:
                    finding = _f(meta, f"{path} contains {{{{ $... }}}} without the leading =", node, path)
                    finding.extra["keys"] = keys  # where fix adds the =
                else:  # the = would make n8n evaluate {{name}} too, which fails or changes the text: for a person to decide
                    what = f"{path} contains {{{{ $... }}}} without the leading =, next to {_shown(other, ctx.wf)}, which has no $"
                    finding = _f(
                        meta, what, node, path, "Fix it by hand: a leading = makes n8n evaluate every {{ }} in the value, a template for another engine too."
                    )
                    finding.autofix = False
                yield finding


@rule(
    "N8D213",
    "invalid-node-entry",
    Severity.ERROR,
    "An entry of the workflow's nodes array is not a node object (null, a string, a number, an array or an empty object), so n8n cannot "
    "import the workflow, or a node's typeVersion is a number no version can be (NaN, infinite, 400 digits).",
    "Remove the entry from the nodes array, or set the node's typeVersion back to its version (1, 2, 4.2, ...); a bad "
    "merge or a script that edited the JSON usually did this.",
)
def _invalid_node_entry(ctx: Context, meta: Rule) -> Iterator[Finding]:
    for position, kind, line in ctx.wf.invalid_entries:
        finding = _f(meta, f"nodes[{position}] is {kind}, not a node object", parameter=f"nodes[{position}]")
        finding.line = line
        yield finding
    for index, why in ctx.wf.bad_versions:
        yield _f(meta, f"typeVersion is {why}, not a version number (checked as version 1)", ctx.wf.node_at.get(index))


@rule(
    "N8D214",
    "invalid-time-value",
    Severity.WARNING,
    "A Schedule, Cron, Interval or Wait node has a time value n8n cannot use: zero, negative, infinite, not a "
    "number, or a cron step that is not a whole number.",
    "Enter a positive whole number (or a valid cron step such as */5) in the node.",
)
def _invalid_time_value(ctx: Context, meta: Rule) -> Iterator[Finding]:
    for node in _active_nodes(ctx.wf):
        if node.type in (nk.SCHEDULE, nk.CRON, nk.INTERVAL, nk.WAIT):
            for path, why in nk.invalid_time_values(node):
                yield _f(meta, why, node, path)


# ============================================================================================
# Reliability
# ============================================================================================

_NON_PRODUCTION_TRIGGERS = {nk.MANUAL_TRIGGER, nk.ERROR_TRIGGER, nk.EXECUTE_WORKFLOW_TRIGGER, nk.BASE + "start"}


@rule(
    "N8D301",
    "no-error-workflow",
    Severity.WARNING,
    "The workflow runs on its own (schedule, webhook, app trigger) but has no error workflow, so failures go unnoticed.",
    "Create a workflow that starts with an Error Trigger and alerts you (Slack, email), then pick it in this workflow's Settings > Error workflow.",
)
def _no_error_workflow(ctx: Context, meta: Rule) -> Iterator[Finding]:
    wf = ctx.wf
    if wf.settings.get("errorWorkflow"):
        return
    auto = [t for t in wf.triggers if t.type not in _NON_PRODUCTION_TRIGGERS and not t.disabled]
    if not auto or any(n.type == nk.ERROR_TRIGGER for n in wf.nodes):
        return
    sev = None if wf.active else Severity.INFO
    yield _f(meta, f"started by {auto[0].name!r} but no error workflow is set" + ("" if wf.active else " (workflow is inactive)"), severity=sev)


def is_idempotent(node: Node) -> bool:
    return nk.http_method(node) in ("GET", "HEAD", "OPTIONS", "PUT", "DELETE")


@rule(
    "N8D302",
    "http-without-timeout",
    Severity.INFO,
    "An HTTP Request has no timeout of its own, so a server that stops answering holds the execution for n8n's default of 5 minutes per request (per retry).",
    "Set Options > Timeout on the node to what the API needs (for example 30000 ms), and a workflow timeout in Settings. "
    "n8n-doctor fix only sets it when asked, with --set-timeout MS: a long POST to an LLM or media host can need the 5 minutes.",
)
def _http_timeout(ctx: Context, meta: Rule) -> Iterator[Finding]:
    for node in _active_nodes(ctx.wf):
        if node.type == nk.HTTP and nk.p(node, "options", "timeout") in (None, "", 0):
            yield _f(meta, f"{_shown(nk.http_method(node), ctx.wf)} request uses the default 5-minute timeout", node, "options.timeout")


@rule(
    "N8D303",
    "http-without-retry",
    Severity.INFO,
    "An HTTP Request fails the execution on the first network error, 429 or 5xx.",
    "Turn on Settings > Retry On Fail (for example 3 tries, 1000 ms apart). Only safe for requests that can be repeated; "
    "n8n-doctor fix only adds it to GET, HEAD, OPTIONS, PUT and DELETE.",
    fixable=True,
)
def _http_retry(ctx: Context, meta: Rule) -> Iterator[Finding]:
    for node in _active_nodes(ctx.wf):
        if node.type != nk.HTTP or node.raw.get("retryOnFail") is True:
            continue
        if node.raw.get("onError") in ("continueRegularOutput", "continueErrorOutput") or node.raw.get("continueOnFail") is True:
            continue  # failures are handled in the flow
        note = "" if is_idempotent(node) else " (POST/PATCH: make sure a retry cannot create duplicates)"
        finding = _f(meta, f"{_shown(nk.http_method(node), ctx.wf)} request does not retry on failure{note}", node, "retryOnFail")
        finding.autofix = is_idempotent(node) and node.raw.get("retryOnFail") is None  # retryOnFail: false is the user's choice
        yield finding


@rule(
    "N8D304",
    "loop-not-closed",
    Severity.ERROR,
    "A 'Loop Over Items' (Split in Batches) node's loop branch does not lead back to it, so only the first batch is "
    "processed and the 'done' branch never runs.",
    "Connect the last node of the loop branch back to the Loop Over Items node's input.",
)
def _loop_not_closed(ctx: Context, meta: Rule) -> Iterator[Finding]:
    wf = ctx.wf
    comp_of: dict[int, int] | None = None
    # by name (nodes that share a name share its connections): whether output 0 / 1 has a connection, and the
    # components of the existing nodes it leads to
    branches: dict[str, tuple[bool, set[int], bool, set[int]]] = {}
    for node in _active_nodes(wf):
        if node.type != nk.SPLIT_IN_BATCHES or node.type_version < 3:
            continue
        if comp_of is None:
            comp_of = {v: i for i, comp in enumerate(_sccs(_main_graph(wf))) for v in comp}
        if node.name not in branches:
            edges = wf.outgoing(node.name)
            done, loop = [e.target for e in edges if e.output == 0], [e.target for e in edges if e.output == 1]
            branches[node.name] = (
                bool(done),
                {comp_of[wf.by_name[t].index] for t in done if t in wf.by_name},
                bool(loop),
                {comp_of[wf.by_name[t].index] for t in loop if t in wf.by_name},
            )
        done_targets, done_comps, loop_targets, loop_comps = branches[node.name]
        # the node connects to each target, so a target leads back to the node exactly when both are in one component
        own = comp_of[node.index]
        if own in loop_comps:
            continue
        if own in done_comps:
            branch = "does not" if loop_targets else "is not connected"
            yield _f(
                meta,
                f"the outputs look swapped: the 'done' branch (output 0) loops back and the 'loop' branch (output 1) {branch}",
                node,
                fix="Output 0 is 'done' (runs once, after the last batch); output 1 is 'loop' (runs per batch). Swap the two connections.",
            )
        elif not loop_targets:
            if done_targets:
                yield _f(meta, "the 'loop' output is not connected, so 'done' never runs", node)
        else:
            yield _f(meta, "nothing on the 'loop' branch connects back to this node", node)


def _cycles(wf: Workflow) -> list[list[Node]]:
    """Strongly connected components with a cycle, over main connections between existing nodes (not sticky notes)."""
    graph = _main_graph(wf, wf.real_nodes)
    comps = [comp for comp in _sccs(graph) if len(comp) > 1 or comp[0] in graph[comp[0]]]
    return [sorted((wf.node_at[i] for i in comp if i >= 0), key=lambda n: (n.name, n.index)) for comp in comps]


# Nodes that can produce no items (or stop the run), which ends a loop through them.
_EXITS = nk.CONDITIONAL | {
    nk.CODE,
    nk.FUNCTION,
    nk.FUNCTION_ITEM,
    nk.BASE + "stopAndError",
    nk.BASE + "splitOut",
    nk.BASE + "itemLists",
    nk.BASE + "aggregate",
    nk.BASE + "compareDatasets",
    nk.BASE + "summarize",
}


@rule(
    "N8D305",
    "unbounded-cycle",
    Severity.WARNING,
    "Nodes are connected in a cycle with no IF, Switch, Filter, Loop Over Items or Code node in it, so nothing can stop the loop.",
    "Add an IF (or Loop Over Items) that ends the loop, for example when there is no next page.",
)
def _unbounded_cycle(ctx: Context, meta: Rule) -> Iterator[Finding]:
    wf = ctx.wf
    for members in _cycles(wf):
        if any(n.type in _EXITS or not n.type.startswith(nk.BASE) for n in members):
            continue
        if any(n.raw.get("onError") == "continueErrorOutput" for n in members):
            continue
        names = " -> ".join(f'"{n.name}"' for n in members[:_LISTED]) + (f" -> ... ({len(members):,} nodes)" if len(members) > _LISTED else "")
        yield _f(meta, f"loop through {names} has no exit condition", members[0])


@rule(
    "N8D306",
    "schedule-overlap",
    Severity.WARNING,
    "A schedule fires more often than one run can finish. n8n starts the next run anyway, so runs overlap and can process the same data twice.",
    "Run less often, or make the workflow skip when a previous run is still going (for example a lock in a data store, or a short Wait plus a check).",
)
def _schedule_overlap(ctx: Context, meta: Rule) -> Iterator[Finding]:
    wf = ctx.wf
    waits: dict[int, list[Any]] | None = None
    longest_after: dict[int, list[Any]] = {}
    node_at = {n.index: n for n in wf.nodes}
    for trig in _active_nodes(wf):
        if trig.type not in (nk.SCHEDULE, nk.CRON, nk.INTERVAL):
            continue
        gap = nk.schedule_interval(trig)
        if not gap:
            continue
        if waits is None:  # once per workflow: the longest Wait after every node
            waits = {n.index: [(-s, n.index)] for n in _active_nodes(wf) if (s := nk.wait_seconds(n))}
            longest_after = _reach_smallest(_main_graph(wf), waits, 1) if waits else {}
        # the trigger itself is never a Wait node, so this is the longest Wait downstream of it (and so reachable)
        best = longest_after.get(trig.index)
        longest = (node_at[best[0][1]], -best[0][0]) if best else None
        if longest and longest[1] >= gap:
            yield _f(
                meta,
                f'runs every {nk.human_seconds(gap)} but "{longest[0].name}" alone waits {nk.human_seconds(longest[1])}, so runs always overlap',
                trig,
                "rule",
            )
        elif gap < 60:
            yield _f(meta, f"runs every {nk.human_seconds(gap)}; any slow run overlaps the next one", trig, "rule", severity=Severity.INFO)


@rule(
    "N8D307",
    "wait-without-limit",
    Severity.INFO,
    "A Wait node waits for a webhook call or form submission with no time limit; if it never comes, the execution waits forever.",
    "Turn on 'Limit Wait Time' on the Wait node and handle the timeout.",
)
def _wait_without_limit(ctx: Context, meta: Rule) -> Iterator[Finding]:
    for node in _active_nodes(ctx.wf):
        limited = nk.p(node, "limitWaitTime") is True or nk.p(node, "options", "limitWaitTime") is True
        if node.type == nk.WAIT and nk.p(node, "resume") in ("webhook", "form") and not limited:
            yield _f(meta, f"waits for a {nk.p(node, 'resume')} without a time limit", node, "limitWaitTime")


@rule(
    "N8D308",
    "unhandled-error-output",
    Severity.WARNING,
    "A node sends failures to its error output, but nothing is connected to it, so errors disappear silently.",
    "Connect the error output (log, alert, retry), or set On Error back to 'Stop Workflow'.",
)
def _error_output(ctx: Context, meta: Rule) -> Iterator[Finding]:
    wf = ctx.wf
    for node in _active_nodes(wf):
        if nk.on_error_output(node) and not nk.is_dynamic_outputs(node):
            err_index = nk.output_count(node) - 1
            if err_index not in wf.connected_outputs(node.name):
                yield _f(meta, "On Error is 'Continue (using error output)' but the error output is not connected", node, "onError")


@rule(
    "N8D309",
    "execute-workflow-without-target",
    Severity.ERROR,
    "An Execute Workflow node (or an AI agent's Call Workflow tool) does not say which workflow to run.",
    "Pick the sub-workflow in the node (From list or By ID).",
)
def _execute_workflow(ctx: Context, meta: Rule) -> Iterator[Finding]:
    for node in _active_nodes(ctx.wf):
        if node.type not in (nk.EXECUTE_WORKFLOW, TOOL_WORKFLOW):
            continue
        source = nk.p(node, "source", default="database")
        if source == "database":
            wid = nk.p(node, "workflowId")
            value = wid.get("value") if isinstance(wid, dict) else wid
            if value in (None, "") or (isinstance(value, str) and not value.strip()):
                yield _f(meta, "no workflow selected", node, "workflowId")
        elif source == "parameter" and not str(nk.p(node, "workflowJson", default="")).strip():
            yield _f(meta, "source is 'Define below' but the workflow JSON is empty", node, "workflowJson")
        elif source in ("localFile", "url") and not str(nk.p(node, "workflowPath" if source == "localFile" else "workflowUrl", default="")).strip():
            yield _f(meta, f"source is {source} but no location is given", node)


@rule(
    "N8D310",
    "failed-executions-not-saved",
    Severity.INFO,
    "The workflow is set not to save failed executions, so there is nothing to debug when it fails.",
    "In Settings, set 'Save failed production executions' to Save (n8n-doctor fix removes the override).",
    fixable=True,
)
def _error_executions(ctx: Context, meta: Rule) -> Iterator[Finding]:
    if ctx.wf.settings.get("saveDataErrorExecution") == "none":
        yield _f(meta, "settings.saveDataErrorExecution is 'none'", parameter="settings.saveDataErrorExecution")


# ============================================================================================
# Code
# ============================================================================================


@rule(
    "N8D401",
    "deprecated-function-node",
    Severity.WARNING,
    "Function and Function Item nodes are deprecated and hidden from the node panel in current n8n.",
    "Replace the node with a Code node (Run Once for All Items for Function, Run Once for Each Item for Function Item).",
)
def _deprecated_function(ctx: Context, meta: Rule) -> Iterator[Finding]:
    for node in ctx.wf.real_nodes:
        if node.type in (nk.FUNCTION, nk.FUNCTION_ITEM):
            yield _f(meta, f"uses the deprecated {node.short_type} node", node)


_LEGACY = [
    (re.compile(r"\$node\s*\[|\$node\.[A-Za-z_]"), "$node[...]", "$('Node name')"),
    (re.compile(r"\$items\s*\("), "$items(...)", "$('Node name').all()"),
    (re.compile(r"\$item\s*\(\s*\d"), "$item(n)", "$('Node name').itemMatching(n)"),
]
_BARE_ITEMS = re.compile(r"(?<![\w$.])items(?![\w$]|\s*:(?!:))")  # not obj.items, not an object key


_DECL_STMT = re.compile(r"\b(?:const|let|var)\b([^;\n]{0,2000})")
_PARAMS = re.compile(r"\(([^()]{0,2000})\)\s*=>|\bfunction\b[^(]{0,200}\(([^()]{0,2000})\)|\bcatch\s*\(([^()]{0,200})\)")
# `items` as a declared name: first, after a comma or inside destructuring, and followed by =, a comma, a bracket or the end
_DECLARED_NAME = re.compile(r"(?:^|[,{\[:])\s*(?:\.\.\.)?items\s*(?:=(?!=)|,|\}|\]|$)")
_ITEMS_WORD = re.compile(r"(?<![\w$.])items(?![\w$])")


def _declares_items(code: str) -> bool:
    """True when the code declares its own ``items`` (variable, destructuring or parameter)."""
    if re.search(r"(?<![\w$.])items\s*=>", code):
        return True
    for m in _DECL_STMT.finditer(code):
        declarators = re.split(r"\b(?:of|in)\b", m.group(1), maxsplit=1)[0]  # `for (const x of items)` reads items
        if _DECLARED_NAME.search(declarators):
            return True
    return any(_ITEMS_WORD.search(next(g for g in m.groups() if g is not None)) for m in _PARAMS.finditer(code))


def _uses_items(code: str) -> bool:
    """True when ``items`` is read as a variable (not declared, not a shorthand property like ``{ items }``)."""
    if "items" not in code:  # the usual case, decided without the declaration scan
        return False
    for m in _BARE_ITEMS.finditer(code):
        i = m.start() - 1
        while i >= 0 and code[i] in " \t\r\n":
            i -= 1
        j = m.end()
        while j < len(code) and code[j] in " \t\r\n":
            j += 1
        before = code[i] if i >= 0 else ""
        after = code[j] if j < len(code) else ""
        if before in ("{", ",") and after in ("}", ","):
            continue  # { items } or { a, items }: a property name or destructuring
        return not _declares_items(code)
    return False


def _raw_js(node: Node, limit: int) -> str | None:
    """The analysed part of a JavaScript Code node's source (see :func:`expressions.code_part`), None for other nodes."""
    if node.type != nk.CODE:
        return None
    if nk.p(node, "language", default="javaScript") not in ("javaScript", None):
        return None
    code = nk.p(node, "jsCode")
    return code_part(code, limit) if isinstance(code, str) else None


def _js(node: Node, limit: int) -> str | None:
    """:func:`_raw_js` with comments removed and string contents blanked."""
    code = _raw_js(node, limit)
    return strip_js_comments(code, blank_strings=True) if code is not None else None


@rule(
    "N8D402",
    "legacy-code-syntax",
    Severity.INFO,
    "A Code node uses syntax from the old Function node ($node[...], $items(), items) that is kept only for compatibility.",
    "Use $input.all() / $input.item for this node's input and $('Node name') to read other nodes.",
)
def _legacy_code(ctx: Context, meta: Rule) -> Iterator[Finding]:
    limit = ctx.wf.limits.max_code_chars
    for node in _active_nodes(ctx.wf):
        code = _js(node, limit)
        raw = _raw_js(node, limit)
        if code is None or raw is None:
            continue
        # $node["X"] needs the string, so search the comment-stripped source with strings intact
        stripped = strip_js_comments(raw)
        used = [(old, new) for pattern, old, new in _LEGACY if pattern.search(stripped)]
        all_items = nk.p(node, "mode", default="runOnceForAllItems") != "runOnceForEachItem"
        if all_items and _uses_items(code):
            used.append(("items", "$input.all()"))
        if used:
            yield _f(
                meta,
                "uses " + ", ".join(old for old, _ in used),
                node,
                "jsCode",
                "Replace " + "; ".join(f"{old} with {new}" for old, new in used) + ".",
            )


# The same test n8n applies to the raw source (comments and strings included) before running the node.
_ALL_ONLY = re.compile(r"\$input\.(?:first|last|all|itemMatching)")


@rule(
    "N8D403",
    "code-mode-mismatch",
    Severity.ERROR,
    "A Code node set to 'Run Once for Each Item' uses $input.all(), first(), last(), itemMatching() or the `items` "
    "variable, which only exist in 'Run Once for All Items' and make the node fail.",
    "Switch the node's Mode to 'Run Once for All Items', or use $input.item for the current item.",
)
def _code_mode(ctx: Context, meta: Rule) -> Iterator[Finding]:
    limit = ctx.wf.limits.max_code_chars
    for node in _active_nodes(ctx.wf):
        if nk.p(node, "mode", default="runOnceForAllItems") != "runOnceForEachItem":
            continue
        code = _js(node, limit)
        raw = _raw_js(node, limit)
        if code is None or raw is None:
            continue
        used = []
        # n8n skips lines that start a comment (//, /*, *) and checks the rest of the raw source
        checked = "\n".join(line for line in raw.split("\n") if not line.lstrip().startswith(("//", "/*", "*")))
        m = _ALL_ONLY.search(checked)
        if m:
            used.append(m.group(0) + "()")
        if _uses_items(code):
            used.append("items")
        if used:
            yield _f(meta, f"uses {' and '.join(used)} but runs once for each item", node, "jsCode")


def by_id() -> dict[str, RegisteredRule]:
    return {r.id: r for r in RULES}
