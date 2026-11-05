"""Running the rules over workflows: file collection, config and suppressions."""

from __future__ import annotations

import re
import sys
from collections import Counter
from collections.abc import Callable, Iterable, Sequence
from pathlib import Path

from .config import Config
from .limits import DEFAULT
from .model import Finding, Rule, Severity, plural
from .rules import NODE_FIXES, RULES, Context, redact, resolve, secret_masker, share_fuzzy_budget
from .workflow import Workflow, WorkflowError, is_workflow, iter_json_files, load_file

# Copies written by `n8n-doctor fix --write`; skipped inside folders (they repeat their originals), linted when named.
FIXED_SUFFIX = ".fixed.json"

# In a node's notes: suppress for that node. In a sticky note: suppress for the whole workflow.
_SUPPRESS = re.compile(r"n8n-doctor-disable(?![\w-])[ \t]*:?([^\n]*)", re.IGNORECASE)


EXCLUDED = ": matches `exclude` in the config, so it was not checked"  # how a file named explicitly is listed as skipped


def collect(targets: Iterable[Path], cfg: Config | None = None, max_files: int | None = None) -> tuple[list[Workflow], list[str], list[str]]:
    """Load workflows from files and folders.

    Returns (workflows, skipped, errors), messages masked. A file named explicitly that cannot be
    read is an error; inside a folder, JSON files that are not workflows (``package.json`` ...) are
    skipped and listed, and a broken workflow file (or one over a limit) is an error. An error does
    not stop the other files from loading.
    """
    flows: list[Workflow] = []
    skipped: list[str] = []
    errors: list[str] = []
    limits = cfg.limits if cfg else DEFAULT
    for target in targets:
        if not target.exists():
            errors.append(redact(f"{target}: no such file or folder"))
            continue
        if target.is_dir():
            for count, path in enumerate(iter_json_files(target)):
                if max_files is not None and count >= max_files:
                    errors.append(f"{target}: more than {max_files} JSON files; check a smaller folder")
                    break
                if path.name.endswith(FIXED_SUFFIX) or (cfg and cfg.is_excluded(path)):
                    continue
                try:
                    flows.extend(load_file(path, limits, recover=True))
                except WorkflowError as exc:
                    # a workflow file broken by a bad merge (or over a limit) must fail the run, not vanish from it
                    (errors if exc.broken_workflow else skipped).append(redact(str(exc)))
            continue
        if cfg and cfg.is_excluded(target):
            skipped.append(redact(f"{target}{EXCLUDED}"))
            continue
        try:
            flows.extend(load_file(target, limits, recover=True))
        except WorkflowError as exc:
            errors.append(redact(str(exc)))
    return flows, skipped, errors


def _suppressed_ids(text: str) -> set[str] | None:
    """Rule ids named by suppression comments in ``text``.

    An empty set means "all rules" (the marker alone on its line); None means nothing is
    suppressed. Names that are not rules are ignored, and a marker followed only by
    unknown words (a typo, or prose that mentions the marker) suppresses nothing.
    """
    found: set[str] | None = None
    for m in _SUPPRESS.finditer(text):
        refs = [r for r in re.split(r"[\s,;]+", m.group(1).strip()) if r]
        if not refs:
            return set()
        ids: set[str] = set()
        for ref in refs:
            try:
                ids.add(resolve(ref).id)
            except KeyError:
                continue
        if ids:
            found = (found or set()) | ids
    return found


# A bare `n8n-doctor-disable` does not silence these: they must be named, so a shared workflow
# cannot hide a leaked secret or an open webhook with one generic note.
EXPLICIT_ONLY = {"N8D101", "N8D102"}


def _matches(ids: set[str] | None, rule_id: str) -> bool:
    if ids is None:
        return False
    return rule_id in ids if ids or rule_id in EXPLICIT_ONLY else True


def _omitted(meta: Rule, over: Counter[str], message: str, label: str | None, fixable: int = 0) -> Finding:
    """One finding that stands for ``over`` findings past a limit: ``message`` follows their count.

    It carries their count by severity (``extra["omitted"]``) and how many of them ``fix`` can fix
    (``extra["omitted_fixable"]``), which reports add to their totals, and is listed after the findings
    of its workflow (``extra["summary"]``).
    """
    n = sum(over.values())
    top = max((s for s in Severity if over[s.label]), default=meta.severity)
    what = plural(n, "more suppressed finding" if label else "more finding")
    finding = Finding(rule=meta, severity=top, message=f"{what} {message}", autofix=False, suppressed=label)
    finding.extra["omitted"] = dict(over)
    finding.extra["omitted_fixable"] = fixable
    finding.extra["summary"] = True
    return finding


def run(
    flows: Sequence[Workflow],
    cfg: Config | None = None,
    suppressed: list[Finding] | None = None,
    inline_suppressions: bool = True,
    capped: bool = True,
    min_severity: Severity | None = None,
    shown: bool = True,
    only: set[str] | None = None,
) -> list[Finding]:
    """Run every enabled rule. Findings silenced by node or sticky notes go to ``suppressed`` (if given).

    Findings below ``min_severity`` are dropped first, so the limits and counts below apply to the rest.
    At most ``max_findings_per_rule`` findings of a rule are listed per workflow (and as many suppressed
    ones), and at most ``max_findings`` of all rules together; the rest are counted in summary findings,
    listed after the others. Listed findings are masked (:func:`rules.secret_masker`). ``fix`` passes
    ``capped=False`` (it fixes them all), ``shown=False`` (it shows none of them: they are neither masked nor
    keep their texts) and ``only`` (the rules it can fix).
    """
    cfg = cfg or Config()
    share_fuzzy_budget(flows)  # typo suggestions (N8D207) have one budget for the whole run
    meta_rule = resolve("N8D001")
    findings: list[Finding] = []
    # per run: past ``run_cap`` listed (and as many suppressed) findings, the rest of every workflow is only counted
    run_cap = min((wf.limits.max_findings_total for wf in flows), default=0) if capped else sys.maxsize
    run_over = {False: _RunOver(), True: _RunOver()}  # by whether the findings are suppressed
    run_listed = {False: 0, True: 0}
    for wf in flows:
        ctx = Context(wf, cfg.options)
        # names and messages can repeat a secret found by its context (a header value); built when something is shown
        mask = _lazy_masker(wf) if shown else None
        cap = wf.limits.max_findings_per_rule if capped else sys.maxsize
        total_cap = wf.limits.max_findings if capped else sys.maxsize
        listed_total = 0
        over_total: Counter[str] = Counter()
        over_total_fixable = 0
        names = Counter(n.name for n in wf.nodes)
        shared = {name for name, count in names.items() if count > 1}
        workflow_suppress: set[str] | None = None
        node_suppress: dict[int, set[str] | None] = {}
        if inline_suppressions:
            for sticky in (n for n in wf.nodes if n.is_sticky):
                ids = _suppressed_ids(str(sticky.parameters.get("content", "")))
                if ids is not None:
                    workflow_suppress = set() if not ids or workflow_suppress == set() else (workflow_suppress or set()) | ids
            node_suppress = {n.index: _suppressed_ids(n.notes) for n in wf.nodes if n.notes}
        may_suppress = workflow_suppress is not None or any(ids is not None for ids in node_suppress.values())
        out: list[Finding] = []
        out_silenced: list[Finding] = []
        for rule in RULES:
            if not cfg.is_enabled(rule.id) or (only is not None and rule.id not in only):
                continue
            listed: list[Finding] = []
            silenced: list[Finding] = []
            over: Counter[str] = Counter()
            over_silenced: Counter[str] = Counter()
            over_fixable = 0
            ctx.counting = capped and not may_suppress and run_listed[False] >= run_cap
            for finding in rule.check(ctx):
                finding.severity = cfg.severity.get(rule.id, finding.severity)
                if min_severity is not None and finding.severity < min_severity:
                    continue
                if _matches(workflow_suppress, rule.id):
                    finding.suppressed = "sticky note"
                elif finding.node_index is not None and _matches(node_suppress.get(finding.node_index), rule.id):
                    finding.suppressed = "node notes"
                into, extra = (silenced, over_silenced) if finding.suppressed else (listed, over)
                node = wf.node_at.get(finding.node_index) if finding.node_index is not None else None
                if node is not None and node.name in shared and rule.id in NODE_FIXES:
                    finding.autofix = False  # fix addresses nodes by name: it leaves nodes that share one alone
                quiet = bool(finding.suppressed)
                n = finding.extra.get("count", 1)  # several findings at once, yielded only while ctx.counting
                if run_listed[quiet] >= run_cap:  # the run's budget is spent: counted for the run only
                    run_over[quiet].add(finding, n)
                    continue
                if len(into) >= cap:  # counted, not masked or kept
                    extra[finding.severity.label] += n
                    over_fixable += n * (finding.fixable and not finding.suppressed)
                    continue
                if not finding.suppressed and listed_total >= total_cap:
                    over_total[finding.severity.label] += n
                    over_total_fixable += n * finding.fixable
                    continue
                if node is not None:
                    finding.line = node.line
                    finding.node_type = mask(node.type) if mask else node.type
                if not shown:
                    finding.message, finding.parameter, finding.fix_hint = "", None, None
                elif mask:  # what the N8D101 patterns match first (shown as "ghp_***"), then every secret of the workflow
                    finding.message = mask(redact(finding.message))
                    for attr in ("node", "parameter", "fix_hint"):
                        value = getattr(finding, attr)
                        if value:
                            setattr(finding, attr, mask(redact(value)))
                into.append(finding)
                listed_total += not finding.suppressed
                run_listed[quiet] += 1
                # what the rule yields next is only counted: past this rule's or the workflow's or the run's limit
                ctx.counting = capped and not may_suppress and (len(listed) >= cap or listed_total >= total_cap or run_listed[False] >= run_cap)
            per_rule = f"of {rule.id} in this workflow not listed (limit: {cap:,} per rule, --max-findings-per-rule)"
            if over:
                listed.append(_omitted(rule.meta, over, per_rule, None, over_fixable))
            if over_silenced:
                silenced.append(_omitted(rule.meta, over_silenced, per_rule, silenced[0].suppressed))
            out.extend(listed)
            out_silenced.extend(silenced)
        if over_total:
            per_workflow = f"in this workflow not listed (limit: {total_cap:,} per workflow, --max-findings)"
            out.append(_omitted(meta_rule, over_total, per_workflow, None, over_total_fixable))
        if out or out_silenced:
            workflow_name = mask(wf.name) if mask else wf.name
            workflow_id = (mask(wf.id) if mask else wf.id) if wf.id else None
        for finding in (*out, *out_silenced):
            finding.source = wf.source
            finding.position = wf.position
            finding.workflow = workflow_name
            finding.workflow_id = workflow_id
        findings.extend(out)
        if suppressed is not None:
            suppressed.extend(out_silenced)
    findings.sort(key=sort_key)
    if run_over[False]:
        findings.append(run_over[False].summary(meta_rule, run_cap, None))
    if suppressed is not None and run_over[True]:
        suppressed.append(run_over[True].summary(meta_rule, run_cap, run_over[True].label))
    return findings


def _lazy_masker(wf: Workflow) -> Callable[[str], str]:
    """:func:`rules.secret_masker` of ``wf``, built on first use: a workflow whose findings are all only counted
    (past the run's limit) never needs it."""
    built: list[Callable[[str], str]] = []

    def mask(text: str) -> str:
        if not built:
            built.append(secret_masker(wf))
        return built[0](text)

    return mask


class _RunOver:
    """Findings past the per-run limit: counted by severity and rule, never masked or kept."""

    def __init__(self) -> None:
        self.by_severity: Counter[str] = Counter()
        self.by_rule: Counter[str] = Counter()
        self.fixable = 0
        self.label: str | None = None

    def __bool__(self) -> bool:
        return bool(self.by_severity)

    def add(self, finding: Finding, n: int = 1) -> None:
        self.by_severity[finding.severity.label] += n
        self.by_rule[finding.rule.id] += n
        self.fixable += n * (finding.fixable and not finding.suppressed)
        self.label = self.label or finding.suppressed

    def summary(self, meta: Rule, cap: int, label: str | None) -> Finding:
        """One finding for the whole run, listed last (``extra["run_summary"]``); it belongs to no workflow."""
        rules = ", ".join(f"{rule_id} {n:,}" for rule_id, n in sorted(self.by_rule.items(), key=lambda kv: (-kv[1], kv[0])))
        message = f"not listed (limit: {cap:,} per run, --max-findings-total); by rule: {rules}"
        finding = _omitted(meta, self.by_severity, message, label, self.fixable)
        finding.extra["run_summary"] = True
        finding.extra["omitted_by_rule"] = dict(sorted(self.by_rule.items()))
        return finding


def sort_key(f: Finding) -> tuple[str, int, bool, int, int, str, str]:
    """Report order: by file and workflow, summaries of findings past a limit last, then by line and severity."""
    return (f.source, f.position, bool(f.extra.get("summary")), f.line, -f.severity, f.rule.id, f.node or "")


def labels(flows: Sequence[Workflow]) -> list[tuple[str, str, int]]:
    return [(wf.source + (f"[{wf.position}]" if wf.position else ""), secret_masker(wf)(wf.name), len(wf.real_nodes)) for wf in flows]


__all__ = ["collect", "is_workflow", "labels", "run"]
