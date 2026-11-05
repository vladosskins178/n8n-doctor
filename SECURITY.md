# Security

`n8n-doctor` reads workflow files and, only when asked (`executions`, `--api`), the n8n
public REST API. Against an instance it makes **GET requests only**, reads the API key from
`N8N_API_KEY`, sends it only to `N8N_API_URL` (redirects are refused), and never prints,
logs or stores it.

What is redacted, and where:

- Finding messages (every format, the MCP `n8n_lint` result): a secret is shown as its
  first four characters and its length (long tokens) or not at all (short values, passwords).
- Names: node names, the workflow name and id, node names in connections (also of missing
  nodes) and in pinned data go through one helper per workflow before any output (lint in
  every format, the MCP tools, `fix` changes, `explain`), which masks what the N8D101 token
  patterns match and every secret found in the workflow's parameters (the same set as the
  `fix` review below), so a header value repeated in a node name is masked there too; names
  in `executions` get the token patterns. N8D101 also reports token-like names, since the
  export still contains them (with the same filters as parameter values, so
  `GET /search?key=customer_id` is not reported).
- The `fix` review (text output, the `changes`, `edits` and `diff` fields of
  `fix --format json`, MCP `n8n_fix` by default) never prints a whole parameter value. It is
  a list of changed values: node, parameter path and only the changed token, such as
  `"$('Prepare emial')" -> "$('Prepare email')"` or `inserted "=" at the start`. In code,
  request and template fields (`jsCode`, `pythonCode`, `body`, `json*` fields such as
  `jsonOutput`, `query`, `sqlQuery`, `html`, `url`, `headers`) and in any field named for a
  secret (or the `value` of an entry named `Authorization`, `X-Api-Key`, ...) a value
  replaced as a whole shows `<value changed, N chars>`; elsewhere so does one longer than 40
  characters or holding a secret, and a shorter one shows old -> new, masked. No field ever
  shows the text around the changed token. Removed pinned data is a count of records. A node with more than 50 changed values
  lists the first 50 and counts the rest.
- Embedded workflows (`workflowJson` of Execute Workflow and Tool Workflow, `workflowObject` of the n8n node, written
  as text or as an object, up to 8 levels inside each other) are read as workflows when looking for secrets: their
  header entries, Code nodes and everything else are reported by N8D101 under the outer node
  (`workflowJson.nodes[1].parameters...`) and masked everywhere the outer workflow's secrets are, `executions`
  messages included. A file's nodes plus workflows, embedded ones included, have one budget (`--max-file-nodes`,
  50,000), spent level by level in document order, so every command reads the same ones. Text that cannot be read as
  a workflow (cut short, a `{{ }}` breaking the JSON, written in `={{ JSON.stringify(...) }}`, over a limit or past
  the budget, which an `info` finding reports) is scanned as text: its patterns, its Code with the quotes unescaped,
  its name/value entries (any indent, other keys between name and value, `\u` escapes in names), Cookie keys, short
  Bearer tokens and sticky note labels, at each level of text in text. Text with a duplicate key, where a parser keeps
  the last value only, is read and also scanned. A duplicate key in the file itself is not: only its last value is
  checked.
- Sticky notes: besides token patterns, a label and a value that ends the line or a list item (`password: hunter2`,
  `**API key:** abc123`) is reported and masked. Prose (`password: see the vault`) and common words (`token: required`)
  are not.
- `explain` (outline, Mermaid, JSON; node summaries and sticky notes) and the `fix` review
  above: every secret that N8D101 can find in the workflow's parameters (values and
  parameter names) is replaced by `***`, all of them and regardless of `allow` lists,
  inline suppressions or comments in Code nodes, in every spelling a JSON string can give
  it, plus anything the N8D101 token patterns match elsewhere (pinned data, sticky notes).
  Private keys (PEM, including encrypted and truncated ones, SSH2 and PuTTY) are masked
  from their header to their END line, also when the key is split over several string
  literals in a Code node (`"-----BEGIN ..." + "MIIE..."`, `[...].join("\n")`), or to the
  end of the value when there is no END line; long base64 runs after such a header are
  masked on their own as well. A secret shorter than 8 characters or with little variety
  (`Pa55`, `hunter22`) is masked where it is a whole word, so `Pa55word` in other text is
  left alone; any other secret is masked wherever it occurs.
- `executions` error messages: the same patterns, sensitive JSON fields (also escaped
  inside another JSON string, with `\u`-escaped keys, or as a Python repr; string, list
  and bare values), form fields (also URL-encoded), `password: value` and
  `password = "value"` pairs, `Authorization` values after any scheme word (`ApiKey`,
  `SSWS`, `Digest ...` to the end of the line; an unknown first word is masked with the
  rest), `Cookie` and `Set-Cookie` values, `Bearer`/`Token`/`Basic` values (also
  URL-encoded), API key headers, XML elements named like credentials
  (`<password>...</password>`), a generated-looking token after a credential word
  (`key <token> is not valid`, and the word after a masked value: `password=abc <token>`),
  URL credentials and query strings are removed before the message is shortened. Besides
  N8D101's names, fields such as `api-token`, `PRIVATE-TOKEN`, `session_token`, `id_token`,
  `secret_access_key` and `access_key_id` count as sensitive. Each message is also masked
  with every secret of its own workflow (the copy the execution carries, or the workflow
  fetched from the API). When that workflow cannot be read, or the run has already read
  `--max-masker-mb` of workflow JSON, the message is not shown at all (fail closed), and
  the workflow and node names are replaced by the workflow id and the node's position and
  type; only `--pattern-masking-only` (less safe) shows them masked by the patterns alone.
  The error class is shown only when it is a class name (`NodeApiError`, `TypeError`);
  any other name shows as `Error`.

Not redacted: the fixed workflow itself (`fix --write`, the `fixed` workflow text, the
JSON Patch, MCP `n8n_fix` with `output: "patch"` or `"workflow"`) is a copy of your file
and keeps its contents, secrets included. That includes the `patch` field that
`fix --format json --include-patch` adds (the raw RFC 6902 JSON Patch), so that output as a
whole is **not** safe to paste into logs or issues; without `--include-patch` the output has
only the `changes`, `edits` and `diff` fields, which are. Detection is pattern- and name-based, so a secret it does not
recognise is not masked either.

The MCP server reads files only below its working directory, or the folders listed in
`N8N_DOCTOR_MCP_ROOTS` (config files above those folders are ignored too), and at most
5000 JSON files per call. It reads request lines of up to 41 MB (a 20 MB inline workflow
escaped inside the request); a longer line is refused with an error and skipped without being
held in memory. Requests to an n8n instance
have a 30 s socket timeout, a 120 s total deadline per response, a 100 MB size limit and a
bounded number of pages.

It writes files only where you ask: `lint --output`, `fix --write` (a new file, never the
input; `--force` is needed to replace an existing output; nothing directly in `/dev`) and `skill install`.

Workflow content is treated as untrusted input: control characters are removed from
terminal output, lines that would start a GitHub Actions workflow command are prefixed
with `>`, lone surrogates (from `\ud800` escapes or file names that are not UTF-8) are
escaped in JSON and SARIF and replaced in text, symlinked folders are skipped, inputs over
the resource limits below are refused, output files are written by atomic rename (never
through a symlink, and never over a device, fifo, socket or folder), and nothing in a workflow is executed.
Output files never widen permissions: a file that is replaced keeps its mode, and `fix --write`
gives a new file the mode of its source, so the copy of a `0600` workflow stays `0600`
(a report, whose secrets are masked, gets the usual mode less the umask). `lint -o` never
replaces what the run reads (a file it was given, the file stdin reads, the config file, any
JSON file of a folder it scans unless that is an earlier report); any other existing file
only if it is an earlier report of `n8n-doctor` (JSON or SARIF that parses as one, text or GitHub by its first line), or with `--force`. Values that rules read as
numbers (intervals, cron steps, Wait amounts, output counts) are accepted only as plain
ASCII digits of bounded length or finite JSON numbers; anything else is reported (N8D214)
or ignored, never converted. Inline suppressions cannot hide N8D101/N8D102 without naming
them, are always counted in reports, and can be ignored with `--no-inline-suppress`.

A config file is trusted input: it can disable rules and add `allow` regexes. Those regexes
are capped at 200 characters and only tried on values up to 1,024 characters, but Python's
regex engine can still backtrack badly on a hostile pattern, so do not read config files
from untrusted pull requests: use `--no-config` (the action's `config: none`), or a config
from the base branch.

## Resource limits

Every file is checked once, when it is loaded, against limits on its size and shape (the
defaults below; each can be changed with a `--max-*` flag or the config file's `[limits]`,
see the README). An input over a hard limit is refused with exit code 2, also inside a
folder:

- 20 MB per file, stdin or MCP `workflow` argument; no setting goes above 64 MB;
- 1,000 workflows per file, JSON nested at most 64 levels deep;
- per workflow: 5,000 nodes; 50,000 connections and 50,000 connection output lists;
  1,000 outputs per node (output lists, Switch rules) and 1,000 connections per output;
  1,024 characters per node or workflow name, node type, workflow id and name in
  connections or pinned data; 200,000 values in node parameters, 10,000 entries per array
  and 1,024 characters per parameter path; 50,000 distinct secrets with a total length of
  2 MB.

Soft limits check part of a value and say so: a value or name longer than 256 KB is checked
for secrets at its first and last 128 KB (an `info` finding says so, `explain` replaces the
whole value with a placeholder and the `fix` review shows only the changed token of it,
since a secret in the unchecked middle could not be masked); Code node source is analysed for references, legacy syntax
and the Code mode in its first 1 MB (an N8D001 `info` finding says so). Output limits:
`lint` lists 200 findings per rule and 5,000 per workflow and counts the rest in summary
findings (listed last; totals, the exit code and the fixable count include them;
`--min-severity` applies first), and `explain` text and Mermaid output stop at 50 levels of
indentation and 2 MB. Stdin with text before the JSON (`n8n export:workflow --all` can
print warnings) is parsed at most twice. Real workflows are far below all of these.

Within the limits, the work per file is bounded by its size, with these hard bounds where a
scan would otherwise repeat (all per file of at most 20 MB, default limits):

- a sticky-note label takes the whole run of value characters at once (at most 257) and the
  next search starts after it, each distinct value is judged once, and each note is scanned
  once per run, so repeating a label costs one pass over the text; `explain` masks at most
  4 MB of sticky-note text and names the size of the rest;
- embedded text that does not parse is read as raw text for at most 8 MB in all per file
  (`--max-raw-scan-mb`, counted at every level of escapes, once for findings and once for
  masking), and a text over 64 KB has its JSON escapes taken off at most twice, not eight
  times. What that leaves unread gets an `info` finding (N8D101), and `explain` replaces
  the embedded field of every node in that file with a placeholder, since a secret in the
  unread part could not be masked;
- telling a weak secret that is a whole token from one inside a longer word costs at most
  16 characters compared per character of the text (plus 4 KB). Past that budget every
  match in the text is masked, which can cut a word apart but shows nothing;
- percent-encoded spellings are only looked for in secrets of at most 256 characters, the
  automaton is built only for a text long enough to hold a secret, and only the maskers of
  the last four workflows stay in memory (a dropped one is rebuilt from the secrets already
  read, which are kept per workflow).

Otherwise the work is near-linear in the size of the file:

- the built-in patterns use bounded repetition and are skipped when their fixed prefix is
  absent; scans that a regex would restart inside the same run (URL query strings and
  `Basic` tokens in execution messages, trailing numbers in node names) are single passes;
  `{{ }}` spans and Code node comments, strings and regex literals are found in one pass;
- graph rules (Respond to Webhook paths, loops, schedule overlap, cycles) make one pass over
  the strongly connected components of a graph with one entry per node and per
  connection: nodes that share a name share one list of successors, which is walked once;
  `explain` lists a shared name's connections on its first node;
- parameter paths are built only for the values a finding names; findings past the limits
  are counted, not formatted or masked; typo suggestions (N8D207) compare names of at most
  128 characters, within a budget of characters per workflow;
- secrets are masked by one Aho-Corasick automaton per workflow, linear in the text except
  for the whole-token check bounded above, about twelve bytes per character of the
  secrets: matches start only where the next
  4 characters begin a secret (found with a regular expression, or by looking up every
  fourth 4-gram of the text when the secrets start with many different characters), runs
  of the trie with a single child are compared with `str.startswith`, and short texts
  (names, types, review lines) are masked once each;
- `fix` addresses a value by its keys, replaces a node's parameters with one patch
  operation when it changes many of them, and builds its review in one walk over the
  changed nodes, comparing long values in blocks; `explain` stops indenting past its depth limit, so each
  output line is bounded.

Measured with the CLI (`/usr/bin/time -v`, one core of a shared 8-vCPU VPS, Python 3.12):
the slowest of `lint` (text and SARIF), `explain` (text, JSON and Mermaid) and `fix` on
crafted files at the largest size the default limits accept, and the largest peak memory.

| File | slowest command | peak memory |
| --- | --- | --- |
| 4,899 nodes all named X, 999 outputs of 50 connections each to Y0..Y49 (2.6 MB) | 0.8 s | 106 MB |
| the same as Webhook, Schedule, Loop Over Items and Wait nodes, Y0..Y49 leading back (2.8 MB) | 1.0 s | 113 MB |
| 199,000 parameter values under a path 57 objects deep (0.9 MB) | 1.8 s | 87 MB |
| 199,000 expressions without `=` under a 1,000-character path, all fixed (3.2 MB) | 6.8 s | 446 MB |
| 4,000 nodes with 1 KB names, 14 MB of Code referring to them with typos (18 MB) | 1.0 s | 135 MB |
| 10 million `x/` in one Code node (19 MB) | 1.9 s | 127 MB |
| 1,000 workflows of 41 nodes in one array (16 MB) | 4.6 s | 422 MB |
| 198 Switch nodes of 1,000 rules, 49 of them with 1,000 output lists (1 MB) | 1.7 s | 206 MB |
| 49 outputs of 1,000 connections, half to missing nodes (2.3 MB) | 1.6 s | 145 MB |
| 4,900 HTTP nodes with 4,900 distinct 400-character passwords next to what `fix` changes (18 MB) | 8.0 s | 253 MB |
| 78 HTTP nodes with eight distinct 245 KB passwords (18 MB) | 2.9 s | 158 MB |
| 49,000 short random passwords and 72 Code nodes of 250 KB random text that `fix` rewrites (19 MB) | 8.0 s | 325 MB |
| 23,000 values that are each one secret in a URL query string (2.1 MB) | 1.4 s | 93 MB |
| 49,600 AWS-style keys in four 250 KB values (1 MB) | 0.9 s | 56 MB |
| A million `$('Mising').all();` in one Code node and a node named Mizing, `fix` (CLI and MCP `n8n_fix`; 20 MB) | 6.3 s | 489 MB |
| 70 Code nodes of 250 KB of `"password":"abc123xyz",`, each node's text different (20.6 MB) | 18.8 s | 145 MB |
| 70 Code nodes of 250 KB of `password:'abcd',`, each node's text different (17.5 MB) | 20.0 s | 144 MB |
| 70 Execute Command nodes of 250 KB of repeated password flags (17.2 MB) | 16.9 s | 90 MB |
| An embedded workflow in each of 4,900 Execute Workflow nodes (18 MB) | 3.5 s | 146 MB |
| 190,000 values in an object nested in 8 embedded workflows (3.8 MB) | 4.3 s | 139 MB |
| Unparseable embedded text of 280,000 name/value entries (21 MB) | 0.6 s | 123 MB |
| 78 sticky notes of `pass=` repeated 52,428 times (20 MB) | 6.9 s | 108 MB |
| 5,000 sticky notes of 3.9 KB with labelled values (20 MB) | 7.8 s | 119 MB |
| 1,900 Set nodes with passwords of `a` in 1,900 lengths, and a sticky note of 250,000 `a` inside a word (2 MB) | 1.0 s | 45 MB |
| 70 Execute Workflow nodes of 261 KB unparseable text with 255 backslashes: the raw scan cut short (20 MB) | 6.1 s | 98 MB |
| 190 workflows with a 95 KB password of URL-reserved characters (18 MB) | 0.6 s | 60 MB |
| 690,000 `{"nodes": [], "connections": 1}` before one workflow (20 MB) | 4.9 s | 304 MB |
| 1,000 workflows of 4,990 empty nodes (15 MB), refused by `--max-file-nodes` | 1.9 s | 452 MB |
| One embedded text of 1,000 workflows of 4,990 empty nodes (15 MB), scanned as text | 2.7 s | 472 MB |
| 1,000 Execute Workflow nodes, each with text of 1,000 one-node workflows (19.5 MB) | 3.0 s | 159 MB |
| 495 Execute Workflow nodes, each with text of 99 nodes with distinct passwords: the budget full (7.6 MB) | 5.6 s | 180 MB |
| 1,000 workflows of 48 HTTP nodes with distinct passwords: 193,000 findings (8 MB) | 7.3 s | 173 MB |
| 78 Execute Workflow nodes with 250 KB of unparseable text: sticky notes of 500 label lines each (19.5 MB) | 8.5 s | 100 MB |
| 1,000 workflows of 80 unconnected HTTP nodes (POST to a test webhook URL, TLS checks off, error output unused): 321,000 findings, with `--max-file-nodes 100000` (18.9 MB) | 10.6 s | 240 MB |

`lint` lists at most 20,000 findings per run (`--max-findings-total`) and counts the rest by
severity and rule; JSON and SARIF reports are written one finding at a time. With the
limit raised over all 321,000 findings of the file above, JSON takes 15.8 s and SARIF 21.7 s,
both within 340 MB.

`executions` keeps the maskers of the last four workflow versions it saw and builds maskers
from at most 16 MB of workflow JSON per run (`--max-masker-mb`); past that, the remaining
messages are hidden, together with the workflow and node names of those executions (or, with
`--pattern-masking-only`, masked by the patterns only) and a note on stderr says so. 1,000
failed executions that each carry a different version of their workflow (0.43 MB of JSON,
5,200 `Authorization` header secrets each) are summarised in 6.8 s and 62 MB; the worst case
we found, where the budget is spent on such versions and every execution then repeats a cached
one with a 200 KB crafted message, takes 18.7 s (24.9 s with `--max-masker-mb 32`). Only the first 16 KB of each error message are
masked and kept (2,000 characters are shown): 1,000 executions with 200 KB messages crafted
to hit the masking patterns (`"password": "x", ` repeated, `Basic ` repeated, URLs with
query strings, XML credential elements) take at most 13 s.

Over a limit, the same kinds of file are refused quickly: 900,000 keys in nine 2 MB values
(0.6 s, 89 MB) or 995,000 query-string secrets (1.3 s, 95 MB) exceed `max-secrets`, and
18 MB of stdin made of 50 lines that each start a JSON array is parsed twice (0.2 s).

If you find a way to make `n8n-doctor` reveal a secret, change an n8n instance, write
somewhere you did not ask, or run code from a workflow, please report it privately through
GitHub's [security advisory form](https://github.com/vladosskins178/n8n-doctor/security/advisories/new)
rather than a public issue.
