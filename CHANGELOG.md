# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [0.1.0] - 2026-11-05

First public release.

### Added

- `n8n-doctor lint`: 33 rules with stable ids in five groups: input (parts checked only in part because of a
  resource limit), security (hardcoded secrets, webhooks and MCP Server Triggers without auth, test webhook URLs,
  unauthenticated Wait resumes, disabled TLS checks), structure (unreachable nodes, no trigger, constant
  IF/Filter/Switch conditions, unconnected outputs, dangling connections, duplicate names, references to missing
  nodes, missing credentials, Respond to Webhook mismatches, disabled nodes mid-flow, pinned data, expressions without
  the leading `=`, entries that are not nodes, times n8n cannot use), reliability (no error workflow, HTTP timeout and
  retry, loops that never finish, overlapping schedules, Wait without limit, unhandled error outputs, Execute Workflow
  without target, failed executions not saved) and code (Function nodes, legacy syntax, Code node mode mismatches).
- Text, JSON, SARIF 2.1.0 and GitHub annotation output; exit codes for CI; `--fail-on`, `--min-severity`, `--select`,
  `--ignore`; `.n8n-doctor.toml` or `[tool.n8n-doctor]` config; suppression through node notes and sticky notes (always
  counted in reports, never silencing secrets or open webhooks unless named).
- Reads single exports, folders (skipping `*.fixed.json` copies), `n8n export:workflow --all` arrays, API responses,
  n8n.io template downloads, stdin, and files with log lines before their JSON. A file that cannot be checked is
  reported and fails the run; the other files are still checked.
- `n8n-doctor explain`: outline of triggers, branches, loops, ends and unreachable nodes; text, Mermaid and JSON output.
- `n8n-doctor fix`: a dry run by default, for pinned data, retries on idempotent requests, dangling connections (a node
  id that one node has becomes its name; a shared id keeps its wiring and is listed as skipped), clear node renames,
  expressions missing their `=` and unsaved failed executions. HTTP timeouts are set only with `--set-timeout MS`. A
  reference is rewritten only for a difference of case, spaces or punctuation or a clear typo, and otherwise suggested.
  The output lists each changed value by node and path with only the changed token; `--format json` returns `changes`,
  `skipped`, `edits` and `diff` (`--include-patch` adds the raw RFC 6902 patch); `--write` saves a new file, with the
  permissions of the input, and never touches the input.
- `n8n-doctor executions`: recent failed executions from the n8n public API, grouped by workflow, node and normalised
  error message. `lint --api` and `explain --api` read workflows from an instance. The API client makes only GET
  requests, refuses redirects and never prints the key.
- `n8n-doctor mcp`: MCP server over stdio with `n8n_lint`, `n8n_explain`, `n8n_fix` and `n8n_executions`; tools take a
  path or the workflow JSON itself.
- Agent skill, Claude Code plugin, marketplace manifests, a composite GitHub Action (annotations, SARIF upload, isolated
  install) and example workflows.
- N8D101 finds private keys, provider tokens, webhook URLs, `curl -u`, Basic auth credentials in code, password flags in commands, literal values in
  fields, headers, JSON text, query strings, form bodies, sticky note labels and pinned data. In Code it reads quoted
  keys, `params.set('token', '...')`, connection strings, password variables, and names ending in `_KEY` or `Key`
  (`OPENAI_KEY`, `consumerKey`) with a generated-looking value. Template forms (`YOUR_N8N_API_KEY_HERE`, `<<API_KEY>>`,
  `change_me`, a private key block holding `[INSERT YOUR KEY HERE]`) are not reported; real passwords that hold such a
  word are.
- N8D207 reads expressions, Code in every field n8n runs as code (Python's `_('Name')` included) and the fields a node
  resolves itself (SQL queries, HTML templates, LDAP). It skips text in string literals, CSS selectors in HTML a Code
  node builds, and every `$()` of a Code node that declares its own `$` (`const $ = cheerio.load(html)`, a parameter
  named `$`).
- N8D209 follows n8n's `checkResponseModeConfiguration`.
- Workflows embedded in a parameter belong to themselves: fixes leave them alone; N8D101 and masking read them, nested
  to 8 levels, text or object.

### Security

- Secrets are never printed in full. Findings show at most a secret's first four characters and its length; `explain`,
  the `fix` review, `executions` and every error message mask them, including private keys, percent-encoded spellings
  and names that contain a token. Every literal value of a secret-named field is masked, whether reported or not. The
  `--include-patch` output is an exact copy of the changed values and is not log-safe.
- `lint -o`, `fix --write` and `skill install` replace regular files only and refuse devices, fifos, sockets and folders.
  `lint -o` never replaces what the run reads, and replaces another file only if it is an earlier report, or with `--force`.
- Every input is checked against resource limits when it is loaded (file size, nesting, nodes, connections, names,
  parameters, secrets), so crafted input stays bounded. Each limit can be raised with a `--max-*` flag or in the
  `[limits]` table of the config file. See README, Resource limits, and `SECURITY.md`.
- `executions` fails closed: a message that cannot be masked with its workflow's secrets is hidden, with the workflow
  and node names. `--timeout` bounds all API calls of a run; an incomplete run says so and exits with code 3.
- API responses are read up to 16 MB each. Limit and API errors never echo a name that can repeat a secret, the
  `N8N_API_URL` or a redirect target.
- The GitHub Action can ignore config files for untrusted pull requests, refuses paths and help flags in `args`, pins
  the SARIF upload action to a commit, and checks that the installed version matches.

[0.1.0]: https://github.com/vladosskins178/n8n-doctor/releases/tag/v0.1.0
