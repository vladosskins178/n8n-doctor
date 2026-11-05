# Rules

Every rule has a stable id and name; both work in `--select`, `--ignore`, the config file
and suppression comments. Severities are defaults and can be changed per rule in
`.n8n-doctor.toml`. Rules marked **fixable** are changed by `n8n-doctor fix`.

| Id | Name | Default | Fixable |
| --- | --- | --- | --- |
| [N8D001](#n8d001-incomplete-check) | incomplete-check | info | |
| [N8D101](#n8d101-hardcoded-secret) | hardcoded-secret | error | |
| [N8D102](#n8d102-webhook-without-auth) | webhook-without-auth | warning | |
| [N8D103](#n8d103-webhook-test-url) | webhook-test-url | error | |
| [N8D104](#n8d104-wait-resume-without-auth) | wait-resume-without-auth | info | |
| [N8D105](#n8d105-tls-verification-disabled) | tls-verification-disabled | warning | |
| [N8D201](#n8d201-unreachable-node) | unreachable-node | warning | |
| [N8D202](#n8d202-no-trigger) | no-trigger | warning | |
| [N8D203](#n8d203-constant-condition) | constant-condition | warning | |
| [N8D204](#n8d204-unconnected-switch-output) | unconnected-switch-output | info | |
| [N8D205](#n8d205-dangling-connection) | dangling-connection | error | yes |
| [N8D206](#n8d206-duplicate-node-name) | duplicate-node-name | error | |
| [N8D207](#n8d207-unknown-node-reference) | unknown-node-reference | error | yes (clear renames) |
| [N8D208](#n8d208-missing-credentials) | missing-credentials | error | |
| [N8D209](#n8d209-respond-to-webhook-mismatch) | respond-to-webhook-mismatch | error | |
| [N8D210](#n8d210-disabled-node-in-path) | disabled-node-in-path | warning | |
| [N8D211](#n8d211-pinned-data) | pinned-data | warning | yes |
| [N8D212](#n8d212-expression-without-prefix) | expression-without-prefix | warning | yes |
| [N8D213](#n8d213-invalid-node-entry) | invalid-node-entry | error | |
| [N8D214](#n8d214-invalid-time-value) | invalid-time-value | warning | |
| [N8D301](#n8d301-no-error-workflow) | no-error-workflow | warning | |
| [N8D302](#n8d302-http-without-timeout) | http-without-timeout | info | |
| [N8D303](#n8d303-http-without-retry) | http-without-retry | info | yes (idempotent methods) |
| [N8D304](#n8d304-loop-not-closed) | loop-not-closed | error | |
| [N8D305](#n8d305-unbounded-cycle) | unbounded-cycle | warning | |
| [N8D306](#n8d306-schedule-overlap) | schedule-overlap | warning | |
| [N8D307](#n8d307-wait-without-limit) | wait-without-limit | info | |
| [N8D308](#n8d308-unhandled-error-output) | unhandled-error-output | warning | |
| [N8D309](#n8d309-execute-workflow-without-target) | execute-workflow-without-target | error | |
| [N8D310](#n8d310-failed-executions-not-saved) | failed-executions-not-saved | info | yes |
| [N8D401](#n8d401-deprecated-function-node) | deprecated-function-node | warning | |
| [N8D402](#n8d402-legacy-code-syntax) | legacy-code-syntax | info | |
| [N8D403](#n8d403-code-mode-mismatch) | code-mode-mismatch | error | |

Rules about run-time behaviour skip disabled nodes. Secrets (N8D101), unreachable,
duplicate, disabled-in-path and deprecated nodes are reported on disabled nodes too, since
they still ship in the JSON. Sticky notes are not nodes for any rule, but their text is
searched for secrets.

## Input

### N8D001 incomplete-check

n8n-doctor checked part of the workflow only in part, because it is over one of the soft
resource limits (see [Resource limits](../README.md#resource-limits)):

- a Code or Function node's source is longer than `--max-code-kb` (1 MB by default): node
  references, legacy syntax and the Code mode are checked in its first 1 MB only (secrets
  are checked at both ends of it, see N8D101);
- the workflow has more findings than `--max-findings` (5,000 by default): the rest are
  counted in one finding, listed last, whose severity is the highest among them; totals,
  the exit code and the fixable count include them;
- the run has more findings than `--max-findings-total` (20,000 by default, all workflows
  together): the rest are counted in one finding for the run, listed after every workflow,
  with their counts by severity and by rule; totals, the exit code and the fixable count
  include them.

Long values checked for secrets only at both ends are reported by N8D101 itself. Check the
rest by hand, or raise the limit.

## Security

### N8D101 hardcoded-secret

A token, API key, password or private key is written into a node. Workflow JSON is shared,
exported, committed to git and kept in n8n's version history, so the value leaks with it.

Detected: provider token formats (AWS, GitHub, Slack tokens and webhook URLs, Discord
webhooks, Stripe live and test keys, OpenAI and Anthropic keys, Google API and OAuth (`ya29.`) keys, Telegram bot
tokens, SendGrid keys, Groq keys (`gsk_`), Notion tokens (`ntn_`), GitLab (`glpat-`), Hugging Face (`hf_`), Shopify
(`shpat_`), npm (`npm_`), Perplexity (`pplx-`), Replicate (`r8_`) and xAI (`xai-`) tokens, HubSpot (`pat-na1-...`) and
Airtable (`pat....`) tokens, Stripe webhook secrets (`whsec_`), DigitalOcean (`dop_v1_`), Linear (`lin_api_`), Tavily (`tvly-`),
Supabase (`sbp_`, `sb_secret_`), Pinecone (`pcsk_`), Atlassian (`ATATT`), Bitbucket (`ATBB`), Apify (`apify_api_`), Brevo (`xkeysib-`), Google client secrets (`GOCSPX-`), Microsoft Teams webhook URLs, Facebook (`EAAB`, `EAAG`), Sentry (`sntrys_`) and Slack app (`xapp-`) tokens,
legacy Notion tokens (`secret_` plus exactly 43 letters and digits), JWTs, PEM, SSH2 and PuTTY private keys, also encrypted or truncated),
Azure keys in connection strings (`AccountKey=`, `SharedAccessKey=`), passwords from 4 characters in URLs (`postgres://admin:admin@db`, `redis://:hunter2@host`, `https://bob:hunter2@a.io`) and in `curl -u bob:hunter2` / `--user` commands (placeholders such as `user:password@host`, `<password>` and any `@example.com` do not count, nor does another tool's `-u`),
password flags in Execute Command and SSH commands (`--password=X` and `--password X` for any tool but the MySQL, MariaDB and PostgreSQL clients, where `--password` alone asks for the password and what follows is the next argument; `--http-password=X` and the like, `mysql -pX` and the other
MySQL and MariaDB clients, `sshpass -p X`, `docker login -p X`, `redis-cli -a X`; shell variables, command substitutions and `{{ }}` do not count, nor do `mkdir -p` or `ssh -p 22`),
sensitive query parameters inside URLs (names ending in `api_key` or `secret`, such as `my_api_key`, `rapidapi-key`, `api_secret`, `webhook_secret`; `oauth_token`, `bot_token`, `secret_token`, `app_key`, `appkey`, `license_key`, `api_token`, `access_key`, `private_token`,
`secret_key`, `x-api-key`, `x-goog-api-key`, `hapikey`, `subscription-key`, `consumer_secret`, `auth_key`, `user_key`, `client_key`, `sessionToken`, `pass`, names ending in `password`, `passwd`, `pwd` or `_pass`, ...; also raw form bodies, the first parameter included (`password=abc&x=1`); `key`, `sig`, `auth`, `appid`, other names ending in `key`, `token` or `auth` (paging names such as `next_token` and `page_token` never count) and
`X-Amz-Signature`, `consumer_key` only when the value looks generated) whose
value looks generated: mixing letters and digits, at least 12 characters and varied enough
(`?api_key=a1B2...`, not `?key=customer_id` or `?sig=2024-01-01T00`),
literal `Bearer` tokens, literal values of sensitive headers or query parameters
(`Authorization`, `Proxy-Authorization`, `X-Authorization` and `Authentication` under any scheme word, such as `Bot`, `OAuth`, `SSWS` or `GenieKey`; `X-API-Key`, `token`, `password`, names ending in a separate `APIKEY`, `APITOKEN`, `AUTHTOKEN` or `PASSPHRASE` such as `X-MBX-APIKEY` or `OK-ACCESS-PASSPHRASE`, ...; `Authentication` alone needs a generated-looking value, as n8n's own field holds words such as `headerAuth`; any name holding the word password, passwd or pwd or ending in `_pass`, such as `db_password`, `userPassword`, `X-Db-Password`, `ftp_pass`, but not `bypass`, `passwordField` or `password_policy`; other header names with auth,
token, key or secret as a whole word such as `X-Custom-Auth` when the value looks generated; not
`X-Author-Id`, `X-Keyword`, `X-Cache-Key`, `object_key`, `file_key`, `X-Partition-Key`, `Sec-WebSocket-Key`, `Sheet Key`, `spreadsheet_key`, `product_key`, `price_key`, `Public Key`, `Next Token`, `Secret Name` or a name ending in `Token Address`, as a token's address is public), the same names as keys in JSON header or
body text, under the same checks: `xi-api-key`, `PRIVATE-TOKEN`, `api_token`, `secret_key`, `bot_token` and the like when the value looks generated, and `Cookie` (also spelled with `\u` escapes), string literals inside an expression in such a header
or field when they look generated (`={{ 'Bearer ' + 'a1B2...' }}`; node and field references such as `$('Login')`, `$json['x']` and `$fromAI(...)` do not count), and assignments like
`const apiKey = "..."`, `{"apiKey": "..."}` or `headers["x-api-key"] = "..."` in code (JavaScript
and Python Code, the LangChain Code node and Code Tool), to names ending in a secret word (`apiKey`, `token`, `password`, `secret`,
`privateKey`, `accessKey`, `signingKey`, `clientSecret`, ...; comments are ignored). Expressions (`={{ $env.TOKEN }}`) and clear template forms are not reported:
a whole value that asks for the secret (`YOUR_API_KEY`, `enter-your-api-key`, `<YOUR_TOKEN>`,
`[your token]`, `replace-with-your-password`), `changeme`, `REPLACE_ME`, `example`, `placeholder`,
`xxxx`, `****`, `<token>`, `%API_KEY%`, environment variable names ending in `_KEY`, `_TOKEN`,
`_SECRET`, `_PASSWORD` or `_ID` (`POSTIZ_API_KEY`), the words `CLIENTSECRET`, `APIKEY`,
`ACCESSTOKEN` and `SECRETKEY`, the providers' documented example keys (`AKIAIOSFODNN7EXAMPLE`), and
known prefixes where filler makes up at least 60% of the rest (`sk-xxxx...`, `ghp_0000...`,
`AKIAXXXX...`, `xoxb-your-token-here`), `REDACTED`, `undefined`, `required` and any "paste your ... here"
(`PASTE_YOUR_NIXGUARD_API_KEY_HERE`). In a field named for a password (not a generic `key` or `token`) a literal counts from
4 characters (`hunter2`, `admin`, `1234`) in headers, bodies, query parameters, URLs, Set nodes, JSON text, Code and plain
parameters, unless it says nothing: `required`, `optional`, `none`, `null`, `undefined`, `true`, `false`, `string`, `plaintext`, `password` and
similar words, hash and password manager names. Other names keep the limit of 8 characters. A field that describes the password
(`password_created_at`, `password_format`, `password_manager`, `password_auth`, `password_protected`, `password_valid`, `password_count`) only counts with a generated-looking value.
In code, a pair after a ternary's `?` (`ok ? 'pass' : 'fail'`), a key called just `pass` without a generated-looking value (`{pass:'green'}`), and values that set up a form do not count: CSS selectors and colours (`#pwd`), validation rules (`required|min:8`), and label words (`Invalid`, `Пароль`, short lowercase words other than passwords everyone tries, such as `admin`). Anything else is reported, real passwords that merely
contain such a word (`Enter-The-Dragon-99`, `addMe2024!`) or are written in capitals
(`ADMINPASS`) included. Whatever this check decides, every literal value of a secret-named
field (`password`, `apiKey`, `token`, `secret`, `Authorization` and other auth headers, JSON
header keys, Code assignments to such names) is masked in all output, short ones included; a value that starts with `=` but has no `{{ }}`
(`=hunter2hunter2`) is an expression with nothing to evaluate, so it is checked as the
literal after the `=`. Every distinct secret in a parameter gets its own
finding, so none is missed when rotating; a value allowed by `allow` does not hide a longer
secret around it. Token formats in parameter names, node names, the workflow name and the
node names in connections and pinned data are reported too (every output shows those names
masked). Values are never printed in full.

In code, Basic auth credentials count whatever variable holds them: a literal `user:password`
given to `Buffer.from` or `btoa` when it reads as credentials (`admin:SuperSecret9`, not
`status:active`) and `'Basic <base64>'` when it decodes to `user:password`. Base64 secrets may
hold `/` and `+`; paths, URLs and media types do not count as generated-looking. Names ending in
`Key` that are not clearly secret (`promptKey`, `COUNTRY_KEY`) do not count when the value is a
few words and a number (`imagePrompt2`).

Plain parameters named `token`, `pwd`, `pass`, `passphrase`, `refreshToken`, `botToken`, `sessionToken`, `x-api-key`,
`encryptionKey`, `licenseKey` or `cookie` count when the value looks generated (`pwd` can be a folder, `pass` a flag;
`pageToken`, `nextPageToken` and `nextToken` are not secret names, nor are the headers `X-Key-Id` and `X-Auth-Scheme`). In name/value entries `pass` and `passphrase` count like `password`,
and `Cookie` when one of its values looks generated. A sticky note is checked for token formats and for a label with a
value that ends the line or a list item (`password: hunter2`), a capitalised product-like word aside (`API key: OpenAI`,
`Token: OAuth2`, `Password: 1Password`); `X-Api-Key: ...`, `Authorization: ...`, `password is ...` and `| password | ... |`
count when the value has digits, symbols or capitals inside, as a word there is usually prose or a type. A workflow embedded in a parameter (see N8D212) is read
as a workflow for this rule, to 8 levels: its findings are on the outer node, under `workflowJson.nodes[1].parameters...`.
Embedded text that cannot be read, or past the file's budget of nodes plus workflows (`max-file-nodes`, 50,000 by
default; an `info` finding says so), is scanned as text.

A node's `notes` are read like a sticky note. Sticky-note labels also count with a prefix or as a setting name
(`OPENAI_API_KEY=...`, `client_secret: ...`, `accessToken: ...`) when the value does not read as a word. In Execute
Command and SSH nodes, `curl -H "X-Api-Key: ..."` and `API_KEY=... command` count; in an expression, an object literal
(`={{ {'api_key': '...'} }}`). A password-named field or entry counts with spaces in its value. Not detected on purpose:
`key-` plus hexadecimal (Mailgun) and `SK` plus hexadecimal (Twilio), which too many ids look like.

A value (or name) longer than the scan limit (`max-value-kb`, 256 KB by default) is checked
at its first and last half of the limit only, and an `info` finding says so; `explain` and
`fix` then show the whole value as `<N characters, too large to check for secrets: not
shown>`, since a secret in its unchecked middle could not be masked.

Fix: create a credential (Header Auth, Basic Auth, or the service's own type) and select it
on the node, then **rotate the exposed value**. Values that are not secrets can be allowed
with a regex: `[rules.hardcoded-secret] allow = ["^pk_test_"]`.

### N8D102 webhook-without-auth

A Webhook node with Authentication `None` accepts requests from anyone who has the URL.
Webhook paths leak through browser history, logs, screenshots and third-party dashboards.
Also reported for a Chat Trigger with "Make Chat Publicly Available" on and no
authentication: anyone can run the agent and spend its model budget.
An MCP Server Trigger with Authentication `None` is reported too: anyone with its URL can
list and call the tools it exposes.

Fix: choose Basic, Header or JWT Auth. If the sender signs requests (Stripe, GitHub, Slack)
and you verify the signature in the next node, add `n8n-doctor-disable webhook-without-auth`
to the Webhook node's Notes.

### N8D103 webhook-test-url

A node calls a URL containing `/webhook-test/`. n8n only serves test URLs while someone
has clicked "Listen for test event" in the editor, so in production the call fails with 404.
Fix: use the production URL (`/webhook/...`) and activate the target workflow.

### N8D104 wait-resume-without-auth

A Wait node set to resume "On Webhook Call" with Authentication `None` continues for
anyone who calls `$execution.resumeUrl`. Current n8n versions sign that URL, so the URL
itself is the secret, and it is often sent to third parties (emails, chat messages,
partner systems); older versions built it from the sequential execution id alone. Fix:
set Authentication on the Wait node.

### N8D105 tls-verification-disabled

"Ignore SSL Issues" (`options.allowUnauthorizedCerts`) is on for an HTTP Request, so
certificate errors are ignored and the connection can be intercepted. Fix: turn it off;
for a private CA, give n8n the CA with `NODE_EXTRA_CA_CERTS`.

## Structure

### N8D201 unreachable-node

A node that no trigger leads to never runs: it is either not connected at all or only
connected to other unreachable nodes. AI sub-nodes (models, tools, memory) count as
reachable when the agent or chain they feed is; one wired with a `main` connection instead
of `ai_languageModel`/`ai_tool`/`ai_memory` gets a hint saying so. Disabled leftovers are
reported as info. Under the legacy execution order (`settings.executionOrder` `v0`, or no
setting, as in older workflows) n8n runs the branches that feed a node with several inputs
(a Merge) even when no trigger leads to them, so those branches are not reported.

### N8D202 no-trigger

The workflow has nodes but no trigger (or no nodes at all), so nothing can start it. Sub-workflows need the
"When Executed by Another Workflow" trigger.

### N8D203 constant-condition

Every condition of an IF, Filter or Switch rule compares fixed values, so the node always
takes the same branch. The usual cause is a value typed without `=`/`{{ }}`
(`"leftValue": "status"` instead of `"={{ $json.status }}"`), or an IF that was never
configured (empty values). Checked for IF v1 and v2+, Filter v2+ and Switch v3 rules.

### N8D204 unconnected-switch-output

Some outputs of a Switch are connected and others are not. Items that match an
unconnected rule (or the fallback output) are dropped without any error. Connect the
output, delete the rule, or send it to a No Operation node to show the drop is intended.

### N8D205 dangling-connection

A connection names a source or target node that does not exist. n8n's editor never writes
this; it comes from hand-edited or merged JSON. One finding per missing source node, and one
per existing node for all of its connections to missing nodes (the first five are named).
A connection written with a node's id instead of its name is said to be one. **Fix** rewrites an id
that exactly one node has to that node's name, removes the other broken connections and lists each
change. An id that several nodes share keeps its wiring and is listed as skipped: connect the node
meant in the editor.

### N8D206 duplicate-node-name

Node names must be unique: connections and expressions refer to nodes by name, so one of
the two is unreachable or referenced by mistake. Rename one in the editor.

### N8D207 unknown-node-reference

An expression (inside its `{{ }}` parts) or a Code node uses `$('Name')`, `$node["Name"]`,
`$node.Name` or `$items("Name")` for a node that does not exist; at run time this fails with "Referenced
node doesn't exist". The usual cause is a rename done outside the editor or a deleted node.
A Code node that declares its own `$` (`const $ = cheerio.load(html)`, a parameter named `$`) has no `$()` references.
**fix** rewrites the reference only where one existing node can only be what was meant, because a wrong rewrite gives
wrong data without any error:

- the names differ only by case, spaces or punctuation, emoji included (`get data` and `Get-Data`, `Configuration` and `⚙️ Configuration`; numbers
  stay apart, and `< > = + * % # $ @ & ^` count, so `Score > 5` is not `Score < 5`), or
- the names have the same number of words and one word is a typo of the node's word: that word has at least 5 letters, the same first
  letter and numbers, and differs by at most 2 edits, a swap of two neighbouring letters being one (`Send Emial`, `Get Custmer`). Under 7 letters only 1 edit counts,
  since two make another word (`Filter` and `Folder`). If several names qualify, the one with the fewest edits must be alone.

Everything else is at most a suggestion in the finding, and **fix** leaves it: another word (`Get Data` and `Set Data`, `Import` and `Export`, `Encode` and `Decode`),
a name with words added or removed (`Get Customer Orders` and `Get Customer`, `Set Variables` and `Set`). Where a node has the same name but for its
number (`Posts1` and `Posts`), nothing is rewritten either: n8n numbers copies, so this may be another node, so no trailing number is ever removed.
In Code
nodes, text inside string and regex literals is not code (`"<script>$('#go')</script>"` is
HTML for a browser), except within `${ }` of a template literal, which n8n evaluates. There,
and in the HTML node's `html` template, a name that is a CSS selector and nothing else (`#go`, `.item`,
`div > p`, `ul li.active`) is taken for jQuery, though within `${ }` a bare word such as `$('form')` is a node name; everywhere else `$()` is n8n's and the name is
checked, and names that only start like a selector (`[PROD] Get Lead`, `.env loader`,
`#1 Fetch`) are always checked. String escapes in a name are decoded as JavaScript (or, in
Python Code, `_('Name')`, as Python) reads them: `$('\x41PI')` names `API`. The source of the
language a Code node does not run (`jsCode` left in a Python Code node, `pythonCode` in a
JavaScript one) and workflows embedded as JSON (see N8D212) are not checked.

### N8D208 missing-credentials

- A credential reference without an `id` (common after sharing or templating a workflow):
  n8n resolves credentials only by id, so the node fails until one is selected again.
- An HTTP Request set to a predefined or generic credential type with no matching
  credential selected.
- A node whose `authentication` parameter is set but no credential is selected.

A node with no `credentials` block at all is not reported: which node types need one is
declared inside n8n, not in the workflow, so the JSON alone cannot tell.

### N8D209 respond-to-webhook-mismatch

- A Webhook with Respond "Using 'Respond to Webhook' Node" and no Respond to Webhook node
  after it: the caller waits, then gets an error.
- The same Webhook where an execution can end without reaching a Respond to Webhook node
  (warning): the paths that end elsewhere, or in an IF/Switch output with nothing connected, are
  listed. n8n runs every node on one output, so Webhook to [Respond, Log] is fine: the response is sent.
- A Respond to Webhook node after a Webhook that answers immediately or with the last
  node. From Webhook version 2 this follows n8n's `checkResponseModeConfiguration`
  (`packages/nodes-base/nodes/Webhook/utils.ts`, called in `Webhook.node.ts`), which fails every request with "Unused Respond
  to Webhook node found in the workflow": every Respond to Webhook among the Webhook's descendants counts, disabled or
  past a Wait or Form node, unless one of its parents is an enabled Wait among those descendants with
  `resume` on `webhook` or `form` and `responseMode` exactly `responseNode`. So Webhook to Wait (not responding through a node) to
  Respond, the same with a disabled Wait or a Form node, and Webhook to a disabled Respond all fail. In a very large crafted
  workflow with such Wait nodes the walk has a budget, past which this is not reported.

A disabled Wait or Form node starts no new request, and a disabled IF or Switch only uses its first output
(`handleDisabledNode`, `packages/core/src/execution-engine/workflow-execute.ts`). A Filter's `Discarded` output
is followed when connected; left open it is no gap, since the editor gives a Filter one connector.

### N8D210 disabled-node-in-path

A disabled node with nodes before and after it does not stop the flow: n8n passes its
first input straight through. The next nodes then work on data the disabled node was meant
to change or filter. Re-enable it, or remove it and connect the neighbours directly.

### N8D211 pinned-data

The workflow carries pinned data. Production executions ignore it, but it is saved and
exported with the workflow (often real customer data) and manual test runs use it instead
of live data, so a test can pass while production fails. **Fix** empties `pinData`. Tokens in
pinned data are also reported under N8D101: each credential as an error, and the signed URLs
(`sig`, `signature`, `X-Amz-Signature`) of a node as one warning, whatever their number.

### N8D212 expression-without-prefix

In workflow JSON an expression is a string that starts with `=`: `"={{ $json.email }}"`.
Without the `=`, n8n uses the text as it is, so the API receives `{{ $json.email }}`
literally. This is the most common mistake in hand-written or generated workflow JSON
(the editor adds the `=` when a field is switched to Expression). Reported for any
parameter that contains `{{ ... $... }}` without the prefix; templates for other engines
such as `{{name}}` in an email template have no `$` and are not reported; braces inside
the expression (`{{ JSON.stringify({a: $json.x}) }}`) are fine. Code is skipped (the Code,
Function and AI Transform nodes, the LangChain Code node and Code Tool, the Sort node's custom
code), and so are fields whose `{{ }}` the node resolves itself: the SQL `query` of
Postgres, MySQL, Microsoft SQL, Snowflake, Oracle Database, QuestDB, TimescaleDB and CrateDB,
Postgres v2's `options.queryReplacement`, the LDAP node's `searchFor`, `customFilter` and
`searchText`, Google BigQuery's `sqlQuery` (v2+) and Merge in SQL mode (v3+), and the HTML
node's `html` template, also in the AI tool variants of those nodes (`postgresTool`, `mySqlTool`, ...).
The Set node's JSON output (`jsonOutput`) is not one of them: n8n resolves it only
when it starts with `=`. A workflow embedded as JSON (Execute Workflow and Call n8n Workflow
Tool with source "Define below" in `workflowJson`, the n8n node's `workflowObject`) is skipped:
its `{{ }}` belong to that workflow, which runs on its own (only a value written as an
expression, starting with `=`, is this workflow's). It is not linted as a workflow of its own;
lint it from its own file (N8D101 does read it, for secrets). What the editor keeps for a picked item (`cachedResultUrl`,
`cachedResultName`, ...) is never evaluated and is not reported. **Fix** adds the `=`, except to a value with another
`{{ }}` that has no `$` (`{{name}} {{ $json.x }}`): that one is reported but left for you, since the `=` would make
n8n evaluate `{{name}}` too. The same goes for a text of 1,000 characters or more in a field named `prompt`, `text`,
`message`, `systemMessage` or `content`: its `{{ }}` can be examples for the model.

### N8D213 invalid-node-entry

An entry of the `nodes` array is `null`, a string, a number, an array or an empty object instead of a node
object. n8n cannot import such a workflow; the entry is usually left by a bad merge or a
script that edited the JSON. The other nodes are still checked (and fixed) by their real
position in the array. Remove the entry.

The rule also reports a node whose `typeVersion` is a number no version can be: NaN,
infinite, or further than 10^12 from zero (a 400-digit integer, `1e308`). n8n-doctor checks
such a node as version 1; set the `typeVersion` back to the node's version.

### N8D214 invalid-time-value

A Schedule Trigger interval, a Cron or Interval node's interval, a cron step (`*/0`,
`*/x`) or a Wait node's amount is a value n8n cannot use: zero or negative, infinite or
NaN, not a number, a number written with characters other than ASCII digits (`"²"`), or
more than 9 digits long (a Wait amount further than 10^12 from zero is too large to be a
time). n8n refuses to activate the workflow or the node fails when it
runs. Expressions (`={{ ... }}`) are not checked. Enter a positive whole number.

## Reliability

### N8D301 no-error-workflow

The workflow is started by a schedule, webhook or app trigger and has no error workflow,
so a failure is only visible in the executions list. Set Settings > Error workflow to a
workflow that starts with an Error Trigger and alerts someone. Workflows that only have a
manual, sub-workflow or Error Trigger are not reported; inactive workflows are reported as
info.

### N8D302 http-without-timeout

The HTTP Request has no `options.timeout`, so a hanging server holds the execution for
n8n's default of 5 minutes (per try, when retries are on). Choose a value that fits the API.
`n8n-doctor fix` leaves it alone unless you give `--set-timeout MS` (`set_timeout_ms` on the MCP
tool; at most 2147483647, the longest delay a Node.js timer takes), since a long POST to an LLM or media host can need the 5 minutes; it is not counted as fixable.

### N8D303 http-without-retry

The HTTP Request fails the whole execution on the first network error, 429 or 5xx. Turn on
Retry On Fail. Not reported when the node already handles errors (On Error set to continue).
**Fix** adds 3 tries, 1000 ms apart, only for GET, HEAD, OPTIONS, PUT and DELETE; for POST
and PATCH decide whether a repeat could create duplicates. Settings already there stay, and
a node with Retry On Fail turned off on purpose (`retryOnFail: false`) is left alone.

### N8D304 loop-not-closed

For Loop Over Items (Split in Batches v3), output 0 is `done` and output 1 is `loop`. The
node only emits `done` after the loop branch has fed every batch back into it. If the loop
output is not connected, or nothing on it connects back, only the first batch is processed
and `done` never runs. When the `done` branch is the one that loops back, the finding says
the outputs look swapped.

### N8D305 unbounded-cycle

Nodes connected in a cycle that contains no IF, Switch, Filter, Loop Over Items, Remove
Duplicates, Limit or Code node: nothing can end the loop, so it runs until the execution
times out or the instance runs out of memory.

### N8D306 schedule-overlap

n8n does not prevent a scheduled workflow from starting while its previous run is still
going. Reported as a warning when a Wait node on the path alone lasts at least as long as
the schedule interval (overlap is certain), and as info for schedules faster than once a
minute. Covers Schedule Trigger (intervals and simple cron expressions), Cron and Interval.

### N8D307 wait-without-limit

A Wait node that resumes on a webhook call or form submission without "Limit Wait Time"
keeps the execution waiting forever if the call never comes.

### N8D308 unhandled-error-output

On Error is "Continue (using error output)" but the error output is not connected, so
failed items disappear without trace.

### N8D309 execute-workflow-without-target

An Execute Workflow node, or an AI agent's Call n8n Workflow tool, with no workflow
selected (or an empty JSON/location for the other sources) fails every time it runs.

### N8D310 failed-executions-not-saved

`settings.saveDataErrorExecution` is `none`, so failed executions are not stored and there
is nothing to debug. **Fix** removes the override (the instance default applies).

## Code

### N8D401 deprecated-function-node

Function and Function Item nodes are deprecated and hidden from the node panel; existing
ones still run. Replace them with a Code node: "Run Once for All Items" for Function,
"Run Once for Each Item" for Function Item.

### N8D402 legacy-code-syntax

A Code node (JavaScript) uses helpers from the old Function node: `$node["Name"]`,
`$items("Name")`, `$item(n)` or the `items` variable. They still work for compatibility; the
current forms are `$('Name')`, `$('Name').all()` and `$input.all()`. Comments, strings and
object keys named `items` are ignored, as is a local variable called `items`.

### N8D403 code-mode-mismatch

A Code node in "Run Once for Each Item" mode calls `$input.all()`, `$input.first()`,
`$input.last()` or `$input.itemMatching()`, or uses `items`. Those only exist in "Run Once
for All Items"; n8n stops the node with "Can't use .all() here" or "items is not defined".

## Suppressing a finding

- For one node: put `n8n-doctor-disable <rule>` (id or name, several separated by commas,
  semicolons or spaces; an optional `:` after the marker is fine) in the node's **Notes**.
  `n8n-doctor-disable` alone on its line silences every rule on the node except N8D101
  and N8D102, which must always be named. Unknown names are ignored, and a marker followed
  only by unknown words suppresses nothing.
- For a whole workflow: put the same text in a **sticky note**.
- For a project: `disable = [...]` in `.n8n-doctor.toml`.

Suppressed findings are never hidden completely: the text report counts them (`-v` lists
them), JSON has `summary.suppressed` and a `suppressed` list, and SARIF marks them with
`suppressions`. When checking workflows written by someone else (templates, pull
requests), `--no-inline-suppress` ignores the notes and reports everything.
