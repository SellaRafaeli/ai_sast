# Test repos for the BOLA detector

Real apps with known BOLA/IDOR bugs, used to check whether `route_tracer.rb` + `analyze_bola.rb` find them.

The clones are not committed (see `.gitignore`). To get them:

```bash
./test_repos/fetch.sh
```

## Running the tests

```bash
test_repos/run_tests.rb                 # trace + LLM analysis on every repo (~2-3 min, ~12 LLM calls)
test_repos/run_tests.rb aegra           # only cases whose name contains "aegra"
test_repos/run_tests.rb --trace-only    # no LLM calls: only check the expected routes get traced
test_repos/run_tests.rb --reuse         # re-check the last results after editing expected.yml (runs nothing)
```

It streams the tracer's and analyzer's output as they run, including each route's verdict and score as its batch comes back. Then for each repo it prints:

- **coverage**: did the tracer find each known-vulnerable route?
- **expected BOLA routes**: was each one flagged (`likely`/`possible`)?
- **expected safe routes**: was each one left `unlikely`? A flag here is a false positive.
- **other flagged routes**: flags on routes `expected.yml` doesn't label, for review by hand.

Each repo is scored by **coverage**: the share of its known BOLAs the scanner flagged. 6 of 7 is 86%. A "not covered" list shows each miss and why. The command exits 1 only if a repo couldn't be run (missing clone, tracer or analyzer failure), not for low coverage. The labels live in [`expected.yml`](expected.yml). Each run's `trace.json`, `bola_report.md` and `run.log` go to `test_repos/results/<case>/` (gitignored).

### Results in the main README

Every run except `--trace-only` saves each repo's result to [`scoreboard.json`](scoreboard.json) and rewrites the **Test results** section at the top of the [main README](../README.md) from it. That section has:

- a one-line total: overall coverage (known BOLAs detected across all apps), false positives, unlabeled flags, and when the apps were tested
- one table row per app: coverage % (🟢 80%+, 🟡 50–79%, 🔴 under 50%), what isn't covered, false positives, unlabeled flags, and the date and time it was tested
- **Not covered**: every missed BOLA across all apps and why. The reason comes from the app's optional `gaps:` note in `expected.yml` (e.g. "GraphQL resolvers aren't traced yet"), plus what happened in the run (not traced, or traced but scored unlikely)
- every false positive across all apps
- a collapsed per-app list of each route: expected vs. what the scanner said

`scoreboard.json` keeps one entry per app, so running a single app (`test_repos/run_tests.rb aegra`) updates only that app's row. Apps in `expected.yml` that haven't been run show as "not run" and are left out of the totals. Commit `scoreboard.json` together with the README. After editing `expected.yml`, run `--reuse` to refresh both without calling the LLM.

To add a test app: add it to `fetch.sh`, clone it with `test_repos/fetch.sh`, add an entry to `expected.yml` (`name`, `repo`, `homepage`, `stack`, `source`, `vulnerable`, `safe`, and optionally `gaps`), then run `test_repos/run_tests.rb <name>`.

## The apps

| Folder | App | Language | Pinned at |
|---|---|---|---|
| `aegra-v0.9.6/` | [aegra](https://github.com/aegra/aegra) | Python / FastAPI | tag `v0.9.6` |
| `node/dvws-node/` | [dvws-node](https://github.com/snoopysecurity/dvws-node) | Node.js / Express (plain JS) | commit `05e1b6f` |
| `ruby/railsgoat/` | [OWASP RailsGoat](https://github.com/OWASP/railsgoat) | Ruby / Rails | commit `f5951f1` |

## aegra v0.9.6: CVE-2026-44504

Advisory: [GHSA-m98r-6667-4wq7](https://github.com/aegra/aegra/security/advisories/GHSA-m98r-6667-4wq7) (CVSS 4.0: 8.6 High). Fixed in v0.9.7 ([PR #337](https://github.com/aegra/aegra/pull/337)).

Any signed-in user who knows another user's `thread_id` can run graphs on that thread, read its full checkpoint state and inject messages into it. The run-creation endpoints never check that the thread belongs to the caller, while the read endpoints in `api/threads.py` do.

Expected findings, all in `libs/aegra-api/src/aegra_api/api/runs.py`:

| Route | Line |
|---|---|
| `POST /threads/{thread_id}/runs` | 39 |
| `POST /threads/{thread_id}/runs/stream` | 78 |
| `POST /threads/{thread_id}/runs/wait` | 294 |

Not vulnerable (good negatives): the thread and run routes that filter by `user_id` (listed under `safe` in `expected.yml`).

Possible bugs the CVE doesn't cover. The scanner flags these, so they're left unlabeled until someone confirms them:

- `POST /runs`, `/runs/stream`, `/runs/wait`: `services/run_preparation.py:201` loads the assistant by `assistant_id` without a user filter. The assistant endpoints only show the caller's own or `"system"` assistants.
- `POST /threads/{thread_id}/state`: the thread in the path is ownership-checked, but `api/threads.py:469` merges the body's `checkpoint` dict into the config. That may let the body override `thread_id`. This is still there in v0.9.7.

The full history is cloned, so you can see the fix with:

```bash
git -C test_repos/aegra-v0.9.6 diff v0.9.6 v0.9.7 -- libs/aegra-api/src/aegra_api/api/runs.py
```

## dvws-node: Damn Vulnerable Web Services

An intentionally vulnerable Express app with ~58 documented bugs. Most aren't BOLA, which makes it a good test for false positives too. Solutions are in its `CHALLENGES.md`.

Expected BOLA/IDOR findings:

| Challenge | Route | Where |
|---|---|---|
| #15 IDOR | `GET/PUT/DELETE /api/v2/notes/:noteId` | `src/routes/notes.js:39` |
| #19 Horizontal access control | `GET /api/v2/passphrase/:username` (no auth at all) | `src/routes/passphrase.js:16` |
| #39 Account recovery IDOR chain | `POST /api/v2/account-recovery/lookup`, `POST /api/v2/account-recovery/reset` | `src/routes/users.js:31`, `:34` |
| #53 Support ticket IDOR | `GET /api/v2/support/tickets/:id` | `src/routes/support-tickets.js:8` |
| #33 GraphQL access control | `POST /graphql` (note resolvers) | `src/graphql/schema.js` |

Current result: 6/7 detected. The miss is `POST /graphql`: the tracer sees only the rate limiter on that route, not the Apollo resolvers behind it (see "Known limits" in the main README).

The scanner also flags routes that `expected.yml` doesn't label. Most match other dvws-node challenges (profile details #38, XML profile import #13, SOAP user service #11, LDAP search #9, monthly statement #46, download path traversal #10). Label them once each one is checked.

Related, but not strictly BOLA: #18 vertical access control (admin endpoints open to regular users) and #46 cross-customer monthly statement (path traversal that reaches other customers' files).

Note: `CHALLENGES.md`, `test/` and `codeql-results.sarif` describe the answers. If the analyzer ever reads files beyond route code, exclude them so it can't copy the answers.

## RailsGoat: OWASP's vulnerable Rails app

An intentionally vulnerable Rails app (an HR portal: pay, benefits, messages, admin). Its own spec (`spec/vulnerabilities/insecure_dor_spec.rb`) documents one IDOR: `GET /users/:user_id/work_info`. The other 7 come from reading the controllers before running the scanner. Each one looks a record up by an ID from the request with no ownership check:

| Route | Bug | Where |
|---|---|---|
| `GET /users/:user_id/work_info` | documented IDOR: `User.find_by(id: params[:user_id])` | `app/controllers/work_info_controller.rb:4` |
| `PATCH /users/:id` | updates the user named in `params[:user][:id]`, not `current_user` | `users_controller.rb:29` |
| `GET` / `DELETE /users/:user_id/messages/:id` | `Message.where(id: params[:id])`: anyone's message | `messages_controller.rb:11`, `:15` |
| `POST /users/:user_id/messages` | `creator_id` is permitted: send as another user | `messages_controller.rb:42` |
| `DELETE /users/:user_id/pay/:id` | `Pay.find_by_id(params[:id]).destroy` | `pay_controller.rb:29` |
| `GET /admin/:admin_id/get_user` | left out of the admin check: any user reads any user | `admin_controller.rb:3`, `:28` |
| `GET /api/v1/mobile/:id` | no login; `model.find(params[:id])` for any `class=` | `api/v1/mobile_controller.rb:11` |

The 9 safe routes load data through `current_user` and ignore the ID in the path.

Unlabeled: `GET /download` (the spec calls it IDOR, but it's a path traversal), the admin `update_user`/`delete_user` routes (their admin check is skipped when `admin_id` is `1`, a function-level access bug), and `POST /password_resets`. The scanner flagged that last one after the run. It's probably a real BOLA (the client sends the serialized user whose password gets reset), but it stays unlabeled until someone confirms it.

`spec/vulnerabilities/` describes the answers, and a few controllers have `# VULNERABILITY:` comments (admin mass assignment, ReDoS tutorials). None of the comments are on the routes above.
