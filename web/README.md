# BOLA Detector, by Variablee (web page)

BOLA Detector is the web page for `route_tracer.rb`. Anyone can paste a public repo URL and start a scan. The server clones the repo, traces its routes and shows them. A second button, **Run the analysis**, then asks an LLM which routes look like BOLA / IDOR. Results are saved in Mongo, the page refreshes itself while a step runs, and every action is emailed through Postmark.

| Page | What it shows |
|---|---|
| `/` | The scan form and the 12 latest scans |
| `/scans` | Every scan with its status, route count and results, 50 per page |
| `/scans/<id>` | One scan: progress, the **Run the analysis** button, flagged routes with fixes, all traced routes, call trees, a timeline of what happened, and the log |
| `/scans/<id>.json` | One scan's full document |

Everything for the server is in [`web.rb`](web.rb): routes, background worker and HTML templates. It runs `../route_tracer.rb` and then `../analyze_bola.rb` as child processes, so the scripts stay unchanged and still work from the command line.

## Run it locally

You need Ruby 4.0, a running MongoDB, `git`, and (to scan JS/TS repos) `node`. From the repo root:

```bash
bundle install
```

```bash
npm install
```

```bash
bundle exec ruby web/web.rb
```

Open http://localhost:4567. By default it uses `mongodb://127.0.0.1:27017/route_tracer`. To use another database:

```bash
MONGODB_URI=mongodb://127.0.0.1:27017/my_db bundle exec ruby web/web.rb
```

## Deploy to Heroku

The files Heroku needs are at the repo root, because Heroku only looks there:

| File | Why |
|---|---|
| `Gemfile`, `Gemfile.lock` | Ruby version and the server's gems |
| `Procfile` | Start command: `bundle exec ruby web/web.rb` |
| `package.json` | Installs TypeScript, used to parse JS/TS repos |
| `requirements.txt` | Empty. It makes Heroku add Python, needed to parse Python repos |
| `app.json` | Buildpacks and settings, for one-click deploys |
| `.slugignore` | Leaves test apps and sample output out of the build |

One-time setup, from the repo root (replace `my-app` with your app's name):

```bash
heroku create my-app
```

```bash
heroku buildpacks:add -a my-app heroku/nodejs
```

```bash
heroku buildpacks:add -a my-app heroku/python
```

```bash
heroku buildpacks:add -a my-app heroku/ruby
```

```bash
heroku config:set -a my-app MONGODB_URI='mongodb+srv://USER:PASS@HOST/route_tracer'
```

The LLM key, for the analysis step (or `OPEN_AI_API_KEY`):

```bash
heroku config:set -a my-app ANTHROPIC_API_KEY='sk-ant-...'
```

Then deploy:

```bash
git push heroku master
```

Use a hosted MongoDB such as MongoDB Atlas, and put a database name in the URI (the `/route_tracer` part). Without one, `route_tracer` is used.

For the emails, add your Postmark server token (see [Emails](#emails)):

```bash
heroku config:set -a my-app POSTMARK_API_TOKEN='...'
```

Keep the app at **one web dyno**: traces and analyses wait in an in-memory queue and run one at a time inside that process. Heroku restarts dynos about once a day. A trace running at that moment is marked failed and has to be started again. An analysis goes back to "Ready to analyze", so one more click reruns it.

## Settings

| Variable | Meaning | Default |
|---|---|---|
| `MONGODB_URI` | Mongo connection string | `mongodb://127.0.0.1:27017/route_tracer` |
| `PORT` | Port to listen on (Heroku sets it) | `4567` |
| `ALLOWED_GIT_HOSTS` | Hosts users may clone from, comma-separated, or `*` for any https host | `github.com,gitlab.com,bitbucket.org` |
| `ANALYZE` | `0` to turn off the **Run the analysis** button and show traces only (no LLM calls) | on, when an LLM key is set |
| `ANTHROPIC_API_KEY` / `OPEN_AI_API_KEY` | LLM key for the analysis (see the main README). Without one, scans show the trace only. | |
| `POSTMARK_API_TOKEN` | Postmark server token. Without it, no emails are sent. | |
| `NOTIFY_EMAIL` | Who gets the emails | `sella.rafaeli@gmail.com` |
| `POSTMARK_FROM` | Sender address. It must be a confirmed sender signature or domain in your Postmark account. | `NOTIFY_EMAIL` |
| `MAX_REPO_MB` | Refuse repos bigger than this after cloning | `500` |
| `MAX_QUEUE` | Refuse new scans when this many are waiting | `10` |

## What's stored

One document per scan in the `scans` collection: the repo URL and commit, status, timings, the log, a summary of each route (handler, input, data-access calls), the call trees, a timeline of events, and the LLM findings (score, verdict, reason, evidence and fix per route). Between the trace and the analysis, the full trace (with each route's code) is kept compressed in the `scan_traces` collection; it's deleted once the analysis succeeds. The scripts' own working data (`defs`, `routes`, `traces`, `findings` for the clone) is deleted after each step.

## Emails

With `POSTMARK_API_TOKEN` set, `NOTIFY_EMAIL` gets one email per action, each with a link to the scan:

- **Scan requested:** someone submitted a repo
- **Trace done:** the route count and frameworks, and whether it's ready to analyze
- **Scan failed:** the clone or trace failed, with the error
- **Analysis requested:** someone clicked **Run the analysis**
- **Analysis done:** likely and possible counts, and the top flagged routes
- **Analysis failed:** with the error

Emails are sent in the background; the server log shows `[email] sent: ...` or why a send failed. To try them without sending anything, set `POSTMARK_API_TOKEN=POSTMARK_API_TEST`: Postmark checks each request and delivers nothing.

## Limits

- Public repos over https only. Clones are shallow (`--depth 1`), and git hooks, LFS files and submodules are skipped.
- Time limits: 3 minutes to clone, 15 minutes to trace, 15 minutes to analyze.
- There's no login or rate limit per visitor. The queue cap and the host list are the only guards, and every analysis click costs LLM calls (about one per 10 routes). Set `ANALYZE=0` if you don't want to pay for anyone's scans.
