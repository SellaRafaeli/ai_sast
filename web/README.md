# Variablee Code (web app)

Variablee Code is the web app for `route_tracer.rb`. Anyone can paste a public repo URL and start a scan. The server clones the repo, traces its routes and shows them. A second button, **Run the analysis**, then asks an LLM which routes look like BOLA / IDOR. Results are saved in Mongo, the page refreshes itself while a step runs, and every action is emailed through Postmark.

| Page | What it shows |
|---|---|
| `/` | The scan form, benchmark numbers, links, and your 15 latest scans |
| `/scans` | Your scans with status, route count and results, 50 per page (admins: everyone's, with who ran each) |
| `/scans/<id>` | One scan: progress, the **Run the analysis** button, flagged routes with fixes, all traced routes, call trees, a timeline of what happened, and the log |
| `/scans/<id>.json` | One scan's full document |
| `/whitepaper`, `/whitepaper.pdf` | The white paper (`public/whitepaper.html`; rebuild the PDF with `web/build_whitepaper_pdf`) |
| `/blog` | Research index: the white paper and blog posts (`POSTS` in `web.rb`) |
| `/privacy`, `/tos` | Privacy Policy and Terms of Service (`LEGAL` in `web.rb`). All four pages open without signing in. |
| `#contact` on every page, `POST /contact` | "Contact us" form (linked from the top bar). Messages are saved in the `contacts` collection and emailed to `NOTIFY_EMAIL` with Reply-To set to the sender. A hidden field catches bots, and one IP can send at most 5 messages an hour. Works without signing in. |

The sign-in page also shows **Sign in with Microsoft** and **Sign in with SSO** buttons. They are not wired up yet: clicking one shows a "coming soon, use Google" note.

Signed-in users see and open only their own scans; someone else's scan is a 404. Admins (`ADMIN_EMAILS`) see everyone's. With sign-in off, everyone sees every scan.

Everything for the server is in [`web.rb`](web.rb): routes, background worker and HTML templates. It runs `../route_tracer.rb` and then `../analyze_bola.rb` as child processes, so the scripts stay unchanged and still work from the command line.

## Run it locally

You need Ruby 4.0, a running MongoDB, `tar`, and (to scan JS/TS repos) `node`. From the repo root:

```bash
bundle install
```

```bash
npm install
```

```bash
web/dev
```

Open http://localhost:4567. `web/dev` restarts the server by itself whenever `web/web.rb`, `llm.rb` or `.env` changes, and open pages reload themselves about a second later (it sets `LIVE_RELOAD=1`, which only `web/dev` uses). Changes to `route_tracer.rb` and `analyze_bola.rb` need no restart: each scan runs them fresh. A restart stops a trace in progress (start that scan again); an interrupted analysis goes back to "Ready to analyze". To run without auto-restart, use `bundle exec ruby web/web.rb`. By default it uses `mongodb://127.0.0.1:27017/route_tracer`. To use another database:

```bash
MONGODB_URI=mongodb://127.0.0.1:27017/my_db bundle exec ruby web/web.rb
```

## Deploy to Heroku

The files Heroku needs are at the repo root, because Heroku only looks there:

| File | Why |
|---|---|
| `Gemfile`, `Gemfile.lock` | Ruby version and the server's gems |
| `Procfile` | Start command: `bundle exec ruby web/web.rb` (no auto-restart on Heroku; `web/dev` is for local use) |
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

For Google sign-in (see [Sign in with Google](#sign-in-with-google)):

```bash
heroku config:set -a my-app GOOGLE_CLIENT_ID='...' GOOGLE_CLIENT_SECRET='...' SESSION_SECRET="$(openssl rand -hex 32)"
```

Keep the app at **one web dyno**: traces and analyses wait in an in-memory queue and run one at a time inside that process. Heroku restarts dynos about once a day. A trace running at that moment is marked failed and has to be started again. An analysis goes back to "Ready to analyze", so one more click reruns it.

To serve it at **ai-sast.com**, add the domain to the app, point your DNS at the target Heroku prints, and turn on Heroku's free certificates (sign-in needs https):

```bash
heroku domains:add -a my-app ai-sast.com
```

```bash
heroku certs:auto:enable -a my-app
```

## Sign in with Google

With `GOOGLE_CLIENT_ID` and `GOOGLE_CLIENT_SECRET` set, every page needs a Google sign-in. Each scan then records who started it and who ran its analysis; both show on the scan page, in the scans tables, in the event timeline and in the emails. Every person who signs in gets a document in the `users` collection (name, email, first and last sign-in, number of sign-ins). Without the two settings the site is open to anyone, scans are "anonymous", and the server log says so at startup.

To limit who can get in, set `ALLOWED_DOMAINS` (like `variablee.com`) and/or `ALLOWED_EMAILS`. Leave both unset to allow any Google account.

### Google Cloud Console, reusing an existing project

In [Google Cloud Console](https://console.cloud.google.com/), pick your existing project in the project picker at the top, then open **Google Auth Platform** (older consoles call it **APIs & Services → OAuth consent screen / Credentials**):

1. **Branding → Authorized domains:** add `ai-sast.com`. If Google asks you to prove you own it, do that in [Google Search Console](https://search.google.com/search-console) with a DNS TXT record.
2. **Audience:** user type **External** (anyone with a Google account) or **Internal** (only your Google Workspace). If the publishing status is **Testing**, only the listed test users can sign in; click **Publish app** to allow everyone. The scopes below are basic ones, so publishing needs no Google review.
3. **Data Access:** make sure the scopes include `openid`, `.../auth/userinfo.email` and `.../auth/userinfo.profile`.
4. **Clients:** create a new **Web application** client for this app (cleaner: its own secret and redirect list), or edit an existing one. Under **Authorized redirect URIs** add every address people will use, exactly:
   - `https://ai-sast.com/auth/google/callback`
   - `https://www.ai-sast.com/auth/google/callback`, if `www` serves the app too
   - `https://my-app.herokuapp.com/auth/google/callback`, if people may use the Heroku address
   - `http://localhost:4567/auth/google/callback`, for running it locally

   **Authorized JavaScript origins** aren't needed. Copy the client ID and secret into `GOOGLE_CLIENT_ID` and `GOOGLE_CLIENT_SECRET`.

Changes can take a few minutes to apply. A `redirect_uri_mismatch` error from Google means the address in the browser isn't in that list.

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
| `POSTMARK_FROM` | Sender address. It must be a confirmed sender signature or domain in your Postmark account. | `sella@indydevs.com` |
| `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET` | Google OAuth client. With both set, every page needs a Google sign-in. | off |
| `SESSION_SECRET` | Signs the sign-in cookie. Without it, everyone is signed out on each restart. | random |
| `ALLOWED_DOMAINS` | Only Google accounts with these email domains may sign in, comma-separated | any |
| `ALLOWED_EMAILS` | Only these Google accounts may sign in, comma-separated (combined with `ALLOWED_DOMAINS`) | any |
| `ADMIN_EMAILS` | These accounts see every user's scans, comma-separated | `sella.rafaeli@gmail.com` |
| `VISIT_EMAILS` | `0` to stop the email for each page visit (visits are still recorded in the `visits` collection). Repeat views of the same page by the same visitor within `VISIT_EMAIL_QUIET` minutes, and bots, are never emailed. | on, `10` |
| `DAILY_SUMMARY`, `DAILY_SUMMARY_HOUR` | Daily email to `NOTIFY_EMAIL` with the last 24 hours of visits, new users, scans, results and contact messages, sent at this hour (UTC). `0` turns it off. Admins can preview it at `/admin/daily-summary` (add `?send=1` to send it now). On an eco dyno that sleeps, it's sent when the dyno wakes. | on, `6` |
| `ANALYZE_BATCH`, `ANALYZE_JOBS` | Routes per LLM call, and LLM calls in parallel, for the analysis. Results appear on the scan page as each call finishes (`analyze_bola.rb --partial`), so smaller batches show results sooner. | `5`, `4` |
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

- Public repos over https only. GitHub, GitLab and Bitbucket repos are downloaded as a `.tar.gz` of the default branch (no `git` needed, which matters on Heroku-24, where `git` exists only at build time). Other hosts, allowed with `ALLOWED_GIT_HOSTS="*"`, use a shallow `git clone` and need `git` on the server. LFS files and submodules are not fetched.
- Time limits: 3 minutes to clone, 15 minutes to trace, 15 minutes to analyze.
- There's no login or rate limit per visitor. The queue cap and the host list are the only guards, and every analysis click costs LLM calls (about one per 10 routes). Set `ANALYZE=0` if you don't want to pay for anyone's scans.
