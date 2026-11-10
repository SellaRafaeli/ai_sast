#!/usr/bin/env ruby
# web.rb — BOLA Detector, by Variablee: a small public web page for route_tracer.rb.
#
# Anyone can paste a git repo URL and start a scan. Each scan:
#   1. CLONE   git clone --depth 1 into a temp folder on the dyno's disk
#   2. TRACE   ruby route_tracer.rb <clone> --with-source   (the route list and call trees)
#              -> results in Mongo (`scans`); the full trace is kept compressed (`scan_traces`); the clone is deleted
#   3. ANALYZE when the visitor clicks "Run the analysis": ruby analyze_bola.rb on the kept trace
#              (an LLM scores each route for BOLA/IDOR; unavailable when no LLM key is set or ANALYZE=0)
# The scan page refreshes itself every few seconds while a step runs. Every step that starts, ends or
# fails is recorded on the scan and emailed through Postmark (when POSTMARK_API_TOKEN is set).
#
#   bundle exec ruby web/web.rb      # http://localhost:4567  (see web/README.md)
#
# Env:
#   MONGODB_URI        Mongo connection string (default mongodb://127.0.0.1:27017/route_tracer).
#                      If it names no database, `route_tracer` is used.
#   PORT               port to listen on (Heroku sets it; default 4567)
#   ANTHROPIC_API_KEY / OPEN_AI_API_KEY   LLM key for the analysis step (see llm.rb)
#   ANALYZE=0          trace only, no LLM calls
#   POSTMARK_API_TOKEN Postmark server token; without it no emails are sent
#   NOTIFY_EMAIL       who gets the emails (default sella.rafaeli@gmail.com)
#   POSTMARK_FROM      sender address, a verified Postmark sender signature (default NOTIFY_EMAIL)
#   GOOGLE_CLIENT_ID / GOOGLE_CLIENT_SECRET   with both set, every page needs a Google sign-in
#   SESSION_SECRET     signs the sign-in cookie; ALLOWED_DOMAINS / ALLOWED_EMAILS limit who may sign in
#   ALLOWED_GIT_HOSTS  comma-separated hosts users may clone from (default github.com,gitlab.com,bitbucket.org;
#                      `*` allows any https host)
#   MAX_REPO_MB        refuse repos bigger than this after cloning (default 500)
#   MAX_QUEUE          refuse new scans when this many are waiting (default 10)
#
# Scans run one at a time in a background thread, so run one web process (Heroku: one dyno).

require "sinatra"
require "mongo"
require "json"
require "open3"
require "securerandom"
require "tmpdir"
require "fileutils"
require "rbconfig"
require "zlib"
require "digest"
require "net/http"
require_relative "../llm"

Encoding.default_external = Encoding::UTF_8 # trace files and logs are UTF-8 even under a C/ASCII locale
LLM.load_dotenv
Mongo::Logger.logger.level = Logger::WARN

TRACER_DIR    = File.expand_path("..", __dir__) # route_tracer.rb, analyze_bola.rb, llm.rb
CLONE_TIMEOUT = 180 # seconds
TRACE_TIMEOUT = 900
ANALYZE_TIMEOUT = 900
MAX_REPO_MB   = Integer(ENV.fetch("MAX_REPO_MB", "500"))
MAX_QUEUE     = Integer(ENV.fetch("MAX_QUEUE", "10"))
MAX_LOG_CHARS = 200_000
MAX_TREE_CHARS = 3_000_000 # keeps a scan document under Mongo's 16 MB limit
ALLOWED_HOSTS = ENV.fetch("ALLOWED_GIT_HOSTS", "github.com,gitlab.com,bitbucket.org").split(",").map(&:strip)
ACTIVE        = %w[queued cloning tracing analysis_queued analyzing].freeze # a step is waiting or running
NOTIFY_EMAIL  = ENV.fetch("NOTIFY_EMAIL", "sella.rafaeli@gmail.com")
POSTMARK_FROM = ENV.fetch("POSTMARK_FROM", NOTIFY_EMAIL)
MAX_TRACE_BYTES = 15_000_000 # compressed trace kept for the analysis must fit in one Mongo document
FRAMEWORKS    = %w[Rails Sinatra Flask FastAPI Django Express Koa Fastify NestJS].freeze
FINDING_KEYS  = %w[rank score verdict route handler framework object data_access auth_checks evidence reason fix].freeze

# Why the LLM step won't run, or nil when it will.
def analysis_off_reason
  return "turned off on this server (ANALYZE=0)" if ENV["ANALYZE"] == "0"
  return "no LLM API key is set on this server" unless LLM.available?
  nil
end

# The tracer reads MONGO_URL and writes its working data there, so it must point at a named database
# (a URI without one would land in `admin`, which hosted Mongo refuses).
def mongo_url
  url = ENV.fetch("MONGODB_URI", "mongodb://127.0.0.1:27017/route_tracer")
  m = url.match(%r{\A(mongodb(?:\+srv)?://[^/?]+)(/[^?]*)?(\?.*)?\z}) or return url
  m[2].to_s.delete_prefix("/").empty? ? "#{m[1]}/route_tracer#{m[3]}" : url
end

MONGO_URL = mongo_url
DB        = Mongo::Client.new(MONGO_URL).database
SCANS     = DB[:scans]
SCANS.indexes.create_one(created_at: -1)
TRACES    = DB[:scan_traces] # { _id: scan id, data: zlib-compressed trace.json } until the analysis runs
JOBS      = Queue.new        # [:trace, id] or [:analyze, id]

# "https://github.com/OWASP/railsgoat" -> ["OWASP/railsgoat", "github.com"]
def repo_name(url)
  uri = URI.parse(url.to_s)
  [uri.path.delete_prefix("/").delete_suffix(".git"), uri.host]
rescue URI::InvalidURIError
  [url.to_s, ""]
end

# ─────────────────────────── events and emails ───────────────────────────

# Record what happened on the scan (shown on its page) and email it.
# `by` is the signed-in user who did it, when a person (not the worker) did it.
def event(id, subject, details = "", send_email: true, by: nil)
  entry = { "at" => Time.now.utc, "text" => subject }
  entry["by"] = by.slice("email", "name") if by
  SCANS.update_one({ _id: id }, { "$push" => { "events" => entry } })
  email(id, by ? "#{subject} by #{by['name']}" : subject, details) if send_email
end

# Send one email through Postmark's API in the background; a failure is only logged.
def email(id, subject, details)
  token = ENV["POSTMARK_API_TOKEN"].to_s
  return if token.empty?
  scan = SCANS.find(_id: id).projection(repo_url: 1, base_url: 1, requested_by: 1).first or return
  name, = repo_name(scan["repo_url"])
  link = "#{scan['base_url']}/scans/#{id}"
  owner = scan["requested_by"] ? "#{scan['requested_by']['name']} <#{scan['requested_by']['email']}>" : "anonymous"
  body = { "From" => POSTMARK_FROM, "To" => NOTIFY_EMAIL, "Subject" => "BOLA Detector · #{name}: #{subject}",
           "TextBody" => [subject, details, "Repo: #{scan['repo_url']}", "Scan started by: #{owner}", "Scan: #{link}",
                          "— BOLA Detector, by Variablee"].reject(&:empty?).join("\n\n"),
           "MessageStream" => "outbound" }
  Thread.new do
    res = Net::HTTP.post(URI("https://api.postmarkapp.com/email"), JSON.dump(body),
                         "Accept" => "application/json", "Content-Type" => "application/json",
                         "X-Postmark-Server-Token" => token)
    warn(res.is_a?(Net::HTTPSuccess) ? "[email] sent: #{body["Subject"]}" : "[email] Postmark #{res.code}: #{res.body}")
  rescue => e
    warn "[email] #{e.class}: #{e.message}"
  end
end

# ─────────────────────────── scanning ───────────────────────────

# https://host/owner/repo(.git) only: no ssh, file://, ext::, or flags that git could mistake for options.
def valid_repo_url(url)
  uri = URI.parse(url.to_s.strip)
  return nil unless uri.is_a?(URI::HTTPS) && uri.host && uri.userinfo.nil? && uri.query.nil? && uri.fragment.nil?
  return nil unless ALLOWED_HOSTS.include?("*") || ALLOWED_HOSTS.include?(uri.host.downcase)
  return nil unless uri.path.match?(%r{\A/[\w.\-~]+(/[\w.\-~]+)+/?\z})
  uri.to_s.chomp("/")
rescue URI::InvalidURIError
  nil
end

def update(id, fields) = SCANS.update_one({ _id: id }, { "$set" => fields })

def append_log(id, text)
  scan = SCANS.find(_id: id).projection(log: 1).first
  log = (scan["log"].to_s + text)
  log = "... (earlier lines cut)\n" + log[-MAX_LOG_CHARS..] if log.size > MAX_LOG_CHARS
  update(id, "log" => log)
end

# Run a command, copy its output into the scan's log every couple of seconds, kill it on timeout.
# Returns [success?, output].
def run(id, env, cmd, chdir:, timeout:)
  append_log(id, "$ #{cmd.map { |a| a.include?(' ') ? a.inspect : a }.join(' ')}\n")
  out = +""
  pending = +""
  last_flush = Time.now
  status = nil
  Open3.popen2e(env, *cmd, chdir: chdir, pgroup: true) do |stdin, io, wait|
    stdin.close
    deadline = Time.now + timeout
    loop do
      if Time.now > deadline
        Process.kill("KILL", -wait.pid) rescue nil
        pending << "\n[timeout] stopped after #{timeout}s\n"
        break
      end
      ready = IO.select([io], nil, nil, 1)
      if ready
        chunk = io.read_nonblock(16_384, exception: false)
        break if chunk.nil? # EOF
        if chunk.is_a?(String)
          chunk = chunk.force_encoding(Encoding::UTF_8).scrub
          out << chunk
          pending << chunk
        end
      end
      if pending.size.positive? && Time.now - last_flush > 2
        append_log(id, pending)
        pending = +""
        last_flush = Time.now
      end
    end
    status = wait.value
  end
  append_log(id, pending) unless pending.empty?
  [status&.success? || false, out]
end

# Command to run one of the scripts with unbuffered output, so its log lines (and the analysis
# progress) reach the page as they happen. Setting $0 keeps route_tracer.rb's `if $PROGRAM_NAME == __FILE__` true.
def ruby_script(name, *args)
  [RbConfig.ruby, "-e", "$stdout.sync = true; $0 = ARGV.shift; load $0", File.join(TRACER_DIR, name), *args]
end

def dir_mb(dir)
  Dir.glob("**/*", File::FNM_DOTMATCH, base: dir).sum { |f| File.size?(File.join(dir, f)) || 0 } / 1_048_576.0
end

# The fields of a trace worth showing; the code itself (sources, source_text) is left out.
def route_summary(t)
  {
    "route" => t["route"], "handler" => t["handler"], "framework" => t["framework"],
    "input" => t["input"] || [], "model_calls" => (t["model_calls"] || []).uniq.first(20),
    "external" => (t["external"] || []).uniq.first(10),
    "methods" => (t["methods"] || []).size, "files" => (t["files"] || []).size
  }
end

def scan(id)
  doc = SCANS.find(_id: id).first or return
  work = Dir.mktmpdir("scan-")
  repo_dir = File.join(work, "repo")
  # Point both scripts at the same database and keep git from prompting or fetching LFS blobs.
  env = { "MONGO_URL" => MONGO_URL, "GIT_TERMINAL_PROMPT" => "0", "GIT_ALLOW_PROTOCOL" => "https",
          "GIT_LFS_SKIP_SMUDGE" => "1" }

  # 1. CLONE
  update(id, "status" => "cloning", "started_at" => Time.now.utc)
  event(id, "Scan started", send_email: false)
  ok, = run(id, env, ["git", "-c", "core.hooksPath=/dev/null", "clone", "--depth", "1", "--single-branch",
                      "--no-tags", "--", doc["repo_url"], repo_dir], chdir: work, timeout: CLONE_TIMEOUT)
  raise "git clone failed (is the repo public?)" unless ok
  repo_dir = File.realpath(repo_dir)
  commit = Open3.capture2("git", "-C", repo_dir, "rev-parse", "HEAD")[0].strip
  size = dir_mb(repo_dir)
  raise format("repo is %.0f MB, over the %d MB limit", size, MAX_REPO_MB) if size > MAX_REPO_MB
  update(id, "commit" => commit, "repo_mb" => size.round(1))

  # 2. TRACE
  update(id, "status" => "tracing")
  trace_json = File.join(work, "trace.json")
  ok, = run(id, env, ruby_script("route_tracer.rb", repo_dir, "--with-source", "--out", trace_json),
            chdir: work, timeout: TRACE_TIMEOUT)
  raise "the tracer failed (see the log)" unless ok && File.file?(trace_json)
  traces = JSON.parse(File.read(trace_json))
  tree = File.read(trace_json.sub(/\.json\z/, ".txt")) rescue ""
  tree = tree[0, MAX_TREE_CHARS] + "\n... (cut: too long to store)\n" if tree.size > MAX_TREE_CHARS

  frameworks = traces.map { |t| t["framework"] }.tally
  update(id, "routes" => traces.map { |t| route_summary(t) }, "route_count" => traces.size, "tree" => tree,
             "frameworks" => frameworks, "clone_path" => repo_dir, "finished_at" => Time.now.utc)
  fw = frameworks.map { |k, v| "#{v} #{k}" }.join(", ")
  summary = "Traced #{traces.size} routes#{fw.empty? ? '' : " (#{fw})"} at commit #{commit[0, 10]}."

  # Keep the trace (with each route's code) for the analysis step, which waits for a click.
  reason = analysis_off_reason
  data = Zlib::Deflate.deflate(File.binread(trace_json), Zlib::BEST_COMPRESSION)
  if traces.empty?
    update(id, "status" => "done", "analysis_note" => "No routes that take input, so there is nothing to analyze.")
    event(id, "Trace done: no routes found", summary)
  elsif reason
    update(id, "status" => "done", "analysis_note" => "The LLM analysis isn't available: #{reason}. Showing the traced routes only.")
    event(id, "Trace done: #{traces.size} routes", "#{summary}\nThe LLM analysis isn't available: #{reason}.")
  elsif data.bytesize > MAX_TRACE_BYTES
    update(id, "status" => "done", "analysis_note" => "This trace is too big to keep for the LLM analysis. Showing the traced routes only.")
    event(id, "Trace done: #{traces.size} routes", "#{summary}\nToo big to keep for the LLM analysis.")
  else
    TRACES.replace_one({ _id: id }, { _id: id, data: BSON::Binary.new(data) }, upsert: true)
    update(id, "status" => "traced")
    event(id, "Trace done: #{traces.size} routes, ready to analyze", "#{summary}\nOpen the scan page and click \"Run the analysis\" to score the routes with the LLM.")
  end
rescue => e
  append_log(id, "\n[error] #{e.message}\n") rescue nil
  update(id, "status" => "failed", "error" => e.message, "finished_at" => Time.now.utc)
  event(id, "Scan failed", e.message)
ensure
  FileUtils.rm_rf(work) if work
  # The tracer keeps its own working copy in Mongo, keyed by the clone path; this scan owns it.
  %i[defs routes traces].each { |c| DB[c].delete_many(repo: repo_dir) } if repo_dir rescue nil
end

# 3. ANALYZE: the LLM scores each traced route, from the trace kept in `scan_traces`.
def analyze(id)
  doc = SCANS.find(_id: id).first or return
  work = Dir.mktmpdir("analyze-")
  update(id, "status" => "analyzing", "model" => LLM.describe, "analysis_started_at" => Time.now.utc, "analysis_error" => nil)
  event(id, "Analysis started", send_email: false)
  saved = TRACES.find(_id: id).first or raise "the saved trace is gone; please scan the repo again"
  trace_json = File.join(work, "trace.json")
  File.binwrite(trace_json, Zlib::Inflate.inflate(saved["data"].data))
  report = File.join(work, "bola_report")
  ok, = run(id, { "MONGO_URL" => MONGO_URL }, ruby_script("analyze_bola.rb", trace_json, "--out", report),
            chdir: work, timeout: ANALYZE_TIMEOUT)
  raise "the analysis failed (see the log)" unless ok && File.file?("#{report}.json")

  r = JSON.parse(File.read("#{report}.json"))
  findings = r["routes"].map { |f| f.slice(*FINDING_KEYS) }
  verdicts = findings.map { |f| f["verdict"] }.tally
  top_finding = findings.find { |f| %w[likely possible].include?(f["verdict"]) }&.slice("route", "score", "verdict")
  update(id, "status" => "done", "findings" => findings, "model" => r["model"], "verdicts" => verdicts, "top_finding" => top_finding,
             "analysis_finished_at" => Time.now.utc)
  TRACES.delete_one(_id: id)
  top = findings.select { |f| %w[likely possible].include?(f["verdict"]) }.first(10)
                .map { |f| "  #{f['score']}  #{f['verdict'].ljust(8)} #{f['route']}" }
  event(id, "Analysis done: #{verdicts['likely'].to_i} likely, #{verdicts['possible'].to_i} possible BOLA",
        "#{findings.size} routes scored by #{r['model']}.#{top.any? ? "\n\nTop flagged routes:\n#{top.join("\n")}" : ''}")
rescue => e
  append_log(id, "\n[error] #{e.message}\n") rescue nil
  # The trace is still saved (unless it's gone), so the visitor can click again.
  update(id, "status" => (TRACES.find(_id: id).first ? "traced" : "failed"), "analysis_error" => e.message, "error" => e.message)
  event(id, "Analysis failed", e.message)
ensure
  FileUtils.rm_rf(work) if work
  DB[:findings].delete_many(repo: doc["clone_path"]) if doc && doc["clone_path"] rescue nil # analyze_bola.rb's own copy
end

# After a restart (Heroku restarts dynos daily) the queue is empty. A trace can't resume (its clone is
# gone), but an analysis can: its trace is still saved, so put it back to "traced" for another click.
SCANS.update_many({ status: { "$in" => %w[queued cloning tracing] } },
                  { "$set" => { status: "failed", error: "the server restarted during the scan; please scan again" } })
SCANS.update_many({ status: { "$in" => %w[analysis_queued analyzing] } },
                  { "$set" => { status: "traced", analysis_error: "the server restarted during the analysis; please run it again" } })

Thread.new do
  loop do
    kind, id = JOBS.pop
    begin
      kind == :analyze ? analyze(id) : scan(id)
    rescue => e
      warn "[worker] #{kind} #{id}: #{e.class}: #{e.message}"
    end
  end
end

# ─────────────────────────── web ───────────────────────────

set :bind, "0.0.0.0"
set :port, Integer(ENV.fetch("PORT", "4567"))
set :server, "puma"

# ─────────────────────────── sign in with Google ───────────────────────────
# With GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET set, every page needs a Google sign-in (OpenID Connect,
# authorization-code flow, no extra gems). Without them the site is open and scans are "anonymous".

GOOGLE_CLIENT_ID     = ENV["GOOGLE_CLIENT_ID"].to_s.strip
GOOGLE_CLIENT_SECRET = ENV["GOOGLE_CLIENT_SECRET"].to_s.strip
AUTH_ON              = !GOOGLE_CLIENT_ID.empty? && !GOOGLE_CLIENT_SECRET.empty?
ALLOWED_EMAILS       = ENV["ALLOWED_EMAILS"].to_s.downcase.split(",").map(&:strip).reject(&:empty?)
ALLOWED_DOMAINS      = ENV["ALLOWED_DOMAINS"].to_s.downcase.split(",").map(&:strip).reject(&:empty?)
USERS                = DB[:users] # one document per person who signed in
PUBLIC_PATHS         = %w[/login /logout /auth/google /auth/google/callback /privacy /tos /terms].freeze
if AUTH_ON
  warn "[auth] Google sign-in is ON#{ALLOWED_DOMAINS.any? || ALLOWED_EMAILS.any? ? " (only #{(ALLOWED_DOMAINS + ALLOWED_EMAILS).join(', ')})" : ''}"
else
  warn "[auth] Google sign-in is OFF: GOOGLE_CLIENT_ID / GOOGLE_CLIENT_SECRET not set, so the site is open to anyone"
end

# The cookie session holds only who is signed in. Sinatra needs a 64+ character secret, so hash whatever
# SESSION_SECRET is; without one, a random secret signs everyone out on every restart.
set :sessions, same_site: :lax, httponly: true, expire_after: 30 * 24 * 3600,
               secure: ENV["RACK_ENV"] == "production"
set :session_secret, Digest::SHA512.hexdigest(ENV.fetch("SESSION_SECRET") { SecureRandom.hex(64) })

def email_allowed?(email)
  return true if ALLOWED_EMAILS.empty? && ALLOWED_DOMAINS.empty?
  ALLOWED_EMAILS.include?(email) || ALLOWED_DOMAINS.include?(email.split("@").last)
end

before do
  next unless AUTH_ON
  next if PUBLIC_PATHS.include?(request.path_info)
  next if session[:user]
  session[:return_to] = request.fullpath if request.get?
  redirect to("/login")
end

get "/login" do
  redirect to("/") if session[:user] || !AUTH_ON
  @error = params[:error]
  @title = "Sign in"
  erb :login
end

# The header's Sign out button posts here; a plain link to /logout works too.
%w[get post].each do |verb|
  send(verb, "/logout") do
    session.clear
    redirect to(AUTH_ON ? "/login" : "/")
  end
end

# Placeholder legal pages (Google's consent screen asks for links to both).
LEGAL = {
  "privacy" => ["Privacy Policy", [
    ["What we collect", "When you sign in with Google we receive your name, email address and profile picture. For each scan we store the repository URL you entered, who started it, and the scan's results."],
    ["How we use it", "To run the scans you ask for, show you their results, and know who ran each scan."],
    ["Sharing", "Repository code is sent to an AI model provider to analyze it. We don't sell your data."],
    ["Contact", "Contact details will be added here."]
  ]],
  "tos" => ["Terms of Service", [
    ["Using BOLA Detector", "Only scan repositories you're allowed to analyze. Results are automated estimates from a static trace of the code, for manual review; they aren't proof that a bug exists or doesn't."],
    ["No warranty", "The service is provided as is, without any warranty."],
    ["Changes", "These terms may change; the date above shows the latest version."]
  ]]
}.freeze

%w[privacy tos terms].each do |page|
  get "/#{page}" do
    @title, @sections = LEGAL.fetch(page == "terms" ? "tos" : page)
    erb :legal
  end
end

# Step 1: send the visitor to Google, with a one-time `state` to match on the way back.
get "/auth/google" do
  halt 404 unless AUTH_ON
  session[:oauth_state] = SecureRandom.hex(16)
  query = URI.encode_www_form(client_id: GOOGLE_CLIENT_ID, redirect_uri: "#{request.base_url}/auth/google/callback",
                              response_type: "code", scope: "openid email profile",
                              state: session[:oauth_state], prompt: "select_account")
  redirect "https://accounts.google.com/o/oauth2/v2/auth?#{query}"
end

# Step 2: Google sends the visitor back with a code; trade it for an ID token naming who they are.
get "/auth/google/callback" do
  halt 404 unless AUTH_ON
  fail_login = ->(msg) { redirect to("/login?error=" + Rack::Utils.escape(msg)) }
  expected = session.delete(:oauth_state)
  fail_login.("Sign-in was cancelled.") if params[:error]
  fail_login.("Sign-in expired, please try again.") if expected.nil? || !Rack::Utils.secure_compare(expected, params[:state].to_s)

  res = Net::HTTP.post_form(URI("https://oauth2.googleapis.com/token"),
                            code: params[:code].to_s, client_id: GOOGLE_CLIENT_ID, client_secret: GOOGLE_CLIENT_SECRET,
                            redirect_uri: "#{request.base_url}/auth/google/callback", grant_type: "authorization_code")
  unless res.is_a?(Net::HTTPSuccess)
    warn "[auth] token exchange failed #{res.code}: #{res.body}"
    fail_login.("Google sign-in failed, please try again.")
  end
  # The ID token came straight from Google over TLS, so its claims can be read without checking the signature
  # (OpenID Connect Core 3.1.3.7); still check it was issued for this app.
  claims = JSON.parse(JSON.parse(res.body)["id_token"].to_s.split(".")[1].to_s.tr("-_", "+/").unpack1("m"))
  fail_login.("Google sign-in failed, please try again.") unless claims["aud"] == GOOGLE_CLIENT_ID &&
    %w[accounts.google.com https://accounts.google.com].include?(claims["iss"]) && claims["exp"].to_i > Time.now.to_i
  email = claims["email"].to_s.downcase
  fail_login.("Your Google account has no verified email.") unless claims["email_verified"] && !email.empty?
  fail_login.("#{email} isn't allowed to use this site.") unless email_allowed?(email)

  user = { "email" => email, "name" => claims["name"] || email, "picture" => claims["picture"] }
  now = Time.now.utc
  USERS.update_one({ _id: email }, { "$set" => user.merge("last_login_at" => now),
                                     "$setOnInsert" => { "first_login_at" => now }, "$inc" => { "logins" => 1 } },
                   upsert: true)
  return_to = session.delete(:return_to).to_s
  session.clear # new session id after sign-in
  session[:user] = user
  redirect to(return_to.start_with?("/") && !return_to.start_with?("//") ? return_to : "/")
end

helpers do
  def h(s) = Rack::Utils.escape_html(s.is_a?(Array) ? s.join("; ") : s.to_s)

  # The signed-in Google user ({ email, name, picture }), or nil when sign-in is off.
  def current_user = session[:user]
  def who(user = current_user) = user ? "#{user['name']} (#{user['email']})" : "Someone (anonymous)"
  def user_name(user) = user ? (user["name"] || user["email"]) : "anonymous"
  def when_s(t) = t ? t.utc.strftime("%b %-d, %H:%M UTC") : ""
  def present?(v) = !(v.nil? || (v.respond_to?(:empty?) && v.empty?))

  def duration(from, to)
    return "" unless from
    secs = ((to || Time.now.utc) - from).round
    secs < 60 ? "#{secs}s" : "#{secs / 60}m #{secs % 60}s"
  end
  def took(scan) = duration(scan["started_at"], scan["finished_at"])                       # clone + trace
  def analysis_took(scan) = duration(scan["analysis_started_at"], scan["analysis_finished_at"])

  STATUS_LABEL = { "queued" => "Waiting", "cloning" => "Cloning", "tracing" => "Tracing", "traced" => "Ready to analyze",
                   "analysis_queued" => "Analysis waiting", "analyzing" => "Analyzing", "done" => "Done", "failed" => "Failed" }.freeze
  def status_pill(status) = %(<span class="pill pill-#{h status}">#{h STATUS_LABEL.fetch(status, status)}</span>)

  # Stepper: which step is current (0 waiting .. 4 done)
  def step_index(status)
    { "queued" => 0, "cloning" => 1, "tracing" => 2, "traced" => 3, "analysis_queued" => 3, "analyzing" => 3, "done" => 4 }.fetch(status, -1)
  end

  def llm_calls(scan) = (scan["route_count"].to_i / 10.0).ceil

  # [batches done, total] while the LLM step runs, from analyze_bola.rb's log lines
  def analysis_progress(log)
    total = log.to_s[/\[batch\] (\d+) LLM calls/, 1]&.to_i
    total && [log.to_s.scan(/\[ask\] batch \d+\//).size, total]
  end

  def verdict_counts(scan) = scan["verdicts"] || (scan["findings"] || []).map { |f| f["verdict"] }.tally

  def score_color(score)
    s = score.to_i
    s >= 70 ? "var(--red)" : s >= 40 ? "var(--amber)" : "var(--muted)"
  end
end

get "/" do
  @scans = SCANS.find.sort(created_at: -1).limit(15).projection(log: 0, tree: 0, routes: 0, findings: 0, events: 0).to_a
  @error = params[:error]
  @analysis_off = analysis_off_reason
  erb :index
end

post "/scans" do
  url = valid_repo_url(params[:repo_url])
  unless url
    hosts = ALLOWED_HOSTS.include?("*") ? "any host" : ALLOWED_HOSTS.join(", ")
    redirect to("/?error=" + Rack::Utils.escape("Enter a public https repo URL, like https://github.com/owner/repo (allowed: #{hosts})"))
  end
  # Same repo already waiting or running: show that scan instead of starting another.
  if (existing = SCANS.find(repo_url: url, status: { "$in" => ACTIVE }).first)
    redirect to("/scans/#{existing['_id']}")
  end
  if JOBS.size >= MAX_QUEUE
    redirect to("/?error=" + Rack::Utils.escape("Too many scans are waiting. Please try again in a few minutes."))
  end
  id = SecureRandom.hex(8)
  SCANS.insert_one(_id: id, repo_url: url, status: "queued", created_at: Time.now.utc, log: "", events: [],
                   base_url: request.base_url, # for links in the emails
                   requested_by: current_user)
  event(id, "Scan requested", "#{who} asked to scan #{url}. #{JOBS.size} scan(s) ahead of it.", by: current_user)
  JOBS << [:trace, id]
  redirect to("/scans/#{id}")
end

# The second button: run the LLM analysis on a finished trace.
post "/scans/:id/analyze" do
  scan = SCANS.find(_id: params[:id]).first or halt 404, "No such scan"
  if scan["status"] == "traced" && !analysis_off_reason && JOBS.size < MAX_QUEUE
    # Only one click wins: the update matches only while the scan is still "traced".
    res = SCANS.update_one({ _id: scan["_id"], status: "traced" },
                           { "$set" => { status: "analysis_queued", analysis_requested_by: current_user } })
    if res.modified_count == 1
      event(scan["_id"], "Analysis requested", "#{who} asked for the analysis: about #{llm_calls(scan)} LLM calls for " \
                                               "#{scan['route_count']} routes.", by: current_user)
      JOBS << [:analyze, scan["_id"]]
    end
  end
  redirect to("/scans/#{scan['_id']}")
end

# Every scan, newest first, 50 per page.
get "/scans" do
  @page = [params[:page].to_i, 1].max
  @total = SCANS.count_documents({})
  @scans = SCANS.find.sort(created_at: -1).skip((@page - 1) * 50).limit(50)
                .projection(log: 0, tree: 0, routes: 0, findings: 0, events: 0).to_a
  @pages = [(@total / 50.0).ceil, 1].max
  @title = "All scans"
  erb :scans
end

get "/scans/:id.json" do
  scan = SCANS.find(_id: params[:id]).first or halt 404
  content_type :json
  JSON.pretty_generate(scan)
end

get "/scans/:id" do
  @scan = SCANS.find(_id: params[:id]).first or halt 404, "No such scan"
  @active = ACTIVE.include?(@scan["status"])
  @ahead = @scan["status"] == "queued" ? SCANS.count_documents(status: "queued", created_at: { "$lt" => @scan["created_at"] }) : 0
  @title = repo_name(@scan["repo_url"]).first
  erb :scan
end

__END__

@@ layout
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<% if @active %><meta http-equiv="refresh" content="3"><% end %>
<title><%= @title ? "#{h @title} · " : '' %>BOLA Detector by Variablee</title>
<link rel="icon" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'><text y='.9em' font-size='90'>🎯</text></svg>">
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;600&display=swap">
<style>
  :root {
    --bg: #f6f5fb; --surface: #ffffff; --surface-2: #f1f0f7; --fg: #19172b; --muted: #6b6880; --line: #e6e4ef;
    --accent: #7c3aed; --red: #e11d48; --red-bg: #fff1f3; --amber: #d97706; --amber-bg: #fff8eb;
    --green: #059669; --green-bg: #ecfdf5; --shadow: 0 1px 2px rgba(25,23,43,.06), 0 8px 24px rgba(25,23,43,.06);
  }
  @media (prefers-color-scheme: dark) {
    :root {
      --bg: #0f0e17; --surface: #1a1826; --surface-2: #232133; --fg: #f3f2fa; --muted: #a29fb8; --line: #2e2b40;
      --accent: #a78bfa; --red: #fb7185; --red-bg: #2a1520; --amber: #fbbf24; --amber-bg: #2a2112;
      --green: #34d399; --green-bg: #0f2620; --shadow: 0 1px 2px rgba(0,0,0,.3), 0 8px 24px rgba(0,0,0,.25);
    }
  }
  * { box-sizing: border-box; }
  body { margin: 0; background: var(--bg); color: var(--fg); font: 15px/1.55 Inter, -apple-system, system-ui, sans-serif; }
  a { color: var(--accent); text-decoration: none; } a:hover { text-decoration: underline; }
  code, pre, .mono { font-family: "JetBrains Mono", ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 13px; }

  /* ── festive header ── */
  .hero { position: relative; overflow: hidden; color: #fff; padding: 56px 16px 72px;
          background: linear-gradient(120deg, #4c1d95, #7c3aed, #db2777, #f59e0b, #06b6d4, #4c1d95);
          background-size: 400% 400%; animation: shift 22s ease infinite; }
  .hero.compact { padding: 28px 16px 40px; }
  @keyframes shift { 0% { background-position: 0% 50%; } 50% { background-position: 100% 50%; } 100% { background-position: 0% 50%; } }
  .hero::after { content: ""; position: absolute; inset: 0; pointer-events: none;
                 background: radial-gradient(circle at 20% 10%, rgba(255,255,255,.18), transparent 40%),
                             radial-gradient(circle at 85% 90%, rgba(255,255,255,.12), transparent 45%); }
  .confetti { position: absolute; top: -20px; width: 10px; height: 14px; border-radius: 2px; opacity: .85;
              animation: fall linear infinite; pointer-events: none; }
  .confetti.round { border-radius: 50%; width: 9px; height: 9px; }
  @keyframes fall { 0% { transform: translateY(-20px) rotate(0deg); } 100% { transform: translateY(520px) rotate(540deg); } }
  @media (prefers-reduced-motion: reduce) { .hero, .confetti { animation: none; } .confetti { display: none; } }
  .hero-inner { position: relative; z-index: 1; max-width: 1040px; margin: 0 auto; }
  .brand { display: inline-flex; align-items: center; gap: 10px; color: #fff; font-weight: 700; letter-spacing: .02em; }
  .brand:hover { text-decoration: none; opacity: .9; }
  .brand .by { font-weight: 500; opacity: .8; margin-left: 4px; }
  .topbar { display: flex; justify-content: space-between; align-items: center; gap: 12px; flex-wrap: wrap; }
  .me { display: flex; align-items: center; gap: 10px; font-size: 14px; padding: 4px 4px 4px 4px; border-radius: 99px;
        background: rgba(255,255,255,.18); backdrop-filter: blur(6px); }
  .me img, .me .avatar { width: 34px; height: 34px; border-radius: 50%; flex: none; }
  .me .avatar { display: grid; place-items: center; background: rgba(255,255,255,.3); font-weight: 800; }
  .me-text { display: flex; flex-direction: column; line-height: 1.2; color: #fff; min-width: 0; }
  .me-text b { font-size: 14px; } .me-text small { font-size: 12px; opacity: .85; }
  .me form { margin: 0; }
  .me .logout { display: inline-block; padding: 7px 14px; border: 0; border-radius: 99px; background: #fff; color: #6d28d9;
                font: inherit; font-size: 13px; font-weight: 700; cursor: pointer; }
  .me .logout:hover { text-decoration: none; opacity: .9; }
  .me.off { padding-right: 14px; }
  @media (max-width: 600px) { .me-text small { display: none; } }
  .legal h1 { font-size: 30px; margin: 0 0 4px; } .legal h2 { margin-top: 28px; font-size: 18px; }
  .legal .placeholder { padding: 10px 14px; border-radius: 10px; background: var(--amber-bg); color: var(--amber); font-weight: 600; }
  footer a { color: var(--muted); text-decoration: underline; }
  .login-card { max-width: 440px; margin: 28px 0 0; padding: 28px; border-radius: 20px; background: rgba(255,255,255,.16);
                backdrop-filter: blur(10px); box-shadow: 0 10px 40px rgba(0,0,0,.15); }
  .login-card p { margin: 0 0 18px; opacity: .95; }
  .google-btn { display: inline-flex; align-items: center; gap: 12px; padding: 12px 22px; border-radius: 12px; background: #fff;
                color: #1f1f1f; font-weight: 700; font-size: 16px; box-shadow: 0 6px 20px rgba(0,0,0,.18); transition: transform .15s; }
  .google-btn:hover { text-decoration: none; transform: translateY(-2px); }
  .by-user { white-space: nowrap; }
  .brand .logo { width: 34px; height: 34px; border-radius: 10px; background: rgba(255,255,255,.2); display: grid; place-items: center;
                 backdrop-filter: blur(6px); font-size: 18px; }
  .hero h1 { font-size: clamp(34px, 6vw, 58px); line-height: 1.05; margin: 28px 0 12px; font-weight: 800; letter-spacing: -.02em;
             text-shadow: 0 2px 20px rgba(0,0,0,.18); }
  @media (max-width: 600px) { .hero h1 br { display: none; } }
  .hero h1 .spark { display: inline-block; animation: twinkle 2.4s ease-in-out infinite; }
  @keyframes twinkle { 0%,100% { transform: scale(1) rotate(0); } 50% { transform: scale(1.2) rotate(12deg); } }
  .hero p.lead { font-size: clamp(16px, 2.2vw, 19px); max-width: 640px; margin: 0 0 28px; opacity: .95; }
  .scan-form { display: flex; gap: 8px; flex-wrap: wrap; max-width: 680px; padding: 8px; border-radius: 16px;
               background: rgba(255,255,255,.18); backdrop-filter: blur(10px); box-shadow: 0 10px 40px rgba(0,0,0,.15); }
  .scan-form input { flex: 1 1 280px; min-width: 0; padding: 14px 16px; font: inherit; font-size: 16px; border: 0; border-radius: 10px;
                     background: #fff; color: #19172b; outline: none; }
  .scan-form input:focus { box-shadow: 0 0 0 3px rgba(255,255,255,.6); }
  .scan-form button { padding: 14px 22px; font: inherit; font-size: 16px; font-weight: 700; border: 0; border-radius: 10px; cursor: pointer;
                      color: #fff; background: #19172b; transition: transform .15s; }
  .scan-form button:hover { transform: translateY(-1px); }
  .chips { display: flex; flex-wrap: wrap; gap: 6px; margin-top: 18px; }
  .chip { font-size: 12px; font-weight: 600; padding: 4px 10px; border-radius: 99px; background: rgba(255,255,255,.18); }
  .hero .error { margin: 14px 0 0; padding: 10px 14px; border-radius: 10px; background: rgba(25,23,43,.55); max-width: 680px; }
  .hero .repo-title { font-size: clamp(26px, 4.5vw, 40px); font-weight: 800; margin: 22px 0 4px; word-break: break-word; }
  .hero .repo-title a { color: #fff; }
  .hero .meta { opacity: .9; font-size: 14px; display: flex; flex-wrap: wrap; gap: 6px 14px; align-items: center; }
  .hero .meta a { color: #fff; text-decoration: underline; }

  /* ── stepper ── */
  .steps { display: flex; gap: 6px; margin-top: 22px; flex-wrap: wrap; }
  .step { display: flex; align-items: center; gap: 8px; padding: 6px 12px 6px 6px; border-radius: 99px; font-size: 13px; font-weight: 600;
          background: rgba(255,255,255,.14); color: rgba(255,255,255,.75); }
  .step .dot { width: 22px; height: 22px; border-radius: 50%; display: grid; place-items: center; font-size: 12px; background: rgba(255,255,255,.2); }
  .step.done { color: #fff; } .step.done .dot { background: #fff; color: #7c3aed; }
  .step.now { color: #19172b; background: #fff; } .step.now .dot { background: #7c3aed; color: #fff; animation: pulse 1.2s ease-in-out infinite; }
  @keyframes pulse { 0%,100% { box-shadow: 0 0 0 0 rgba(124,58,237,.5); } 50% { box-shadow: 0 0 0 6px rgba(124,58,237,0); } }
  .bar { height: 6px; border-radius: 99px; background: rgba(255,255,255,.25); margin-top: 14px; max-width: 520px; overflow: hidden; }
  .bar > span { display: block; height: 100%; background: #fff; border-radius: 99px; transition: width .5s; }

  /* ── content ── */
  main { max-width: 1040px; margin: -32px auto 0; padding: 0 16px 72px; position: relative; z-index: 2; }
  .card { background: var(--surface); border: 1px solid var(--line); border-radius: 16px; box-shadow: var(--shadow); padding: 20px; margin-bottom: 16px; }
  h2 { font-size: 20px; margin: 36px 0 12px; letter-spacing: -.01em; }
  h2 .count { color: var(--muted); font-weight: 500; }
  .muted { color: var(--muted); }
  .stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 12px; margin-bottom: 8px; }
  .stat { background: var(--surface); border: 1px solid var(--line); border-radius: 16px; box-shadow: var(--shadow); padding: 16px 18px; }
  .stat b { display: block; font-size: 32px; font-weight: 800; line-height: 1.1; }
  .stat span { color: var(--muted); font-size: 13px; font-weight: 500; }
  .stat.red b { color: var(--red); } .stat.amber b { color: var(--amber); } .stat.green b { color: var(--green); }
  .notice { padding: 14px 18px; border-radius: 12px; background: var(--surface-2); border: 1px solid var(--line); margin: 16px 0; }
  .notice.bad { background: var(--red-bg); border-color: transparent; color: var(--red); }
  .notice.good { background: var(--green-bg); border-color: transparent; color: var(--green); font-weight: 600; }

  /* findings */
  .finding { display: grid; grid-template-columns: 64px 1fr; gap: 16px; border-left: 4px solid var(--line); }
  .finding.likely { border-left-color: var(--red); } .finding.possible { border-left-color: var(--amber); }
  .ring { width: 56px; height: 56px; border-radius: 50%; display: grid; place-items: center; font-weight: 800; font-size: 17px; }
  .ring > span { width: 44px; height: 44px; border-radius: 50%; background: var(--surface); display: grid; place-items: center; }
  .finding .route { font-size: 15px; font-weight: 600; word-break: break-all; }
  .finding .handler { color: var(--muted); font-size: 13px; }
  .finding .why { margin: 10px 0 12px; }
  .kv { display: grid; grid-template-columns: max-content 1fr; gap: 6px 14px; font-size: 14px; }
  .kv dt { color: var(--muted); font-weight: 600; } .kv dd { margin: 0; word-break: break-word; }
  .fix { margin-top: 12px; padding: 10px 14px; border-radius: 10px; background: var(--green-bg); color: var(--fg); font-size: 14px; }
  .fix b { color: var(--green); }
  .verdict { display: inline-block; font-size: 11px; font-weight: 700; text-transform: uppercase; letter-spacing: .06em;
             padding: 2px 8px; border-radius: 99px; margin-left: 6px; vertical-align: 2px; }
  .verdict.likely { background: var(--red-bg); color: var(--red); } .verdict.possible { background: var(--amber-bg); color: var(--amber); }
  .verdict.unlikely, .verdict.error { background: var(--surface-2); color: var(--muted); }

  /* tables */
  .table-wrap { overflow-x: auto; }
  table { border-collapse: collapse; width: 100%; font-size: 14px; }
  th, td { text-align: left; padding: 9px 10px; border-bottom: 1px solid var(--line); vertical-align: top; }
  th { color: var(--muted); font-weight: 600; font-size: 12px; text-transform: uppercase; letter-spacing: .05em; }
  tr:last-child td { border-bottom: 0; }
  details > summary { cursor: pointer; font-weight: 600; list-style: none; display: flex; align-items: center; gap: 8px; }
  details > summary::-webkit-details-marker { display: none; }
  details > summary::before { content: "▸"; color: var(--muted); transition: transform .15s; }
  details[open] > summary::before { transform: rotate(90deg); }
  details[open] > summary { margin-bottom: 12px; }
  pre { background: var(--surface-2); border-radius: 10px; padding: 14px; overflow: auto; max-height: 560px; margin: 0; line-height: 1.5; }

  /* status pills and recent scans */
  .pill { display: inline-block; padding: 3px 10px; border-radius: 99px; font-size: 12px; font-weight: 700; background: var(--surface-2); color: var(--muted); }
  .hero .pill { background: rgba(255,255,255,.22); color: #fff; }
  .pill-done { background: var(--green-bg); color: var(--green); } .pill-failed { background: var(--red-bg); color: var(--red); }
  .pill-cloning, .pill-tracing, .pill-analyzing, .pill-queued { background: var(--amber-bg); color: var(--amber); }
  table.scans td { vertical-align: middle; } .summary .top { margin-top: 4px; font-size: 13px; word-break: break-all; }
  .nowrap { white-space: nowrap; }
  .how { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 12px; }
  .how .card { margin: 0; } .how .num { font-size: 24px; } .how h3 { margin: 6px 0 4px; font-size: 16px; } .how p { margin: 0; color: var(--muted); font-size: 14px; }
  .section-head { display: flex; justify-content: space-between; align-items: baseline; gap: 12px; }
  .section-head a { font-weight: 600; font-size: 14px; }

  /* the "run the analysis" call to action */
  .cta { display: flex; gap: 20px; align-items: center; flex-wrap: wrap; border: 0; color: #fff;
         background: linear-gradient(120deg, #6d28d9, #db2777 60%, #f59e0b); }
  .cta .text { flex: 1 1 320px; } .cta h3 { margin: 0 0 4px; font-size: 20px; } .cta p { margin: 0; opacity: .92; }
  .cta button { padding: 14px 24px; font: inherit; font-size: 16px; font-weight: 800; border: 0; border-radius: 12px; cursor: pointer;
                background: #fff; color: #6d28d9; box-shadow: 0 6px 20px rgba(0,0,0,.18); transition: transform .15s; }
  .cta button:hover { transform: translateY(-2px) scale(1.02); }

  /* event timeline */
  .timeline { list-style: none; margin: 0; padding: 0; }
  .timeline li { display: grid; grid-template-columns: 130px 1fr; gap: 12px; padding: 6px 0; border-bottom: 1px dashed var(--line); font-size: 14px; }
  .timeline li:last-child { border-bottom: 0; }
  .pager { display: flex; gap: 12px; justify-content: center; margin-top: 16px; }
  footer { text-align: center; color: var(--muted); font-size: 13px; padding: 0 16px 40px; }
  #boom { position: fixed; inset: 0; pointer-events: none; z-index: 50; }
</style>
</head>
<body>
<%= yield %>
<footer>BOLA Detector, by Variablee · finds BOLA / IDOR candidates from a static trace of the code. Scores are a triage order for manual review, not proof.
<br><a href="/privacy">Privacy</a> · <a href="/tos">Terms</a></footer>
</body>
</html>

@@ confetti
<% colors = %w[#fde68a #fbcfe8 #a5f3fc #ffffff #c4b5fd #fdba74] %>
<% 18.times do |i| %>
  <span class="confetti<%= ' round' if i.odd? %>" style="left:<%= (i * 37 + 11) % 100 %>%;background:<%= colors[i % colors.size] %>;animation-duration:<%= 7 + (i * 5) % 9 %>s;animation-delay:-<%= (i * 3) % 11 %>s"></span>
<% end %>

@@ index
<header class="hero">
  <%= erb :confetti, layout: false %>
  <div class="hero-inner">
    <%= erb :brand, layout: false %>
    <h1>Find the routes that leak <br>other users' data <span class="spark">✨</span></h1>
    <p class="lead">BOLA Detector traces every HTTP route in a public repo through its filters and handlers, then an LLM flags
      the ones that load objects by ID without checking who owns them (BOLA / IDOR).</p>
    <form class="scan-form" method="post" action="/scans">
      <input name="repo_url" type="url" required placeholder="https://github.com/owner/repo.git" autofocus aria-label="Repo URL">
      <button type="submit">Scan it 🚀</button>
    </form>
    <% if @error %><p class="error"><%= h @error %></p><% end %>
    <div class="chips"><% FRAMEWORKS.each do |f| %><span class="chip"><%= f %></span><% end %></div>
  </div>
</header>
<main>
  <div class="how">
    <div class="card"><div class="num">📥</div><h3>1. Clone</h3><p>A shallow copy of the repo's default branch. Public https repos only.</p></div>
    <div class="card"><div class="num">🧭</div><h3>2. Trace</h3><p>Every route, the filters that run before it, and the code it calls.</p></div>
    <div class="card"><div class="num">🔍</div><h3>3. Analyze</h3>
      <p><% if @analysis_off %>Off on this server: <%= h @analysis_off %>.<% else %>An LLM scores each route for missing ownership checks.<% end %></p></div>
  </div>

  <div class="section-head"><h2>Recent scans</h2><a href="/scans">See all scans →</a></div>
  <div class="card"><%= erb :scan_table, layout: false %></div>
</main>

@@ scan
<% s = @scan; name, host = repo_name(s['repo_url']); routes = s['routes'] || []; findings = s['findings']
   step = step_index(s['status']); progress = s['status'] == 'analyzing' && analysis_progress(s['log'])
   counts = verdict_counts(s); flagged = (findings || []).select { |f| %w[likely possible].include?(f['verdict']) }
   others = (findings || []) - flagged %>
<header class="hero compact">
  <%= erb :confetti, layout: false %>
  <div class="hero-inner">
    <%= erb :brand, layout: false %>
    <div class="repo-title"><a href="<%= h s['repo_url'] %>"><%= h name %></a></div>
    <div class="meta">
      <%= status_pill s['status'] %>
      <span><%= h host %></span>
      <% if present?(s['commit']) %><span>commit <span class="mono"><%= h s['commit'][0, 10] %></span></span><% end %>
      <span><%= when_s s['created_at'] %></span>
      <span>by <%= h user_name(s['requested_by']) %></span>
      <% if s['analysis_requested_by'] %><span>analysis by <%= h user_name(s['analysis_requested_by']) %></span><% end %>
      <% if s['started_at'] %><span>⏱ trace <%= took s %></span><% end %>
      <% if s['analysis_started_at'] %><span>⏱ analysis <%= analysis_took s %></span><% end %>
      <a href="/scans/<%= h s['_id'] %>.json">JSON</a>
    </div>
    <% if s['status'] != 'failed' %>
    <div class="steps">
      <% ["Waiting", "Clone", "Trace", "Analyze", "Done"].each_with_index do |label, i| %>
        <span class="step <%= i < step || step == 4 ? 'done' : (i == step ? 'now' : '') %>">
          <span class="dot"><%= i < step || step == 4 ? '✓' : i + 1 %></span><%= label %>
        </span>
      <% end %>
    </div>
    <% end %>
    <% if @active %>
      <div class="meta" style="margin-top:14px">
        <%= { "queued" => (@ahead.positive? ? "#{@ahead} scan(s) ahead of this one." : "Starting…"),
              "cloning" => "Cloning the repo…", "tracing" => "Tracing routes through filters and handlers…",
              "analysis_queued" => "The analysis starts when the scans ahead of it finish…",
              "analyzing" => (progress ? "Asking the LLM: batch #{progress[0]} of #{progress[1]} done…" : "Asking the LLM about each route…") }[s['status']] %>
        <span style="opacity:.75">This page refreshes every 3 seconds.</span>
      </div>
      <% if progress %><div class="bar"><span style="width:<%= (100.0 * progress[0] / [progress[1], 1].max).round %>%"></span></div><% end %>
    <% end %>
  </div>
</header>
<main>
  <% if s['status'] == 'failed' %>
    <div class="card"><div class="notice bad" style="margin:0"><b>Scan failed:</b> <%= h s['error'] %></div></div>
  <% end %>

  <% if routes.any? || s['status'] == 'done' %>
  <div class="stats">
    <div class="stat"><b><%= routes.size %></b><span>routes traced</span></div>
    <% if findings %>
      <div class="stat red"><b><%= counts['likely'].to_i %></b><span>likely BOLA</span></div>
      <div class="stat amber"><b><%= counts['possible'].to_i %></b><span>possible BOLA</span></div>
      <div class="stat green"><b><%= counts['unlikely'].to_i %></b><span>look fine</span></div>
    <% end %>
    <% (s['frameworks'] || {}).each do |fw, n| %><div class="stat"><b><%= n %></b><span><%= h fw %> routes</span></div><% end %>
  </div>
  <% end %>

  <% if s['status'] == 'traced' %>
    <% if present?(s['analysis_error']) %><div class="notice bad">Last analysis attempt failed: <%= h s['analysis_error'] %></div><% end %>
    <form class="card cta" method="post" action="/scans/<%= h s['_id'] %>/analyze">
      <div class="text">
        <h3>Trace done! Ready for the BOLA analysis 🔍</h3>
        <p>An LLM reads each route's traced code and scores how likely it is to let one user reach another user's data.
           <%= s['route_count'] %> routes, about <%= llm_calls(s) %> LLM calls, usually a minute or two.</p>
      </div>
      <button type="submit">Run the analysis ✨</button>
    </form>
  <% end %>
  <% if present?(s['analysis_note']) %><div class="notice"><%= h s['analysis_note'] %></div><% end %>
  <% if s['status'] == 'done' && routes.empty? %>
    <div class="notice">No routes that take input were found. The tracer may not support this framework yet.</div>
  <% end %>

  <% if findings %>
    <% if flagged.empty? %>
      <div class="notice good">🎉 No likely or possible BOLAs found in <%= findings.size %> routes.</div>
    <% else %>
      <h2>Flagged routes <span class="count">· <%= flagged.size %></span></h2>
      <p class="muted" style="margin-top:-6px">Ranked by <%= h s['model'] %>. Check each one by hand: the trace is static and may miss a check.</p>
      <% flagged.each do |f| %>
      <div class="card finding <%= h f['verdict'] %>">
        <div class="ring" style="background:conic-gradient(<%= score_color(f['score']) %> <%= f['score'].to_i * 3.6 %>deg, var(--surface-2) 0)">
          <span style="color:<%= score_color(f['score']) %>"><%= h f['score'] %></span>
        </div>
        <div>
          <div class="route mono"><%= h f['route'] %><span class="verdict <%= h f['verdict'] %>"><%= h f['verdict'] %></span></div>
          <div class="handler"><%= h f['handler'] %><% if present?(f['framework']) %> · <%= h f['framework'] %><% end %></div>
          <p class="why"><%= h f['reason'] %></p>
          <dl class="kv">
            <% if present?(f['object']) %><dt>Object</dt><dd><%= h f['object'] %></dd><% end %>
            <% if present?(f['data_access']) %><dt>Data access</dt><dd class="mono"><%= h f['data_access'] %></dd><% end %>
            <% if present?(f['auth_checks']) %><dt>Auth checks</dt><dd><%= h f['auth_checks'] %></dd><% end %>
            <% if present?(f['evidence']) %><dt>Evidence</dt><dd class="mono"><%= h f['evidence'] %></dd><% end %>
          </dl>
          <% if present?(f['fix']) %><div class="fix"><b>Fix:</b> <%= h f['fix'] %></div><% end %>
        </div>
      </div>
      <% end %>
    <% end %>

    <% if others.any? %>
    <div class="card">
      <details><summary>Routes that look fine <span class="muted">· <%= others.size %></span></summary>
      <div class="table-wrap"><table>
        <tr><th>Score</th><th>Route</th><th>Why</th></tr>
        <% others.each do |f| %>
        <tr><td><span class="verdict <%= h f['verdict'] %>"><%= h f['score'] %></span></td>
            <td class="mono"><%= h f['route'] %></td><td class="muted"><%= h f['reason'] %></td></tr>
        <% end %>
      </table></div></details>
    </div>
    <% end %>
  <% end %>

  <% if routes.any? %>
  <h2>Trace</h2>
  <div class="card">
    <details <%= 'open' unless findings %>><summary>All traced routes <span class="muted">· <%= routes.size %></span></summary>
    <div class="table-wrap"><table>
      <tr><th>Route</th><th>Handler</th><th>Input</th><th>Data access</th><th>Reached</th></tr>
      <% routes.each do |r| %>
      <tr>
        <td class="mono"><%= h r['route'] %></td>
        <td><%= h r['handler'] %><br><span class="muted"><%= h r['framework'] %></span></td>
        <td><%= h r['input'].join(', ') %></td>
        <td class="mono"><% r['model_calls'].each do |m| %><%= h m %><br><% end %></td>
        <td class="muted"><%= r['methods'] %> methods, <%= r['files'] %> files</td>
      </tr>
      <% end %>
    </table></div></details>
  </div>
  <% end %>

  <% if present?(s['tree']) %>
  <div class="card"><details><summary>Call trees <span class="muted">· filters first, then the handler</span></summary>
    <pre><%= h s['tree'] %></pre></details></div>
  <% end %>

  <% if present?(s['events']) %>
  <div class="card"><details open><summary>What happened <span class="muted">· <%= s['events'].size %> events</span></summary>
    <ul class="timeline">
      <% s['events'].each do |e| %><li><span class="muted"><%= when_s e['at'] %></span><span><%= h e['text'] %><% if e['by'] %> <span class="muted">by <%= h e['by']['name'] %> (<%= h e['by']['email'] %>)</span><% end %></span></li><% end %>
    </ul></details></div>
  <% end %>

  <div class="card"><details <%= 'open' if @active || s['status'] == 'failed' %>><summary>Log</summary>
    <pre id="log"><%= h s['log'] %></pre></details></div>
</main>
<script>
  // Keep the log scrolled to the end while the scan runs; throw confetti when a scan you watched finishes.
  (function () {
    var key = "watching-<%= h s['_id'] %>", log = document.getElementById("log");
    <% if @active %>
      if (log) log.scrollTop = log.scrollHeight;
      try { sessionStorage.setItem(key, "1"); } catch (e) {}
    <% elsif s['status'] == 'done' %>
      var watched = false;
      try { watched = sessionStorage.getItem(key) === "1"; sessionStorage.removeItem(key); } catch (e) {}
      if (!watched || matchMedia("(prefers-reduced-motion: reduce)").matches) return;
      var c = document.createElement("canvas"); c.id = "boom"; document.body.appendChild(c);
      var ctx = c.getContext("2d"), W = c.width = innerWidth, H = c.height = innerHeight;
      var colors = ["#7c3aed", "#db2777", "#f59e0b", "#06b6d4", "#10b981", "#fde68a"], bits = [];
      for (var i = 0; i < 160; i++) bits.push({ x: W / 2, y: H / 3, vx: (Math.random() - .5) * 16, vy: Math.random() * -14 - 4,
        r: Math.random() * 6 + 4, a: Math.random() * 6, va: (Math.random() - .5) * .3, c: colors[i % colors.length] });
      var t0 = performance.now();
      (function frame(t) {
        ctx.clearRect(0, 0, W, H);
        bits.forEach(function (b) { b.vy += .35; b.vx *= .99; b.x += b.vx; b.y += b.vy; b.a += b.va;
          ctx.save(); ctx.translate(b.x, b.y); ctx.rotate(b.a); ctx.fillStyle = b.c; ctx.fillRect(-b.r / 2, -b.r / 4, b.r, b.r / 2); ctx.restore(); });
        if (t - t0 < 3500) requestAnimationFrame(frame); else c.remove();
      })(t0);
    <% end %>
  })();
</script>

@@ scans
<header class="hero compact">
  <%= erb :confetti, layout: false %>
  <div class="hero-inner">
    <%= erb :brand, layout: false %>
    <div class="repo-title">All scans</div>
    <div class="meta"><span><%= @total %> scans so far</span><a href="/">Start a new scan</a></div>
  </div>
</header>
<main>
  <div class="card"><%= erb :scan_table, layout: false %></div>
  <% if @pages > 1 %>
  <div class="pager">
    <% if @page > 1 %><a href="/scans?page=<%= @page - 1 %>">← Newer</a><% end %>
    <span class="muted">Page <%= @page %> of <%= @pages %></span>
    <% if @page < @pages %><a href="/scans?page=<%= @page + 1 %>">Older →</a><% end %>
  </div>
  <% end %>
</main>

@@ brand
<div class="topbar">
  <a class="brand" href="/"><span class="logo">🎯</span><span>BOLA Detector <span class="by">by sella.rafaeli @ Variablee</span></span></a>
  <% if current_user %>
  <div class="me">
    <% if current_user['picture'] %><img src="<%= h current_user['picture'] %>" alt="" referrerpolicy="no-referrer">
    <% else %><span class="avatar"><%= h current_user['name'].to_s[0].to_s.upcase %></span><% end %>
    <span class="me-text"><b><%= h current_user['name'] %></b><small><%= h current_user['email'] %></small></span>
    <form method="post" action="/logout"><button type="submit" class="logout">Sign out</button></form>
  </div>
  <% elsif !AUTH_ON %>
  <div class="me off" title="Set GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET, then restart, to require Google sign-in">
    <span class="avatar">?</span><span class="me-text"><b>Not signed in</b><small>Google sign-in is off</small></span>
  </div>
  <% elsif request.path_info != "/login" %>
  <div class="me"><a class="logout" href="/login">Sign in</a></div>
  <% end %>
</div>

@@ scan_table
<% if @scans.empty? %>
  <p class="muted" style="margin:0">No scans yet. Be the first! 🎉</p>
<% else %>
<div class="table-wrap"><table class="scans">
  <tr><th>Repo</th><th>By</th><th>Status</th><th>Results</th><th>Started</th><th>Took</th></tr>
  <% @scans.each do |s| name, host = repo_name(s['repo_url']); v = s['verdicts']; n = s['route_count']; link = "/scans/#{h s['_id']}" %>
  <tr>
    <td><a href="<%= link %>"><b><%= h name %></b></a><br><span class="muted"><%= h host %></span></td>
    <td class="by-user"><%= h user_name(s['requested_by']) %></td>
    <td><%= status_pill s['status'] %></td>
    <td class="summary">
      <% if v %>
        <span class="verdict likely"><%= v['likely'].to_i %> likely</span>
        <span class="verdict possible"><%= v['possible'].to_i %> possible</span>
        <span class="verdict unlikely"><%= v['unlikely'].to_i %> fine</span>
        <% if n %><span class="muted">of <%= n %> routes</span><% end %>
        <% if (t = s['top_finding']) %><div class="top">Top: <code><%= h t['route'] %></code> <span class="muted">(score <%= h t['score'] %>)</span></div>
        <% elsif v['likely'].to_i + v['possible'].to_i == 0 %><div class="top">🎉 Nothing flagged</div><% end %>
      <% elsif s['status'] == 'traced' %>
        <%= n %> routes traced · <a href="<%= link %>">Run the analysis →</a>
      <% elsif s['status'] == 'done' %>
        <%= n || 'Some' %> routes traced <span class="muted">· no LLM analysis</span>
      <% elsif s['status'] == 'failed' %>
        <span class="muted"><%= h s['error'].to_s[0, 90] %></span>
      <% else %>
        <span class="muted"><%= n ? "#{n} routes traced, analyzing…" : 'In progress…' %></span>
      <% end %>
    </td>
    <td class="muted nowrap"><%= when_s s['created_at'] %></td>
    <td class="muted nowrap"><%= took s %><% if s['analysis_started_at'] %> + <%= analysis_took s %><% end %></td>
  </tr>
  <% end %>
</table></div>
<% end %>

@@ login
<header class="hero">
  <%= erb :confetti, layout: false %>
  <div class="hero-inner">
    <%= erb :brand, layout: false %>
    <h1>Find the routes that leak <br>other users' data <span class="spark">✨</span></h1>
    <div class="login-card">
      <p>Sign in with your Google account to scan repos and see results.</p>
      <a class="google-btn" href="/auth/google">
        <svg width="20" height="20" viewBox="0 0 48 48" aria-hidden="true"><path fill="#FFC107" d="M43.6 20.5H42V20H24v8h11.3C33.7 32.7 29.2 36 24 36c-6.6 0-12-5.4-12-12s5.4-12 12-12c3.1 0 5.8 1.2 7.9 3l5.7-5.7C34 6.1 29.3 4 24 4 12.9 4 4 12.9 4 24s8.9 20 20 20 20-8.9 20-20c0-1.3-.1-2.4-.4-3.5z"/><path fill="#FF3D00" d="M6.3 14.7l6.6 4.8C14.7 15.1 19 12 24 12c3.1 0 5.8 1.2 7.9 3l5.7-5.7C34 6.1 29.3 4 24 4 16.3 4 9.7 8.3 6.3 14.7z"/><path fill="#4CAF50" d="M24 44c5.2 0 9.9-2 13.4-5.2l-6.2-5.2C29.2 35.1 26.7 36 24 36c-5.2 0-9.6-3.3-11.3-8l-6.5 5C9.5 39.6 16.2 44 24 44z"/><path fill="#1976D2" d="M43.6 20.5H42V20H24v8h11.3c-.8 2.2-2.2 4.2-4.1 5.6l6.2 5.2C37 39.2 44 34 44 24c0-1.3-.1-2.4-.4-3.5z"/></svg>
        Sign in with Google
      </a>
      <% if @error %><p class="error" style="margin:16px 0 0"><%= h @error %></p><% end %>
    </div>
  </div>
</header>
<main style="margin-top:24px"></main>

@@ legal
<header class="hero compact">
  <%= erb :confetti, layout: false %>
  <div class="hero-inner"><%= erb :brand, layout: false %><div class="repo-title"><%= h @title %></div></div>
</header>
<main>
  <div class="card legal">
    <p class="placeholder">Placeholder text: this page will be replaced with the final <%= h @title.downcase %>.</p>
    <p class="muted">BOLA Detector, by Variablee · Last updated <%= Time.now.utc.strftime("%B %-d, %Y") %></p>
    <% @sections.each do |heading, text| %><h2><%= h heading %></h2><p><%= h text %></p><% end %>
  </div>
</main>
