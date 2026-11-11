#!/usr/bin/env ruby
# web.rb — Variablee Code: the web app around route_tracer.rb and analyze_bola.rb.
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
#   POSTMARK_FROM      sender address, a verified Postmark sender signature (default sella@indydevs.com)
#   GOOGLE_CLIENT_ID / GOOGLE_CLIENT_SECRET   with both set, every page needs a Google sign-in
#   SESSION_SECRET     signs the sign-in cookie; ALLOWED_DOMAINS / ALLOWED_EMAILS limit who may sign in
#   ADMIN_EMAILS       see every user's scans (default sella.rafaeli@gmail.com); everyone else sees only their own
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
POSTMARK_FROM = ENV.fetch("POSTMARK_FROM", "sella@indydevs.com")
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
  r = parse_repo_url(url)
  return [url.to_s, ""] if r[:path].empty?
  ["#{r[:path].join('/')}#{r[:ref] ? " @ #{r[:ref]}" : ''}", r[:host]]
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
  return if ENV["POSTMARK_API_TOKEN"].to_s.empty?
  scan = SCANS.find(_id: id).projection(repo_url: 1, base_url: 1, requested_by: 1).first or return
  name, = repo_name(scan["repo_url"])
  link = "#{scan['base_url']}/scans/#{id}"
  owner = scan["requested_by"] ? "#{scan['requested_by']['name']} <#{scan['requested_by']['email']}>" : "anonymous"
  postmark_send("Variablee Code · #{name}: #{subject}",
                [subject, details, "Repo: #{scan['repo_url']}", "Scan started by: #{owner}", "Scan: #{link}",
                 "— Variablee Code"].reject(&:empty?).join("\n\n"))
end

# POST one email to NOTIFY_EMAIL through Postmark's API, in the background; a failure is only logged.
def postmark_send(subject, text, reply_to: nil)
  token = ENV["POSTMARK_API_TOKEN"].to_s
  return if token.empty?
  body = { "From" => POSTMARK_FROM, "To" => NOTIFY_EMAIL, "Subject" => subject, "TextBody" => text,
           "MessageStream" => "outbound" }
  body["ReplyTo"] = reply_to if reply_to
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

# ── getting the code ──
# GitHub, GitLab and Bitbucket serve any public repo's default branch as a .tar.gz over HTTPS, so we download
# and unpack that: no git needed (Heroku-24 dynos have no git at run time) and faster than a clone.
# Other hosts (ALLOWED_GIT_HOSTS="*") fall back to a shallow `git clone` where git is installed.

# "https://github.com/OWASP/railsgoat(.git)" -> the archive URL for its default branch, or nil
# "https://github.com/aegra/aegra/tree/v0.9.6" -> { host:, path: ["aegra", "aegra"], ref: "v0.9.6" }.
# A version is given the way each host links to it: GitHub /tree/<ref> (or /releases/tag/<ref>, /commit/<sha>),
# GitLab /-/tree/<ref>, Bitbucket /src/<ref>. No version means the default branch (ref nil).
def parse_repo_url(url)
  uri = URI.parse(url.to_s)
  parts = uri.path.delete_prefix("/").delete_suffix("/").split("/")
  host = uri.host.to_s.downcase
  ref = nil
  case host
  when "github.com", "www.github.com"
    if parts.size >= 4 && %w[tree commit].include?(parts[2]) then ref = parts[3..].join("/"); parts = parts[0, 2]
    elsif parts.size >= 5 && parts[2] == "releases" && parts[3] == "tag" then ref = parts[4..].join("/"); parts = parts[0, 2]
    end
  when "gitlab.com"
    if (i = parts.index("-")) && %w[tree commit].include?(parts[i + 1]) && parts[i + 2]
      ref = parts[(i + 2)..].join("/"); parts = parts[0, i]
    end
  when "bitbucket.org"
    if parts.size >= 4 && %w[src commits].include?(parts[2]) then ref = parts[3..].join("/"); parts = parts[0, 2] end
  end
  parts[-1] = parts[-1].delete_suffix(".git") if parts.any?
  { host: host, path: parts, ref: ref }
rescue URI::InvalidURIError
  { host: "", path: [], ref: nil }
end

# The .tar.gz URL for a repo URL (at its version, or the default branch), or nil for hosts we can't download from.
def archive_url(url)
  r = parse_repo_url(url)
  parts, ref = r[:path], r[:ref]
  return nil if parts.size < 2
  repo = parts.last
  esc = ->(s) { s.split("/").map { |p| URI.encode_www_form_component(p) }.join("/") }
  case r[:host]
  when "github.com", "www.github.com"
    parts.size == 2 ? "https://codeload.github.com/#{parts[0]}/#{repo}/tar.gz/#{esc.(ref || 'HEAD')}" : nil
  when "gitlab.com" # namespaces can be nested groups
    v = ref || "HEAD"
    "https://gitlab.com/#{parts.join('/')}/-/archive/#{esc.(v)}/#{repo}-#{v.tr('/', '-')}.tar.gz"
  when "bitbucket.org"
    parts.size == 2 ? "https://bitbucket.org/#{parts[0]}/#{repo}/get/#{esc.(ref || 'HEAD')}.tar.gz" : nil
  end
end

# Download `url` to `file`, following redirects, giving up past `max_bytes` or `timeout` seconds.
def download(url, file, max_bytes:, timeout:)
  deadline = Time.now + timeout
  5.times do
    uri = URI.parse(url)
    Net::HTTP.start(uri.host, uri.port, use_ssl: uri.scheme == "https", open_timeout: 20, read_timeout: 60) do |http|
      http.request(Net::HTTP::Get.new(uri)) do |res|
        case res
        when Net::HTTPRedirection
          url = URI.join(url, res["location"]).to_s
        when Net::HTTPSuccess
          bytes = 0
          File.open(file, "wb") do |f|
            res.read_body do |chunk|
              bytes += chunk.bytesize
              raise format("repo archive is over %d MB", max_bytes / 1_048_576) if bytes > max_bytes
              raise "download took longer than #{timeout}s" if Time.now > deadline
              f.write(chunk)
            end
          end
          return bytes
        when Net::HTTPNotFound, Net::HTTPUnauthorized, Net::HTTPForbidden
          raise "repo not found (is it public?)"
        else
          raise "download failed: HTTP #{res.code}"
        end
      end
    end
  end
  raise "too many redirects"
end

# Put the repo's default branch in `repo_dir`; returns the commit id ("" when unknown).
def fetch_repo(id, env, url, work, repo_dir)
  if (archive = archive_url(url))
    file = File.join(work, "repo.tar.gz")
    append_log(id, "$ download #{archive}\n")
    bytes = download(archive, file, max_bytes: MAX_REPO_MB * 1_048_576, timeout: CLONE_TIMEOUT)
    append_log(id, format("downloaded %.1f MB\n", bytes / 1_048_576.0))
    # git-made archives (GitHub, GitLab) record the commit in their first header: "comment=<sha>"
    head = Zlib::GzipReader.open(file) { |gz| gz.read(2048) }.to_s rescue ""
    commit = head[/comment=([0-9a-f]{40})/, 1]
    out = File.join(work, "unpacked")
    FileUtils.mkdir_p(out)
    ok, = run(id, env, ["tar", "-xzf", file, "-C", out, "--no-same-owner"], chdir: work, timeout: CLONE_TIMEOUT)
    top = Dir.children(out)
    raise "could not unpack the repo archive" unless ok && top.size == 1 && File.directory?(File.join(out, top[0]))
    File.rename(File.join(out, top[0]), repo_dir)
    FileUtils.rm_f(file)
    commit || top[0][/[0-9a-f]{7,40}\z/].to_s # Bitbucket names the folder owner-repo-<short sha>
  else
    ok, = run(id, env, ["git", "-c", "core.hooksPath=/dev/null", "clone", "--depth", "1", "--single-branch",
                        "--no-tags", "--", url, repo_dir], chdir: work, timeout: CLONE_TIMEOUT)
    raise "git clone failed (is the repo public?)" unless ok
    Open3.capture2("git", "-C", repo_dir, "rev-parse", "HEAD")[0].strip
  end
rescue Errno::ENOENT => e
  raise e.message.include?("git") ? "git isn't installed on this server, so only GitHub, GitLab and Bitbucket repos can be scanned" : e.message
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
  commit = fetch_repo(id, env, doc["repo_url"], work, repo_dir)
  repo_dir = File.realpath(repo_dir)
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

  # Languages the tracer had to skip because this server lacks their parser (no python3, no node/typescript):
  # say so, rather than showing a quiet "0 routes".
  trace_log = SCANS.find(_id: id).projection(log: 1).first["log"].to_s
  skipped = trace_log.scan(/^\[index\] (python3 not found -> skipping \d+ \.py files|node not found -> skipping \d+ JS\/TS files|JS indexer failed -> skipping JS\/TS files)/).flatten
  warnings = skipped.map do |line|
    lang, tool = line.start_with?("python3") ? ["Python", "python3"] : ["JavaScript / TypeScript", "node and the typescript package"]
    "#{lang} files were skipped: this server is missing #{tool}, so routes in those files aren't included."
  end

  frameworks = traces.map { |t| t["framework"] }.tally
  update(id, "routes" => traces.map { |t| route_summary(t) }, "route_count" => traces.size, "tree" => tree,
             "frameworks" => frameworks, "clone_path" => repo_dir, "finished_at" => Time.now.utc, "warnings" => warnings)
  fw = frameworks.map { |k, v| "#{v} #{k}" }.join(", ")
  summary = "Traced #{traces.size} routes#{fw.empty? ? '' : " (#{fw})"} at commit #{commit[0, 10]}." +
            warnings.map { |w| "\nWarning: #{w}" }.join

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

# Smaller batches than the CLI default (10) so results reach the page sooner; more of them run in parallel.
ANALYZE_BATCH = Integer(ENV.fetch("ANALYZE_BATCH", "5"))
ANALYZE_JOBS  = Integer(ENV.fetch("ANALYZE_JOBS", "4"))

# Copy the verdicts written so far (one JSON line per route) into the scan, if there are new ones.
def save_partial(id, file)
  return unless File.file?(file)
  rows = File.readlines(file, chomp: true).filter_map { |l| JSON.parse(l) rescue nil } # a half-written last line is skipped
  return if rows.size == SCANS.find(_id: id).projection(partial_count: 1).first&.dig("partial_count").to_i
  findings = rows.map { |f| f.slice(*FINDING_KEYS) }
  update(id, "partial_findings" => findings, "partial_count" => findings.size)
rescue => e
  warn "[partial] #{e.class}: #{e.message}"
end

# 3. ANALYZE: the LLM scores each traced route, from the trace kept in `scan_traces`.
def analyze(id)
  doc = SCANS.find(_id: id).first or return
  work = Dir.mktmpdir("analyze-")
  update(id, "status" => "analyzing", "model" => LLM.describe, "analysis_started_at" => Time.now.utc, "analysis_error" => nil,
             "partial_findings" => [], "partial_count" => 0)
  event(id, "Analysis started", send_email: false)
  saved = TRACES.find(_id: id).first or raise "the saved trace is gone; please scan the repo again"
  trace_json = File.join(work, "trace.json")
  File.binwrite(trace_json, Zlib::Inflate.inflate(saved["data"].data))
  report = File.join(work, "bola_report")
  # analyze_bola.rb appends each batch's verdicts to this file as soon as the batch finishes; copy them into the
  # scan every 2 seconds so the page can show results while the rest are still being reviewed.
  partial = File.join(work, "partial.jsonl")
  watcher = Thread.new do
    loop do
      sleep 2
      save_partial(id, partial)
    end
  end
  ok, = run(id, { "MONGO_URL" => MONGO_URL },
            ruby_script("analyze_bola.rb", trace_json, "--out", report, "--batch", ANALYZE_BATCH.to_s,
                        "--jobs", ANALYZE_JOBS.to_s, "--partial", partial),
            chdir: work, timeout: ANALYZE_TIMEOUT)
  watcher.kill
  raise "the analysis failed (see the log)" unless ok && File.file?("#{report}.json")

  r = JSON.parse(File.read("#{report}.json"))
  findings = r["routes"].map { |f| f.slice(*FINDING_KEYS) }
  verdicts = findings.map { |f| f["verdict"] }.tally
  top_finding = findings.find { |f| %w[likely possible].include?(f["verdict"]) }&.slice("route", "score", "verdict")
  update(id, "status" => "done", "findings" => findings, "model" => r["model"], "verdicts" => verdicts, "top_finding" => top_finding,
             "analysis_finished_at" => Time.now.utc, "partial_findings" => nil)
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

# web/dev sets LIVE_RELOAD=1: pages poll /__live and reload when the server restarts with a new boot id.
LIVE_RELOAD = ENV["LIVE_RELOAD"] == "1"
BOOT_ID = SecureRandom.hex(6)
if LIVE_RELOAD
  get "/__live" do
    cache_control :no_store
    content_type :text
    BOOT_ID
  end
end

# ─────────────────────────── sign in with Google ───────────────────────────
# With GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET set, every page needs a Google sign-in (OpenID Connect,
# authorization-code flow, no extra gems). Without them the site is open and scans are "anonymous".

GOOGLE_CLIENT_ID     = ENV["GOOGLE_CLIENT_ID"].to_s.strip
GOOGLE_CLIENT_SECRET = ENV["GOOGLE_CLIENT_SECRET"].to_s.strip
AUTH_ON              = !GOOGLE_CLIENT_ID.empty? && !GOOGLE_CLIENT_SECRET.empty?
ALLOWED_EMAILS       = ENV["ALLOWED_EMAILS"].to_s.downcase.split(",").map(&:strip).reject(&:empty?)
ALLOWED_DOMAINS      = ENV["ALLOWED_DOMAINS"].to_s.downcase.split(",").map(&:strip).reject(&:empty?)
USERS                = DB[:users] # one document per person who signed in
CONTACTS             = DB[:contacts] # messages sent through the contact form
# Admins see every user's scans; everyone else sees only their own.
ADMIN_EMAILS         = ENV.fetch("ADMIN_EMAILS", "sella.rafaeli@gmail.com").downcase.split(",").map(&:strip).reject(&:empty?)
SCANS.indexes.create_one("requested_by.email" => 1, created_at: -1)
PUBLIC_PATHS         = %w[/login /logout /auth/google /auth/google/callback /privacy /tos /terms /whitepaper /blog /__live /contact].freeze
LINKS = { whitepaper: "/whitepaper", blog: "/blog", blog_post: "https://sellarafaeli.com/blog/ai_native_sast_for_idor_bola",
          github: "https://github.com/sellarafaeli/ai_sast", variablee: "https://variablee.com" }.freeze
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

# Privacy Policy and Terms of Service. Each section is [heading, text] or [heading, [bullet, ...]].
# Keep these in step with what the app really stores and sends (see web/README.md "What's stored").
LEGAL_UPDATED = "November 11, 2026"
LEGAL = {
  "privacy" => {
    title: "Privacy Policy",
    intro: "This policy explains what Variablee collects when you use Variablee Code, how we use it, and the choices you have. Variablee Code is operated by Variablee (\"we\", \"us\").",
    sections: [
      ["Information we collect", [
        "Account information. When you sign in with Google we receive your name, email address and profile picture. We record when you first and last signed in and how many times.",
        "Scan information. For each scan we store the repository URL you submit, the commit scanned, who started the scan and who ran its analysis, timestamps, a log of the scan, and its results: the routes found, their call trees, and the findings, which can include short excerpts of the scanned code.",
        "Repository code. We clone the public repository you submit to analyze it. The clone is deleted as soon as the trace finishes. The trace of each route, including that route's code, is kept until you run the analysis (or until the scan is deleted), then deleted.",
        "Contact requests. When you write to us through the contact form we receive your name, email address, company (if given) and message, and the page and IP address it was sent from.",
        "Technical information. We use a single cookie to keep you signed in. Our servers keep standard logs (such as IP addresses and request times) for security and troubleshooting."
      ]],
      ["How we use information", [
        "To run the scans you request and show you their results.",
        "To operate, secure and improve Variablee Code, including notifying our team when scans are started and completed.",
        "To reply to messages you send us, and to communicate with you about the service."
      ]],
      ["AI analysis",
        "When you run an analysis, the traced code of each route is sent to a large language model provider (Anthropic or OpenAI) through its API to evaluate it. These providers process the code under their API terms. We do not send your account information to them."],
      ["Service providers", [
        "Google, for sign-in.",
        "Our hosting and database providers, which store the application and its data.",
        "Postmark, which delivers notification emails to our team.",
        "Google Fonts, which serves the fonts our pages use."
      ]],
      ["Who can see your scans",
        "Your scans and their results are visible to you and to Variablee administrators. They are not visible to other users. We do not sell your information."],
      ["Retention",
        "We keep your account information and scan results until you ask us to delete them. Repository clones are deleted when tracing ends, and stored traces are deleted once their analysis completes."],
      ["Your choices and rights",
        "You can ask us to access, correct, export or delete your information at any time. Depending on where you live, you may have additional rights under laws such as the GDPR or CCPA; we will honor them."],
      ["Security",
        "Data is transmitted over HTTPS, sign-in uses Google's OpenID Connect, and each user can access only their own scans. No system is perfectly secure, and we cannot guarantee absolute security."],
      ["Changes to this policy",
        "We may update this policy. When we do, we will change the date at the top of this page."],
      ["Contact",
        "Questions or requests about privacy: contact us through variablee.com."]
    ]
  },
  "tos" => {
    title: "Terms of Service",
    intro: "These terms govern your use of Variablee Code, a service operated by Variablee. By signing in or using the service, you agree to them.",
    sections: [
      ["The service",
        "Variablee Code analyzes source code to find potential security vulnerabilities. It is offered free of charge as a research preview. We may change, suspend or discontinue any part of it at any time."],
      ["Your account",
        "You sign in with a third-party identity provider. You are responsible for activity under your account and for keeping access to it secure."],
      ["Acceptable use", [
        "Only scan code that you own or are authorized to analyze.",
        "Do not use the service, or its results, to attack, exploit or gain unauthorized access to any system.",
        "If you find a vulnerability in code you do not own, report it responsibly to its maintainers.",
        "Do not attempt to disrupt, overload, probe or reverse engineer the service, or to access other users' data."
      ]],
      ["Your code and results",
        "You keep all rights to your code. You grant us a limited license to copy, store and process it, including through third-party AI providers, solely to provide the service to you. Scan results are provided for your use."],
      ["Automated results",
        "Findings are automated estimates produced from a static analysis of the code and AI review. They may be incomplete or wrong, and they are a triage aid for expert review, not proof that a vulnerability exists or does not exist."],
      ["Intellectual property",
        "The service, including its algorithms, software and content, belongs to Variablee and its licensors. Components we publish as open source are licensed under their own licenses."],
      ["Disclaimer",
        "The service is provided \"as is\" and \"as available\", without warranties of any kind, express or implied, including fitness for a particular purpose and non-infringement."],
      ["Limitation of liability",
        "To the fullest extent permitted by law, Variablee will not be liable for any indirect, incidental, special, consequential or punitive damages, or for any loss of data, profits or revenue, arising from your use of the service."],
      ["Termination",
        "You may stop using the service at any time. We may suspend or end your access if you breach these terms or to protect the service or others."],
      ["Changes to these terms",
        "We may update these terms. When we do, we will change the date at the top of this page; continuing to use the service means you accept the updated terms."],
      ["Contact",
        "Questions about these terms: contact us through variablee.com."]
    ]
  }
}.freeze

%w[privacy tos terms].each do |page|
  get "/#{page}" do
    @legal = LEGAL.fetch(page == "terms" ? "tos" : page)
    @title = @legal[:title]
    erb :legal
  end
end

# ── contact form (bottom of every page) ──
# Saved to Mongo `contacts` and emailed to NOTIFY_EMAIL with Reply-To set to the sender.
# Spam guards: a hidden "website" field that people leave empty, and at most 5 messages per IP per hour.
CONTACT_HITS = Hash.new { |h, k| h[k] = [] }
CONTACT_LOCK = Mutex.new

def contact_rate_limited?(ip)
  CONTACT_LOCK.synchronize do
    hits = CONTACT_HITS[ip].select! { |t| t > Time.now - 3600 } || CONTACT_HITS[ip]
    return true if hits.size >= 5
    hits << Time.now
    false
  end
end

post "/contact" do
  back = params[:back].to_s
  back = "/" unless back.start_with?("/") && !back.start_with?("//")
  back = back.split("#").first
  redirect to("#{back}#contact") unless params[:website].to_s.empty? # bot filled the hidden field: drop silently

  f = %w[name email company message].to_h { |k| [k, params[k].to_s.strip] }
  error =
    if f["name"].empty? || f["name"].size > 100 then "Please enter your name."
    elsif !f["email"].match?(/\A[^@\s]+@[^@\s]+\.[^@\s]+\z/) || f["email"].size > 200 then "Please enter a valid work email."
    elsif f["company"].size > 150 then "Company name is too long."
    elsif f["message"].size < 10 then "Please write a short message (at least 10 characters)."
    elsif f["message"].size > 5000 then "Please keep your message under 5,000 characters."
    elsif contact_rate_limited?(request.ip) then "Too many messages from your network. Please try again in an hour."
    end
  if error
    session[:contact] = { "error" => error, "values" => f }
    redirect to("#{back}#contact")
  end

  CONTACTS.insert_one(f.merge("created_at" => Time.now.utc, "ip" => request.ip, "page" => back,
                              "signed_in_as" => current_user&.dig("email")))
  who = f["company"].empty? ? f["name"] : "#{f['name']} (#{f['company']})"
  postmark_send("Variablee Code · Contact request from #{who}",
                ["New message from the contact form.", "Name: #{f['name']}", "Email: #{f['email']}",
                 "Company: #{f['company'].empty? ? '-' : f['company']}", "Message:\n#{f['message']}",
                 "Sent from: #{request.base_url}#{back}", "— Variablee Code"].join("\n\n"),
                reply_to: f["email"])
  session[:contact] = { "sent" => true }
  redirect to("#{back}#contact")
end

# Research index: the white paper and blog posts.
POSTS = [
  { kind: "White paper", date: "November 2026", url: "/whitepaper", external: false,
    title: "Route-Sliced Context: Scalable LLM-Based Detection of Broken Object-Level Authorization in Large Codebases",
    by: "Variablee research team",
    summary: "The core algorithm behind Variablee Code: why BOLA is a route-local property, how we build a bounded context slice for every route across nine frameworks, and how it performs on 25 documented vulnerabilities (24 detected, one false positive on 28 known-safe routes)." },
  { kind: "Blog", date: "November 9, 2026", url: "https://sellarafaeli.com/blog/ai_native_sast_for_idor_bola", external: true,
    title: "AI-native SAST for IDOR / BOLA",
    by: "Sella Rafaeli, Security Research Lead",
    summary: "Why AI code review runs out of context on large codebases, how narrowing it to one route at a time solves that, and how we benchmark the scanner on applications with known, published vulnerabilities." }
].freeze

get "/blog" do
  @title = "Blog"
  erb :blog
end

# The white paper: a standalone academic page (public/whitepaper.html) and its PDF (public/whitepaper.pdf,
# rebuilt with web/build_whitepaper_pdf).
get "/whitepaper" do
  send_file File.join(settings.public_folder, "whitepaper.html")
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
  def admin? = !AUTH_ON || ADMIN_EMAILS.include?(current_user&.dig("email").to_s) # sign-in off (local dev): everyone sees all

  # The Mongo filter for the scans this visitor may see.
  def visible_scans = admin? ? {} : { "requested_by.email" => current_user&.dig("email").to_s }

  # One scan, or 404 when it doesn't exist or isn't theirs (404, not 403, so ids of other people's scans don't leak).
  def find_scan!(id) = SCANS.find(visible_scans.merge(_id: id.to_s)).first || halt(404, "No such scan")
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
  @scans = SCANS.find(visible_scans).sort(created_at: -1).limit(15).projection(log: 0, tree: 0, routes: 0, findings: 0, events: 0).to_a
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
  if (existing = SCANS.find(visible_scans.merge(repo_url: url, status: { "$in" => ACTIVE })).first)
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
  scan = find_scan!(params[:id])
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
  @total = SCANS.count_documents(visible_scans)
  @scans = SCANS.find(visible_scans).sort(created_at: -1).skip((@page - 1) * 50).limit(50)
                .projection(log: 0, tree: 0, routes: 0, findings: 0, events: 0).to_a
  @pages = [(@total / 50.0).ceil, 1].max
  @title = admin? ? "All scans" : "My scans"
  erb :scans
end

get "/scans/:id.json" do
  scan = find_scan!(params[:id])
  content_type :json
  JSON.pretty_generate(scan)
end

# The live results panel alone, polled by the scan page every few seconds while the analysis runs.
get "/scans/:id/live" do
  @scan = find_scan!(params[:id])
  headers "X-Scan-Status" => @scan["status"].to_s, "Cache-Control" => "no-store"
  erb :live, layout: false
end

get "/scans/:id" do
  @scan = find_scan!(params[:id])
  @active = ACTIVE.include?(@scan["status"])
  @live = %w[analysis_queued analyzing].include?(@scan["status"]) # results stream in; the page polls instead of reloading
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
<% if @active && !@live %><meta http-equiv="refresh" content="3"><% end %>
<title><%= @title ? "#{h @title} · " : '' %>Variablee Code · AI vulnerability detection for large codebases</title>
<link rel="icon" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 32 32'><rect width='32' height='32' rx='8' fill='%236d28d9'/><path d='M9 10l7 13 7-13' stroke='white' stroke-width='3.4' fill='none' stroke-linecap='round' stroke-linejoin='round'/></svg>">
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
  .brand .product { font-weight: 400; opacity: .9; }
  .brand { font-size: 17px; letter-spacing: 0; }
  .nav { display: flex; align-items: center; gap: 22px; margin-left: auto; font-size: 14px; font-weight: 600; line-height: 1.2; }
  .nav a { color: rgba(255,255,255,.88); } .nav a:hover { color: #fff; text-decoration: none; }
  .nav a { white-space: nowrap; }
  /* phones: links on their own full-width row under the logo, wrapping to a second row instead of squeezing */
  @media (max-width: 760px) { .nav { order: 3; width: 100%; margin-left: 0; flex-wrap: wrap; gap: 10px 18px; } }
  .login-card .google-btn { display: flex; justify-content: center; width: 100%; margin-top: 0; border: 0; cursor: pointer; font: inherit; font-weight: 700; font-size: 16px; }
  .login-card .google-btn + .google-btn { margin-top: 10px; }
  .login-card .sso { background: #19172b; color: #fff; }
  .muted-in { font-weight: 500; font-size: 12px; opacity: .7; }
  .or { display: flex; align-items: center; gap: 10px; margin: 14px 0 4px; font-size: 12px; opacity: .8; text-transform: uppercase; letter-spacing: .1em; }
  .or::before, .or::after { content: ''; flex: 1; height: 1px; background: rgba(255,255,255,.35); }
.signin-row { display: flex; flex-wrap: wrap; gap: 20px; align-items: stretch; margin-top: 28px; }
.signin-row .login-card { margin: 0; flex: 0 1 440px; }
.badges { flex: 1 1 420px; display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 12px; align-content: center; }
.badge-card { text-align: center; padding: 16px 12px 18px; border-radius: 18px; background: rgba(255,255,255,.12);
              border: 1px solid rgba(255,255,255,.28); backdrop-filter: blur(8px); box-shadow: 0 10px 30px rgba(0,0,0,.12); }
  .badge-card .trophy { width: 72px; height: 72px; display: block; margin: 0 auto 8px;
                        filter: drop-shadow(0 4px 10px rgba(0,0,0,.2)); }
.badge-kicker { font-size: 11px; font-weight: 700; letter-spacing: .1em; text-transform: uppercase; opacity: .85; }
.badge-title { font-size: 19px; font-weight: 800; margin: 3px 0 4px; line-height: 1.15; }
.badge-caption { font-size: 12.5px; line-height: 1.35; opacity: .9; }
@media (max-width: 560px) { .badges { grid-template-columns: 1fr 1fr 1fr; gap: 8px; } .badge-title { font-size: 15px; } .badge-caption { font-size: 11px; } }
.nav .nav-cta { padding: 8px 16px; border-radius: 99px; background: #fff; color: #6d28d9; }
.nav .nav-cta:hover { color: #4c1d95; }
.contact-wrap { max-width: 1040px; margin: 8px auto 40px; padding: 0 16px; scroll-margin-top: 16px; }
.contact { display: grid; grid-template-columns: minmax(0, 1fr) minmax(0, 1.25fr); gap: 32px; padding: 28px; }
@media (max-width: 760px) { .contact { grid-template-columns: 1fr; gap: 18px; padding: 20px; } }
.contact .kicker { font-size: 12px; font-weight: 700; letter-spacing: .08em; text-transform: uppercase; color: var(--accent); }
.contact h2 { margin: 6px 0 8px; font-size: 24px; }
.contact-text p { margin: 0 0 12px; color: var(--muted); }
.contact-text ul { margin: 0; padding-left: 18px; color: var(--muted); } .contact-text li { margin: 4px 0; }
.contact-form { display: grid; gap: 12px; }
.contact-form .row2 { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; }
@media (max-width: 560px) { .contact-form .row2 { grid-template-columns: 1fr; } }
.contact-form label { display: grid; gap: 5px; font-size: 13px; font-weight: 600; }
.contact-form .opt { color: var(--muted); font-weight: 500; }
.contact-form input, .contact-form textarea { font: inherit; font-size: 15px; font-weight: 400; padding: 10px 12px; border-radius: 10px;
  border: 1px solid var(--line); background: var(--surface-2); color: var(--fg); width: 100%; }
.contact-form textarea { resize: vertical; min-height: 110px; }
.contact-form input:focus, .contact-form textarea:focus { outline: 2px solid var(--accent); outline-offset: 0; border-color: transparent; }
.contact-form button { justify-self: start; padding: 11px 22px; font: inherit; font-weight: 700; border: 0; border-radius: 10px;
  background: var(--accent); color: #fff; cursor: pointer; }
.contact-form .fine-print { margin: 0; font-size: 12px; color: var(--muted); }
.contact-form .hp { position: absolute; left: -10000px; width: 1px; height: 1px; overflow: hidden; }
.contact-ok { padding: 18px; border-radius: 12px; background: var(--green-bg); color: var(--green); }
.contact-err { padding: 10px 14px; border-radius: 10px; background: var(--red-bg); color: var(--red); font-size: 14px; }
.live-head { padding: 16px 20px; }
.live-top { display: flex; align-items: center; gap: 10px; flex-wrap: wrap; }
.live-top .flag-count { color: var(--red); font-weight: 600; }
.live-dot { width: 10px; height: 10px; border-radius: 50%; background: var(--red); animation: blink 1.4s ease-in-out infinite; }
@keyframes blink { 0%, 100% { opacity: 1; } 50% { opacity: .25; } }
.live-bar { height: 6px; border-radius: 99px; background: var(--surface-2); margin-top: 12px; overflow: hidden; }
.live-bar > span { display: block; height: 100%; background: var(--accent); border-radius: 99px; transition: width .6s; }
.pending { color: var(--muted); font-size: 12px; font-weight: 600; }
.pending::before { content: ""; display: inline-block; width: 7px; height: 7px; border-radius: 50%; margin-right: 6px;
                   background: var(--amber); animation: blink 1.4s ease-in-out infinite; }
.fresh { animation: fresh 2.4s ease-out; }
@keyframes fresh { 0% { background-color: rgba(124,58,237,.18); } 100% { background-color: transparent; } }
.card.finding.fresh { animation: fresh-card 2.4s ease-out; }
@keyframes fresh-card { 0% { box-shadow: 0 0 0 3px var(--accent); } 100% { box-shadow: var(--shadow); } }
@media (prefers-reduced-motion: reduce) { .live-dot, .pending::before, .fresh, .card.finding.fresh { animation: none; } }
  .soon-note { margin: 12px 0 0 !important; padding: 10px 12px; border-radius: 10px; background: rgba(25,23,43,.45); font-size: 14px; }
  .legal ul { padding-left: 20px; } .legal li { margin: 4px 0; } .legal .intro { font-size: 16px; }
  .posts { display: grid; gap: 14px; } .post { display: block; color: inherit; }
  .post:hover { text-decoration: none; border-color: var(--accent); }
  .post .meta-line { font-size: 13px; color: var(--muted); } .post h2 { margin: 6px 0 8px; font-size: 21px; }
  .post p { margin: 0 0 10px; color: var(--muted); } .post .more { font-weight: 600; color: var(--accent); }
  .post .kind { display: inline-block; font-size: 11px; font-weight: 700; letter-spacing: .08em; text-transform: uppercase; color: var(--accent); }
  .topbar { display: flex; justify-content: space-between; align-items: center; gap: 12px; flex-wrap: wrap; }
  .me { display: flex; align-items: center; gap: 10px; font-size: 14px; padding: 4px 4px 4px 4px; border-radius: 99px;
        background: rgba(255,255,255,.18); backdrop-filter: blur(6px); }
  .me img, .me .avatar { width: 34px; height: 34px; border-radius: 50%; flex: none; }
  .me .avatar { display: grid; place-items: center; background: rgba(255,255,255,.3); font-weight: 800; }
  .me-text { display: flex; flex-direction: column; line-height: 1.2; color: #fff; min-width: 0; }
  .me-text b { font-size: 14px; } .me-text small { font-size: 12px; opacity: .85; }
  .me form { margin: 0; }
  .me.plain { padding: 0; background: none; backdrop-filter: none; }
  .me .logout { display: inline-block; padding: 8px 16px; font-size: 14px; line-height: 1.2; border: 0; border-radius: 99px; background: #fff; color: #6d28d9;
                font-family: inherit; font-weight: 700; cursor: pointer; }
  .me .logout:hover { text-decoration: none; opacity: .9; }
  .me.off { padding-right: 14px; }
  @media (max-width: 600px) { .me-text small { display: none; } }
  .legal h1 { font-size: 30px; margin: 0 0 4px; } .legal h2 { margin-top: 28px; font-size: 18px; }
  .legal .placeholder { padding: 10px 14px; border-radius: 10px; background: var(--amber-bg); color: var(--amber); font-weight: 600; }
  footer a { color: var(--muted); text-decoration: underline; }
  .foot-links { margin-bottom: 6px; font-weight: 500; }
  .eyebrow { display: inline-block; margin-top: 28px; padding: 5px 12px; border-radius: 99px; font-size: 12px; font-weight: 700;
             letter-spacing: .08em; text-transform: uppercase; background: rgba(255,255,255,.18); }
  .eyebrow + h1 { margin-top: 14px; }
  .hero p.fine { margin: 10px 0 0; font-size: 13px; opacity: .9; }
  .res-links { display: flex; flex-wrap: wrap; gap: 8px; margin-top: 18px; }
  .res-links a { display: inline-flex; align-items: center; gap: 6px; padding: 7px 14px; border-radius: 10px; font-size: 14px;
                 font-weight: 600; color: #fff; background: rgba(25,23,43,.35); border: 1px solid rgba(255,255,255,.25); }
  .res-links a:hover { text-decoration: none; background: rgba(25,23,43,.5); }
  .res-links .soon { font-size: 11px; opacity: .75; font-weight: 500; }
  .proof { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 12px; }
  .proof .stat span { display: block; margin-top: 4px; }
  .proof-note { font-size: 13px; margin: 10px 0 16px; }
.about-head { margin-top: 44px; }
.showcase { margin-top: 40px; display: grid; gap: 48px; }
.feature { display: grid; grid-template-columns: minmax(0, 1fr) minmax(0, 1.35fr); gap: 28px; align-items: center; }
.feature.flip .text { order: 2; }
.feature .kicker, .author .kicker { font-size: 12px; font-weight: 700; letter-spacing: .08em; text-transform: uppercase; color: var(--accent); }
.feature h2 { margin: 6px 0 10px; font-size: 24px; line-height: 1.2; }
.feature p { margin: 0; color: var(--muted); }
.shot { display: block; border-radius: 16px; overflow: hidden; box-shadow: 0 12px 40px rgba(25,23,43,.18); border: 1px solid var(--line);
        background: #0f1720; transition: transform .2s; }
.shot:hover { transform: translateY(-3px); }
.shot img { display: block; width: 100%; height: auto; }
.shot.tall img { max-height: 520px; object-fit: cover; object-position: top; }
@media (max-width: 760px) { .feature { grid-template-columns: 1fr; gap: 16px; } .feature.flip .text { order: 0; } }
.author { display: flex; gap: 18px; align-items: center; color: inherit; }
.author:hover { text-decoration: none; border-color: var(--accent); }
.author img { width: 72px; height: 72px; border-radius: 50%; object-fit: cover; flex: none; }
.author b { display: block; font-size: 18px; margin: 2px 0; } .author span { color: var(--muted); font-size: 14px; }
  .sample-result { margin-top: 40px; } .sample-result h2 { margin: 0; }
  .sample-result .section-head { flex-wrap: wrap; } .sample-tag { font-size: 13px; }
  .sample-intro { margin: 6px 0 14px; }
  .slice { margin-top: 12px; } .slice h3 { margin: 0 0 4px; }
  .slice-lines { margin: 10px 0; padding: 12px 14px; border-radius: 10px; background: var(--surface-2); }
  .slice-lines .ln { display: flex; flex-wrap: wrap; align-items: center; gap: 4px 10px; padding: 3px 0; }
  .slice-lines .ln code { word-break: break-all; }
  .slice-lines .l1 { padding-left: 18px; } .slice-lines .l2 { padding-left: 36px; }
  .slice .tag { display: inline-block; padding: 0 8px; border-radius: 99px; font-size: 11px; background: var(--surface); color: var(--muted); }
  .slice .tag.red { background: var(--red-bg); color: var(--red); }
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
<% unless @active %><%= erb :contact, layout: false %><% end %>
<footer>
  <div class="foot-links">
    <a href="<%= LINKS[:whitepaper] %>">White paper</a> · <a href="<%= LINKS[:blog] %>">Blog</a> ·
    <a href="<%= LINKS[:github] %>" target="_blank" rel="noopener">GitHub</a> · <a href="<%= LINKS[:variablee] %>" target="_blank" rel="noopener">variablee.com</a> ·
    <a href="/privacy">Privacy</a> · <a href="/tos">Terms</a> · <a href="#contact">Contact</a>
  </div>
  © <%= Time.now.year %> Variablee · Frontier AI Security Lab. Variablee Code findings are a triage order for expert review, not proof.
</footer>
<% if LIVE_RELOAD %>
<script>
  // Dev only (web/dev): reload this page when the server restarts after a code change.
  (function () {
    var boot = null;
    setInterval(function () {
      fetch("/__live", { cache: "no-store" }).then(function (r) { return r.text(); }).then(function (id) {
        if (boot && id !== boot) location.reload();
        boot = id;
      }).catch(function () {});
    }, 1000);
  })();
</script>
<% end %>
</body>
</html>

@@ confetti
<% colors = %w[#fde68a #fbcfe8 #a5f3fc #ffffff #c4b5fd #fdba74] %>
<% 18.times do |i| %>
  <span class="confetti<%= ' round' if i.odd? %>" style="left:<%= (i * 37 + 11) % 100 %>%;background:<%= colors[i % colors.size] %>;animation-duration:<%= 7 + (i * 5) % 9 %>s;animation-delay:-<%= (i * 3) % 11 %>s"></span>
<% end %>

@@ index
<header class="hero">
  <div class="hero-inner">
    <%= erb :brand, layout: false %>
    <div class="eyebrow">Variablee · Frontier AI Security Lab</div>
    <!-- <h1>Code-aware AI for the vulnerabilities <br>in your largest codebases</h1>
    <p class="lead">Variablee Code is a set of proprietary, code-aware algorithms that map how every route in your application
      executes, through its auth logic and down to the data it touches, then put frontier AI on each path to find the
      vulnerabilities in it. Built for very large enterprise codebases.</p>
    <p>Maintained by an Israeli Frontier AI Security Lab, it is the #1 performer on industry benchmarks in Enterprise AI SAST vulnerability detection.</p> -->
    <form class="scan-form" method="post" action="/scans">
      <input name="repo_url" type="url" required placeholder="https://github.com/owner/repo" autofocus aria-label="Repo URL">
      <button type="submit">Start free scan</button>
    </form>
    <p class="fine">Free during research preview · public repos · results in minutes · scan a specific version with a link like github.com/owner/repo/tree/v1.2.3</p>
    <% if @error %><p class="error"><%= h @error %></p><% end %>
    <div class="chips"><% FRAMEWORKS.each do |f| %><span class="chip"><%= f %></span><% end %></div>
  </div>
</header>
<main>
  <div class="section-head"><h2><%= admin? ? "Recent scans · all users" : "Your recent scans" %></h2><a href="/scans"><%= admin? ? "See all scans →" : "See all your scans →" %></a></div>
  <div class="card"><%= erb :scan_table, layout: false %></div>

  <h2 class="about-head">How Variablee Code works</h2>
  <%= erb :about, layout: false %>
</main>

@@ scan
<% s = @scan; name, host = repo_name(s['repo_url']); routes = s['routes'] || []; findings = s['findings']
   step = step_index(s['status']); progress = s['status'] == 'analyzing' && analysis_progress(s['log'])
   counts = verdict_counts(s); flagged = (findings || []).select { |f| %w[likely possible].include?(f['verdict']) }
   others = (findings || []) - flagged %>
<header class="hero compact">
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
        <span style="opacity:.75"><%= @live ? "Results appear below as each batch is reviewed." : "This page refreshes every 3 seconds." %></span>
      </div>
      <% if progress && !@live %><div class="bar"><span style="width:<%= (100.0 * progress[0] / [progress[1], 1].max).round %>%"></span></div><% end %>
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
        <h3>Trace complete. Ready for frontier analysis 🧠</h3>
        <p>Our frontier model reads each route's traced code and scores how likely it is to let one user reach another user's data.
           <%= s['route_count'] %> routes, about <%= llm_calls(s) %> LLM calls, usually a minute or two.</p>
      </div>
      <button type="submit">Run the analysis ✨</button>
    </form>
  <% end %>
  <% (s['warnings'] || []).each do |w| %><div class="notice bad"><b>Incomplete trace:</b> <%= h w %></div><% end %>
  <% if present?(s['analysis_note']) %><div class="notice"><%= h s['analysis_note'] %></div><% end %>
  <% if @live %><div id="live"><%= erb :live, layout: false %></div><% end %>
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
      <%= erb :finding_card, layout: false, locals: { f: f } %>
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
<% if @live %>
<script>
  // While the analysis runs: refresh the live panel every 3 seconds, highlight what's new, and reload the
  // whole page once the analysis is over (to show the final, ranked results).
  (function () {
    var url = "/scans/<%= h s['_id'] %>/live";
    setInterval(function () {
      fetch(url, { cache: "no-store", credentials: "same-origin" }).then(function (r) {
        var st = r.headers.get("X-Scan-Status");
        if (!r.ok || (st !== "analyzing" && st !== "analysis_queued")) { location.reload(); return null; }
        return r.text();
      }).then(function (html) {
        var box = document.getElementById("live");
        if (html == null || !box) return;
        var seen = {};
        box.querySelectorAll("[data-k]").forEach(function (e) { seen[e.getAttribute("data-k")] = 1; });
        box.innerHTML = html;
        box.querySelectorAll("[data-k]").forEach(function (e) { if (!seen[e.getAttribute("data-k")]) e.classList.add("fresh"); });
      }).catch(function () {});
    }, 3000);
  })();
</script>
<% end %>
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
  <div class="hero-inner">
    <%= erb :brand, layout: false %>
    <div class="repo-title"><%= admin? ? "All scans" : "My scans" %></div>
    <div class="meta">
      <span><%= @total %> <%= @total == 1 ? "scan" : "scans" %></span>
      <% if admin? && AUTH_ON %><span class="pill">Admin view · every user's scans</span><% end %>
      <a href="/">Start a new scan</a>
    </div>
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
  <a class="brand" href="/"><span class="logo"><svg viewBox="0 0 24 24" width="18" height="18" aria-hidden="true"><path d="M5 6l7 13 7-13" stroke="#fff" stroke-width="2.8" fill="none" stroke-linecap="round" stroke-linejoin="round"/></svg></span><span>Variablee <span class="product">Code</span></span></a>
  <nav class="nav" aria-label="Main">
    <a href="<%= LINKS[:whitepaper] %>">White paper</a>
    <a href="<%= LINKS[:blog] %>">Blog</a>
    <a href="<%= LINKS[:github] %>" target="_blank" rel="noopener">GitHub</a>
    <a href="/privacy">Privacy</a>
    <a href="/tos">Terms</a>
    <a class="nav-cta" href="#contact">Contact us</a>
  </nav>
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
  <div class="me plain"><a class="logout" href="/login">Sign in</a></div>
  <% end %>
</div>

@@ scan_table
<% if @scans.empty? %>
  <p class="muted" style="margin:0">No scans yet. Paste a repo URL above to run your first one, free. 🚀</p>
<% else %>
<div class="table-wrap"><table class="scans">
  <tr><th>Repo</th><% if admin? %><th>By</th><% end %><th>Status</th><th>Results</th><th>Started</th><th>Took</th></tr>
  <% @scans.each do |s| name, host = repo_name(s['repo_url']); v = s['verdicts']; n = s['route_count']; link = "/scans/#{h s['_id']}" %>
  <tr>
    <td><a href="<%= link %>"><b><%= h name %></b></a><br><span class="muted"><%= h host %></span></td>
    <% if admin? %><td class="by-user"><%= h user_name(s['requested_by']) %><% if s['requested_by'] %><br><span class="muted"><%= h s['requested_by']['email'] %></span><% end %></td><% end %>
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
  <div class="hero-inner">
    <%= erb :brand, layout: false %>
    <div class="eyebrow">Next-Gen Code-aware Vulnerability Detection for Very Large Codebases</div>
    <h1>AI SAST for The Enterprise<br></h1>
    <p class="lead">A swarm of AI agents with proprietary code-aware algorithms that map how every route in your application executes through its auth logic and down to the data it touches, and surface provable 
      vulnerabilities.</p>
      <p class=lead>Built for very large enterprise codebases by an Israeli Frontier AI Security Lab, Variablee Code is the #1 performer on industry benchmarks in Enterprise AI SAST vulnerability detection.</p>
    <div class="signin-row">
    <div class="login-card">
      <p><b>Try It On Your Repo.</b> Sign in to run your first scan in minutes.</p>
      <a class="google-btn" href="/auth/google">
        <svg width="20" height="20" viewBox="0 0 48 48" aria-hidden="true"><path fill="#FFC107" d="M43.6 20.5H42V20H24v8h11.3C33.7 32.7 29.2 36 24 36c-6.6 0-12-5.4-12-12s5.4-12 12-12c3.1 0 5.8 1.2 7.9 3l5.7-5.7C34 6.1 29.3 4 24 4 12.9 4 4 12.9 4 24s8.9 20 20 20 20-8.9 20-20c0-1.3-.1-2.4-.4-3.5z"/><path fill="#FF3D00" d="M6.3 14.7l6.6 4.8C14.7 15.1 19 12 24 12c3.1 0 5.8 1.2 7.9 3l5.7-5.7C34 6.1 29.3 4 24 4 16.3 4 9.7 8.3 6.3 14.7z"/><path fill="#4CAF50" d="M24 44c5.2 0 9.9-2 13.4-5.2l-6.2-5.2C29.2 35.1 26.7 36 24 36c-5.2 0-9.6-3.3-11.3-8l-6.5 5C9.5 39.6 16.2 44 24 44z"/><path fill="#1976D2" d="M43.6 20.5H42V20H24v8h11.3c-.8 2.2-2.2 4.2-4.1 5.6l6.2 5.2C37 39.2 44 34 44 24c0-1.3-.1-2.4-.4-3.5z"/></svg>
        Sign in with Google
      </a>
      <br/>
      <button type="button" class="google-btn" data-soon="Microsoft">
        <svg width="18" height="18" viewBox="0 0 23 23" aria-hidden="true"><path fill="#f25022" d="M1 1h10v10H1z"/><path fill="#7fba00" d="M12 1h10v10H12z"/><path fill="#00a4ef" d="M1 12h10v10H1z"/><path fill="#ffb900" d="M12 12h10v10H12z"/></svg>
        Sign in with Microsoft
      </button>
      <div class="or"><span>or</span></div>
      <button type="button" class="google-btn sso" data-soon="SSO">
        <svg width="18" height="18" viewBox="0 0 24 24" aria-hidden="true" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>
        Sign in with SSO <span class="muted-in">SAML · OIDC</span>
      </button>
      <p class="soon-note" role="status" hidden></p>
      <% if @error %><p class="error" style="margin:16px 0 0"><%= h @error %></p><% end %>
    </div>
    <%= erb :badges, layout: false %>
    </div>
    <script>
      document.querySelectorAll("[data-soon]").forEach(function (b) {
        b.addEventListener("click", function () {
          var n = document.querySelector(".soon-note");
          n.textContent = "Sign-in with " + b.dataset.soon + " is coming soon. Use Google for now, or contact us at variablee.com to set up your organization.";
          n.hidden = false;
        });
      });
    </script>
  </div>
</header>
<main>
  <%= erb :about, layout: false %>
</main>

@@ legal
<header class="hero compact">
  <div class="hero-inner"><%= erb :brand, layout: false %><div class="repo-title"><%= h @legal[:title] %></div>
    <div class="meta"><span>Last updated <%= LEGAL_UPDATED %></span></div></div>
</header>
<main>
  <div class="card legal">
    <p class="intro"><%= h @legal[:intro] %></p>
    <% @legal[:sections].each do |heading, body| %>
      <h2><%= h heading %></h2>
      <% if body.is_a?(Array) %><ul><% body.each do |item| %><li><%= h item %></li><% end %></ul>
      <% else %><p><%= h body %></p><% end %>
    <% end %>
  </div>
</main>

@@ blog
<header class="hero compact">
  <div class="hero-inner"><%= erb :brand, layout: false %><div class="repo-title">Research &amp; Blog</div>
    <div class="meta"><span>Research from Variablee, the frontier AI security lab behind Variablee Code</span></div></div>
</header>
<main>
  <div class="posts">
    <% POSTS.each do |p| %>
    <a class="card post" href="<%= h p[:url] %>"<%= ' target="_blank" rel="noopener"' if p[:external] %>>
      <span class="kind"><%= h p[:kind] %></span>
      <h2><%= h p[:title] %></h2>
      <div class="meta-line"><%= h p[:by] %> · <%= h p[:date] %></div>
      <p style="margin-top:10px"><%= h p[:summary] %></p>
      <span class="more"><%= p[:kind] == "White paper" ? "Read the white paper →" : "Read the post →" %></span>
    </a>
    <% end %>
  </div>
</main>


@@ about
  <div class="proof">
    <div class="stat red"><b>96%</b><span>of known BOLAs caught (24 of 25) on our benchmark</span></div>
    <div class="stat green"><b>1 / 28</b><span>false positives on routes known to be safe</span></div>
    <div class="stat"><b>4</b><span>real-world apps with published BOLAs, from CVEs to OWASP targets</span></div>
    <div class="stat"><b>9</b><span>frameworks across Ruby, Python and JavaScript / TypeScript</span></div>
  </div>
  <p class="muted proof-note">Benchmark: OWASP RailsGoat, OWASP crAPI, dvws-node and aegra (CVE-2026-44504).
    <a href="<%= LINKS[:github] %>#benchmarks-and-up-to-date-test-results" target="_blank" rel="noopener">See the full results →</a></p>

  <div class="how">
    <div class="card"><div class="num">🧩</div><h3>1. Parse</h3><p>Indexes every method and class across Ruby, Python and JS / TS, and finds every route in Rails, Django, FastAPI, Express, NestJS and more.</p></div>
    <div class="card"><div class="num">✂️</div><h3>2. Slice</h3><p>Follows each route through its auth filters, middleware and guards into the handler and the calls that read or write data, and packs that path into its own context slice.</p></div>
    <div class="card"><div class="num">🧠</div><h3>3. Reason</h3>
      <p><% if @analysis_off %>Off on this server: <%= h @analysis_off %>.<% else %>A frontier model reviews each slice on its own: is the requested object tied to the current user? Every flag comes with evidence and a fix.<% end %></p></div>
  </div>

  <div class="card slice">
    <h3>One route, one slice</h3>
    <p class="muted">Only the code that runs for this request goes to the model, in the order it runs:</p>
<div class="slice-lines">
      <div class="ln l0"><code>GET /orders/:id → OrdersController#show</code><span class="tag">route</span></div>
      <div class="ln l1"><code>ApplicationController#authenticate_user!</code><span class="tag">auth filter</span></div>
      <div class="ln l1"><code>OrdersController#show</code><span class="tag">handler</span></div>
      <div class="ln l2"><code>Order.find(params[:id])</code><span class="tag red">data access, not scoped to current_user</span></div>
    </div>
    <p class="muted" style="margin-bottom:0">Because each slice is small and self-contained, the codebase's size doesn't limit the review: every route gets the model's full attention.</p>
  </div>

  <div class="sample-result">
    <div class="section-head"><h2>What a finding looks like</h2><span class="muted sample-tag">Example from the OWASP crAPI benchmark</span></div>
    <p class="muted sample-intro">Every flagged route comes with a score, the object at risk, the exact data-access call, the checks
      that did run, file-and-line evidence, and a concrete fix.</p>
    <div class="card finding likely">
      <div class="ring" style="background:conic-gradient(var(--red) 342.0deg, var(--surface-2) 0)">
        <span style="color:var(--red)">95</span>
      </div>
      <div>
        <div class="route mono">GET /workshop/api/mechanic/mechanic_report<span class="verdict likely">likely</span></div>
        <div class="handler">GetReportView#get · django</div>
        <p class="why">Fetches a ServiceRequest by an ID supplied in the query without verifying that it belongs to the requester, enabling access to others’ reports.</p>
        <dl class="kv">
          <dt>Object</dt><dd>query.report_id -&gt; ServiceRequest</dd>
          <dt>Data access</dt><dd class="mono">ServiceRequest.objects.filter(id=report_id).first()</dd>
          <dt>Auth checks</dt><dd>jwt_auth_required (authentication only), no ownership check</dd>
          <dt>Evidence</dt><dd class="mono">views.py:214-244; jwt.py:32-90</dd>
        </dl>
        <div class="fix"><b>Fix:</b> Authorize access by checking the ServiceRequest belongs to the authenticated mechanic/user before returning it.</div>
      </div>
    </div>
  </div>

<section class="showcase">
  <div class="feature">
    <div class="text">
      <div class="kicker">The bug class</div>
      <h2>One ID swap away from someone else's data</h2>
      <p>A signed-in user changes an ID in the URL and gets another customer's invoice, order or account. Nothing crashes and
         no pattern matches: the bug is a permission check that isn't there. That's BOLA / IDOR, the #1 risk in the OWASP API
         Security Top 10.</p>
    </div>
    <a class="shot" href="/img/blog/bolaimg1.svg" target="_blank"><img src="/img/blog/bolaimg1.svg" width="960" height="510" loading="lazy"
       alt="Diagram: a caller-controlled invoice ID flows from the request through the controller and an ID-only lookup to the response, with no object-level permission check"></a>
  </div>

  <div class="feature flip">
    <div class="text">
      <div class="kicker">Our method</div>
      <h2>One route at a time</h2>
      <p>We inventory every route, collect the shared middleware and the handler code that governs the object ID, and review
         access for that route alone. Then the next route, until the whole inventory is covered.</p>
    </div>
    <a class="shot" href="/img/blog/bola2.png" target="_blank"><img src="/img/blog/bola2.png" width="960" height="530" loading="lazy"
       alt="Three steps: inventory routes, collect route context (shared middleware, handler and calls), review access and flag a possible BOLA"></a>
  </div>

  <div class="feature">
    <div class="text">
      <div class="kicker">Under the hood</div>
      <h2>A real context slice</h2>
      <p>This is the actual trace for one route: the handler, every call it makes with its file and lines, and the source of
         each filter on the way. That slice, and nothing else, is what the model reviews, so a large codebase never
         crowds out the code that matters.</p>
    </div>
    <a class="shot tall" href="/img/blog/example_from_trace.png" target="_blank"><img src="/img/blog/example_from_trace.png" width="1212" height="1532" loading="lazy"
       alt="JSON trace of GET /admin/users/:id: its handler, the calls it makes with file and line ranges, and the source of its before filter"></a>
  </div>

  <div class="feature flip">
    <div class="text">
      <div class="kicker">What you get</div>
      <h2>Findings you can triage</h2>
      <p>Each candidate names the auth it passed, the check that's missing, nearby checks that hint at intent, and a concrete
         next step to confirm it, so your team spends time on real issues.</p>
    </div>
    <a class="shot" href="/img/blog/bola3.png" target="_blank"><img src="/img/blog/bola3.png" width="1920" height="1299" loading="lazy"
       alt="Illustrative scan output: three candidate BOLA findings, each with shared auth, the missing or unclear check, a nearby check, and a next step"></a>
  </div>

  <a class="card author" href="<%= LINKS[:blog_post] %>" target="_blank" rel="noopener">
    <img src="/img/blog/tux1.jpeg" width="800" height="800" loading="lazy" alt="Sella Rafaeli">
    <div>
      <div class="kicker">From the lab</div>
      <b>AI-native SAST for IDOR / BOLA</b>
      <span>The research behind Variablee Code, by Sella Rafaeli · Read the post →</span>
    </div>
  </a>
</section>

@@ badges
<% badges = [
     ["Accurate", "96% recall", "96% of documented BOLAs caught in industry benchmark apps, <3% false positives"]     ,
     ["Fast", "Seconds to map", "42 RailsGoat routes traced in 3 seconds; AI review in about 2 minutes"],
     ["Polyglot", "Python, Ruby, NodeJS", "Expected in 2027: PHP, Java"],
   ] %>
<div class="badges">
  <% badges.each_with_index do |(kicker, title, caption), i| %>
  <div class="badge-card">
    <img class="trophy" src="/img/cyber-trophy.svg" width="128" height="128" alt="">
    <div class="badge-kicker"><%= kicker %></div>
    <div class="badge-title"><%= title %></div>
    <div class="badge-caption"><%= caption %></div>
  </div>
  <% end %>
</div>

@@ contact
<% c = session.delete(:contact) || {}; v = c["values"] || {}
   v = { "name" => current_user&.dig("name"), "email" => current_user&.dig("email") }.compact.merge(v) %>
<section id="contact" class="contact-wrap">
  <div class="contact card">
    <div class="contact-text">
      <div class="kicker">Contact us</div>
      <h2>Talk to our team</h2>
      <p>Want to run Variablee Code on your organization's codebase, plan a pilot, or ask about our research?
         Send us a note and we'll get back to you.</p>
      <ul>
        <li>Pilots on large enterprise codebases</li>
        <li>Private repositories and SSO</li>
        <li>Research collaborations</li>
      </ul>
    </div>
    <form class="contact-form" method="post" action="/contact">
      <% if c["sent"] %>
        <div class="contact-ok" role="status"><b>Thanks, your message is on its way.</b> We'll reply to you by email.</div>
      <% else %>
        <% if c["error"] %><div class="contact-err" role="alert"><%= h c["error"] %></div><% end %>
        <input type="hidden" name="back" value="<%= h request.fullpath %>">
        <div class="hp" aria-hidden="true"><label>Website <input name="website" tabindex="-1" autocomplete="off"></label></div>
        <div class="row2">
          <label>Name<input name="name" required maxlength="100" autocomplete="name" value="<%= h v['name'] %>"></label>
          <label>Work email<input name="email" type="email" required maxlength="200" autocomplete="email" value="<%= h v['email'] %>"></label>
        </div>
        <label><span>Company <span class="opt">(optional)</span></span><input name="company" maxlength="150" autocomplete="organization" value="<%= h v['company'] %>"></label>
        <label>Message<textarea name="message" required minlength="10" maxlength="5000" rows="4"><%= h v['message'] %></textarea></label>
        <button type="submit">Send message</button>
        <p class="fine-print">We use what you send only to reply to you. See our <a href="/privacy">Privacy Policy</a>.</p>
      <% end %>
    </form>
  </div>
</section>

@@ finding_card
<div class="card finding <%= h f['verdict'] %>" data-k="card|<%= h f['route'] %>">
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

@@ live
<% s = @scan; rows = s['partial_findings'] || []; total = [s['route_count'].to_i, rows.size].max; done = rows.size
   by_route = rows.to_h { |f| [f['route'], f] }
   flagged = rows.select { |f| %w[likely possible].include?(f['verdict']) }.sort_by { |f| -f['score'].to_i } %>
<div class="card live-head">
  <div class="live-top">
    <span class="live-dot" aria-hidden="true"></span><b>Live results</b>
    <span class="muted"><%= done %> of <%= total %> routes reviewed<% if flagged.any? %> · <span class="flag-count"><%= flagged.size %> flagged so far</span><% end %></span>
  </div>
  <div class="live-bar"><span style="width:<%= total.positive? ? (100.0 * done / total).round : 0 %>%"></span></div>
</div>
<% if flagged.any? %>
  <h2>Flagged so far <span class="count">· <%= flagged.size %></span></h2>
  <% flagged.each do |f| %><%= erb :finding_card, layout: false, locals: { f: f } %><% end %>
<% elsif done.positive? %>
  <div class="notice good">Nothing flagged in the first <%= done %> routes so far.</div>
<% end %>
<div class="card">
  <div class="table-wrap"><table class="live-routes">
    <tr><th>Route</th><th>Handler</th><th>Result</th></tr>
    <% all = s['routes'] || []
       ordered = all.select { |r| by_route[r['route']] }.sort_by { |r| -by_route[r['route']]['score'].to_i } +
                 all.reject { |r| by_route[r['route']] } # reviewed first, highest score on top; then the rest %>
    <% ordered.each do |r| f = by_route[r['route']] %>
    <tr data-k="row|<%= h r['route'] %>|<%= f ? h(f['verdict']) : 'pending' %>">
      <td class="mono"><%= h r['route'] %></td>
      <td class="muted"><%= h r['handler'] %></td>
      <td class="nowrap"><% if f %><span class="verdict <%= h f['verdict'] %>"><%= h f['verdict'] %> · <%= h f['score'] %></span>
          <% else %><span class="pending">Reviewing…</span><% end %></td>
    </tr>
    <% end %>
  </table></div>
</div>
