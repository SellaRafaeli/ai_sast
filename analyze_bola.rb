#!/usr/bin/env ruby
# analyze_bola.rb — send each traced route's code to an LLM, ask whether it looks like
# a BOLA/IDOR, and rank the routes from most to least likely.
#
#   ruby route_tracer.rb /path/to/repo --with-source      # -> trace.json
#   ruby analyze_bola.rb [trace.json] [--batch 10] [--jobs 3] [--out bola_report]
#
# Steps (each step logs what it does):
#   1. LOAD     read trace.json (must be produced with --with-source)
#   2. BATCH    pack routes into batches of up to --batch routes / --max-chars characters
#   3. ASK      one LLM call per batch: a JSON verdict + 0..100 score per route
#   4. RANK     sort all routes by score
#   5. OUTPUT   bola_report.json (all fields) + bola_report.md (ranked table + details)
#               + Mongo `findings` collection when the mongo gem is available
#
# LLM key: ANTHROPIC_API_KEY or OPEN_AI_API_KEY in the environment or .env (see llm.rb).

require "json"
require "time"
require "optparse"
require_relative "llm"
Encoding.default_external = Encoding::UTF_8

def log(step, msg) = puts("[#{step}] #{msg}")

SYSTEM_PROMPT = <<~TXT
  You are an application security reviewer specialising in Broken Object Level Authorization
  (BOLA, also called IDOR). You review HTTP routes from a static trace of their code.

  A route has a BOLA when ALL of these hold:
  - the request carries an identifier of an object (path param, query param, or body field such as
    id, user_id, account_id, owner_id, org_id), and
  - the code reads, changes, or deletes that object (or objects referenced by it) using that identifier, and
  - nothing ties the object to the current user/tenant/role: no ownership check, no policy/permission
    check, and the lookup is not scoped through the current user (e.g. current_user.posts.find(id),
    where(owner: user), filter(owner=request.user), findOne({ id, userId })).

  Important:
  - Authentication (logged-in check, JWT guard, authenticate middleware) is NOT authorization.
  - Library guards/middleware whose code is not shown: only assume they check ownership if their name
    clearly says so (OwnerGuard, PolicyGuard, authorize_resource...). Otherwise treat them as authentication.
  - Creating an object is a BOLA if the caller can attach it to someone else's object via an ID in
    the body (e.g. post_id, account_id) without a check.
  - The trace is partial: code may be missing. Lower your confidence when the decisive code is not shown.
  - Routes whose objects are intentionally public, or that take no object identifier, are not BOLAs.

  Score each route 0-100 for how likely it contains a BOLA:
    80-100  user-controlled ID reaches a lookup/mutation with no ownership or policy check in the shown code
    50-79   probably vulnerable, but some relevant code is missing or a check is ambiguous
    20-49   a check exists but looks weak, partial, or easy to bypass (e.g. checks role, not ownership)
    0-19    properly scoped or authorized, or no user-controlled object identifier
TXT

def batch_prompt(items)
  routes = items.map { |id, _t, text| "===== ROUTE #{id} =====\n#{text}" }.join("\n\n")
  <<~TXT
    Review these #{items.size} routes for BOLA/IDOR.

    #{routes}

    Reply with ONLY a JSON array, one object per route, in the same order, with these keys:
      "id":          the route id (#{items.map(&:first).join(', ')})
      "verdict":     "likely" | "possible" | "unlikely"
      "score":       integer 0-100 (see the rubric)
      "object":      the user-controlled identifier and the object it selects, or "" if none
      "data_access": the call that loads/changes the object (e.g. "Post.find(params[:id])"), or ""
      "auth_checks": the authentication/authorization checks seen on this route, or "none"
      "evidence":    file:line references for the decisive code
      "reason":      1-3 sentences explaining the verdict
      "fix":         one sentence on how to fix it, or "" if not vulnerable
  TXT
end

# ── 1. LOAD ──
opts = { in: "trace.json", out: "bola_report", batch: 10, jobs: 3, max_chars: 150_000, limit: nil, dry: false }
OptionParser.new do |o|
  o.banner = "usage: ruby analyze_bola.rb [trace.json] [options]"
  o.on("--out NAME", "report base name (default bola_report -> .json and .md)") { |v| opts[:out] = v.sub(/\.(json|md)\z/, "") }
  o.on("--batch N", Integer, "routes per LLM call (default 10)") { |v| opts[:batch] = v }
  o.on("--jobs N", Integer, "LLM calls in parallel (default 3)") { |v| opts[:jobs] = v }
  o.on("--max-chars N", Integer, "max code characters per call (default 150000)") { |v| opts[:max_chars] = v }
  o.on("--limit N", Integer, "only analyze the first N routes (cheap test run)") { |v| opts[:limit] = v }
  o.on("--dry-run", "build the batches and print the first prompt; no LLM calls") { opts[:dry] = true }
end.parse!
opts[:in] = ARGV[0] if ARGV[0]

traces = JSON.parse(File.read(opts[:in]))
traces = traces.first(opts[:limit]) if opts[:limit]
missing = traces.count { |t| t["source_text"].to_s.empty? }
abort "#{opts[:in]} has no source_text — rerun: ruby route_tracer.rb REPO --with-source" if missing == traces.size && traces.any?
log(:load, "#{traces.size} routes from #{opts[:in]}#{missing.positive? ? " (#{missing} without source_text, skipped)" : ''}")
traces = traces.reject { |t| t["source_text"].to_s.empty? }

# ── 2. BATCH ── items are [id, trace, text]; a single huge route is truncated to fit
batches, cur, size = [], [], 0
traces.each do |t|
  text = t["source_text"]
  text = text[0, opts[:max_chars]] + "\n... (truncated)\n" if text.size > opts[:max_chars]
  if cur.any? && (cur.size >= opts[:batch] || size + text.size > opts[:max_chars])
    batches << cur
    cur, size = [], 0
  end
  cur << ["R#{cur.size + 1}", t, text]
  size += text.size
end
batches << cur if cur.any?
log(:batch, "#{batches.size} LLM calls (up to #{opts[:batch]} routes / #{opts[:max_chars]} chars each)")

if opts[:dry]
  puts "\n----- SYSTEM -----\n#{SYSTEM_PROMPT}\n----- PROMPT (batch 1) -----\n#{batch_prompt(batches.first || [])}"
  exit
end

LLM.load_dotenv
abort "[llm] #{LLM.describe}" unless LLM.available?
log(:llm, LLM.describe)

# ── 3. ASK ── one call per batch, --jobs at a time
def analyze(items)
  answer = nil
  2.times do |attempt|
    text = LLM.ask(batch_prompt(items), system: SYSTEM_PROMPT, max_tokens: 400 * items.size + 1000)
    answer = Array(LLM.extract_json(text))
    break
  rescue LLM::Error => e
    raise if attempt == 1 || e.message.start_with?("HTTP 4") && !e.message.start_with?("HTTP 429")
    log(:ask, "retrying batch (#{e.message[0, 80]})")
  end
  by_id = answer.select { |r| r.is_a?(Hash) }.to_h { |r| [r["id"].to_s, r] }
  items.map do |id, t, _text|
    r = by_id[id] || { "verdict" => "error", "score" => nil, "reason" => "missing from the LLM answer" }
    { "route" => t["route"], "framework" => t["framework"], "handler" => t["handler"], "input" => t["input"],
      "repo" => t["repo"] }.merge(r.reject { |k, _| k == "id" })
  end
rescue LLM::Error => e
  log(:ask, "batch failed: #{e.message[0, 200]}")
  items.map { |_id, t, _| { "route" => t["route"], "handler" => t["handler"], "verdict" => "error", "score" => nil, "reason" => e.message[0, 200] } }
end

queue = Queue.new
batches.each_with_index { |b, i| queue << [b, i] }
results = Array.new(batches.size)
mutex = Mutex.new
workers = Array.new([opts[:jobs], batches.size].min) do
  Thread.new do
    while (job = (queue.pop(true) rescue nil))
      b, i = job
      t0 = Time.now
      res = analyze(b)
      results[i] = res
      flagged = res.count { |r| %w[likely possible].include?(r["verdict"]) }
      mutex.synchronize do
        log(:ask, "batch #{i + 1}/#{batches.size}: #{b.size} routes, #{flagged} flagged (#{(Time.now - t0).round}s)")
        res.sort_by { |r| -r["score"].to_i }.each do |r|
          log(:verdict, format("%3s  %-8s  %s", r["score"] || "-", r["verdict"], r["route"]))
        end
      end
    end
  end
end
workers.each(&:join)

# ── 4. RANK ──
VERDICT_ORDER = { "likely" => 0, "possible" => 1, "unlikely" => 2, "error" => 3 }.freeze
ranked = results.flatten.compact.sort_by { |r| [-(r["score"] || -1).to_i, VERDICT_ORDER.fetch(r["verdict"], 4), r["route"]] }
ranked.each_with_index { |r, i| r["rank"] = i + 1 }
counts = ranked.map { |r| r["verdict"] }.tally
log(:rank, counts.map { |k, v| "#{k}: #{v}" }.join(", "))

# ── 5. OUTPUT ──
meta = { "generated_at" => Time.now.utc.iso8601, "model" => LLM.describe, "trace_file" => opts[:in], "counts" => counts }
File.write("#{opts[:out]}.json", JSON.pretty_generate(meta.merge("routes" => ranked)))

cell = ->(s) { s.to_s.gsub("|", "\\|").gsub(/\s+/, " ").strip }
md = []
md << "# BOLA / IDOR report"
md << ""
md << "#{ranked.size} routes analyzed with #{LLM.describe} from `#{opts[:in]}` on #{meta['generated_at']}."
md << "Verdicts: #{counts.map { |k, v| "#{v} #{k}" }.join(', ')}."
md << ""
md << "Scores are the model's estimate from a partial static trace — treat them as a triage order, not proof."
md << ""
md << "## Ranking"
md << ""
md << "| # | Score | Verdict | Route | Handler | Object | Why |"
md << "|---|---|---|---|---|---|---|"
ranked.each do |r|
  md << "| #{r['rank']} | #{r['score'] || '-'} | #{r['verdict']} | `#{cell[r['route']]}` | #{cell[r['handler']]} | " \
        "#{cell[r['object']]} | #{cell[r['reason']]} |"
end
flagged = ranked.select { |r| %w[likely possible].include?(r["verdict"]) }
if flagged.any?
  md << ""
  md << "## Details (likely and possible)"
  flagged.each do |r|
    md << ""
    md << "### #{r['rank']}. `#{r['route']}` — #{r['score']} (#{r['verdict']})"
    md << ""
    md << "- **Handler:** #{r['handler']} (#{r['framework']})"
    md << "- **Object:** #{r['object']}" unless r["object"].to_s.empty?
    md << "- **Data access:** `#{r['data_access']}`" unless r["data_access"].to_s.empty?
    md << "- **Auth checks:** #{r['auth_checks']}"
    md << "- **Evidence:** #{r['evidence']}" unless r["evidence"].to_s.empty?
    md << "- **Why:** #{r['reason']}"
    md << "- **Fix:** #{r['fix']}" unless r["fix"].to_s.empty?
  end
end
File.write("#{opts[:out]}.md", md.join("\n") + "\n")

begin
  require "mongo"
  Mongo::Logger.logger.level = Logger::WARN
  db = Mongo::Client.new(ENV.fetch("MONGO_URL", "mongodb://127.0.0.1:27017/route_tracer")).database
  repos = ranked.map { |r| r["repo"] }.compact.uniq
  db[:findings].delete_many(repo: { "$in" => repos }) if repos.any?
  db[:findings].insert_many(ranked.map { |r| r.merge("analyzed_at" => meta["generated_at"]) }) if ranked.any?
  log(:store, "saved #{ranked.size} findings to Mongo #{db.name}.findings")
rescue LoadError
  log(:store, "mongo gem not found -> report files only")
end

log(:done, "wrote #{opts[:out]}.json and #{opts[:out]}.md")
