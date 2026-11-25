#!/usr/bin/env ruby
# Neon.rb — give a frontier model nothing but a repo URL (pinned to a commit) and let it find the
# HTTP routes, trace each one's execution path, and judge whether it may have a BOLA/IDOR.
# Two providers, same task prompt and loop:
#   --provider gemini (default)  Google Gemini 4 Neon (gemini-4-neon), reads URLs with its url_context tool
#   --provider openai / --openai OpenAI's flagship (gpt-6.2-astra), reads URLs with its web_search tool
#
# Run it against Aegra v0.9.6 (commit d7d80c8), keeping a copy of the log:
#
#   cd ~/Code/ai_sast && mkdir -p logs && ruby Neon.rb https://github.com/aegra/aegra/tree/d7d80c850010a9c5a3d2be59254c19b9eb0e25dd --thinking high --turns 12 --out neon_aegra_v0.9.6 2>&1 | tee logs/neon_aegra_v0.9.6.log
#
# Same thing with OpenAI's best model (uses OPEN_AI_API_KEY):
#
#   cd ~/Code/ai_sast && mkdir -p logs && ruby Neon.rb https://github.com/aegra/aegra/tree/d7d80c850010a9c5a3d2be59254c19b9eb0e25dd --openai --thinking high --turns 12 --out openai_aegra_v0.9.6 2>&1 | tee logs/openai_aegra_v0.9.6.log
#
# Usage:
#   ruby Neon.rb [REPO_URL] [--provider gemini|openai | --openai] [--model ID] [--turns 12]
#                [--thinking low|medium|high|xhigh|max] [--out BASE] [--quiet] [--dry]
#   REPO_URL defaults to the Aegra v0.9.6 URL above. Logging is verbose by default; --quiet keeps one line per step.
#   --thinking: Gemini's thinking_level (low..xhigh) or OpenAI's reasoning.effort (low..max).
#
# This script never sends code. The model reads the repo itself with its built-in web tool.
# Gemini's tool only fetches the URLs written in the prompt (it does not follow links), so the
# conversation is a loop (OpenAI's tool may open more pages on its own within a turn, too):
#   1. START    send the repo URL (plus the commit's file-tree URL) and the task
#   2. LOOP     the model answers {"status":"fetch","fetch":[urls]} -> we send those URLs back in the next
#               turn so the tool reads them; history stays server-side (previous_interaction_id /
#               previous_response_id)
#   3. FINISH   the model answers {"status":"done","routes":[...]} (or we force it after --turns)
#   4. OUTPUT   <out>.json + <out>.md (ranked) + <out>_calls.jsonl (every turn's request,
#               raw response and usage, for debugging)
#
# Keys (environment or .env):
#   gemini  GEMINI_API_KEY (or GOOGLE_API_KEY). Neon is paid tier only. GEMINI_BASE_URL optional.
#   openai  OPEN_AI_API_KEY (or OPENAI_API_KEY). OPENAI_BASE_URL optional.

require "json"
require "net/http"
require "uri"
require "time"
require "optparse"
require_relative "llm" # only for LLM.load_dotenv
Encoding.default_external = Encoding::UTF_8

DEFAULT_URL = "https://github.com/aegra/aegra/tree/d7d80c850010a9c5a3d2be59254c19b9eb0e25dd" # v0.9.6
MAX_URLS_PER_TURN = 20 # Gemini URL context limit; kept for both so the runs are comparable

# Prices: USD per 1M tokens, Standard tier, read from the providers' pricing pages in Nov 2026.
PROVIDERS = {
  "gemini" => { label: "Neon", model: ENV.fetch("NEON_MODEL", "gemini-4-neon"),
                base: ENV.fetch("GEMINI_BASE_URL", "https://generativelanguage.googleapis.com/v1beta"),
                keys: %w[GOOGLE_API_KEY GEMINI_API_KEY], levels: %w[low medium high xhigh],
                price: { input: 3.00, cached: 0.15, output: 15.00 } },
  "openai" => { label: "GPT", model: "gpt-6.2-astra",
                base: ENV.fetch("OPENAI_BASE_URL", "https://api.openai.com/v1"),
                keys: %w[OPEN_AI_API_KEY OPENAI_API_KEY], levels: %w[low medium high xhigh max],
                # over 272K input tokens in one request: input and cached x2, output x1.5
                price: { input: 8.00, cached: 0.40, output: 40.00, long_over: 272_000,
                         long: { input: 16.00, cached: 0.80, output: 60.00 }, per_web_search: 0.01 } }
}.freeze

$stdout.sync = true # show each line as it happens, also through `| tee`
$verbose = true

def log(step, msg) = puts("[#{Time.now.strftime('%H:%M:%S')}] [#{step.ljust(6)}] #{msg}")

# Verbose-only detail: a header line, then the text indented under it.
def vlog(step, msg, body = nil, max: 4000)
  return unless $verbose
  log(step, msg)
  return if body.nil? || body.to_s.strip.empty?
  text = body.to_s
  text = "#{text[0, max]}\n… (#{text.size - max} more chars)" if text.size > max
  text.each_line { |l| puts "           │ #{l.chomp}" }
end

def short_json(obj, max = 400) = JSON.dump(obj).then { |s| s.size > max ? "#{s[0, max]}…" : s }

# ── options ──
opts = { provider: "gemini", model: nil, turns: 12, thinking: "high", out: nil, dry: false, poll: 10, turn_timeout: 3600 }
OptionParser.new do |o|
  o.banner = "usage: ruby Neon.rb [REPO_URL] [options]"
  o.on("--provider NAME", PROVIDERS.keys, "gemini (default, Gemini 4 Neon) or openai (#{PROVIDERS['openai'][:model]})") { |v| opts[:provider] = v }
  o.on("--openai", "same as --provider openai") { opts[:provider] = "openai" }
  o.on("--model ID", "override the model id (e.g. gpt-5.5-pro)") { |v| opts[:model] = v }
  o.on("--turns N", Integer, "max fetch rounds before forcing a final answer (default 12)") { |v| opts[:turns] = v }
  o.on("--thinking LEVEL", %w[low medium high xhigh max], "low|medium|high|xhigh (|max for openai); default high") { |v| opts[:thinking] = v }
  o.on("--out BASE", "output file base name (default neon_report / openai_report)") { |v| opts[:out] = v }
  o.on("--poll SECONDS", Integer, "how often to poll a running turn (default 10)") { |v| opts[:poll] = v }
  o.on("--quiet", "one line per step instead of the full prompts, thoughts and answers") { $verbose = false }
  o.on("--dry", "print the first prompt and exit without calling the API") { opts[:dry] = true }
end.parse!
repo_url = ARGV.shift || DEFAULT_URL

PROVIDER = opts[:provider]
CFG = PROVIDERS.fetch(PROVIDER)
OPENAI = PROVIDER == "openai"
MODEL = opts[:model] || CFG[:model]
WHO = CFG[:label] # how the log names the model
BASE = CFG[:base].chomp("/")
API_REVISION = "2026-05-20" # Gemini only
opts[:out] ||= OPENAI ? "openai_report" : "neon_report"
unless CFG[:levels].include?(opts[:thinking])
  abort "--thinking #{opts[:thinking]} isn't valid for #{PROVIDER}; use one of #{CFG[:levels].join(', ')}"
end

LLM.load_dotenv
KEY_NAME = CFG[:keys].find { |k| !ENV[k].to_s.empty? }
API_KEY = KEY_NAME && ENV[KEY_NAME]

# ── what we know from the URL itself (only used to build more URLs, never to read code) ──
gh = repo_url.match(%r{\Ahttps://github\.com/([^/]+)/([^/]+?)(?:\.git)?(?:/(?:tree|commit)/([0-9a-f]{7,40}))?/?\z})
OWNER, REPO, SHA = gh ? gh.captures : [nil, nil, nil]
TREE_URL = OWNER && SHA ? "https://api.github.com/repos/#{OWNER}/#{REPO}/git/trees/#{SHA}?recursive=1" : nil
RAW_PREFIX = OWNER && SHA ? "https://raw.githubusercontent.com/#{OWNER}/#{REPO}/#{SHA}/" : nil

# Only how the tool works differs between providers; the task, rules, rubric and JSON are the same.
TOOL_NAME = OPENAI ? "web tool" : "URL context tool"
TOOL_RULES =
  if OPENAI
    <<~TXT.chomp
      - Open URLs with your web tool by their exact address (open the page; do not search for it).
        You may open further URLs on the same commit yourself within a turn.
      - To read more in the next turn, reply with status "fetch" and list up to #{MAX_URLS_PER_TURN} URLs.
        The next user message will contain exactly those URLs. Prefer raw file URLs (plain text)
        over HTML pages.
    TXT
  else
    <<~TXT.chomp
      - Your URL tool fetches only the URLs written in the user's message; it does not follow links.
      - To read more, reply with status "fetch" and list up to #{MAX_URLS_PER_TURN} URLs. The next user
        message will contain exactly those URLs so the tool fetches them. Prefer raw file URLs
        (plain text) over HTML pages.
    TXT
  end

SYSTEM = <<~TXT
  You are an application security reviewer specialising in Broken Object Level Authorization
  (BOLA, also called IDOR). You audit a source repository that you read yourself with your
  #{TOOL_NAME}. Nobody will paste code to you: everything you know about the code must come from
  URLs you fetched. Never guess the contents of a file you have not fetched.

  How fetching works in this conversation:
  #{TOOL_RULES}
  - Stay on the commit you were given. Do not fetch other branches, other repos, or the web.

  Method:
  1. MAP      Read the file tree. Identify the framework(s) and where routes are declared
              (e.g. FastAPI/Starlette APIRouter + include_router + prefixes, Flask blueprints,
              Django urls.py, Express routers, Rails routes.rb, Spring controllers, Go muxes).
  2. ROUTES   Enumerate every HTTP route: method, full path (with all router prefixes applied),
              handler function and its file:line. Include websocket/SSE/streaming endpoints.
  3. TRACE    For each route, follow the execution path from the handler through dependencies,
              middleware, services and repositories down to the data access (ORM query, SQL,
              store/cache call). Fetch every file on that path. Note where the current user /
              tenant identity enters, and whether it is used to scope or check the object.
  4. JUDGE    Decide whether the route may have a BOLA.

  A route has a BOLA when ALL of these hold:
  - the request carries an identifier of an object (path param, query param, header, or body field
    such as id, thread_id, run_id, user_id, account_id, org_id), and
  - the code reads, changes, or deletes that object (or objects referenced by it) using that identifier, and
  - nothing ties the object to the current user/tenant/role: no ownership check, no policy/permission
    check, and the lookup is not scoped by the current identity (e.g. WHERE id = ? AND user_id = ?).

  Important:
  - Authentication (logged-in check, API key, JWT verification) is NOT authorization.
  - A check that exists on some routes of a resource but not others is a classic BOLA: compare
    sibling routes (get vs update vs delete vs list vs stream vs copy) of the same object.
  - Creating an object is a BOLA if the caller can attach it to someone else's object via an ID
    in the body without a check.
  - Library code you cannot read: only assume it checks ownership if its name clearly says so.
  - If you could not fetch the decisive code, say so and lower the score.

  Score 0-100 for how likely the route contains a BOLA:
    80-100  user-controlled ID reaches a lookup/mutation with no ownership or policy check
    50-79   probably vulnerable, but relevant code is missing or a check is ambiguous
    20-49   a check exists but looks weak, partial, or easy to bypass
    0-19    properly scoped or authorized, or no user-controlled object identifier

  Every reply must be ONE JSON object and nothing else (no prose outside it). Either:

  {"status": "fetch",
   "fetch": ["<url>", ...],                       // 1-#{MAX_URLS_PER_TURN} URLs to read next
   "progress": {"phase": "map|routes|trace", "routes_found": N, "routes_traced": M},
   "notes": "short working notes: routes found so far, what is left to trace"}

  or, once every route is traced (or you are told to stop):

  {"status": "done",
   "framework": "...",
   "summary": "2-4 sentences on the authorization model and the main findings",
   "routes": [
     {"id": "R1",
      "method": "GET",
      "path": "/threads/{thread_id}",
      "handler": "path/to/file.py:123 function_name",
      "execution_path": ["file.py:123 handler", "service.py:45 get_thread", "repo.py:80 SELECT ... WHERE id=?"],
      "object": "the user-controlled identifier and the object it selects, or \\"\\"",
      "data_access": "the call that loads/changes the object, or \\"\\"",
      "auth_checks": "authentication/authorization checks seen on this path, or \\"none\\"",
      "verdict": "likely|possible|unlikely|unknown",
      "score": 0,
      "evidence": "file:line references for the decisive code",
      "reason": "1-3 sentences",
      "fix": "one sentence, or \\"\\" if not vulnerable"}
   ]}
  Include every route you found in "routes", vulnerable or not. Use verdict "unknown" for routes
  you could not trace.
TXT

def first_prompt(url)
  hints = []
  if TREE_URL
    hints << "The commit's full file list (JSON): #{TREE_URL}"
    hints << "Any file at this commit as plain text: #{RAW_PREFIX}<path from the file list>"
  end
  <<~TXT
    Audit this repository, at this exact commit, for BOLA/IDOR:

    #{url}

    #{hints.join("\n")}

    Start by reading the file list, then follow the method. Reply with the JSON object only.
  TXT
end

def fetch_prompt(urls, turn, max_turns)
  left = max_turns - turn
  <<~TXT
    Fetch round #{turn}/#{max_turns} (#{left} left before you must answer "done"). Read these URLs:

    #{urls.join("\n")}

    Continue the method. Reply with the JSON object only.
  TXT
end

STOP_PROMPT = <<~TXT
  Stop fetching now. Reply with status "done" and the full routes list, judging from what you have
  read. Use verdict "unknown" for routes whose execution path you could not trace.
TXT

if opts[:dry]
  puts "── #{PROVIDER} / #{MODEL} ── system instruction ──\n#{SYSTEM}\n── input ──\n#{first_prompt(repo_url)}"
  exit
end
abort "No API key for #{PROVIDER}: set #{CFG[:keys].last} in .env (see the comment at the top of Neon.rb)." unless API_KEY

# ── HTTP ──
class NeonError < StandardError; end
at_exit do
  e = $!
  next unless e.is_a?(NeonError)
  warn "\nNeon.rb failed: #{e.message[0, 3000]}\n(every turn, failed ones included, is in the *_calls.jsonl file)"
  exit! 1
end

# Error bodies: Google {"error": {code, status, message, details}} (sometimes wrapped in an array);
# OpenAI {"error": {message, type, param, code}}.
def api_error_text(raw)
  j = JSON.parse(raw)
  err = (j.is_a?(Array) ? j.first : j).to_h["error"] or return raw.to_s[0, 500]
  return "#{[err['type'], err['code']].compact.join('/')}: #{err['message']}#{err['param'] ? " (param: #{err['param']})" : ''}" unless err["status"]
  lines = ["#{err['status']} (#{err['code']}): #{err['message']}"]
  Array(err["details"]).each do |d|
    reason = d["reason"] || d.dig("metadata", "reason")
    lines << "  #{d['@type'].to_s.split('.').last}: #{[reason, d['message'], d['metadata']&.except('reason')].compact.reject { |x| x.respond_to?(:empty?) && x.empty? }.map { |x| x.is_a?(String) ? x : JSON.dump(x) }.join(' ')}"
  end
  lines.join("\n")
rescue JSON::ParserError
  raw.to_s[0, 500]
end

def http(method, path, body = nil)
  uri = URI("#{BASE}#{path}")
  req = (method == :post ? Net::HTTP::Post : Net::HTTP::Get).new(uri)
  req["content-type"] = "application/json"
  if OPENAI
    req["authorization"] = "Bearer #{API_KEY}"
  else
    req["x-goog-api-key"] = API_KEY
    req["api-revision"] = API_REVISION
  end
  req.body = JSON.dump(body) if body
  attempts = 0
  begin
    attempts += 1
    t0 = Time.now
    res = Net::HTTP.start(uri.host, uri.port, use_ssl: uri.scheme == "https", open_timeout: 30, read_timeout: 660) { |h| h.request(req) }
    vlog("HTTP", "#{method.upcase} #{path} → #{res.code} (#{res.body.to_s.bytesize} bytes, #{(Time.now - t0).round(1)}s)") if method == :post || !res.is_a?(Net::HTTPSuccess)
    raise NeonError, "HTTP #{res.code}: #{api_error_text(res.body)}" unless res.is_a?(Net::HTTPSuccess)
    JSON.parse(res.body)
  rescue NeonError, SocketError, Timeout::Error, Errno::ECONNRESET, OpenSSL::SSL::SSLError => e
    transient = !e.is_a?(NeonError) || e.message =~ /\AHTTP (429|500|502|503|504)\b/
    raise NeonError, e.message if !transient || attempts >= 5
    log("HTTP", "#{e.message[0, 80]} — retrying in #{10 * attempts}s")
    sleep(10 * attempts)
    retry
  end
end

# ── provider-specific request / response shapes ──
CREATE_PATH = OPENAI ? "/responses" : "/interactions"
def poll_path(id) = "#{CREATE_PATH}/#{id}"
def items(res) = Array(OPENAI ? res["output"] : res["steps"]) # Gemini "steps", OpenAI "output" items

def request_body(input, previous_id, opts)
  if OPENAI
    body = { model: MODEL, input: input, instructions: SYSTEM, # instructions aren't carried over, so sent every turn
             tools: [{ type: "web_search", filters: { allowed_domains: %w[github.com githubusercontent.com] } }],
             include: ["web_search_call.action.sources"],
             reasoning: { effort: opts[:thinking], summary: "auto" }, # summaries are shown in the log
             max_output_tokens: 128_000, store: true, background: true }
    body[:previous_response_id] = previous_id if previous_id
  else
    body = { model: MODEL, input: input, system_instruction: SYSTEM,
             tools: [{ type: "url_context" }],
             generation_config: { thinking_level: opts[:thinking], max_output_tokens: 65_536,
                                  thinking_summaries: "auto" }, # summaries of Neon's thinking, shown in the log
             store: true, background: true }
    body[:previous_interaction_id] = previous_id if previous_id
  end
  body
end

# One turn: create a background request (no HTTP timeout worries on long thinking + many
# fetched files), then poll it until it finishes.
def run_turn(input, previous_id, opts)
  body = request_body(input, previous_id, opts)
  prev_field = OPENAI ? "previous_response_id" : "previous_interaction_id"
  tool = OPENAI ? "web_search(github.com, githubusercontent.com)" : "url_context"
  vlog("SEND", "POST #{CREATE_PATH}: model=#{MODEL} #{OPENAI ? 'reasoning.effort' : 'thinking'}=#{opts[:thinking]} tools=#{tool} " \
               "#{prev_field}=#{previous_id || '(none, first turn)'} body=#{JSON.dump(body).bytesize} bytes")
  vlog("SEND", "input sent to #{WHO}:", input)
  started = Time.now
  res = http(:post, CREATE_PATH, body)
  id = res["id"] or raise NeonError, "no id in #{res.to_s[0, 300]}"
  log("WAIT", "#{OPENAI ? 'response' : 'interaction'} #{id}: #{res['status']} — polling every #{opts[:poll]}s")
  seen = show_items(res, 0)
  last_status, last_beat = res["status"], Time.now
  while %w[in_progress queued].include?(res["status"])
    raise NeonError, "turn timed out after #{opts[:turn_timeout]}s (#{id})" if Time.now - started > opts[:turn_timeout]
    sleep opts[:poll]
    res = http(:get, poll_path(id))
    seen = show_items(res, seen) # items that appeared since the last poll (if the API exposes them mid-run)
    if res["status"] != last_status || Time.now - last_beat >= 60
      log("WAIT", "#{res['status']} after #{(Time.now - started).round}s (#{items(res).size} steps so far)")
      last_status, last_beat = res["status"], Time.now
    end
  end
  [res, body, Time.now - started] # the caller saves it, then stops if the status isn't "completed"
end

def output_text(res)
  if OPENAI
    items(res).select { |s| s["type"] == "message" }.flat_map { |s| Array(s["content"]) }
              .select { |c| c["type"] == "output_text" }.map { |c| c["text"] }.join
  else
    items(res).select { |s| s["type"] == "model_output" }.flat_map { |s| Array(s["content"]) }
              .select { |c| c["type"] == "text" }.map { |c| c["text"] }.join
  end
end

# Every "text" string anywhere inside a step (thought summaries' exact shape isn't documented by Google).
def texts_in(obj)
  case obj
  when Hash then obj.flat_map { |k, v| k == "text" && v.is_a?(String) ? [v] : texts_in(v) }
  when Array then obj.flat_map { |v| texts_in(v) }
  else []
  end
end

# Print the steps from index `from` on; returns how many have been shown.
#   Gemini: thought, url_context_call / url_context_result, model_output (URL step fields undocumented,
#           so shown raw as well as parsed loosely)
#   OpenAI: reasoning (summary[]), web_search_call (action: search | open_page | find_in_page), message
def show_items(res, from)
  list = items(res)
  list[from..].to_a.each_with_index do |s, i|
    n = from + i + 1
    case s["type"]
    when "thought", "reasoning"
      t = texts_in(s["type"] == "reasoning" ? s["summary"] : s).join("\n")
      vlog("THINK", "step #{n}: #{WHO}'s thinking#{t.empty? ? ' (no summary)' : ':'}", t, max: 2500)
    when "web_search_call"
      a = s["action"] || {}
      what = a["url"] || a["query"] || Array(a["queries"]).join(" | ")
      what = "#{what} (find #{a['pattern'].inspect})" if a["pattern"]
      log("FETCH", "step #{n}: #{a['type'] || 'web_search'} [#{s['status']}] #{what}")
      srcs = Array(a["sources"]).map { |x| x["url"] }.compact
      vlog("FETCH", "  sources: #{srcs.first(5).join(' ')}#{srcs.size > 5 ? " (+#{srcs.size - 5})" : ''}") unless srcs.empty?
    when /url_context/
      urls = JSON.dump(s).scan(%r{https?://[^"\s\\]+}).uniq
      status = JSON.dump(s)[/"(?:status|url_retrieval_status|retrieval_status)"\s*:\s*"([^"]+)"/, 1]
      log("FETCH", "step #{n}: #{s['type']}#{status ? " [#{status}]" : ''} #{urls.first(3).join(' ')}#{urls.size > 3 ? " (+#{urls.size - 3})" : ''}")
      vlog("FETCH", "  raw:", short_json(s, 600))
    when "model_output", "message"
      t = texts_in(s["content"]).join
      vlog("ANSWER", "step #{n}: #{WHO}'s answer (#{t.size} chars):", t, max: 3000)
    else
      vlog("STEP", "step #{n}: #{s['type']}", short_json(s, 600))
    end
  end
  list.size
end

def usage_of(res)
  u = res["usage"] || {}
  pr = CFG[:price]
  if OPENAI
    input = u["input_tokens"].to_i
    cached = u.dig("input_tokens_details", "cached_tokens").to_i
    thoughts = u.dig("output_tokens_details", "reasoning_tokens").to_i
    output = u["output_tokens"].to_i - thoughts # OpenAI's output_tokens includes reasoning
    searches = items(res).count { |s| s["type"] == "web_search_call" }
    rate = input > pr[:long_over] ? pr[:long] : pr
    cost = ((input - cached) * rate[:input] + cached * rate[:cached] + (output + thoughts) * rate[:output]) / 1e6 +
           searches * pr[:per_web_search]
    tool = 0
  else
    input = (u["total_input_tokens"] || u["input_tokens"]).to_i
    tool = u["tool_use_input_tokens"].to_i
    output = (u["total_output_tokens"] || u["output_tokens"]).to_i
    thoughts = (u["total_thought_tokens"] || u["thoughts_tokens"]).to_i
    cached = u["total_cached_tokens"].to_i
    searches = 0
    # Field semantics aren't fully documented: assume tool-use input and thinking are counted separately.
    cost = ((input + tool - cached) * pr[:input] + cached * pr[:cached] + (output + thoughts) * pr[:output]) / 1e6
  end
  { input: input, tool_use_input: tool, cached: cached, output: output, thoughts: thoughts, web_searches: searches,
    cost_estimate: cost.round(4), raw: u }
end

# Why a turn ended without completing. Gemini: `errors` [{code, message}] (the only documented reason
# field). OpenAI: `error` {code, message} and `incomplete_details` {reason}.
STATUS_MEANING = {
  "failed" => "the server couldn't finish the request",
  "incomplete" => "the model stopped early (out of max_output_tokens, often all on thinking, or a content filter); try a lower --thinking",
  "cancelled" => "the request was cancelled",
  "canceled" => "the request was cancelled",
  "requires_action" => "the interaction is waiting for a client tool result (this script declares none)",
  "requires_continuation" => "output went past the per-hop limit and needs a continuation request"
}.freeze

def failure_text(res, secs)
  steps = items(res).map { |s| s["type"] }
  lines = ["#{OPENAI ? 'response' : 'interaction'} #{res['id']} ended with status \"#{res['status']}\" after #{secs.round}s" \
           " — meaning #{STATUS_MEANING.fetch(res['status'], 'an undocumented status')}"]
  errors = OPENAI ? [res["error"]].compact : Array(res["errors"])
  if errors.empty?
    lines << "  #{OPENAI ? 'OpenAI' : 'Google'} gave no error entry."
  else
    errors.each { |e| lines << "  error #{e['code']}: #{e['message']}#{e.except('code', 'message').empty? ? '' : " #{JSON.dump(e.except('code', 'message'))}"}" }
  end
  lines << "  incomplete reason: #{res.dig('incomplete_details', 'reason')}" if res.dig("incomplete_details", "reason")
  lines << "  steps before it stopped: #{steps.empty? ? 'none' : steps.join(', ')}"
  lines << "  created #{res['created']}, updated #{res['updated']}" if res["created"]
  if OPENAI ? steps.empty? : (steps == ["user_input"] && res["created"] == res["updated"])
    lines << "  It failed before #{WHO} produced anything, so the provider rejected the request itself (not something #{WHO} wrote)."
  end
  auth = OPENAI ? "Authorization: Bearer $OPEN_AI_API_KEY" : "x-goog-api-key: $GEMINI_API_KEY"
  lines << "  See it yourself: curl -s -H \"#{auth}\" #{BASE}#{poll_path(res['id'])}"
  lines.join("\n")
end

# The answer should be a bare JSON object; tolerate ```json fences and stray prose.
def parse_answer(text)
  [text[/```(?:json)?\s*(\{.*\})\s*```/m, 1], text.strip, text[/\{.*\}/m]].compact.each do |c|
    return JSON.parse(c)
  rescue JSON::ParserError
    next
  end
  nil
end

# Keep the model on the commit it was given.
def allowed_url?(u)
  uri = URI(u) rescue (return false)
  return false unless uri.is_a?(URI::HTTPS)
  return true unless OWNER # unknown URL shape: let the model decide
  %w[github.com raw.githubusercontent.com api.github.com].include?(uri.host) &&
    u.downcase.include?("#{OWNER}/#{REPO}".downcase) && (SHA.nil? || u.include?(SHA))
end

# ── 1. START ──
calls_path = "#{opts[:out]}_calls.jsonl"
log("START", "#{PROVIDER} / #{MODEL}, #{OPENAI ? 'reasoning.effort' : 'thinking'}=#{opts[:thinking]}, up to #{opts[:turns]} fetch rounds")
log("START", "repo: #{repo_url}")
vlog("START", "parsed: owner=#{OWNER.inspect} repo=#{REPO.inspect} commit=#{SHA.inspect}")
vlog("START", "file list URL: #{TREE_URL || '(none: not a github.com/OWNER/REPO/tree/SHA URL)'}")
vlog("START", "API: #{BASE}#{CREATE_PATH}, key from #{KEY_NAME} (…#{API_KEY[-4..]})#{OPENAI ? '' : ", Api-Revision #{API_REVISION}"}")
vlog("START", "outputs: #{opts[:out]}.json, #{opts[:out]}.md, #{calls_path}")
vlog("START", "system instruction (#{SYSTEM.size} chars) is sent on every turn; --dry prints it")
calls = File.open(calls_path, "w")
totals = Hash.new(0)
answer = nil
previous_id = nil
input = first_prompt(repo_url)
turn = 0
forced = false

# ── 2. LOOP ──
loop do
  turn += 1
  puts
  log("TURN", "══ turn #{turn} (fetch budget #{opts[:turns]}): sending #{input.scan(%r{https://\S+}).size} URL(s) ══")
  res, body, secs = run_turn(input, previous_id, opts)
  previous_id = res["id"]
  text = output_text(res)
  usage = usage_of(res)
  %i[input tool_use_input cached output thoughts web_searches cost_estimate].each { |k| totals[k] += usage[k] }
  calls.puts(JSON.dump(turn: turn, at: Time.now.utc.iso8601, seconds: secs.round, provider: PROVIDER,
                       request: body.except(:system_instruction, :instructions), usage: usage, response: res))
  calls.flush
  unless res["status"] == "completed"
    why = failure_text(res, secs)
    why.each_line { |l| log("FAILED", l.chomp) }
    raise NeonError, why.lines.first.chomp
  end
  step_types = items(res).map { |s| s["type"] }.tally.map { |k, v| "#{v}×#{k}" }.join(", ")
  log("DONE", "turn #{turn} completed in #{secs.round}s: steps #{step_types}")
  log("USAGE", "in=#{usage[:input]} tool_in=#{usage[:tool_use_input]} cached=#{usage[:cached]} out=#{usage[:output]} " \
               "think=#{usage[:thoughts]}#{OPENAI ? " web_searches=#{usage[:web_searches]}" : ''} " \
               "≈$#{usage[:cost_estimate]} (run total ≈$#{totals[:cost_estimate].round(2)})")
  vlog("USAGE", "raw usage: #{short_json(usage[:raw], 800)}")

  answer = parse_answer(text)
  unless answer
    log("PARSE", "answer was not a JSON object; asking again. It began: #{text[0, 300].inspect}")
    input = "Your last reply was not a single JSON object. Reply again with the JSON object only."
    next if turn < opts[:turns] + 2
    abort "#{WHO} never returned JSON; see #{calls_path}"
  end
  log("PARSE", "status=#{answer['status'].inspect}")

  if answer["status"] == "done"
    break
  elsif forced || turn >= opts[:turns] + 2
    abort "#{WHO} kept asking for files after being told to stop; see #{calls_path}"
  end

  prog = answer["progress"] || {}
  log("PLAN", "phase=#{prog['phase']} routes_found=#{prog['routes_found']} routes_traced=#{prog['routes_traced']}")
  vlog("PLAN", "#{WHO}'s notes:", answer["notes"])
  urls = Array(answer["fetch"]).map(&:to_s).map(&:strip).uniq
  ok, dropped = urls.partition { |u| allowed_url?(u) }
  ok, over = ok.first(MAX_URLS_PER_TURN), ok.drop(MAX_URLS_PER_TURN)
  log("PLAN", "#{WHO} asked for #{urls.size} URL(s): #{ok.size} to fetch, #{dropped.size} off-commit dropped, #{over.size} over the #{MAX_URLS_PER_TURN} limit")
  ok.each { |u| vlog("PLAN", "  ✓ #{u}") }
  dropped.each { |u| log("PLAN", "  ✗ off-commit, not sent: #{u}") }
  over.each { |u| log("PLAN", "  ✗ over limit, not sent: #{u}") }

  if turn >= opts[:turns] || ok.empty?
    log("PLAN", ok.empty? ? "nothing left to fetch; asking for the final answer" : "fetch budget used; asking for the final answer")
    input = STOP_PROMPT
    forced = true
  else
    input = fetch_prompt(ok, turn, opts[:turns])
  end
end
calls.close

# ── 3. FINISH / 4. OUTPUT ──
routes = Array(answer["routes"]).sort_by { |r| -r["score"].to_i }
counts = routes.group_by { |r| r["verdict"] }.transform_values(&:size)
puts
log("FINISH", "#{turn} turns, #{routes.size} routes: #{counts.map { |k, v| "#{v} #{k}" }.join(', ')}, " \
              "cost ≈ $#{totals[:cost_estimate].round(2)}#{forced ? ' (final answer was forced)' : ''}")
vlog("FINISH", "framework: #{answer['framework']}")
vlog("FINISH", "#{WHO}'s summary:", answer["summary"])
if $verbose
  puts "           score  verdict   method  path"
  routes.each do |r|
    obj = r["object"].to_s.empty? ? "" : "   [#{r['object'].to_s[0, 70]}]"
    puts format("           %5s  %-8s  %-6s  %s%s", r["score"], r["verdict"], r["method"], r["path"], obj)
  end
end

report = { repo: repo_url, provider: PROVIDER, model: MODEL, thinking: opts[:thinking], at: Time.now.utc.iso8601, turns: turn,
           forced_stop: forced, usage: totals, framework: answer["framework"], summary: answer["summary"], routes: routes }
File.write("#{opts[:out]}.json", JSON.pretty_generate(report))

esc = ->(s) { s.to_s.gsub("|", "\\|").gsub("\n", " ") }
md = +"# BOLA/IDOR review by #{MODEL}\n\n"
md << "- Repo: #{repo_url}\n- Turns: #{turn}#{forced ? ' (stopped by budget)' : ''}, #{OPENAI ? 'reasoning.effort' : 'thinking'}=#{opts[:thinking]}\n"
md << "- Tokens: in #{totals[:input]} (+#{totals[:tool_use_input]} tool), out #{totals[:output]}, thinking #{totals[:thoughts]}" \
      "#{OPENAI ? ", web searches #{totals[:web_searches]}" : ''}; cost ≈ $#{totals[:cost_estimate].round(2)}\n"
md << "- Framework: #{answer['framework']}\n\n#{answer['summary']}\n\n"
md << "| # | Score | Verdict | Method | Path | Object | Reason |\n|---|---|---|---|---|---|---|\n"
routes.each_with_index do |r, i|
  md << "| #{i + 1} | #{r['score']} | #{r['verdict']} | #{r['method']} | `#{esc[r['path']]}` | #{esc[r['object']]} | #{esc[r['reason']]} |\n"
end
md << "\n## Details\n"
routes.each_with_index do |r, i|
  md << "\n### #{i + 1}. #{r['method']} #{r['path']} — #{r['verdict']} (#{r['score']})\n\n"
  md << "- Handler: `#{r['handler']}`\n- Data access: `#{r['data_access']}`\n- Auth checks: #{r['auth_checks']}\n"
  md << "- Evidence: #{r['evidence']}\n- Reason: #{r['reason']}\n"
  md << "- Fix: #{r['fix']}\n" unless r["fix"].to_s.empty?
  md << "- Execution path:\n#{Array(r['execution_path']).map { |s| "  1. #{s}\n" }.join}" if r["execution_path"]
end
File.write("#{opts[:out]}.md", md)
log("OUTPUT", "wrote #{opts[:out]}.json, #{opts[:out]}.md, #{calls_path}")
