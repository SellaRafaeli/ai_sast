#!/usr/bin/env ruby
# Run the BOLA detector against every test repo and check it against test_repos/expected.yml.
#
#   test_repos/run_tests.rb                    # trace + LLM analysis for every repo
#   test_repos/run_tests.rb aegra              # only cases whose name contains "aegra"
#   test_repos/run_tests.rb --trace-only       # no LLM calls: only check the routes get traced
#   test_repos/run_tests.rb --reuse            # re-check the last results against expected.yml; runs nothing
#
# The scanner's own output is streamed live (indented), then each case gets a result block,
# and a summary at the end. Outputs go to test_repos/results/<case>/. Exit code 1 if any case fails.
#
# Every run except --trace-only also saves each case's result to test_repos/scoreboard.json (one entry
# per case, so running one case keeps the others) and rewrites the "Test results" section at the top
# of README.md from it.

require "yaml"
require "json"
require "time"
require "optparse"
require "fileutils"

$stdout.sync = true
Encoding.default_external = Encoding::UTF_8
HERE = __dir__
ROOT = File.expand_path("..", HERE)
FLAGGED = %w[likely possible].freeze
SCOREBOARD = File.join(HERE, "scoreboard.json")
README = File.join(ROOT, "README.md")
SCANNER_FILES = %w[route_tracer.rb analyze_bola.rb llm.rb].freeze

opts = { trace_only: false, jobs: nil, reuse: false }
OptionParser.new do |o|
  o.banner = "usage: test_repos/run_tests.rb [NAME_FILTER] [options]"
  o.on("--trace-only", "skip the LLM analysis; only check that expected routes are traced") { opts[:trace_only] = true }
  o.on("--jobs N", Integer, "LLM calls in parallel (passed to analyze_bola.rb)") { |v| opts[:jobs] = v }
  o.on("--reuse", "re-check the last run's results/ against expected.yml; runs nothing") { opts[:reuse] = true }
end.parse!
filter = ARGV[0]

# ── output helpers ──
COLOR = $stdout.tty? && !ENV["NO_COLOR"]
def paint(s, code) = COLOR ? "\e[#{code}m#{s}\e[0m" : s
def green(s) = paint(s, 32)
def red(s) = paint(s, 31)
def yellow(s) = paint(s, 33)
def dim(s) = paint(s, 2)
def bold(s) = paint(s, 1)

# Run a command, echoing its output line by line as it arrives. Returns true on exit 0.
def stream(cmd, log)
  puts dim("  $ #{cmd.map { |a| a.include?(' ') ? a.inspect : a }.join(' ')}")
  IO.popen(cmd, err: %i[child out], chdir: ROOT) do |io|
    io.each_line do |line|
      log.write(line)
      puts dim("  │ ") + colorize_verdict(line.chomp)
    end
  end
  $?.success?
end

def colorize_verdict(line)
  return line unless line.start_with?("[verdict]")
  line.include?(" likely ") ? red(line) : line.include?(" possible ") ? yellow(line) : line
end

# Scanner version: short commit of this repo, "-dirty" when the scanner files have uncommitted changes
def scanner_version
  sha = `git -C #{ROOT} rev-parse --short HEAD 2>/dev/null`.strip
  dirty = !`git -C #{ROOT} status --porcelain -- #{SCANNER_FILES.join(' ')} 2>/dev/null`.strip.empty?
  sha.empty? ? "unknown" : "#{sha}#{dirty ? '-dirty' : ''}"
end

# ── route matching ──
# "POST /threads/{thread_id}/runs" -> ["POST", ["threads", ":", "runs"]]
def norm(route)
  verb, path = route.to_s.strip.split(/\s+/, 2)
  segs = path.to_s.split("/").reject(&:empty?).map { |s| s.match?(/\A(:\w+|\{[^}]*\}|<[^>]*>)\z/) ? ":" : s }
  [verb.upcase, segs]
end

# Expected route matches a traced route if the verbs match and the paths are equal, or (with
# loose: true) the traced path is the expected one minus up to 2 leading literal segments
# (in case the tracer misses a mounted-router prefix like /api), e.g. /api/v2/notes/: ~ /v2/notes/:.
def match?(expected, traced, loose: true)
  ev, es = norm(expected)
  tv, ts = norm(traced)
  return false unless ev == tv || %w[ANY ALL].include?(tv)
  return true if es == ts
  drop = es.size - ts.size
  loose && !ts.empty? && drop.between?(1, 2) && es.last(ts.size) == ts && es.first(drop).none?(":")
end

# Exact match first, so "POST /runs" never stands in for "POST /threads/{id}/runs".
def find(list, expected)
  list.find { |r| match?(expected, r["route"], loose: false) } || list.find { |r| match?(expected, r["route"]) }
end

# ── checking: one case's analyzer results -> a result entry (what goes into scoreboard.json) ──
def scored(hit) = { "verdict" => hit["verdict"], "score" => hit["score"] }

def check(c, results, traces)
  vulnerable = Array(c["vulnerable"]).map do |r|
    hit = find(results, r)
    result = if hit.nil? then find(traces, r) ? "missed" : "not_traced"
             elsif FLAGGED.include?(hit["verdict"]) then "detected"
             else "missed"
             end
    { "route" => r, "result" => result }.merge(hit ? scored(hit) : {})
  end
  safe = Array(c["safe"]).map do |r|
    hit = find(results, r)
    result = hit.nil? ? "not_traced" : FLAGGED.include?(hit["verdict"]) ? "false_positive" : "ok"
    { "route" => r, "result" => result }.merge(hit ? scored(hit) : {})
  end
  labeled = Array(c["vulnerable"]) + Array(c["safe"])
  unlabeled = results.select { |h| FLAGGED.include?(h["verdict"]) && labeled.none? { |r| match?(r, h["route"]) } }
                     .map { |h| { "route" => h["route"] }.merge(scored(h)) }
  ok = vulnerable.all? { |v| v["result"] == "detected" } && safe.none? { |s| s["result"] == "false_positive" }
  { "status" => ok ? "pass" : "fail", "routes_traced" => traces.size,
    "routes_flagged" => results.count { |h| FLAGGED.include?(h["verdict"]) },
    "vulnerable" => vulnerable, "safe" => safe, "unlabeled" => unlabeled }
end

def counts(e)
  v, s = e["vulnerable"] || [], e["safe"] || []
  { detected: v.count { |x| x["result"] == "detected" }, known: v.size,
    fp: s.count { |x| x["result"] == "false_positive" }, safe: s.size, unlabeled: (e["unlabeled"] || []).size }
end

def print_entry(e)
  puts bold("  ▸ expected BOLA routes")
  e["vulnerable"].each do |v|
    label = v["result"] == "not_traced" ? "✗ not traced" : "#{v['result'] == 'detected' ? '✓' : '✗'} #{v['verdict']} #{v['score']}"
    puts "    #{v['result'] == 'detected' ? green(label.ljust(15)) : red(label.ljust(15))}  #{v['route']}"
  end
  if e["safe"].any?
    puts bold("  ▸ expected safe routes")
    e["safe"].each do |s|
      next puts("    #{dim('- not traced'.ljust(15))}  #{s['route']}") if s["result"] == "not_traced"
      label = "#{s['result'] == 'ok' ? '✓' : '✗'} #{s['verdict']} #{s['score']}".ljust(15)
      puts "    #{s['result'] == 'ok' ? green(label) : red(label)}  #{s['route']}"
    end
  end
  return if e["unlabeled"].empty?
  puts bold("  ▸ other flagged routes") + dim("  (not in expected.yml; review by hand)")
  e["unlabeled"].each { |u| puts "    #{yellow("? #{u['verdict']} #{u['score']}")}  #{u['route']}" }
end

# ── README "Test results" section, rebuilt from scoreboard.json ──
START_MARK = "<!-- test-results:start — generated by test_repos/run_tests.rb; edits here are overwritten -->"
END_MARK = "<!-- test-results:end -->"

def cell(s) = s.to_s.gsub("|", "\\|").gsub(/\s+/, " ").strip
def code(s) = "`#{cell(s)}`"
def pct(a, b) = b.zero? ? "–" : "#{(100.0 * a / b).round}%"
def day(t) = t.to_s[0, 10]
def scanner_said(x) = x["result"] == "not_traced" ? "not traced" : "#{x['verdict']} #{x['score']}"

def why_missed(v)
  return "not traced: the tracer didn't find the route" if v["result"] == "not_traced"
  return "traced, but missing from the analyzer's answer" unless v["verdict"]
  "traced, but scored #{v['verdict']} (#{v['score']})"
end

def render_results(cases, board)
  entries = cases.map { |c| [c, board[c["name"]]] }
  ran = entries.select { |_c, e| e && e["status"] != "error" }
  tot = ran.map { |_c, e| counts(e) }
  sum = ->(k) { tot.sum { |t| t[k] } }
  passing = ran.count { |_c, e| e["status"] == "pass" }
  models = ran.map { |_c, e| e["model"] }.compact.uniq
  scanners = ran.map { |_c, e| e["scanner"] }.compact.uniq - ["unknown"]
  last = ran.map { |_c, e| e["run_at"] }.compact.max

  md = [START_MARK, "## Test results", ""]
  md << "**#{sum[:detected]} of #{sum[:known]} known BOLAs detected (#{pct(sum[:detected], sum[:known])}) across " \
        "#{ran.size} app#{ran.size == 1 ? '' : 's'} · #{sum[:fp]} false positives on #{sum[:safe]} safe routes · " \
        "#{passing}/#{ran.size} apps pass.**"
  not_run = entries.size - ran.size
  md << "#{not_run} app#{not_run == 1 ? '' : 's'} in `expected.yml` #{not_run == 1 ? 'has' : 'have'} no results (not run yet, or the last run errored) and #{not_run == 1 ? 'is' : 'are'} left out of the totals." if not_run.positive?
  md << ""
  md << "Last run #{day(last)}" \
        "#{models.size == 1 ? " with #{models.first}" : models.any? ? " with #{models.join(', ')}" : ''}" \
        "#{scanners.size == 1 ? ", scanner `#{scanners.first}`" : scanners.any? ? ", scanner versions #{scanners.map { |s| "`#{s}`" }.join(', ')}" : ''}."
  md << ""
  md << "Each test app is a real codebase with known BOLA/IDOR bugs. [`test_repos/expected.yml`](test_repos/expected.yml) " \
        "lists them, plus routes known to check ownership (\"safe\"). An app **passes** when the scanner flags every known BOLA " \
        "(verdict `likely` or `possible`) and none of its safe routes. **Unlabeled flags** are flags on routes the file doesn't " \
        "list: possible new findings or false positives, to review by hand. Run `test_repos/run_tests.rb` to update this section " \
        "(see [test_repos/README.md](test_repos/README.md))."
  md << ""
  md << "| App | Stack | Known bugs from | Detected | Missed | False positives | Unlabeled flags | Result | Last run |"
  md << "|---|---|---|---|---|---|---|---|---|"
  entries.each do |c, e|
    if e.nil? || e["status"] == "error"
      md << "| #{cell(c['name'])} | #{cell(c['stack'])} | #{cell(c['source'])} | – | – | – | – | " \
            "#{e ? "⚠️ error: #{cell(e['error'])}" : 'not run'} | #{e ? day(e['run_at']) : '–'} |"
      next
    end
    k = counts(e)
    md << "| #{cell(c['name'])} | #{cell(c['stack'])} | #{cell(c['source'])} | #{k[:detected]}/#{k[:known]} | " \
          "#{k[:known] - k[:detected]} | #{k[:fp]}/#{k[:safe]} | #{k[:unlabeled]} | " \
          "#{e['status'] == 'pass' ? '✅ pass' : '❌ fail'} | #{day(e['run_at'])} |"
  end
  md << "| **Total** | | | **#{sum[:detected]}/#{sum[:known]} (#{pct(sum[:detected], sum[:known])})** | " \
        "**#{sum[:known] - sum[:detected]}** | **#{sum[:fp]}/#{sum[:safe]}** | **#{sum[:unlabeled]}** | " \
        "**#{passing}/#{ran.size} pass** | |"

  missed = ran.flat_map { |c, e| e["vulnerable"].reject { |v| v["result"] == "detected" }.map { |v| [c, v] } }
  md << "" << "### Missed BOLAs (#{missed.size})" << ""
  if missed.empty?
    md << "None."
  else
    md << "| App | Route | Why |" << "|---|---|---|"
    missed.each { |c, v| md << "| #{cell(c['name'])} | #{code(v['route'])} | #{cell(why_missed(v))} |" }
  end

  fps = ran.flat_map { |c, e| e["safe"].select { |s| s["result"] == "false_positive" }.map { |s| [c, s] } }
  md << "" << "### False positives on safe routes (#{fps.size})" << ""
  if fps.empty?
    md << "None."
  else
    md << "| App | Route | Scanner said |" << "|---|---|---|"
    fps.each { |c, s| md << "| #{cell(c['name'])} | #{code(s['route'])} | #{s['verdict']} #{s['score']} |" }
  end

  md << "" << "### Details by app" << ""
  ran.each do |c, e|
    k = counts(e)
    md << "<details><summary><b>#{cell(c['name'])}</b> #{e['status'] == 'pass' ? '✅' : '❌'} " \
          "#{k[:detected]}/#{k[:known]} detected · #{k[:fp]}/#{k[:safe]} false positives · #{k[:unlabeled]} unlabeled flags</summary>"
    md << ""
    md << "#{cell(c['stack'])} · bugs from #{cell(c['source'])} · #{e['routes_traced']} routes traced, " \
          "#{e['routes_flagged']} flagged · run #{e['run_at']} with #{e['model'] || 'unknown model'}#{e['scanner'] && e['scanner'] != 'unknown' ? ", scanner `#{e['scanner']}`" : ''}"
    md << ""
    md << "| | Route | Expected | Scanner said |" << "|---|---|---|---|"
    e["vulnerable"].each { |v| md << "| #{v['result'] == 'detected' ? '✅' : '❌'} | #{code(v['route'])} | BOLA | #{scanner_said(v)} |" }
    e["safe"].each do |s|
      icon = { "ok" => "✅", "false_positive" => "❌" }.fetch(s["result"], "➖")
      md << "| #{icon} | #{code(s['route'])} | safe | #{scanner_said(s)} |"
    end
    e["unlabeled"].each { |u| md << "| 🔍 | #{code(u['route'])} | unlabeled | #{u['verdict']} #{u['score']} |" }
    md << "" << "</details>" << ""
  end
  md << END_MARK
  md.join("\n")
end

# Replace the marked section, or insert it right after the README's title.
def write_readme(section)
  text = File.read(README)
  text = if text.include?(START_MARK) && text.include?(END_MARK)
           text.sub(/#{Regexp.escape(START_MARK)}.*?#{Regexp.escape(END_MARK)}/m) { section }
         else
           lines = text.lines
           title = lines.index { |l| l.start_with?("# ") } || -1
           (lines[0..title] + ["\n", section, "\n\n"] + lines[(title + 1)..]).join
         end
  File.write(README, text.sub(/#{Regexp.escape(END_MARK)}\n{3,}/) { "#{END_MARK}\n\n" })
end

# ── main ──
all_cases = YAML.load_file(File.join(HERE, "expected.yml"))
cases = filter ? all_cases.select { |c| c["name"].include?(filter) } : all_cases
abort "no cases match #{filter.inspect}" if cases.empty?
board = File.exist?(SCOREBOARD) ? JSON.parse(File.read(SCOREBOARD)) : {}

summary = []
cases.each_with_index do |c, i|
  name = c["name"]
  repo = File.join(HERE, c["repo"])
  out = File.join(HERE, "results", name)
  FileUtils.mkdir_p(out)
  vulnerable = Array(c["vulnerable"])
  base = { "name" => name, "stack" => c["stack"], "source" => c["source"] }

  puts
  puts bold("━━━ [#{i + 1}/#{cases.size}] #{name}") + dim("  (#{c['source']})")
  unless File.directory?(repo)
    puts red("  repo missing: #{repo} — run test_repos/fetch.sh")
    board[name] = base.merge("status" => "error", "error" => "repo missing", "run_at" => Time.now.utc.iso8601) unless opts[:trace_only]
    summary << { name: name, ok: false, note: "repo missing" }
    next
  end

  log = File.open(opts[:reuse] ? File::NULL : File.join(out, "run.log"), "w")
  t0 = Time.now

  # 1. Trace
  puts bold("  ▸ trace")
  trace_file = File.join(out, "trace.json")
  traced_ok = if opts[:reuse]
                puts dim("  reusing #{trace_file}")
                File.exist?(trace_file)
              else
                stream(["ruby", "route_tracer.rb", repo, "--with-source", "--out", trace_file], log)
              end
  traces = traced_ok && File.exist?(trace_file) ? JSON.parse(File.read(trace_file)) : []

  puts bold("  ▸ coverage") + dim("  (expected BOLA routes found by the tracer)")
  missing = vulnerable.reject { |r| find(traces, r) }
  vulnerable.each { |r| puts "    #{find(traces, r) ? green('✓ traced ') : red('✗ missing')}  #{r}" }

  # 2. Analyze
  report = File.join(out, "bola_report.json")
  scanner_file = File.join(out, "scanner.txt")
  analyzed = false
  if opts[:trace_only]
    puts dim("  ▸ analysis skipped (--trace-only)")
  elsif traces.empty?
    puts red("  ▸ analysis skipped: no routes traced")
  elsif opts[:reuse]
    puts dim("  reusing #{report}")
    analyzed = File.exist?(report)
    puts red("  no earlier report — run without --reuse first") unless analyzed
  else
    puts bold("  ▸ analyze")
    File.delete(report) if File.exist?(report)
    cmd = ["ruby", "analyze_bola.rb", trace_file, "--out", report.delete_suffix(".json")]
    cmd += ["--jobs", opts[:jobs].to_s] if opts[:jobs]
    analyzed = stream(cmd, log) && File.exist?(report)
    File.write(scanner_file, scanner_version) if analyzed
    puts red("  analyzer failed — see #{out}/run.log") unless analyzed
  end
  log.close

  # 3. Check
  if opts[:trace_only]
    ok = traced_ok && missing.empty?
    note = "#{vulnerable.size - missing.size}/#{vulnerable.size} traced"
  elsif analyzed
    rep = JSON.parse(File.read(report))
    entry = base.merge(check(c, rep["routes"], traces))
                .merge("run_at" => rep["generated_at"], "model" => rep["model"],
                       "scanner" => File.exist?(scanner_file) ? File.read(scanner_file).strip : "unknown")
    board[name] = entry
    print_entry(entry)
    k = counts(entry)
    ok = entry["status"] == "pass"
    note = "#{k[:detected]}/#{k[:known]} detected, #{k[:fp]}/#{k[:safe]} false positives, #{k[:unlabeled]} unlabeled flags"
  else
    error = traces.empty? ? "no routes traced" : "analyzer failed"
    board[name] = base.merge("status" => "error", "error" => error, "run_at" => Time.now.utc.iso8601)
    ok = false
    note = error
  end
  puts "  #{ok ? green(bold('PASS')) : red(bold('FAIL'))}  #{note}  " + dim("(#{(Time.now - t0).round}s, results in test_repos/results/#{name}/)")
  summary << { name: name, ok: ok, note: note }
end

puts
puts bold("━━━ summary")
summary.each { |s| puts "  #{s[:ok] ? green('PASS') : red('FAIL')}  #{s[:name].ljust(20)} #{s[:note]}" }

if opts[:trace_only]
  puts dim("  README and scoreboard not updated (--trace-only has no detection results)")
else
  names = all_cases.map { |c| c["name"] }
  board = board.select { |k, _| names.include?(k) }.sort_by { |k, _| names.index(k) }.to_h   # drop removed cases
  File.write(SCOREBOARD, JSON.pretty_generate(board) + "\n")
  write_readme(render_results(all_cases, board))
  puts dim("  updated README.md (Test results) and test_repos/scoreboard.json")
end
exit(summary.all? { |s| s[:ok] } ? 0 : 1)
