#!/usr/bin/env ruby
# Run the BOLA detector against every test repo and check it against test_repos/expected.yml.
#
#   test_repos/run_tests.rb                    # trace + LLM analysis for every repo
#   test_repos/run_tests.rb aegra              # only cases whose name contains "aegra"
#   test_repos/run_tests.rb --trace-only       # no LLM calls: only check the routes get traced
#   test_repos/run_tests.rb --reuse            # re-check the last results against expected.yml; runs nothing
#
# The scanner's own output is streamed live (indented), then each case gets a result block,
# and a summary at the end. Each case is scored by coverage: the % of its known BOLAs the scanner flagged.
# Outputs go to test_repos/results/<case>/. Exit code 1 only if a case couldn't be run.
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
  { "status" => "ok", "routes_traced" => traces.size,
    "routes_flagged" => results.count { |h| FLAGGED.include?(h["verdict"]) },
    "vulnerable" => vulnerable, "safe" => safe, "unlabeled" => unlabeled }
end

def counts(e)
  v, s = e["vulnerable"] || [], e["safe"] || []
  { detected: v.count { |x| x["result"] == "detected" }, known: v.size,
    fp: s.count { |x| x["result"] == "false_positive" }, safe: s.size, unlabeled: (e["unlabeled"] || []).size }
end

# Coverage = share of known BOLAs the scanner flagged
def pct_num(a, b) = b.zero? ? nil : (100.0 * a / b).round
def pct(a, b) = b.zero? ? "–" : "#{pct_num(a, b)}%"
def coverage(k) = "#{pct(k[:detected], k[:known])} (#{k[:detected]}/#{k[:known]})"
def grade(p) = p.nil? ? "⚪" : p >= 80 ? "🟢" : p >= 50 ? "🟡" : "🔴"
def color_for(p, s) = p.nil? ? s : p >= 80 ? green(s) : p >= 50 ? yellow(s) : red(s)
def when_tested(t) = t ? Time.parse(t).utc.strftime("%Y-%m-%d %H:%M UTC") : "–"

# Why a known BOLA wasn't flagged: the explanation from expected.yml `gaps:` when there is one,
# plus what happened mechanically.
def why_missed(v, c)
  how = if v["result"] == "not_traced" then "not traced: the tracer didn't find the route"
        elsif !v["verdict"] then "traced, but missing from the analyzer's answer"
        else "traced, but scored #{v['verdict']} #{v['score']}"
        end
  note = (c["gaps"] || {}).find { |r, _| match?(r, v["route"], loose: false) }&.last
  note ? "#{note} (#{how})" : how
end

def misses(e) = (e["vulnerable"] || []).reject { |v| v["result"] == "detected" }

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
MAX_LISTED = 3 # "Not covered" cell in the main table lists at most this many routes

def cell(s) = s.to_s.gsub("|", "\\|").gsub(/\s+/, " ").strip
def code(s) = "`#{cell(s)}`"
# The app's name, linked to its homepage when expected.yml has one
def app_link(c) = c["homepage"] ? "[#{cell(c['name'])}](#{c['homepage']})" : cell(c["name"])
def scanner_said(x) = x["result"] == "not_traced" ? "not traced" : "#{x['verdict']} #{x['score']}"

# Short "what isn't covered" for the main table: the routes, with the gap note when there is one
def not_covered_cell(e, c)
  m = misses(e)
  return "—" if m.empty?
  notes = c["gaps"] || {}
  items = m.first(MAX_LISTED).map do |v|
    note = notes.find { |r, _| match?(r, v["route"], loose: false) }&.last
    note ? "#{code(v['route'])}: #{cell(note)}" : "#{code(v['route'])} (#{v['result'] == 'not_traced' ? 'not traced' : "scored #{v['score']}"})"
  end
  items << "+#{m.size - MAX_LISTED} more" if m.size > MAX_LISTED
  items.join("<br>")
end

def render_results(cases, board)
  entries = cases.map { |c| [c, board[c["name"]]] }
  ran = entries.select { |_c, e| e && e["status"] != "error" }
  tot = ran.map { |_c, e| counts(e) }
  sum = ->(k) { tot.sum { |t| t[k] } }
  models = ran.map { |_c, e| e["model"] }.compact.uniq
  scanners = ran.map { |_c, e| e["scanner"] }.compact.uniq - ["unknown"]
  dates = ran.map { |_c, e| e["run_at"] }.compact.sort
  overall = pct_num(sum[:detected], sum[:known])

  md = [START_MARK, "## Test results", ""]
  md << "**#{grade(overall)} Coverage: #{pct(sum[:detected], sum[:known])}**: #{sum[:detected]} of #{sum[:known]} known BOLAs " \
        "detected across #{ran.size} app#{ran.size == 1 ? '' : 's'} · #{sum[:fp]} false positive#{sum[:fp] == 1 ? '' : 's'} on #{sum[:safe]} safe routes · " \
        "#{sum[:unlabeled]} unlabeled flags to review."
  md << ""
  tested = if dates.empty? then "No app has been tested yet"
           elsif when_tested(dates.first) == when_tested(dates.last) then "Tested #{when_tested(dates.last)}"
           else "Tested between #{when_tested(dates.first)} and #{when_tested(dates.last)} (each app's date is in the table)"
           end
  md << "#{tested}" \
        "#{models.any? ? " with #{models.join(', ')}" : ''}" \
        "#{scanners.size == 1 ? ", scanner `#{scanners.first}`" : scanners.any? ? ", scanner versions #{scanners.map { |s| "`#{s}`" }.join(', ')}" : ''}."
  not_run = entries.size - ran.size
  md << "#{not_run} app#{not_run == 1 ? '' : 's'} in `expected.yml` #{not_run == 1 ? 'has' : 'have'} no results (not run yet, or the last run errored) and #{not_run == 1 ? 'is' : 'are'} left out of the totals." if not_run.positive?
  md << ""
  md << "Each test app is a real codebase with known BOLA/IDOR bugs. [`test_repos/expected.yml`](test_repos/expected.yml) lists them, " \
        "plus routes known to check ownership (\"safe\"). **Coverage** is the share of known BOLAs the scanner flagged " \
        "(verdict `likely` or `possible`): 🟢 80% or more, 🟡 50–79%, 🔴 under 50%. **False positives** are safe routes it flagged. " \
        "**Unlabeled flags** are flags on routes the file doesn't list: possible new findings or false positives, to review by hand. " \
        "Run `test_repos/run_tests.rb` to update this section (see [test_repos/README.md](test_repos/README.md))."
  md << ""
  md << "| App | Stack | Known bugs from | Coverage | Not covered | False positives | Unlabeled flags | Tested |"
  md << "|---|---|---|---|---|---|---|---|"
  entries.each do |c, e|
    if e.nil? || e["status"] == "error"
      md << "| #{app_link(c)} | #{cell(c['stack'])} | #{cell(c['source'])} | " \
            "#{e ?"⚠️ error: #{cell(e['error'])}" : 'not run'} | – | – | – | #{e ? when_tested(e['run_at']) : '–'} |"
      next
    end
    k = counts(e)
    md << "| #{app_link(c)} | #{cell(c['stack'])} | #{cell(c['source'])} | " \
          "#{grade(pct_num(k[:detected], k[:known]))} #{coverage(k)} | #{not_covered_cell(e, c)} | " \
          "#{k[:fp]}/#{k[:safe]} | #{k[:unlabeled]} | #{when_tested(e['run_at'])} |"
  end
  md << "| **Total** | | | **#{grade(overall)} #{coverage(detected: sum[:detected], known: sum[:known])}** | " \
        "**#{sum[:known] - sum[:detected]} not covered** | **#{sum[:fp]}/#{sum[:safe]}** | **#{sum[:unlabeled]}** | |"

  missed = ran.flat_map { |c, e| misses(e).map { |v| [c, e, v] } }
  md << "" << "### Not covered (#{missed.size})" << ""
  md << "Known BOLAs the scanner didn't flag, and why. Explanations come from `gaps:` in `expected.yml`; the part in " \
        "parentheses is what happened in the run." << "" if missed.any?
  if missed.empty?
    md << "None: every known BOLA was flagged."
  else
    md << "| App | Route | Why | Tested |" << "|---|---|---|---|"
    missed.each { |c, e, v| md << "| #{cell(c['name'])} | #{code(v['route'])} | #{cell(why_missed(v, c))} | #{when_tested(e['run_at'])} |" }
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
    md << "<details><summary><b>#{cell(c['name'])}</b> #{grade(pct_num(k[:detected], k[:known]))} #{coverage(k)} coverage · " \
          "#{k[:fp]}/#{k[:safe]} false positives · #{k[:unlabeled]} unlabeled flags · tested #{when_tested(e['run_at'])}</summary>"
    md << ""
    md << "#{c['homepage'] ? "[Homepage](#{c['homepage']}) · " : ''}#{cell(c['stack'])} · bugs from #{cell(c['source'])} · #{e['routes_traced']} routes traced, " \
          "#{e['routes_flagged']} flagged · tested #{when_tested(e['run_at'])} with #{e['model'] || 'unknown model'}" \
          "#{e['scanner'] && e['scanner'] != 'unknown' ? ", scanner `#{e['scanner']}`" : ''}"
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
    summary << { name: name, error: true, p: nil, label: "ERROR: repo missing", note: "" }
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
  # The headline per case is coverage: % of known BOLAs flagged (or, with --trace-only, % traced)
  if opts[:trace_only]
    got = vulnerable.size - missing.size
    p = pct_num(got, vulnerable.size)
    label = "#{pct(got, vulnerable.size)} traced (#{got}/#{vulnerable.size})"
    note = ""
  elsif analyzed
    rep = JSON.parse(File.read(report))
    entry = base.merge(check(c, rep["routes"], traces))
                .merge("run_at" => rep["generated_at"], "model" => rep["model"],
                       "scanner" => File.exist?(scanner_file) ? File.read(scanner_file).strip : "unknown")
    board[name] = entry
    print_entry(entry)
    k = counts(entry)
    p = pct_num(k[:detected], k[:known])
    label = "#{coverage(k)} coverage"
    note = "#{k[:fp]}/#{k[:safe]} false positives · #{k[:unlabeled]} unlabeled flags · tested #{when_tested(entry['run_at'])}"
    gaps = misses(entry)
    if gaps.any?
      puts bold("  ▸ not covered")
      gaps.each { |v| puts "    #{red('✗')} #{v['route']}: #{why_missed(v, c)}" }
    end
  else
    error = traces.empty? ? "no routes traced" : "analyzer failed"
    board[name] = base.merge("status" => "error", "error" => error, "run_at" => Time.now.utc.iso8601)
    p = nil
    label = red("ERROR: #{error}")
  end
  puts "  #{bold(color_for(p, label))}  #{note}  " + dim("(#{(Time.now - t0).round}s, results in test_repos/results/#{name}/)")
  summary << { name: name, error: p.nil? && !opts[:trace_only], p: p, label: label, note: note }
end

puts
puts bold("━━━ summary")
summary.each { |s| puts "  #{s[:name].ljust(20)} #{color_for(s[:p], s[:label].ljust(26))} #{s[:note]}" }

if opts[:trace_only]
  puts dim("  README and scoreboard not updated (--trace-only has no detection results)")
else
  names = all_cases.map { |c| c["name"] }
  board = board.select { |k, _| names.include?(k) }.sort_by { |k, _| names.index(k) }.to_h   # drop removed cases
  File.write(SCOREBOARD, JSON.pretty_generate(board) + "\n")
  write_readme(render_results(all_cases, board))
  puts dim("  updated README.md (Test results) and test_repos/scoreboard.json")
end
# Coverage is a score, not a gate: exit 1 only when a case couldn't be run (missing repo, tracer/analyzer failure)
exit(summary.any? { |s| s[:error] } ? 1 : 0)
