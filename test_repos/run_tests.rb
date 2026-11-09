#!/usr/bin/env ruby
# Run the BOLA detector against every test repo and check it against test_repos/expected.yml.
#
#   test_repos/run_tests.rb                    # trace + LLM analysis for every repo
#   test_repos/run_tests.rb aegra              # only cases whose name contains "aegra"
#   test_repos/run_tests.rb --trace-only       # no LLM calls: only check the routes get traced
#
# The scanner's own output is streamed live (indented), then each case gets a result block,
# and a summary at the end. Outputs go to test_repos/results/<case>/. Exit code 1 if any case fails.

require "yaml"
require "json"
require "optparse"
require "fileutils"

$stdout.sync = true
Encoding.default_external = Encoding::UTF_8
HERE = __dir__
ROOT = File.expand_path("..", HERE)
FLAGGED = %w[likely possible].freeze

opts = { trace_only: false, jobs: nil }
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

# "POST /threads/{thread_id}/runs" -> ["POST", ["threads", ":", "runs"]]
def norm(route)
  verb, path = route.to_s.strip.split(/\s+/, 2)
  segs = path.to_s.split("/").reject(&:empty?).map { |s| s.match?(/\A(:\w+|\{[^}]*\}|<[^>]*>)\z/) ? ":" : s }
  [verb.upcase, segs]
end

# Expected route matches a traced route if the verbs match and the paths are equal, or (with
# loose: true) the traced path is the expected one minus up to 2 leading literal segments
# (the tracer drops mounted-router prefixes like /api), e.g. /api/v2/notes/: ~ /v2/notes/:.
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

cases = YAML.load_file(File.join(HERE, "expected.yml"))
cases = cases.select { |c| c["name"].include?(filter) } if filter
abort "no cases match #{filter.inspect}" if cases.empty?

summary = []
cases.each_with_index do |c, i|
  name = c["name"]
  repo = File.join(HERE, c["repo"])
  out = File.join(HERE, "results", name)
  FileUtils.mkdir_p(out)
  vulnerable = Array(c["vulnerable"])
  safe = Array(c["safe"])

  puts
  puts bold("━━━ [#{i + 1}/#{cases.size}] #{name}") + dim("  (#{c['source']})")
  unless File.directory?(repo)
    puts red("  repo missing: #{repo} — run test_repos/fetch.sh")
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
  results = nil
  if opts[:trace_only]
    puts dim("  ▸ analysis skipped (--trace-only)")
  elsif traces.empty?
    puts red("  ▸ analysis skipped: no routes traced")
  elsif opts[:reuse]
    report = File.join(out, "bola_report.json")
    puts dim("  reusing #{report}")
    results = JSON.parse(File.read(report))["routes"] if File.exist?(report)
    puts red("  no earlier report — run without --reuse first") unless results
  else
    puts bold("  ▸ analyze")
    report = File.join(out, "bola_report")
    cmd = ["ruby", "analyze_bola.rb", trace_file, "--out", report]
    cmd += ["--jobs", opts[:jobs].to_s] if opts[:jobs]
    results = JSON.parse(File.read("#{report}.json"))["routes"] if stream(cmd, log) && File.exist?("#{report}.json")
    puts red("  analyzer failed — see #{out}/run.log") unless results
  end
  log.close

  # 3. Check
  detected = missed = []
  false_pos = []
  if results
    puts bold("  ▸ expected BOLA routes")
    detected, missed = vulnerable.partition { |r| (hit = find(results, r)) && FLAGGED.include?(hit["verdict"]) }
    vulnerable.each do |r|
      hit = find(results, r)
      tag = if hit.nil? then red("✗ not traced".ljust(15))
            elsif FLAGGED.include?(hit["verdict"]) then green("✓ #{hit['verdict']} #{hit['score']}".ljust(15))
            else red("✗ #{hit['verdict']} #{hit['score']}".ljust(15))
            end
      puts "    #{tag}  #{r}"
    end

    if safe.any?
      puts bold("  ▸ expected safe routes")
      safe.each do |r|
        hit = find(results, r)
        next puts("    #{dim('- not traced'.ljust(15))}  #{r}") unless hit
        bad = FLAGGED.include?(hit["verdict"])
        false_pos << r if bad
        label = "#{bad ? '✗' : '✓'} #{hit['verdict']} #{hit['score']}".ljust(15)
        puts "    #{bad ? red(label) : green(label)}  #{r}"
      end
    end

    labeled = vulnerable + safe
    others = results.select { |h| FLAGGED.include?(h["verdict"]) && labeled.none? { |r| match?(r, h["route"]) } }
    if others.any?
      puts bold("  ▸ other flagged routes") + dim("  (not in expected.yml; review by hand)")
      others.each { |h| puts "    #{yellow("? #{h['verdict']} #{h['score']}")}  #{h['route']}" }
    end
  end

  ok = if results then missed.empty? && false_pos.empty?
       else traced_ok && missing.empty?
       end
  note = if results
           "#{detected.size}/#{vulnerable.size} detected, #{false_pos.size}/#{safe.size} false positives"
         else
           "#{vulnerable.size - missing.size}/#{vulnerable.size} traced#{opts[:trace_only] ? '' : ' (no analysis)'}"
         end
  puts "  #{ok ? green(bold('PASS')) : red(bold('FAIL'))}  #{note}  " + dim("(#{(Time.now - t0).round}s, results in test_repos/results/#{name}/)")
  summary << { name: name, ok: ok, note: note }
end

puts
puts bold("━━━ summary")
summary.each { |s| puts "  #{s[:ok] ? green('PASS') : red('FAIL')}  #{s[:name].ljust(20)} #{s[:note]}" }
exit(summary.all? { |s| s[:ok] } ? 0 : 1)
