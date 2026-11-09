#!/usr/bin/env ruby
# route_tracer.rb — POC: for every HTTP route in a repo, build the tree of
# methods/files that may run when the route is hit.
#
#   ruby route_tracer.rb /path/to/repo [--out trace.json] [--depth 6] [--route posts]
#
# Pipeline (each step logs what it does):
#   1. INDEX   parse every .rb (Prism) and .py (python3 ast) file into
#              defs = {id, name, owner(class), file, lines, calls[]}  -> Mongo `defs`
#   2. ROUTES  find routes: Rails routes.rb, Sinatra, Flask/FastAPI, Django urls.py
#                                                                     -> Mongo `routes`
#   3. TRACE   BFS from each handler: look up each call name in the index,
#              resolve it with simple heuristics (+ optional LLM), recurse.
#                                                                     -> Mongo `traces`
#   4. OUTPUT  trace.json (full) + trace.txt (indented, human-readable)
#
# Mongo: set MONGO_URL (default mongodb://127.0.0.1:27017/route_tracer).
#        If the `mongo` gem is missing, an in-memory store is used instead.
# LLM:   set ANTHROPIC_API_KEY to let an LLM pick among ambiguous call targets.
#        Without it, ambiguous calls (2..MAX_FANOUT candidates) follow all candidates.

require "prism"
require "json"
require "optparse"
require "set"
require "net/http"

MAX_FANOUT = 3 # follow at most this many same-named candidates for one call
SKIP_DIRS  = %w[.git node_modules vendor venv .venv env tmp log spec test tests
                __pycache__ site-packages dist build coverage].freeze
VERBS      = %w[get post put patch delete].freeze
# Calls on unknown receivers with these names are almost never app code.
NOISY      = %w[each map select reject find_each to_s to_h to_a to_i to_json inspect
                call get set first last count size length join strip split
                present? blank? nil? empty? include? key? merge append items keys
                values format].to_set.freeze

def log(step, msg) = puts("[#{step}] #{msg}")

# ─────────────────────────── store (Mongo or memory) ───────────────────────────

class Store
  def self.open(repo)
    require "mongo"
    Mongo::Logger.logger.level = Logger::WARN
    MongoStore.new(repo)
  rescue LoadError
    log(:store, "mongo gem not found -> using in-memory store (gem install mongo)")
    MemoryStore.new
  end
end

class MongoStore
  def initialize(repo)
    @repo = repo
    @db = Mongo::Client.new(ENV.fetch("MONGO_URL", "mongodb://127.0.0.1:27017/route_tracer")).database
    %i[defs routes traces].each { |c| @db[c].delete_many(repo: repo) } # fresh run per repo
    @db[:defs].indexes.create_one(repo: 1, name: 1)
    @cache = {}
    log(:store, "using Mongo #{@db.name}")
  end

  def insert(coll, docs)
    @db[coll].insert_many(docs.map { |d| d.merge("repo" => @repo) }) unless docs.empty?
  end

  def defs_named(name)
    @cache[name] ||= @db[:defs].find(repo: @repo, name: name).map { |d| clean(d) }
  end

  def def_by_id(id) = (d = @db[:defs].find(repo: @repo, id: id).first) && clean(d)

  private def clean(doc) = doc.to_h.reject { |k, _| %w[_id repo].include?(k) }
end

class MemoryStore
  def initialize = (@data = Hash.new { |h, k| h[k] = [] })
  def insert(coll, docs) = @data[coll].concat(docs)
  def defs_named(name) = (@by_name ||= @data[:defs].group_by { |d| d["name"] })[name] || []
  def def_by_id(id) = (@by_id ||= @data[:defs].to_h { |d| [d["id"], d] })[id]
end

# ─────────────────────────── 1. INDEX: Ruby (Prism) ───────────────────────────

class RubyIndexer
  attr_reader :defs, :classes, :filters, :routes

  def initialize
    @defs = []      # every method (+ synthetic defs for Sinatra blocks)
    @classes = {}   # "Api::PostsController" => {superclass, includes, file}
    @filters = []   # before_action / skip_before_action / Sinatra `before`
    @routes = []    # Sinatra routes (Rails routes come from RailsRoutes)
  end

  def index(rel, src)
    @file = rel
    walk(Prism.parse(src).value, nil)
  end

  private

  def walk(node, owner)
    case node
    when Prism::ClassNode, Prism::ModuleNode
      name = [owner, node.constant_path.slice].compact.join("::")
      sup = node.is_a?(Prism::ClassNode) ? node.superclass&.slice : nil
      @classes[name] ||= { "superclass" => sup, "includes" => [], "file" => @file }
      walk(node.body, name) if node.body
      return
    when Prism::DefNode
      @defs << make_def(node.name.to_s, owner, node, node.body)
      return
    when Prism::CallNode
      return if handle_call(node, owner)
    end
    node&.compact_child_nodes&.each { |c| walk(c, owner) }
  end

  # Returns true if the call was consumed (don't walk inside it).
  def handle_call(node, owner)
    name = node.name.to_s
    args = node.arguments&.arguments || []

    if %w[include extend prepend].include?(name) && owner && node.receiver.nil?
      args.each { |a| @classes[owner]["includes"] << a.slice }
      return true
    end

    if name =~ /\A(prepend_)?(before|around)_(action|filter)\z/ || name =~ /\Askip_(before|around)_(action|filter)\z/
      kind = name.start_with?("skip") ? "skip" : "before"
      opts = keyword_opts(args)
      args.grep(Prism::SymbolNode).each do |s|
        @filters << { "owner" => owner, "kind" => kind, "name" => s.unescaped,
                      "only" => opts["only"], "except" => opts["except"] }
      end
      return true
    end

    # Sinatra: `get '/x' do ... end` and `before do ... end` (not in Rails routes files)
    sinatra = node.receiver.nil? && node.block.is_a?(Prism::BlockNode) && !@file.include?("config/routes")
    if sinatra && VERBS.include?(name) && args.first.is_a?(Prism::StringNode)
      path = args.first.unescaped
      d = make_def("#{name.upcase} #{path}", owner, node, node.block)
      @defs << d
      @routes << { "verb" => name.upcase, "path" => path, "framework" => "sinatra", "handler_id" => d["id"] }
      return true
    end
    if sinatra && name == "before"
      d = make_def("before_filter", owner, node, node.block)
      @defs << d
      @filters << { "scope_file" => @file, "def_id" => d["id"] }
      return true
    end
    false
  end

  def make_def(name, owner, node, body)
    loc = node.location
    { "id" => "#{@file}:#{loc.start_line}:#{name}", "name" => name, "owner" => owner, "file" => @file,
      "start" => loc.start_line, "end" => loc.end_line, "calls" => body ? calls_in(body) : [] }
  end

  # Every method call inside a body: {name, recv} where recv is nil/self/Constant/"expr".
  def calls_in(body)
    found = []
    stack = [body]
    while (n = stack.pop)
      found << n if n.is_a?(Prism::CallNode) && n.name.to_s.match?(/\A[a-z_]\w*[?!]?\z/i)
      stack.concat(n.compact_child_nodes)
    end
    found.sort_by { |n| n.location.start_offset } # source order
         .map { |n| { "name" => n.name.to_s, "recv" => recv_of(n.receiver) } }.uniq
  end

  def recv_of(r)
    case r
    when nil then nil
    when Prism::SelfNode then "self"
    when Prism::ConstantReadNode, Prism::ConstantPathNode then r.slice
    else "expr"
    end
  end

  def keyword_opts(args)
    hash = args.find { |a| a.is_a?(Prism::KeywordHashNode) }
    return {} unless hash
    hash.elements.each_with_object({}) do |el, h|
      next unless el.respond_to?(:key) && el.key.is_a?(Prism::SymbolNode)
      v = el.value
      list = v.is_a?(Prism::ArrayNode) ? v.elements : [v]
      h[el.key.unescaped] = list.select { |x| x.respond_to?(:unescaped) }.map(&:unescaped)
    end
  end
end

# ─────────────────────────── 2a. ROUTES: Rails routes.rb ───────────────────────────

class RailsRoutes
  REST = { "index" => %w[GET], "show" => %w[GET :id], "new" => %w[GET new], "create" => %w[POST],
           "edit" => %w[GET :id/edit], "update" => %w[PATCH :id], "destroy" => %w[DELETE :id] }.freeze

  def self.parse(src)
    r = new
    r.walk(Prism.parse(src).value, path: "", mod: [], resource: nil)
    r.routes
  end

  attr_reader :routes

  def initialize = (@routes = [])

  def walk(node, ctx)
    return unless node
    if node.is_a?(Prism::CallNode) && node.receiver.nil?
      return if route_call(node, ctx)
    end
    node.compact_child_nodes.each { |c| walk(c, ctx) }
  end

  private

  def route_call(node, ctx)
    name = node.name.to_s
    args = node.arguments&.arguments || []
    first = args.first
    first_s = first.respond_to?(:unescaped) ? first.unescaped : nil
    opts = hash_opts(args)
    block = node.block.is_a?(Prism::BlockNode) ? node.block.body : nil

    case name
    when "namespace"
      walk(block, ctx.merge(path: "#{ctx[:path]}/#{first_s}", mod: ctx[:mod] + [first_s]))
    when "scope"
      sub = first_s ? "#{ctx[:path]}/#{first_s.delete_prefix('/')}" : ctx[:path]
      walk(block, ctx.merge(path: sub, mod: ctx[:mod] + [opts["module"]].compact))
    when "resources", "resource"
      plural = name == "resources"
      actions = REST.keys
      actions -= %w[index] unless plural
      actions &= opts["only"] if opts["only"]
      actions -= opts["except"] if opts["except"]
      ctrl = controller_for(ctx[:mod], opts["controller"] || (plural ? first_s : "#{first_s}s"))
      base = "#{ctx[:path]}/#{first_s}"
      actions.each do |a|
        verb, suffix = REST[a]
        suffix = suffix&.delete_prefix(":id") if !plural && suffix&.start_with?(":id")
        add(verb, [base, suffix].reject { |s| s.nil? || s.empty? }.join("/").sub(%r{/+\z}, ""), ctrl, a)
      end
      member_base = plural ? "#{base}/:#{first_s.chomp('s')}_id" : base
      walk(block, ctx.merge(path: member_base, resource: { ctrl: ctrl, base: plural ? "#{base}/:id" : base }))
    when "member", "collection"
      res = ctx[:resource]
      base = name == "member" ? res[:base] : res[:base].sub(%r{/:id\z}, "")
      walk(block, ctx.merge(path: base, resource: res.merge(here: base)))
    when "root"
      ca = first_s || opts["to"]
      add("GET", ctx[:path].empty? ? "/" : ctx[:path], *split_ca(ca, ctx)) if ca
    when *VERBS
      # get 'x', to: 'c#a'   |   get 'x' => 'c#a'   |   get :search (inside resources)
      target = opts["to"] || opts["__arrow"]
      res = ctx[:resource]
      if target
        add(name.upcase, "#{ctx[:path]}/#{(opts['__arrow_path'] || first_s).to_s.delete_prefix('/')}", *split_ca(target, ctx))
      elsif res && first.is_a?(Prism::SymbolNode)
        add(name.upcase, "#{res[:here] || res[:base]}/#{first_s}", res[:ctrl], first_s)
      elsif first_s&.include?("/")
        # get 'posts/recent' (implicit controller#action from path)
        c, a = first_s.delete_prefix("/").split("/", 2)
        add(name.upcase, "#{ctx[:path]}/#{first_s.delete_prefix('/')}", controller_for(ctx[:mod], c), a) if a
      end
    else
      return false
    end
    true
  end

  def add(verb, path, ctrl, action)
    @routes << { "verb" => verb, "path" => path.empty? ? "/" : path, "framework" => "rails",
                 "controller" => ctrl, "action" => action }
  end

  def split_ca(ca, ctx)
    c, a = ca.split("#", 2)
    [controller_for(ctx[:mod], c), a]
  end

  def controller_for(mod, name)
    parts = (mod + name.split("/")).map { |p| p.split("_").map(&:capitalize).join }
    parts[-1] += "Controller"
    parts.join("::")
  end

  def hash_opts(args)
    args.select { |a| a.is_a?(Prism::KeywordHashNode) || a.is_a?(Prism::HashNode) }
        .flat_map(&:elements).each_with_object({}) do |el, h|
      next unless el.respond_to?(:key)
      v = el.value
      vals = (v.is_a?(Prism::ArrayNode) ? v.elements : [v]).select { |x| x.respond_to?(:unescaped) }.map(&:unescaped)
      if el.key.is_a?(Prism::SymbolNode)
        k = el.key.unescaped
        h[k] = %w[only except].include?(k) ? vals : vals.first
      elsif el.key.is_a?(Prism::StringNode) # 'path' => 'c#a'
        h["__arrow_path"] = el.key.unescaped
        h["__arrow"] = vals.first
      end
    end
  end
end

# ─────────────────────────── 1+2b. INDEX + ROUTES: Python (ast) ───────────────────────────

PY_INDEXER = <<~'PY'
  import ast, json, sys
  VERBS = {'route', 'get', 'post', 'put', 'patch', 'delete'}

  def recv_of(v):
      if isinstance(v, ast.Name): return v.id
      if isinstance(v, ast.Attribute) and v.attr[:1].isupper(): return v.attr  # models.User
      return 'expr'

  def call_of(f):
      if isinstance(f, ast.Call): f = f.func
      if isinstance(f, ast.Name): return f.id, None
      if isinstance(f, ast.Attribute): return f.attr, recv_of(f.value)
      return None, None

  def calls_in(fn):
      out = []
      for root in [fn.args] + fn.body:
          for n in ast.walk(root):
              if isinstance(n, ast.Call):
                  name, recv = call_of(n.func)
                  if name in ('Depends', 'Security'):  # FastAPI dependency = implicit call
                      for a in n.args:
                          nm, rv = call_of(a)
                          if nm: out.append({'name': nm, 'recv': rv})
                  elif name:
                      out.append({'name': name, 'recv': recv})
      for d in fn.decorator_list:  # @login_required etc. (route decorators are skipped)
          nm, rv = call_of(d)
          if nm and nm not in VERBS and nm != 'before_request':
              out.append({'name': nm, 'recv': rv})
      return [dict(t) for t in {tuple(sorted(c.items(), key=str)) for c in out}]

  res = {'defs': [], 'classes': {}, 'routes': [], 'filters': []}
  for path, rel in json.load(sys.stdin):
      try:
          tree = ast.parse(open(path, encoding='utf-8', errors='replace').read())
      except SyntaxError:
          continue

      def visit(body, owner):
          for node in body:
              if isinstance(node, ast.ClassDef):
                  res['classes'][node.name] = {'superclass': None, 'file': rel,
                      'includes': [b.id if isinstance(b, ast.Name) else getattr(b, 'attr', '?') for b in node.bases]}
                  visit(node.body, node.name)
              elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                  did = f'{rel}:{node.lineno}:{node.name}'
                  res['defs'].append({'id': did, 'name': node.name, 'owner': owner, 'file': rel,
                                      'start': node.lineno, 'end': node.end_lineno, 'calls': calls_in(node)})
                  for d in node.decorator_list:
                      f = d.func if isinstance(d, ast.Call) else d
                      if not isinstance(f, ast.Attribute): continue
                      if f.attr == 'before_request':
                          res['filters'].append({'scope_file': rel, 'def_id': did})
                      elif isinstance(d, ast.Call) and f.attr in VERBS and d.args \
                              and isinstance(d.args[0], ast.Constant) and isinstance(d.args[0].value, str):
                          verbs = [f.attr.upper()]
                          if f.attr == 'route':
                              m = [k.value for k in d.keywords if k.arg == 'methods']
                              verbs = [e.value for e in m[0].elts] if m and isinstance(m[0], ast.List) else ['GET']
                          for v in verbs:
                              res['routes'].append({'verb': v, 'path': d.args[0].value,
                                                    'framework': 'flask/fastapi', 'handler_id': did})
      visit(tree.body, None)

      if rel.endswith('urls.py'):  # Django: path('x/', views.fn) / path('x/', Cls.as_view())
          for n in ast.walk(tree):
              if isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id in ('path', 're_path') \
                      and len(n.args) >= 2 and isinstance(n.args[0], ast.Constant):
                  view = n.args[1]
                  r = {'verb': 'ANY', 'path': '/' + str(n.args[0].value), 'framework': 'django'}
                  if isinstance(view, ast.Call) and isinstance(view.func, ast.Attribute) and view.func.attr == 'as_view':
                      r['handler_class'] = recv_of(view.func.value)
                  else:
                      r['handler_name'] = call_of(view)[0]
                  res['routes'].append(r)
  json.dump(res, sys.stdout)
PY

def index_python(files)
  return { "defs" => [], "classes" => {}, "routes" => [], "filters" => [] } if files.empty?
  out = IO.popen(["python3", "-I", "-c", PY_INDEXER], "r+") do |io|
    io.write(JSON.dump(files))
    io.close_write
    io.read
  end
  JSON.parse(out)
rescue Errno::ENOENT
  log(:index, "python3 not found -> skipping #{files.size} .py files")
  { "defs" => [], "classes" => {}, "routes" => [], "filters" => [] }
end

# ─────────────────────────── 3. TRACE ───────────────────────────

class Tracer
  def initialize(store, classes, filters, repo, depth)
    @store, @classes, @filters, @repo, @depth = store, classes, filters, repo, depth
    @llm_cache = {}
  end

  # ── class hierarchy helpers ──
  def find_class(name)
    return nil unless name
    return name if @classes.key?(name)
    short = name.split("::").last
    @classes.keys.find { |k| k.split("::").last == short }
  end

  # [C, its superclass, included modules, ...] (closest first)
  def ancestors(owner)
    out, queue = [], [find_class(owner)].compact
    while (c = queue.shift)
      next if out.include?(c)
      out << c
      info = @classes[c]
      queue.concat(([info["superclass"]] + info["includes"]).filter_map { |n| find_class(n) })
    end
    out
  end

  # ── route → handler def + the filters that run before it ──
  def entry_for(route)
    case route["framework"]
    when "rails"
      handler = @store.defs_named(route["action"]).find { |d| same_class?(d["owner"], route["controller"]) }
      chain = ancestors(route["controller"]).reverse # base class first
      active = []
      chain.each do |c|
        @filters.select { |f| f["owner"] == c && f["name"] }.each do |f|
          next if f["only"] && !f["only"].include?(route["action"])
          next if f["except"]&.include?(route["action"])
          f["kind"] == "skip" ? active.delete(f["name"]) : active |= [f["name"]]
        end
      end
      filter_defs = active.filter_map do |fname|
        cands = @store.defs_named(fname)
        cands.find { |d| chain.include?(find_class(d["owner"])) } || cands.first ||
          { "id" => "external:#{fname}", "name" => fname, "external" => true }
      end
      [handler, filter_defs]
    else
      handler = @store.def_by_id(route["handler_id"]) if route["handler_id"]
      handler ||= @store.defs_named(route["handler_name"]).find { |d| d["owner"].nil? } if route["handler_name"]
      file = handler && handler["file"]
      filter_defs = @filters.select { |f| f["scope_file"] && f["scope_file"] == file }.map { |f| @store.def_by_id(f["def_id"]) }
      [handler, filter_defs.compact]
    end
  end

  def same_class?(a, b) = a && b && (a == b || a.end_with?("::#{b}") || b.end_with?("::#{a}"))

  # ── call resolution: call {name, recv} inside caller def → [target defs] ──
  def resolve(call, caller)
    name, recv = call["name"], call["recv"]

    if recv&.match?(/\A[A-Z]/) # Constant receiver: Post.find, User.objects ...
      name = "initialize" if name == "new"
      chain = ancestors(recv)
      targets = @store.defs_named(name).select { |d| chain.include?(find_class(d["owner"])) }
      return [targets, "call"] unless targets.empty?
      # Not defined in the app (e.g. ORM finder) but the class is: keep as a leaf — useful for IDOR.
      cls = find_class(recv)
      return [[{ "id" => "model:#{recv}.#{name}", "name" => name, "owner" => cls,
                 "file" => @classes[cls]["file"], "leaf" => true }], "model_call"] if cls
      return [[], nil]
    end

    cands = @store.defs_named(name)
    return [[], nil] if cands.empty?

    if recv.nil? || recv == "self" # implicit self: same class, then ancestors, then same file
      chain = ancestors(caller["owner"])
      mine = chain.lazy.map { |c| cands.select { |d| find_class(d["owner"]) == c } }.find(&:any?)
      return [mine, "call"] if mine
      same_file = cands.select { |d| d["file"] == caller["file"] }
      return [same_file, "call"] if same_file.any?
    end

    return [[], nil] if recv && NOISY.include?(name)
    # `@post.update(...)`: a call on some other object is not a call on our own class.
    if recv == "expr"
      own = ancestors(caller["owner"])
      cands = cands.reject { |d| own.include?(find_class(d["owner"])) }
      return [[], nil] if cands.empty?
    end
    return [cands, "call"] if cands.size == 1
    return [[], "too_many:#{cands.size}"] if cands.size > MAX_FANOUT

    picked = llm_pick(call, caller, cands)
    picked ? [picked, "llm"] : [cands, "ambiguous"]
  end

  # Optional: ask the LLM which of the same-named candidates the call really hits.
  def llm_pick(call, caller, cands)
    key = ENV["ANTHROPIC_API_KEY"]
    return nil unless key
    @llm_cache[[caller["id"], call["name"]]] ||= begin
      lines = File.readlines(File.join(@repo, caller["file"]))[(caller["start"] - 1)...caller["end"]].join
      prompt = <<~P
        In this code, which definitions can the call `#{[call['recv'], call['name']].compact.join('.')}` resolve to?
        Caller (#{caller['file']}):
        ```
        #{lines[0, 6000]}
        ```
        Candidates:
        #{cands.map { |d| "- #{d['id']} (class #{d['owner'] || '-'})" }.join("\n")}
        Reply ONLY with a JSON array of the candidate ids that are plausible.
      P
      uri = URI("https://api.anthropic.com/v1/messages")
      req = Net::HTTP::Post.new(uri, "content-type" => "application/json", "x-api-key" => key,
                                     "anthropic-version" => "2023-06-01")
      req.body = JSON.dump(model: ENV.fetch("TRACER_MODEL", "claude-sonnet-5-5"), max_tokens: 300,
                           messages: [{ role: "user", content: prompt }])
      res = Net::HTTP.start(uri.host, uri.port, use_ssl: true) { |h| h.request(req) }
      text = JSON.parse(res.body).dig("content", 0, "text").to_s
      ids = JSON.parse(text[/\[.*\]/m] || "[]")
      log(:llm, "#{caller['name']} -> #{call['name']}: #{ids.size}/#{cands.size} candidates kept")
      cands.select { |d| ids.include?(d["id"]) }
    rescue StandardError => e
      log(:llm, "failed (#{e.class}): following all candidates")
      nil
    end
  end

  # ── build the tree for one route ──
  def trace(route)
    handler, filter_defs = entry_for(route)
    @seen = Set.new
    @files = Set.new
    @unresolved = []
    roots = filter_defs.map { |f| node(f, "before_filter", 1, []) }
    roots << (handler ? node(handler, "handler", 1, []) : { "label" => "(handler not found)", "via" => "handler" })
    { "route" => "#{route['verb']} #{route['path']}", "framework" => route["framework"],
      "handler" => handler && label(handler), "files" => @files.to_a.sort, "methods" => @seen.to_a,
      "unresolved" => @unresolved.uniq, "tree" => roots }
  end

  def label(d) = [d["owner"], d["name"]].compact.join(d["owner"]&.match?(/\A[A-Z]/) && !d["leaf"] ? "#" : ".")

  def node(d, via, depth, path)
    n = { "label" => label(d), "via" => via }
    n["file"] = "#{d['file']}:#{d['start']}-#{d['end']}" if d["file"] && d["start"]
    n["file"] ||= d["file"] if d["file"]
    @files << d["file"] if d["file"]
    return n.merge("external" => true) if d["external"]
    return n.merge("leaf" => true) if d["leaf"]
    return n.merge("cycle" => true) if path.include?(d["id"])
    return n.merge("seen" => true) if @seen.include?(d["id"]) # already expanded in this route
    @seen << d["id"]
    return n.merge("truncated" => true) if depth >= @depth

    kids = []
    d["calls"].each do |call|
      targets, how = resolve(call, d)
      @unresolved << "#{d['name']} -> #{call['name']} (#{how})" if how&.start_with?("too_many")
      targets.each { |t| kids << node(t, how, depth + 1, path + [d["id"]]) }
    end
    kids.empty? ? n : n.merge("children" => kids)
  end
end

# ─────────────────────────── 4. OUTPUT helpers ───────────────────────────

def tree_text(nodes, indent = 1)
  nodes.flat_map do |n|
    tags = %w[cycle seen truncated leaf external].select { |t| n[t] }
    line = "#{'  ' * indent}#{n['label']}  [#{n['via']}]  #{n['file']}#{tags.empty? ? '' : "  (#{tags.join(', ')})"}"
    [line] + tree_text(n["children"] || [], indent + 1)
  end
end

# ─────────────────────────── main ───────────────────────────

if $PROGRAM_NAME == __FILE__
  opts = { out: "trace.json", depth: 6, route: nil }
  OptionParser.new do |o|
    o.banner = "usage: ruby route_tracer.rb REPO [options]"
    o.on("--out FILE", "output JSON (a .txt tree is written next to it)") { |v| opts[:out] = v }
    o.on("--depth N", Integer, "max call depth (default 6)") { |v| opts[:depth] = v }
    o.on("--route TEXT", "only trace routes whose 'VERB /path' contains TEXT") { |v| opts[:route] = v }
  end.parse!
  repo = File.expand_path(ARGV.fetch(0) { abort "usage: ruby route_tracer.rb REPO [--out trace.json]" })

  # 1. INDEX
  files = Dir.glob("**/*.{rb,py}", base: repo).reject { |f| f.split("/").any? { |p| SKIP_DIRS.include?(p) } }
  rb_files, py_files = files.partition { |f| f.end_with?(".rb") }
  log(:index, "#{rb_files.size} Ruby + #{py_files.size} Python files in #{repo}")

  rb = RubyIndexer.new
  rb_files.each { |f| rb.index(f, File.read(File.join(repo, f))) }
  py = index_python(py_files.map { |f| [File.join(repo, f), f] })

  defs = rb.defs + py["defs"]
  classes = rb.classes.merge(py["classes"])
  filters = rb.filters + py["filters"]
  log(:index, "#{defs.size} methods/functions, #{classes.size} classes/modules, #{filters.size} filters")

  store = Store.open(repo)
  store.insert(:defs, defs)

  # 2. ROUTES
  routes = rb.routes + py["routes"]
  rb_files.select { |f| f.match?(%r{\Aconfig/routes(\.rb|/)}) }.each do |f|
    routes.concat(RailsRoutes.parse(File.read(File.join(repo, f))))
  end
  # Django class-based views: one route per HTTP method defined on the class
  routes = routes.flat_map do |r|
    next [r] unless r["handler_class"]
    %w[get post put patch delete].filter_map do |m|
      d = store.defs_named(m).find { |x| x["owner"] == r["handler_class"] }
      d && r.merge("verb" => m.upcase, "handler_id" => d["id"]).tap { |h| h.delete("handler_class") }
    end
  end
  routes.select! { |r| "#{r['verb']} #{r['path']}".include?(opts[:route]) } if opts[:route]
  log(:routes, "#{routes.size} routes (#{routes.map { |r| r['framework'] }.tally.map { |k, v| "#{k}: #{v}" }.join(', ')})")
  store.insert(:routes, routes)

  # 3. TRACE
  tracer = Tracer.new(store, classes, filters, repo, opts[:depth])
  traces = routes.map do |r|
    t = tracer.trace(r)
    log(:trace, "#{t['route'].ljust(40)} -> #{t['handler'] || '?'}: #{t['methods'].size} methods, #{t['files'].size} files")
    t
  end
  store.insert(:traces, traces.map(&:dup))

  # 4. OUTPUT
  File.write(opts[:out], JSON.pretty_generate(traces))
  txt = opts[:out].sub(/\.json\z/, "") + ".txt"
  File.write(txt, traces.map { |t| (["#{t['route']}  ->  #{t['handler']}"] + tree_text(t["tree"])).join("\n") }.join("\n\n") + "\n")
  log(:done, "wrote #{opts[:out]} and #{txt}")
end