#!/usr/bin/env ruby
# route_tracer.rb — POC: for every HTTP route in a repo, build the tree of
# methods/files that may run when the route is hit.
#
#   ruby route_tracer.rb /path/to/repo [--out trace.json] [--depth 6] [--route posts]
#                                      [--with-source] [--all-routes]
#
# Pipeline (each step logs what it does):
#   1. INDEX   parse every .rb (Prism), .py (python3 ast) and .js/.ts (node + typescript)
#              file into defs = {id, name, owner(class), file, lines, calls[]} -> Mongo `defs`
#   2. ROUTES  find routes: Rails routes.rb, Sinatra, Flask/FastAPI, Django urls.py,
#              Express/Koa/Fastify (app.get(...)), NestJS (@Controller/@Get) -> Mongo `routes`
#   3. TRACE   BFS from each handler: look up each call name in the index,
#              resolve it with simple heuristics (+ optional LLM), recurse.
#   4. TRIM    keep only routes that take input (path params, a body, query args,
#              or code on the path that reads request params)  -> Mongo `traces`
#   5. OUTPUT  trace.json (full) + trace.txt (indented, human-readable)
#
# Node/TS: needs `node` and the `typescript` package (npm i -g typescript).
# Mongo: set MONGO_URL (default mongodb://127.0.0.1:27017/route_tracer).
#        If the `mongo` gem is missing, an in-memory store is used instead.
# LLM:   set ANTHROPIC_API_KEY to let an LLM pick among ambiguous call targets.
#        Without it, ambiguous calls (2..MAX_FANOUT candidates) follow all candidates.

require "prism"
require "json"
Encoding.default_external = Encoding::UTF_8 # source files are UTF-8 even under a C/ASCII locale
require "optparse"
require "set"
require "net/http"

MAX_FANOUT = 3 # follow at most this many same-named candidates for one call
MAX_SOURCE_LINES = 300 # --with-source: cap per method
SKIP_DIRS  = %w[.git node_modules vendor venv .venv env tmp log spec test tests __tests__
                __pycache__ site-packages dist build coverage .next
                frontend client public static assets].freeze # browser code isn't server routes
# Constant receivers that are language/stdlib classes, not data access (JSON.parse, Math.max, Time.now...)
STDLIB     = %w[JSON Math Object Promise Array Date Number String Boolean Error Buffer Reflect Symbol
                Map Set URL Intl Rails File Dir Time Integer Float Hash Struct Kernel Base64 SecureRandom
                ActiveSupport Logger Process IO Regexp Thread Mutex Digest OpenSSL CSV ERB URI Net
                Faraday HTTParty BigDecimal Pathlib Path].to_set.freeze
VERBS      = %w[get post put patch delete].freeze
# Calls on unknown receivers with these names are almost never app code.
NOISY      = %w[each map select reject find_each to_s to_h to_a to_i to_json inspect
                call get set first last count size length join strip split
                present? blank? nil? empty? include? key? merge append items keys
                values format].to_set.freeze
JS_EXT     = /\.(js|jsx|mjs|cjs|ts|tsx)\z/
# Code that reads request input (Ruby, Python, Node). Used by the TRIM step.
INPUT_CODE = /\bparams\b|\brequest\.(args|form|json|get_json|values|GET|POST|data|body|query_params|FILES)\b|
              \b(req|request|ctx)\.(params|query|body)\b|ctx\.request\.body|@(Param|Body|Query)\(/x

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
      chain = []                       # User.objects -> ['User', 'objects'];  models.User -> ['models', 'User']
      while isinstance(v, ast.Attribute):
          chain.insert(0, v.attr); v = v.value
      if isinstance(v, ast.Name): chain.insert(0, v.id)
      return next((c for c in chain if c[:1].isupper()), 'expr')  # first class name in the chain

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

  def params_of(fn):  # handler args = path/query/body input (minus Depends() and framework args)
      a = fn.args
      pos = a.posonlyargs + a.args
      dep = set()
      pairs = list(zip(pos[len(pos) - len(a.defaults):], a.defaults)) + list(zip(a.kwonlyargs, a.kw_defaults))
      for arg, d in pairs:
          if isinstance(d, ast.Call) and call_of(d.func)[0] in ('Depends', 'Security'):
              dep.add(arg.arg)
      skip = {'self', 'cls', 'request', 'req', 'db', 'session', 'response', 'background_tasks'}
      return [x.arg for x in pos + a.kwonlyargs if x.arg not in dep and x.arg not in skip]

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
                                      'start': node.lineno, 'end': node.end_lineno, 'calls': calls_in(node),
                                      'params': params_of(node)})
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
                                                    'framework': 'flask/fastapi', 'handler_id': did, 'file': rel})
      visit(tree.body, None)

      if rel.endswith('urls.py'):  # Django: path('x/', views.fn) / path('x/', Cls.as_view())
          for n in ast.walk(tree):
              if isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id in ('path', 're_path') \
                      and len(n.args) >= 2 and isinstance(n.args[0], ast.Constant):
                  view = n.args[1]
                  r = {'verb': 'ANY', 'path': '/' + str(n.args[0].value), 'framework': 'django', 'file': rel}
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

# ─────────────────────────── 1+2c. INDEX + ROUTES: Node (TypeScript compiler) ───────────────────────────

JS_INDEXER = <<~'JS'
  const ts = require('typescript'), fs = require('fs');
  const VERBS = new Set(['get', 'post', 'put', 'patch', 'delete', 'all']);
  const NEST = { Get: 'GET', Post: 'POST', Put: 'PUT', Patch: 'PATCH', Delete: 'DELETE', All: 'ANY' };
  // Receivers that are HTTP *clients* or maps, not servers: axios.get('/x'), cache.get(...)
  const NOT_SERVER = /axios|http|fetch|client|api|request|\$|cache|map|params|headers|storage|query/i;
  const res = { defs: [], classes: {}, routes: [], filters: [] };

  let input = '';
  process.stdin.on('data', d => input += d).on('end', () => {
    for (const [path, rel] of JSON.parse(input)) indexFile(path, rel);
    process.stdout.write(JSON.stringify(res));
  });

  function indexFile(path, rel) {
    let src; try { src = fs.readFileSync(path, 'utf8'); } catch { return; }
    const kind = /\.tsx$/.test(rel) ? ts.ScriptKind.TSX : /\.ts$/.test(rel) ? ts.ScriptKind.TS
               : /\.jsx$/.test(rel) ? ts.ScriptKind.JSX : ts.ScriptKind.JS;
    const sf = ts.createSourceFile(path, src, ts.ScriptTarget.Latest, true, kind);
    const line = n => sf.getLineAndCharacterOfPosition(n.getStart(sf)).line + 1;
    const endLine = n => sf.getLineAndCharacterOfPosition(n.getEnd()).line + 1;
    const isFn = n => n && (ts.isArrowFunction(n) || ts.isFunctionExpression(n));
    const str = n => n && (ts.isStringLiteral(n) || ts.isNoSubstitutionTemplateLiteral(n)) ? n.text : null;
    const decs = n => (ts.canHaveDecorators && ts.canHaveDecorators(n) ? ts.getDecorators(n) : n.decorators) || [];
    const decName = d => (ts.isCallExpression(d.expression) ? d.expression.expression : d.expression).getText(sf);
    const decArgs = d => ts.isCallExpression(d.expression) ? [...d.expression.arguments] : [];
    const isConst = s => /^[A-Z]/.test(s || '');

    function addDef(name, owner, node, body) {
      const id = `${rel}:${line(node)}:${name}`;
      res.defs.push({ id, name, owner, file: rel, start: line(node), end: endLine(node), calls: body ? callsIn(body) : [] });
      return id;
    }
    function recvOf(e) {
      if (e.kind === ts.SyntaxKind.ThisKeyword) return 'self';
      const last = ts.isIdentifier(e) ? e.text : ts.isPropertyAccessExpression(e) ? e.name.text : null;
      return isConst(last) ? last : 'expr'; // UserService.find -> constant; userService.find -> any object
    }
    function callOf(e) {
      if (ts.isIdentifier(e)) return [e.text, null];
      if (ts.isPropertyAccessExpression(e)) return [e.name.text, recvOf(e.expression)];
      return [null, null];
    }
    function callsIn(body) {
      const out = [], seen = new Set();
      const push = (name, recv) => { const k = name + '|' + recv; if (!seen.has(k)) { seen.add(k); out.push({ name, recv }); } };
      (function walk(n) {
        if (ts.isCallExpression(n)) { const [nm, rv] = callOf(n.expression); if (nm) push(nm, rv); }
        else if (ts.isNewExpression(n) && ts.isIdentifier(n.expression)) push('constructor', n.expression.text);
        ts.forEachChild(n, walk);
      })(body);
      return out;
    }
    // A middleware/handler argument -> {def_id} (inline fn) or {name, recv} (a reference)
    function ref(a, synth) {
      if (isFn(a)) return { def_id: addDef(synth, null, a, a.body) };
      if (ts.isIdentifier(a)) return { name: a.text };
      if (ts.isPropertyAccessExpression(a)) {             // ctrl.show / UserController.show
        const r = recvOf(a.expression);
        return { name: a.name.text, recv: r === 'expr' || r === 'self' ? null : r };
      }
      if (ts.isCallExpression(a)) {                       // asyncHandler(fn) / auth('admin') / h.bind(x)
        const inner = a.arguments.find(isFn);
        if (inner) return { def_id: addDef(synth, null, inner, inner.body) };
        if (ts.isPropertyAccessExpression(a.expression) && a.expression.name.text === 'bind') return ref(a.expression.expression, synth);
        const [nm, rv] = callOf(a.expression);
        if (nm) return { name: nm, recv: isConst(rv) ? rv : null };
      }
      return null;
    }
    // Express / Koa-router / Fastify:  app.get('/x', mw1, mw2, handler)   and   app.use(mw)
    function routeCall(n) {
      const e = n.expression;
      if (!ts.isPropertyAccessExpression(e) || NOT_SERVER.test(e.expression.getText(sf))) return;
      const verb = e.name.text, args = [...n.arguments];
      if (verb === 'use' && args.length && !str(args[0])) {           // global middleware in this file
        for (const a of args) { const r = ref(a, 'middleware'); if (r) res.filters.push({ scope_file: rel, ...r }); }
        return;
      }
      const path = str(args[0]);
      if (!VERBS.has(verb) || args.length < 2 || !path || !path.startsWith('/')) return;
      const v = verb === 'all' ? 'ANY' : verb.toUpperCase();
      const mws = args.slice(1, -1).flatMap(a => ts.isArrayLiteralExpression(a) ? [...a.elements] : [a]);
      const h = ref(args[args.length - 1], `${v} ${path}`);
      if (!h) return;
      res.routes.push({ verb: v, path, framework: 'express', file: rel,
                        middleware: mws.map(a => ref(a, 'middleware')).filter(Boolean),
                        ...(h.def_id ? { handler_id: h.def_id } : { handler_name: h.name, handler_recv: h.recv }) });
    }
    // NestJS @UseGuards(AuthGuard, new RolesGuard()) -> calls to Guard#canActivate
    const guards = d => decName(d) !== 'UseGuards' ? [] : decArgs(d).map(a =>
      ts.isIdentifier(a) ? { name: 'canActivate', recv: a.text }
      : ts.isNewExpression(a) && ts.isIdentifier(a.expression) ? { name: 'canActivate', recv: a.expression.text }
      : ts.isCallExpression(a) ? { name: a.expression.getText(sf) } : null).filter(Boolean);
    const joinPath = (...p) => '/' + p.filter(Boolean).map(s => s.replace(/^\/+|\/+$/g, '')).filter(Boolean).join('/');

    function visitClass(n, owner) {
      const name = n.name ? n.name.text : 'AnonymousClass';
      const ext = (n.heritageClauses || []).find(h => h.token === ts.SyntaxKind.ExtendsKeyword);
      res.classes[name] = { superclass: ext ? ext.types[0].expression.getText(sf) : null, includes: [], file: rel };
      const ctrl = decs(n).find(d => decName(d) === 'Controller');
      const prefix = ctrl ? (str(decArgs(ctrl)[0]) || '') : null;
      const classGuards = decs(n).flatMap(guards);
      for (const m of n.members) {
        let id = null;
        if ((ts.isMethodDeclaration(m) || ts.isConstructorDeclaration(m)) && m.body)
          id = addDef(ts.isConstructorDeclaration(m) ? 'constructor' : m.name.getText(sf), name, m, m.body);
        else if (ts.isPropertyDeclaration(m) && isFn(m.initializer))  // handle = async (req, res) => {...}
          id = addDef(m.name.getText(sf), name, m, m.initializer.body);
        if (!id || prefix === null) continue;
        const http = decs(m).find(d => NEST[decName(d)]);
        if (http) res.routes.push({ verb: NEST[decName(http)], path: joinPath(prefix, str(decArgs(http)[0])),
                                    framework: 'nestjs', file: rel, handler_id: id,
                                    middleware: [...classGuards, ...decs(m).flatMap(guards)] });
      }
      ts.forEachChild(n, c => visit(c, name)); // routes may be registered inside methods
    }

    function visit(n, owner) {
      if (ts.isClassDeclaration(n) || ts.isClassExpression(n)) return visitClass(n, owner);
      if (ts.isFunctionDeclaration(n) && n.name && n.body) addDef(n.name.text, owner, n, n.body);
      else if (ts.isVariableDeclaration(n) && ts.isIdentifier(n.name) && isFn(n.initializer))
        addDef(n.name.text, owner, n, n.initializer.body);                       // const show = async (req, res) => {}
      else if (ts.isPropertyAssignment(n) && isFn(n.initializer))
        addDef(n.name.getText(sf), owner, n, n.initializer.body);                // module.exports = { show: function () {} }
      else if (ts.isMethodDeclaration(n) && ts.isObjectLiteralExpression(n.parent) && n.body)
        addDef(n.name.getText(sf), owner, n, n.body);                            // { show(req, res) {} }
      else if (ts.isBinaryExpression(n) && n.operatorToken.kind === ts.SyntaxKind.EqualsToken
               && ts.isPropertyAccessExpression(n.left) && isFn(n.right))
        addDef(n.left.name.text, owner, n, n.right.body);                        // exports.show = (req, res) => {}
      else if (ts.isCallExpression(n)) routeCall(n);
      ts.forEachChild(n, c => visit(c, owner));
    }
    visit(sf, null);
  }
JS

def index_js(files)
  empty = { "defs" => [], "classes" => {}, "routes" => [], "filters" => [] }
  return empty if files.empty?
  # Find the `typescript` package in local or global node_modules.
  global = `npm root -g 2>/dev/null`.strip rescue ""
  env = { "NODE_PATH" => [ENV["NODE_PATH"], global].reject { |p| p.nil? || p.empty? }.join(File::PATH_SEPARATOR) }
  out = IO.popen(env, ["node", "-e", JS_INDEXER], "r+", err: %i[child out]) do |io|
    io.write(JSON.dump(files))
    io.close_write
    io.read
  end
  JSON.parse(out)
rescue Errno::ENOENT
  log(:index, "node not found -> skipping #{files.size} JS/TS files")
  empty
rescue JSON::ParserError
  log(:index, "JS indexer failed -> skipping JS/TS files (is `typescript` installed? npm i -g typescript)\n#{out.to_s[0, 400]}")
  empty
end

# ─────────────────────────── 3. TRACE ───────────────────────────

class Tracer
  def initialize(store, classes, filters, repo, depth, with_source: false)
    @store, @classes, @filters, @repo, @depth = store, classes, filters, repo, depth
    @with_source = with_source
    @llm_cache = {}
    @file_lines = {}
  end

  # The code of one def, read from the repo (capped so one huge method can't blow up the doc).
  def source_of(d)
    lines = @file_lines[d["file"]] ||= File.readlines(File.join(@repo, d["file"]))
    body = lines[(d["start"] - 1)...d["end"]] || []
    body = body.first(MAX_SOURCE_LINES) + ["# ... (#{body.size - MAX_SOURCE_LINES} more lines truncated)\n"] if body.size > MAX_SOURCE_LINES
    { "id" => d["id"], "label" => label(d), "file" => d["file"], "lines" => "#{d['start']}-#{d['end']}", "code" => body.join }
  end

  # ── languages: a Ruby call never resolves to a Python/JS def, and vice versa ──
  def lang_of(file)
    case file.to_s
    when /\.rb\z/ then "rb"
    when /\.py\z/ then "py"
    else "js"
    end
  end

  def defs_in(name, lang) = @store.defs_named(name).select { |d| lang_of(d["file"]) == lang }

  # ── class hierarchy helpers (classes are keyed "lang:Name", e.g. "rb:Api::PostsController") ──
  def find_class(name, lang)
    return nil unless name
    key = "#{lang}:#{name}"
    return key if @classes.key?(key)
    short = name.split("::").last
    @classes.keys.find { |k| k.start_with?("#{lang}:") && k.delete_prefix("#{lang}:").split("::").last == short }
  end

  def class_of(d) = find_class(d["owner"], lang_of(d["file"]))
  def plain(key) = key&.split(":", 2)&.last

  # [C, its superclass, included modules, ...] (closest first)
  def ancestors(owner, lang)
    out, queue = [], [find_class(owner, lang)].compact
    while (c = queue.shift)
      next if out.include?(c)
      out << c
      info = @classes[c]
      queue.concat(([info["superclass"]] + info["includes"]).filter_map { |n| find_class(n, lang) })
    end
    out
  end

  # ── route → handler def + the filters that run before it ──
  def entry_for(route)
    case route["framework"]
    when "rails"
      handler = defs_in(route["action"], "rb").find { |d| same_class?(d["owner"], route["controller"]) }
      chain = ancestors(route["controller"], "rb").reverse # base class first
      active = []
      chain.each do |c|
        @filters.select { |f| f["owner"] == plain(c) && f["name"] }.each do |f|
          next if f["only"] && !f["only"].include?(route["action"])
          next if f["except"]&.include?(route["action"])
          f["kind"] == "skip" ? active.delete(f["name"]) : active |= [f["name"]]
        end
      end
      filter_defs = active.filter_map do |fname|
        cands = defs_in(fname, "rb")
        cands.find { |d| chain.include?(class_of(d)) } || cands.first ||
          { "id" => "external:#{fname}", "name" => fname, "external" => true }
      end
      [handler, filter_defs]
    else
      handler = route["handler_id"] ? @store.def_by_id(route["handler_id"])
                                    : resolve_ref({ "name" => route["handler_name"], "recv" => route["handler_recv"] }, route["file"])
      file = route["file"] || handler&.dig("file")
      # file-wide filters (Sinatra `before`, Flask before_request, app.use(mw)): skip unknown libs like cors()
      file_wide = @filters.select { |f| f["scope_file"] && f["scope_file"] == file }.filter_map { |f| resolve_ref(f, file) }
      # per-route middleware (Express args, NestJS guards): keep unknown ones as visible external nodes
      per_route = (route["middleware"] || []).map do |m|
        resolve_ref(m, file) || { "id" => "external:#{m['name']}", "name" => m["name"], "owner" => m["recv"], "external" => true }
      end
      [handler, file_wide + per_route]
    end
  end

  # {def_id} or {name, recv} -> a def (prefer same file, then a plain function, then anything)
  def resolve_ref(ref, near_file)
    return @store.def_by_id(ref["def_id"]) if ref["def_id"]
    return nil unless ref["name"]
    cands = defs_in(ref["name"], lang_of(near_file))
    cands = cands.select { |d| same_class?(d["owner"], ref["recv"]) } if ref["recv"]
    cands.find { |d| d["file"] == near_file } || cands.find { |d| d["owner"].nil? } || cands.first
  end

  def same_class?(a, b) = a && b && (a == b || a.end_with?("::#{b}") || b.end_with?("::#{a}"))

  # ── call resolution: call {name, recv} inside caller def → [target defs] ──
  def resolve(call, caller)
    name, recv = call["name"], call["recv"]
    lang = lang_of(caller["file"])

    if recv&.match?(/\A[A-Z]/) # Constant receiver: Post.find, User.objects.get, new OrderRepo() ...
      ctor = %w[new initialize constructor __init__].include?(name)
      name = "initialize" if name == "new"
      chain = ancestors(recv, lang)
      targets = defs_in(name, lang).select { |d| chain.include?(class_of(d)) }
      return [targets, "call"] unless targets.empty?
      return [[], nil] if ctor || STDLIB.include?(recv.split("::").first)
      # Not defined in the app (an ORM finder like Post.find / Invoice.findById): keep as a leaf,
      # pointing at the model's file when the class is in the app — the key signal for IDOR.
      cls = find_class(recv, lang)
      return [[{ "id" => "model:#{recv}.#{name}", "name" => name, "owner" => plain(cls) || recv,
                 "file" => cls && @classes[cls]["file"], "leaf" => true }], "model_call"]
    end

    cands = defs_in(name, lang)
    return [[], nil] if cands.empty?

    if recv.nil? || recv == "self" # implicit self: same class, then ancestors, then same file
      chain = ancestors(caller["owner"], lang)
      mine = chain.lazy.map { |c| cands.select { |d| class_of(d) == c } }.find(&:any?)
      return [mine, "call"] if mine
      same_file = cands.select { |d| d["file"] == caller["file"] }
      return [same_file, "call"] if same_file.any?
    end

    return [[], nil] if recv && NOISY.include?(name)
    # `@post.update(...)`: a call on some other object is not a call on our own class.
    if recv == "expr"
      own = ancestors(caller["owner"], lang)
      cands = cands.reject { |d| own.include?(class_of(d)) }
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
    @via = {}
    @model_calls = Set.new
    @externals = Set.new
    @unresolved = []
    roots = filter_defs.map { |f| node(f, "before_filter", 1, []) }
    roots << (handler ? node(handler, "handler", 1, []) : { "label" => "(handler not found)", "via" => "handler" })
    result = { "route" => "#{route['verb']} #{route['path']}", "framework" => route["framework"],
               "handler" => handler && label(handler), "input" => input_kinds(route, handler),
               "files" => @files.to_a.sort, "methods" => @seen.to_a, "model_calls" => @model_calls.to_a,
               "external" => @externals.to_a,
               "unresolved" => @unresolved.uniq, "tree" => roots }
    if @with_source
      # the body of every method reached, in the order it was first visited ...
      result["sources"] = @seen.map { |id| source_of(@store.def_by_id(id)).merge("via" => @via[id]) }
      # ... and the same code as one text, ready to hand to an LLM
      result["source_text"] = source_text(result)
    end
    result
  end

  # Why this route can carry attacker-controlled input (empty = no input -> trimmed).
  def input_kinds(route, handler)
    names = route["path"].scan(/:(\w+)|\{(\w+)\}|<(?:\w+:)?(\w+)>/).flatten.compact
    kinds = []
    kinds << "path" if names.any?
    kinds << "body" if %w[POST PUT PATCH].include?(route["verb"])
    kinds << "query" if ((handler&.dig("params") || []) - names).any? # Flask/FastAPI handler args not in the path
    kinds << "request_read" if @seen.any? { |id| (d = @store.def_by_id(id)) && source_of(d)["code"].match?(INPUT_CODE) }
    kinds
  end

  def source_text(t)
    head = ["Route: #{t['route']}  (#{t['framework']})", "Handler: #{t['handler'] || '(not found)'}",
            "Input: #{t['input'].join(', ')}"]
    head << "External filters/middleware (library code, not shown): #{t['external'].join(', ')}" if t["external"].any?
    head << "Data-access calls (defined outside the app code): #{t['model_calls'].join(', ')}" if t["model_calls"].any?
    blocks = t["sources"].map do |s|
      "### [#{s['via']}] #{s['label']} — #{s['file']}:#{s['lines']}\n```\n#{s['code'].chomp}\n```"
    end
    (head + [""] + blocks).join("\n") + "\n"
  end

  def label(d) = [d["owner"], d["name"]].compact.join(d["owner"]&.match?(/\A[A-Z]/) && !d["leaf"] ? "#" : ".")

  def node(d, via, depth, path)
    n = { "label" => label(d), "via" => via }
    n["file"] = "#{d['file']}:#{d['start']}-#{d['end']}" if d["file"] && d["start"]
    n["file"] ||= d["file"] if d["file"]
    @files << d["file"] if d["file"]
    if d["external"]
      @externals << "#{n['label']} [#{via}]"
      return n.merge("external" => true)
    end
    if d["leaf"]
      @model_calls << n["label"]
      return n.merge("leaf" => true)
    end
    return n.merge("cycle" => true) if path.include?(d["id"])
    return n.merge("seen" => true) if @seen.include?(d["id"]) # already expanded in this route
    @seen << d["id"]
    @via[d["id"]] = via
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
  opts = { out: "trace.json", depth: 6, route: nil, source: false }
  OptionParser.new do |o|
    o.banner = "usage: ruby route_tracer.rb REPO [options]"
    o.on("--out FILE", "output JSON (a .txt tree is written next to it)") { |v| opts[:out] = v }
    o.on("--depth N", Integer, "max call depth (default 6)") { |v| opts[:depth] = v }
    o.on("--route TEXT", "only trace routes whose 'VERB /path' contains TEXT") { |v| opts[:route] = v }
    o.on("--with-source", "include the code of every reached method (sources + source_text)") { opts[:source] = true }
    o.on("--all-routes", "keep routes that take no input too") { opts[:all] = true }
  end.parse!
  repo = File.expand_path(ARGV.fetch(0) { abort "usage: ruby route_tracer.rb REPO [--out trace.json]" })

  # 1. INDEX
  files = Dir.glob("**/*.{rb,py,js,jsx,mjs,cjs,ts,tsx}", base: repo)
             .reject { |f| f.split("/").any? { |p| SKIP_DIRS.include?(p) } || f.end_with?(".d.ts", ".min.js") }
  rb_files = files.select { |f| f.end_with?(".rb") }
  py_files = files.select { |f| f.end_with?(".py") }
  js_files = files.grep(JS_EXT)
  log(:index, "#{rb_files.size} Ruby + #{py_files.size} Python + #{js_files.size} JS/TS files in #{repo}")

  rb = RubyIndexer.new
  rb_files.each { |f| rb.index(f, File.read(File.join(repo, f))) }
  py = index_python(py_files.map { |f| [File.join(repo, f), f] })
  js = index_js(js_files.map { |f| [File.join(repo, f), f] })

  defs = rb.defs + py["defs"] + js["defs"]
  classes = { "rb" => rb.classes, "py" => py["classes"], "js" => js["classes"] }
              .flat_map { |lang, cs| cs.map { |name, info| ["#{lang}:#{name}", info] } }.to_h
  filters = rb.filters + py["filters"] + js["filters"]
  log(:index, "#{defs.size} methods/functions, #{classes.size} classes/modules, #{filters.size} filters")

  store = Store.open(repo)
  store.insert(:defs, defs)

  # 2. ROUTES
  routes = rb.routes + py["routes"] + js["routes"]
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
  tracer = Tracer.new(store, classes, filters, repo, opts[:depth], with_source: opts[:source])
  traces = routes.map do |r|
    t = tracer.trace(r)
    log(:trace, "#{t['route'].ljust(40)} -> #{t['handler'] || '?'}: #{t['methods'].size} methods, " \
                "#{t['files'].size} files, input: #{t['input'].empty? ? 'none' : t['input'].join('+')}")
    t
  end

  # 4. TRIM: only routes that take input can have BOLA/IDOR
  unless opts[:all]
    dropped = traces.select { |t| t["input"].empty? }
    traces -= dropped
    log(:trim, "kept #{traces.size} routes with input, dropped #{dropped.size}: #{dropped.map { |t| t['route'] }.join(', ')}")
  end
  store.insert(:traces, traces.map(&:dup))

  # 5. OUTPUT
  File.write(opts[:out], JSON.pretty_generate(traces))
  txt = opts[:out].sub(/\.json\z/, "") + ".txt"
  File.write(txt, traces.map { |t| (["#{t['route']}  ->  #{t['handler']}"] + tree_text(t["tree"])).join("\n") }.join("\n\n") + "\n")
  log(:done, "wrote #{opts[:out]} and #{txt}")
end