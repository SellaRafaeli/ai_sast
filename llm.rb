# llm.rb — tiny LLM client shared by route_tracer.rb and analyze_bola.rb.
#
# Keys come from the environment or a .env file (current dir, then this script's dir):
#   ANTHROPIC_API_KEY=...          -> Anthropic (default model claude-sonnet-5-5)
#   OPEN_AI_API_KEY=...            -> OpenAI    (default model gpt-5; OPENAI_API_KEY also works)
# Optional:
#   LLM_PROVIDER=anthropic|openai  pick one when both keys are set (default: anthropic)
#   LLM_MODEL=...                  override the model
#   ANTHROPIC_BASE_URL / OPENAI_BASE_URL  for proxies or compatible endpoints

require "json"
require "net/http"
require "uri"

module LLM
  class Error < StandardError; end

  module_function

  # Minimal .env reader: KEY=value lines, `export` prefix and quotes allowed.
  # Never overrides variables that are already set in the environment.
  def load_dotenv
    [File.join(Dir.pwd, ".env"), File.join(__dir__, ".env")].uniq.each do |path|
      next unless File.file?(path)
      File.foreach(path, chomp: true) do |line|
        next unless line =~ /\A\s*(?:export\s+)?([A-Za-z_]\w*)\s*=\s*(.*)\z/
        key, val = Regexp.last_match(1), Regexp.last_match(2).strip
        val = val =~ /\A(["'])(.*?)\1/ ? Regexp.last_match(2) : val.sub(/\s+#.*\z/, "") # "quoted" or bare # comment
        ENV[key] = val if ENV[key].to_s.empty?
      end
    end
  end

  def anthropic_key = ENV["ANTHROPIC_API_KEY"].to_s.then { |k| k.empty? ? nil : k }
  def openai_key = (ENV["OPEN_AI_API_KEY"] || ENV["OPENAI_API_KEY"]).to_s.then { |k| k.empty? ? nil : k }

  def provider
    case ENV["LLM_PROVIDER"].to_s.downcase
    when "openai" then return :openai if openai_key
    when "anthropic" then return :anthropic if anthropic_key
    end
    return :anthropic if anthropic_key
    return :openai if openai_key
    nil
  end

  def available? = !provider.nil?
  def model = ENV["LLM_MODEL"] || (provider == :openai ? "gpt-5" : "claude-sonnet-5-5")
  def describe = available? ? "#{provider} / #{model}" : "no LLM key (set ANTHROPIC_API_KEY or OPEN_AI_API_KEY in .env)"

  # Send one prompt, get the text answer. Retries rate limits / overloads / 5xx a few times.
  def ask(prompt, system: nil, max_tokens: 4000)
    raise Error, describe unless available?
    attempts = 0
    begin
      attempts += 1
      provider == :anthropic ? ask_anthropic(prompt, system, max_tokens) : ask_openai(prompt, system, max_tokens)
    rescue Error => e
      retryable = e.message =~ /\AHTTP (429|500|502|503|504|529)\b/ || e.message.start_with?("network")
      raise unless retryable && attempts < 4
      sleep(5 * attempts)
      retry
    end
  end

  def ask_anthropic(prompt, system, max_tokens)
    base = ENV.fetch("ANTHROPIC_BASE_URL", "https://api.anthropic.com").chomp("/")
    body = { model: model, max_tokens: max_tokens, messages: [{ role: "user", content: prompt }] }
    body[:system] = system if system
    res = post("#{base}/v1/messages", body,
               "x-api-key" => anthropic_key, "anthropic-version" => "2023-06-01")
    res.fetch("content", []).select { |b| b["type"] == "text" }.map { |b| b["text"] }.join
  end

  def ask_openai(prompt, system, max_tokens)
    base = ENV.fetch("OPENAI_BASE_URL", "https://api.openai.com/v1").chomp("/")
    messages = []
    messages << { role: "system", content: system } if system
    messages << { role: "user", content: prompt }
    # Reasoning models count hidden reasoning toward this limit, so give them room.
    body = { model: model, messages: messages, max_completion_tokens: max_tokens * 4 }
    res = post("#{base}/chat/completions", body, "authorization" => "Bearer #{openai_key}")
    res.dig("choices", 0, "message", "content").to_s
  end

  def post(url, body, headers)
    uri = URI(url)
    req = Net::HTTP::Post.new(uri, { "content-type" => "application/json" }.merge(headers))
    req.body = JSON.dump(body)
    res = Net::HTTP.start(uri.host, uri.port, use_ssl: uri.scheme == "https", read_timeout: 600, open_timeout: 30) do |h|
      h.request(req)
    end
    raise Error, "HTTP #{res.code}: #{res.body.to_s[0, 300]}" unless res.is_a?(Net::HTTPSuccess)
    JSON.parse(res.body)
  rescue SocketError, Timeout::Error, Errno::ECONNREFUSED, Errno::ECONNRESET, OpenSSL::SSL::SSLError => e
    raise Error, "network: #{e.class}: #{e.message}"
  end

  # Pull the first JSON array/object out of a model answer (handles ```json fences and chatter).
  def extract_json(text)
    fenced = text[/```(?:json)?\s*(.*?)```/m, 1]
    candidates = [fenced, text[/\[.*\]/m], text[/\{.*\}/m]].compact
    candidates.each do |c|
      return JSON.parse(c)
    rescue JSON::ParserError
      next
    end
    raise Error, "no JSON in answer: #{text[0, 200]}"
  end
end
