# pricing.rb — what LLM tokens cost, fetched from public price lists so the web app can show the cost of each call.
#
# Two sources, both public JSON, no key needed:
#   OpenRouter's model list   ranks the models: the newest TOP_N per provider (anthropic, openai), by release date
#   LiteLLM's price list      exact prices by API model id, including cached-input prices
# A model's price comes from LiteLLM when it lists that id, otherwise from OpenRouter. When OpenRouter has fewer than
# TOP_N models of a provider, the list is topped up from LiteLLM's. Prices are US dollars per token.
#
#   Pricing.load(collection)   use the copy saved in Mongo (instant), then refresh from the web in the background
#   Pricing.refresh!           fetch both lists now (the web app does it at boot and once a day)
#   Pricing.find("openai", "gpt-5")  -> { "input" =>, "output" =>, "cache_read" =>, "cache_write" =>, ... } or nil
#   Pricing.cost("openai", "gpt-5", input: 13978, output: 1922, cache_read: 0)  -> dollars, or nil without a price

require "json"
require "net/http"
require "uri"
require "time"

module Pricing
  OPENROUTER = "https://openrouter.ai/api/v1/models"
  LITELLM    = "https://raw.githubusercontent.com/BerriAI/litellm/main/model_prices_and_context_window.json"
  PROVIDERS  = %w[anthropic openai].freeze
  TOP_N      = 50

  @table = nil # { "fetched_at" =>, "sources" =>, "models" => { "anthropic" => { id => price }, "openai" => {...} } }
  @lock = Mutex.new

  module_function

  def table = @lock.synchronize { @table }

  # Start from the copy saved in `coll` (a Mongo collection), then refresh in the background and every day after.
  def load(coll, extra_models: [])
    @coll = coll
    saved = coll.find(_id: "pricing").first
    @lock.synchronize { @table = saved.to_h.except("_id") } if saved
    Thread.new do
      loop do
        refresh!(extra_models: extra_models)
        sleep 24 * 3600
      end
    end
  end

  # Fetch both price lists and keep the TOP_N newest models of each provider (plus `extra_models`, as
  # [provider, id] pairs, such as the model this server is configured with). Keeps the old table on failure.
  def refresh!(extra_models: [])
    litellm = fetch_json(LITELLM)
    ranked = (fetch_json(OPENROUTER)["data"] rescue nil) || [] # optional: only used to rank
    models = PROVIDERS.to_h do |prov|
      by_id = litellm.select { |_, v| v.is_a?(Hash) && v["litellm_provider"] == prov && v["mode"] == "chat" }
      list = {}
      ranked.select { |m| m["id"].to_s.start_with?("#{prov}/") && !m["id"].include?(":") }
            .sort_by { |m| -m["created"].to_i }.each do |m|
        break if list.size >= TOP_N
        id = m["id"].split("/", 2)[1]
        id = id.tr(".", "-") if prov == "anthropic" # OpenRouter writes claude-sonnet-4.5; the API id is claude-sonnet-4-5
        p = by_id[id] ? from_litellm(by_id[id]) : from_openrouter(m)
        list[id] = p.merge("rank" => list.size + 1, "released" => m["created"] && Time.at(m["created"]).utc.iso8601) if p
      end
      by_id.each do |id, v| # top up from LiteLLM when OpenRouter lists fewer
        break if list.size >= TOP_N
        list[id] ||= from_litellm(v)&.merge("rank" => list.size + 1)
      end
      extra_models.each { |pv, id| list[id] ||= from_litellm(by_id[id] || {})&.merge("rank" => nil) if pv == prov && id }
      [prov, list.compact]
    end
    t = { "fetched_at" => Time.now.utc, "sources" => [OPENROUTER, LITELLM], "models" => models }
    @lock.synchronize { @table = t }
    @coll&.replace_one({ _id: "pricing" }, t.merge("_id" => "pricing"), upsert: true)
    warn "[pricing] #{models.map { |k, v| "#{v.size} #{k}" }.join(', ')} models from OpenRouter + LiteLLM"
    t
  rescue => e
    warn "[pricing] refresh failed, keeping #{table ? 'the saved prices' : 'no prices'}: #{e.class}: #{e.message[0, 200]}"
    table
  end

  # "openai / gpt-5" (LLM.describe) -> ["openai", "gpt-5"]
  def split(described) = described.to_s.split(" / ", 2).map(&:strip)

  # The price of a model, also trying its id without a date suffix (claude-sonnet-4-5-20250929 -> claude-sonnet-4-5).
  def find(provider, model)
    list = table&.dig("models", provider.to_s) or return nil
    list[model.to_s] || list[model.to_s.sub(/-\d{8}\z/, "")] || list[model.to_s.sub(/-\d{4}-\d{2}-\d{2}\z/, "")]
  end

  # Dollars for one call. `input` counts every input token, cached or not (as llm.rb reports it); cached reads and
  # cache writes are priced at their own rates when the list has them.
  def cost(provider, model, input:, output:, cache_read: 0, cache_write: 0)
    p = find(provider, model) or return nil
    plain = [input.to_i - cache_read.to_i - cache_write.to_i, 0].max
    plain * p["input"] + cache_read.to_i * (p["cache_read"] || p["input"]) +
      cache_write.to_i * (p["cache_write"] || p["input"]) + output.to_i * p["output"]
  end

  def from_litellm(v)
    return nil unless v["input_cost_per_token"] && v["output_cost_per_token"]
    { "input" => v["input_cost_per_token"].to_f, "output" => v["output_cost_per_token"].to_f,
      "cache_read" => v["cache_read_input_token_cost"]&.to_f, "cache_write" => v["cache_creation_input_token_cost"]&.to_f,
      "source" => "litellm" }
  end

  def from_openrouter(m)
    pr = m["pricing"] || {}
    return nil unless pr["prompt"] && pr["completion"]
    { "input" => pr["prompt"].to_f, "output" => pr["completion"].to_f,
      "cache_read" => pr["input_cache_read"]&.to_f, "cache_write" => pr["input_cache_write"]&.to_f, "source" => "openrouter" }
  end

  def fetch_json(url, redirects: 3)
    uri = URI(url)
    res = Net::HTTP.start(uri.host, uri.port, use_ssl: true, open_timeout: 15, read_timeout: 45) do |h|
      h.request(Net::HTTP::Get.new(uri, "User-Agent" => "variablee-code-pricing", "Accept" => "application/json"))
    end
    return fetch_json(URI.join(url, res["location"]).to_s, redirects: redirects - 1) if res.is_a?(Net::HTTPRedirection) && redirects.positive?
    raise "#{url}: HTTP #{res.code}" unless res.is_a?(Net::HTTPSuccess)
    JSON.parse(res.body)
  end
end
