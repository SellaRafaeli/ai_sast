# Gems for the web server (web/web.rb). The command-line scripts need none of these,
# except `mongo` if you want them to save to Mongo.
source "https://rubygems.org"

ruby "~> 4.0" # route_tracer.rb needs 3.3+ (built-in Prism parser)

gem "sinatra", "~> 4.1"
gem "rackup"
gem "puma"
gem "mongo", "~> 2.20.0" # 2.21+ needs MongoDB 4.4+; 2.20 works with older local servers and current hosted ones
gem "bigdecimal" # the mongo gem uses it; Ruby 4.0 no longer loads it without the Gemfile
