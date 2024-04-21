# frozen_string_literal: true

my_gem_path = Dir["./vendor/bundle/ruby/3.2.0/gems/**/lib"]
$LOAD_PATH.unshift(*my_gem_path)

require "srack"

RACK_APP_CONFIG = "#{__dir__}/app/config.ru"

# Global object that responds to the call method. Stay outside of the handler
# to take advantage of container reuse
$app ||= Rack::Builder.parse_file(RACK_APP_CONFIG)
ENV["RACK_ENV"] ||= "production"

def lambda_handler(event:, context:)
  SRack::AWSLambdaHandler
    .new($app)
    .handle(event:   event,
            context: context)
end
