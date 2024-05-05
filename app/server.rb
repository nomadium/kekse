require "sinatra"
require "ssh_data"

require_relative "helpers"

set :foofoo, true

before do
  reject if unauthorized?
end

get "/hello" do
  puts settings.foofoo
  erb :hello
end

get "/role" do
  "protected"
end

get "/console" do
  # binding.irb
  erb :console, locals: {challenge: console_challenge.to_s}
end

post "/console" do
  challenge     = request.params["challenge"]
  raw_signature = request.params["user_signature"]
  ssh_signature = console_access_signature(challenge, raw_signature)
  public_key    = ssh_signature.public_key

  reject_with :bad_request if ssh_signature.invalid? #|| unknown?(public_key)
  "signed"

  # result = federate
  # reject_with :bad_request if !result.ok?
  # redirect federate.url
  #   "signed"
  #   # once we know the message is signed:
  #   # generate a random 256 bits value (or 512)
  #   # fetch credentials and store them in a key with the random value
  #   # send url with the random value to a sns topic
  #   # if link clicked, redirect to console
end
