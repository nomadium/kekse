require "sinatra"
require "ssh_data"

require_relative "helpers"

before do
  reject if unauthorized?
end

get "/hello" do
  erb :hello
end

get "/role" do
  "protected"
end

get "/console" do
  binding.irb
  erb :console, locals: {challenge: console_challenge}
end

post "/console" do
  fingerprint = "ZDtwx65wb2PwVnZfHjIIS9TbtmDw+yg+YJ+Kqzfwf2w"

  halt 400 if request.params.empty?
  halt 400 if %w[challenge user_signature].any? { |p| !request.params.key?(p) }

  message       = request.params["challenge"]
  # challenge should be validated:
  # it has the expected format
  # it cannot be replayed
  # expires after 5 mins
  ssh_signature = request.params["user_signature"]

  signature = SSHData::Signature.parse_pem(Base64.decode64(ssh_signature))

  halt 400 unless signature.public_key.fingerprint == fingerprint
  halt 400 unless signature.verify(message)

  "signed"
  # once we know the message is signed:
  # generate a random 256 bits value (or 512)
  # fetch credentials and store them in a key with the random value
  # send url with the random value to a sns topic
  # if link clicked, redirect to console
end
