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
  ssh_signature = request.params["user_signature"]

  signature = SSHData::Signature.parse_pem(Base64.decode64(ssh_signature))

  halt 400 unless signature.public_key.fingerprint == fingerprint
  halt 400 unless signature.verify(message)

  "signed"
end
