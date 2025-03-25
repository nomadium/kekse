require "sinatra"

require_relative "helpers"
require_relative "middlewares/signature"

use Rack::Auth::Signature, except: "/hello",
                           pubkey: "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAvZ3iaUt5pPpTsJM40tI6I/SeI/+KVJWoZmyv9VoT36c=\n-----END PUBLIC KEY-----\n"

get "/hello" do
  erb :hello
end

get "/role" do
  "protected"
end
