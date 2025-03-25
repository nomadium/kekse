require "sinatra"

require_relative "helpers"
require_relative "middlewares/signature"

use Rack::Auth::Signature, except: "/hello"

get "/hello" do
  erb :hello
end

get "/role" do
  "protected"
end
