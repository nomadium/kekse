require "sinatra"
require "base64"
require "linzer"

require_relative "helpers"

before do
  halt 401 if unauthorized?
end

get "/hello" do
  "hello"
end

get "/role" do
  "protected"
end
