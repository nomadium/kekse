require "sinatra"

require_relative "helpers"

before do
  reject if unauthorized?
end

get "/hello" do
  "hello"
end

get "/role" do
  "protected"
end
