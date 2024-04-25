require "sinatra"

require_relative "helpers"

before do
  reject 401, :unauthorized if unauthorized?
end

get "/hello" do
  erb :hello
end

get "/role" do
  # reject 400, :bad_request if some_error?
  "protected"
end
