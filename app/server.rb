# frozen_string_literal: true

require "sinatra"
require "cgi"
require "open-uri"
require "digest"

require_relative "aws"
require_relative "helpers"

# set :known_keys, %w[ZDtwx65wb2PwVnZfHjIIS9TbtmDw+yg+YJ+Kqzfwf2w]
set :known_keys, %w[]
set :iam, Kekse::Aws.iam_stub_client # fix
set :sts, Kekse::Aws.sts_stub_client # fix
set :data_store, {} # delete this, it should be dynamo

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
  erb :console, locals: {challenge: console_challenge.to_s}
end

post "/console" do
  challenge     = request.params["challenge"]
  raw_signature = request.params["user_signature"]
  ssh_signature = console_access_signature(challenge, raw_signature)
  public_key    = ssh_signature.public_key

  reject_with :bad_request if ssh_signature.invalid? || unknown?(public_key)

  iam_roles = list_assumable_iam_roles
  signature_id = Digest::SHA512.hexdigest(raw_signature)
  settings.data_store[signature_id] = [false]

  vars = {account_id: aws_account_id, roles: iam_roles, signature: signature_id}
  erb :console_roles, locals: vars
end

# GET /console/role/foo?signature=sha512(raw_signature)
# if signature found in db ? render template with button : bad request
get "/console/role/:name" do
  params = request.params

  if params.nil? || params.empty? || params.size > 1 || !params.key?("signature")
    reject_with :bad_request
  end

  signature_id = params["signature"]
  reject_with :bad_request unless sha512_hash?(signature_id)

  signature = settings.data_store[signature_id]
  reject_with :bad_request if !signature

  "Hello " + params["name"]
end
