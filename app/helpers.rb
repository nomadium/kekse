# frozen_string_literal: true

require "base64"
require "linzer"
require "cgi"
require "open-uri"
require_relative "models"
require_relative "aws"

helpers do
  def reject
    halt(*unauthorized_error)
  end

  def reject_with(error)
    halt(*(send error))
  end

  def title
    "Kekse"
  end

  def console_challenge
    Kekse::Challenge.new
  end

  def console_access_signature(message, raw_signature)
    Kekse::Challenge::Signature.build(message, raw_signature)
  end

  def unknown?(public_key)
    public_key.nil? || !settings.known_keys.include?(public_key.fingerprint)
  end

  def pubkey
    pubkey_material = ENV["PUBKEY"]
    return nil if pubkey_material.nil?
    pubkey_material = Base64.strict_decode64(pubkey_material)
    # XXX: catch exception(s)
    @pubkey ||= Linzer.new_ed25519_public_key(pubkey_material)
  end

  def require_authorization?
    return false if request.path_info.match?(/\A\/console\/role\/.+/)
    return false if request.path_info == "/console"
    request.path_info != "/hello" || !request.get?
  end

  def request_headers
    request
      .env
      .select { |(k, _)| k.start_with?("HTTP_") }
      .transform_keys do |k|
        k.downcase
          .gsub(/^http_/, "")
          .tr("_", "-")
      end
  end

  def signature
    @signature ||= Linzer::Signature.build(request_headers)
  rescue Linzer::Error => _
    nil
  end

  def signed?
    request_headers.slice("signature", "signature-input").size == 2
  end

  def valid_signature?
    return false unless pubkey
    return false unless signature
    return false unless signature.components.include?("x-foo")

    message = Linzer::Message.new(request)
    Linzer.verify(pubkey, message, signature)
  rescue Linzer::Error => _error
    # puts error.message # XXX: use a logger for this
    false
  end

  def authorized?
    signed? && valid_signature?
  end

  def unauthorized?
    require_authorization? && !authorized?
  end

  def unauthorized_error
    [401, {}, (erb :unauthorized)]
  end

  def internal_server_error
    [500, {}, (erb :internal_server_error)]
  end

  def bad_request
    [400, {}, (erb :bad_request)]
  end

  def iam_client
    settings.iam
  end

  def sts_client
    settings.sts
  end

  def list_assumable_iam_roles
    Kekse::Aws.list_assumable_iam_roles(iam_client)
  rescue Seahorse::Client::NetworkingError, Aws::IAM::Errors::AccessDenied => ex
    ex.full_message
    # logger.fatal ex.full_message
    # halt 500
    reject_with :internal_server_error
  end

  def aws_account_id
    Kekse::Aws.aws_account_id(sts_client)
  end

  # require "cgi"
  # require "open-uri"
  def federated_access_aws_console(aws_credentials)
    signin_url = "https://signin.aws.amazon.com/federation"

    session_json = {
      sessionId:    aws_credentials.access_key_id,
      sessionKey:   aws_credentials.secret_access_key,
      sessionToken: aws_credentials.session_token
    }.to_json

    get_signin_token_url = signin_url
    get_signin_token_url << "?Action=getSigninToken"
    get_signin_token_url << "&SessionType=json&Session="
    get_signin_token_url << CGI.escape(session_json)

    URI.parse(get_signin_token_url).read
  end

  def sha512_hash?(str)
    str.match?(/\A[0-9a-f]{128}\z/)
  end
end
