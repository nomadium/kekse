require "base64"

helpers do
  def pubkey
    pubkey_material = ENV["PUBKEY"]
    return nil if pubkey_material.nil?
    pubkey_material = Base64.strict_decode64(pubkey_material)
    # XXX: catch exception(s)
    @pubkey ||= Linzer.new_ed25519_public_key(pubkey_material)
  end

  def require_authorization?
    request.path_info != "/hello"
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
    [401, {}, "<h1>Unauthorized</h1>"]
  end
end
