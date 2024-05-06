# frozen_string_literal: true

require "base64"
require "securerandom"
require "linzer"
require "digest"

ENV["PUBKEY"] = "/NRYfVPJ9ca84wgoNeo/oppjg1Ko6SHpKLh0Z5RpiPY="

module SSHData
  module Encoding
    # Get a PEM encoded blob from signature object.
    #
    # signature  - The SSHData::Signature signature object.
    #
    def encode_openssh_signature(signature)
      pem_type = "SSH SIGNATURE"
      header = "-----BEGIN #{pem_type}-----"
      footer = "-----END #{pem_type}-----"

      fields =
        OPENSSH_SIGNATURE_FIELDS
          .map do |field, type|
            case field
            when :publickey then [type, signature.public_key.rfc4253]
            else                 [type, signature.public_send(field)]
            end
          end

      blob = OPENSSH_SIGNATURE_MAGIC + encode_fields(*fields)
      "%s\n%s%s" % [header, Base64.encode64(blob), footer]
    end
  end

  class Signature
    def to_pem
      Encoding.encode_openssh_signature(self)
    end
  end
end

def ssh_sign(key, message, namespace, reserved, hash_algorithm)
  signed_data     = signed_data(message, namespace, reserved, hash_algorithm)
  inner_signature = key.sign(signed_data)

  SSHData::Signature.new(
    sigversion:     SSHData::Signature::MIN_SUPPORTED_VERSION,
    publickey:      key.public_key.rfc4253,
    namespace:      namespace,
    reserved:       reserved,
    hash_algorithm: hash_algorithm,
    signature:      inner_signature
  )
end

def openssh_signature(key, message)
  namespace      = "file"
  reserved       = ""
  hash_algorithm = "sha512"
  ssh_sign(key, message, namespace, reserved, hash_algorithm)
end

# refactor: move
def signed_data(message, namespace, reserved, hash_algorithm)
  digest = Digest.const_get(hash_algorithm.upcase)
                 .digest(message)
  fields = [
    [:string, namespace],
    [:string, reserved],
    [:string, hash_algorithm],
    [:string, digest]
  ]

  preamble = SSHData::Signature::SIGNATURE_PREAMBLE
  preamble + SSHData::Encoding.encode_fields(*fields)
end

def to_rack_headers(headers)
  headers.transform_keys! { |k| "HTTP_" + k.upcase.tr("-", "_") }
end

RSpec.describe "Kekse service" do
  include Rack::Test::Methods

  context "without credentials" do
    it "should succeed on /hello GET request" do
      get "/hello"
      expect(last_response).to      be_ok
      expect(last_response.body).to match(/Hello/)
    end

    it "should succeed on /console GET request" do
      get "/console"
      expect(last_response).to        be_ok
      expect(last_response.status).to eq(200)
      expect(last_response.body).to   match(/Console access/)
    end

    it "should fail with 401 on any other request type and URL" do
      verb = %i[get post put patch delete options head].sample
      send verb, "/whatever"
      expect(last_response).to_not           be_ok
      expect(last_response.status).to        eq(401)
      if last_request.head?
        expect(last_response.body.empty?).to eq(true)
      else
        expect(last_response.body).to        match(/Unauthorized/)
      end
    end
  end

  context "using ssh signature with /console" do
    it "should fail if no parameters are provided" do
      post "/console"
      expect(last_response).to_not    be_ok
      expect(last_response.status).to eq(400)
      expect(last_response.body).to   match(/Bad Request/)
    end

    it "should fail with no challenge provided" do
      post "/console", {"user_signature" => "signature"}
      expect(last_response).to_not    be_ok
      expect(last_response.status).to eq(400)
      expect(last_response.body).to   match(/Bad Request/)
    end

    it "should fail with no signature provided" do
      post "/console", {"challenge" => "challenge"}
      expect(last_response).to_not    be_ok
      expect(last_response.status).to eq(400)
      expect(last_response.body).to   match(/Bad Request/)
    end

    it "should fail with invalid challenge provided" do
      invalid_challenge = Base64.strict_encode64("-^#23")
      post "/console", {"challenge" => invalid_challenge}
      expect(last_response).to_not    be_ok
      expect(last_response.status).to eq(400)
      expect(last_response.body).to   match(/Bad Request/)
    end

    it "should fail with incomplete challenge" do
      incomplete_challenge = Base64.strict_encode64("challenge-")
      post "/console", {"challenge" => incomplete_challenge}
      expect(last_response).to_not    be_ok
      expect(last_response.status).to eq(400)
      expect(last_response.body).to   match(/Bad Request/)
    end

    it "should fail with a challenge with invalid payload" do
      invalid_challenge = Kekse::Challenge.new(SecureRandom.base64(15))
      post "/console", {"challenge" => invalid_challenge.to_s}
      expect(last_response).to_not    be_ok
      expect(last_response.status).to eq(400)
      expect(last_response.body).to   match(/Bad Request/)
    end

    it "should fail with challenge with a time too old" do
      challenge = Kekse::Challenge.new(SecureRandom.base64(15), 1234567890)
      post "/console", {"challenge" => challenge.to_s}
      expect(last_response).to_not    be_ok
      expect(last_response.status).to eq(400)
      expect(last_response.body).to   match(/Bad Request/)
    end

    it "should fail with invalid signature" do
      challenge = Kekse::Challenge.new
      signature = "crap"
      post "/console", {"challenge" => challenge.to_s, "user_signature" => signature}
      expect(last_response).to_not    be_ok
      expect(last_response.status).to eq(400)
      expect(last_response.body).to   match(/Bad Request/)
    end

    # also add a test case for a challenge with future time and reject it
    # fix: refactor
    it "should succeed with a good signature from known key" do
      challenge = Kekse::Challenge.new
      key       = SSHData::PrivateKey::ED25519.generate
      signature = openssh_signature(key, challenge.to_s)

      app.settings.known_keys << key.public_key.fingerprint

      params = {
        "challenge" => challenge.to_s,
        "user_signature" => Base64.strict_encode64(signature.to_pem)
      }

      post "/console", params
      expect(last_response).to        be_ok
      expect(last_response.status).to eq(200)
      expect(last_response.body).to   eq("signed")
    end

    # fix
    # create a new challenge
    # create a new key
    # add key to app
    # sign random data with key
    xit "should fail with a good signature from known key but wrong message" do
      app.settings.known_keys.clear
      expect(false).to eq(true)
    end

    # fix
    # create a new challenge
    # create a new key
    # sign challenge with key
    xit "should fail with a signature from unknown key and right message" do
      app.settings.known_keys.clear
      expect(false).to eq(true)
    end
  end

  context "with credentials" do
    let(:key) do
      key_material = "kqnM+q2GO/pGSzgxdNz0AOxQYK/9DMFaB7RxVNjIMxI="
      Linzer.new_ed25519_key(Base64.strict_decode64(key_material))
    end

    let(:headers) { {"x-foo" => "bar", "date" => Time.now.to_s} }

    it "should succeed on /role GET request" do
      request = Linzer.new_request(:get, "/role", {}, headers)
      message = Linzer::Message.new(request)
      fields = %w[x-foo date @method]

      signature = Linzer.sign(key, message, fields)
      rack_headers = to_rack_headers(headers.merge(signature.to_h))

      get "/role", {}, rack_headers
      expect(last_response.status).to eq(200)
      expect(last_response).to        be_ok
      expect(last_response.body).to   eq("protected")
    end
  end

  context "with invalid credentials" do
    let(:invalid_key) do
      key_material = "yEXEypRr2zK6RAfl3wuBnax4FtF/SV1arrxXW6rgQT4="
      Linzer.new_ed25519_key(Base64.strict_decode64(key_material))
    end

    let(:headers) { {"x-foo" => "bar", "user-agent" => "Ruby"} }

    it "should fail with 401 on /role GET request" do
      request = Linzer.new_request(:get, "/role", {}, headers)
      message = Linzer::Message.new(request)
      fields = %w[x-foo user-agent @method]

      signature = Linzer.sign(invalid_key, message, fields)
      rack_headers = to_rack_headers(headers.merge(signature.to_h))

      get "/role", {}, rack_headers
      expect(last_response.status).to eq(401)
      expect(last_response).to_not    be_ok
      expect(last_response.body).to   match(/Unauthorized/)
    end
  end
end
