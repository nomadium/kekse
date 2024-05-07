# frozen_string_literal: true

require "base64"
require "securerandom"
require "linzer"
require_relative "../app/utils"
require_relative "../app/monkey_patches"

ENV["PUBKEY"] = "/NRYfVPJ9ca84wgoNeo/oppjg1Ko6SHpKLh0Z5RpiPY="

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
      challenge = Kekse::Challenge.new(SecureRandom.base64(16), 1234567890)
      post "/console", {"challenge" => challenge.to_s, "user_signature" => ".."}
      expect(last_response).to_not    be_ok
      expect(last_response.status).to eq(400)
      expect(last_response.body).to   match(/Bad Request/)
    end

    it "should fail with challenge with time in the future" do
      future_time = Time.now.to_i + 5000
      challenge = Kekse::Challenge.new(SecureRandom.base64(16), future_time)
      post "/console", {"challenge" => challenge.to_s, "user_signature" => ".."}
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
    it "should succeed with a good signature from known key" do
      key = SSHData::PrivateKey::ED25519.generate
      app.settings.known_keys << key.public_key.fingerprint

      challenge = Kekse::Challenge.new
      signature = Kekse::Utils.openssh_signature(key, challenge.to_s)

      params = {
        "challenge"      => challenge.to_s,
        "user_signature" => Base64.strict_encode64(signature.to_pem)
      }

      post "/console", params
      expect(last_response).to        be_ok
      expect(last_response.status).to eq(200)
      expect(last_response.body).to   eq("signed")
    end

    it "should fail with a good signature from known key but wrong message" do
      app.settings.known_keys.clear

      key = SSHData::PrivateKey::ED25519.generate
      app.settings.known_keys << key.public_key.fingerprint

      challenge = Kekse::Challenge.new
      signature = Kekse::Utils.openssh_signature(key, "bad data")

      params = {
        "challenge"      => challenge.to_s,
        "user_signature" => Base64.strict_encode64(signature.to_pem)
      }

      post "/console", params
      expect(last_response).to_not    be_ok
      expect(last_response.status).to eq(400)
      expect(last_response.body).to   match(/Bad Request/)
    end

    it "should fail with a signature from unknown key" do
      app.settings.known_keys.clear

      key = SSHData::PrivateKey::ED25519.generate

      challenge = Kekse::Challenge.new
      signature = Kekse::Utils.openssh_signature(key, challenge.to_s)

      params = {
        "challenge"      => challenge.to_s,
        "user_signature" => Base64.strict_encode64(signature.to_pem)
      }

      post "/console", params
      expect(last_response).to_not    be_ok
      expect(last_response.status).to eq(400)
      expect(last_response.body).to   match(/Bad Request/)
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
