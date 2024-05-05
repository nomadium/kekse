# frozen_string_literal: true

require "base64"
require "securerandom"
require "linzer"

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
      payload = SecureRandom.base64(15)
      raw_challenge = "challenge-#{payload}-1234567890"
      invalid_challenge = Base64.strict_encode64(raw_challenge)
      post "/console", {"challenge" => invalid_challenge}
      expect(last_response).to_not    be_ok
      expect(last_response.status).to eq(400)
      expect(last_response.body).to   match(/Bad Request/)
    end

    it "should fail with challenge with a time too old" do
      payload = SecureRandom.base64(16)
      raw_challenge = "challenge-#{payload}-1234567890"
      challenge = Base64.strict_encode64(raw_challenge)
      post "/console", {"challenge" => challenge}
      expect(last_response).to_not    be_ok
      expect(last_response.status).to eq(400)
      expect(last_response.body).to   match(/Bad Request/)
    end

    it "should fail with invalid signature" do
      raw_challenge = "Y2hhbGxlbmdlLWtLdVYwYkpMNmNIMW13ZThpOXBsUnc9PS0xNzE0ODYwNDE1"
      signature = "crap"
      post "/console", {"challenge" => raw_challenge, "user_signature" => signature}
      expect(last_response).to_not    be_ok
      expect(last_response.status).to eq(400)
      expect(last_response.body).to   match(/Bad Request/)
    end

    # fix
    # create a new challenge
    # create a new key
    # add key to app
    # sign challenge with key
    it "should succeed with a good signature from known key" do
      # payload = SecureRandom.base64(16)
      # binding.irb
      # time = Time.now.to_i - 30
      # raw_challenge = "challenge-#{payload}-#{time}"
      # challenge = Base64.strict_encode64(raw_challenge)
      # challenge = Kekse::Challenge.new
      raw_challenge = "Y2hhbGxlbmdlLWtLdVYwYkpMNmNIMW13ZThpOXBsUnc9PS0xNzE0ODYwNDE1"
      # challenge = "challenge-kKuV0bJL6cH1mwe8i9plRw==-1714860415"
      pem_encoded_ssh_signature = <<~SIG
        -----BEGIN SSH SIGNATURE-----
        U1NIU0lHAAAAAQAAADMAAAALc3NoLWVkMjU1MTkAAAAgnTE8/uaUtQYW4RjNzcJdu0LP74
        goqlHiLItn+sB1aqIAAAAEZmlsZQAAAAAAAAAGc2hhNTEyAAAAUwAAAAtzc2gtZWQyNTUx
        OQAAAECUgAcpR5OrC+GaeeU2p/QfqyBFSMJl+dUWKJRhj0pVl0X+sXf3MBd9uQ+zy4m7mC
        ws82uT7jWyAZWMlAp3+okI
        -----END SSH SIGNATURE-----
      SIG
      signature = Base64.strict_encode64(pem_encoded_ssh_signature)

      # signing_key = Ed25519::SigningKey.generate
      # verify_key = signing_key.verify_key
      # key = SSHData::PrivateKey::ED25519.new(
      #   algo: SSHData::PublicKey::ALGO_ED25519,
      #   pk: verify_key.to_bytes,
      #   sk: signing_key.to_bytes + verify_key.to_bytes,
      #   comment: "comment"
      # )
      # subject.sign(message))

      post "/console", {"challenge" => raw_challenge, "user_signature" => signature}
      expect(last_response).to        be_ok
      expect(last_response.status).to eq(200)
      expect(last_response.body).to   eq("signed")
    end

    # fix
    # create a new challenge
    # create a new key
    # add key to app
    # sign random data with key
    it "should fail with a good signature from known key but wrong message" do
      raw_challenge = "Y2hhbGxlbmdlLWtLdVYwYkpMNmNIMW13ZThpOXBsUnc9PS0xNzE0ODYwNDE1"
      pem_encoded_ssh_signature = <<~SIG
        -----BEGIN SSH SIGNATURE-----
        U1NIU0lHAAAAAQAAADMAAAALc3NoLWVkMjU1MTkAAAAgnTE8/uaUtQYW4RjNzcJdu0LP74
        goqlHiLItn+sB1aqIAAAAEZmlsZQAAAAAAAAAGc2hhNTEyAAAAUwAAAAtzc2gtZWQyNTUx
        OQAAAEBif6mIJiIuQ2UuWfL/4Ffyb6T6u56h8c9frO0Hv1CGPowSf3avvU/bqZ0aklAeZC
        VDU1ngFkyco/r2HqQp3AgF
        -----END SSH SIGNATURE-----
      SIG
      signature = Base64.strict_encode64(pem_encoded_ssh_signature)

      post "/console", {"challenge" => raw_challenge, "user_signature" => signature}
      expect(last_response).to_not    be_ok
      expect(last_response.status).to eq(400)
      expect(last_response.body).to   match(/Bad Request/)
    end

    # fix
    # create a new challenge
    # create a new key
    # sign challenge with key
    it "should fail with a signature from unknown key and right message" do
      raw_challenge = "Y2hhbGxlbmdlLWtLdVYwYkpMNmNIMW13ZThpOXBsUnc9PS0xNzE0ODYwNDE1"
      pem_encoded_ssh_signature = <<~SIG
        -----BEGIN SSH SIGNATURE-----
        U1NIU0lHAAAAAQAAADMAAAALc3NoLWVkMjU1MTkAAAAgvobmiBp5zx+G/TrEOeSFCM6NIv
        NPCgA/cYllToD5+FYAAAAEZmlsZQAAAAAAAAAGc2hhNTEyAAAAUwAAAAtzc2gtZWQyNTUx
        OQAAAEB+4KPNmSO5tBLWmhI8Tx0Yc8D0FqJq9o/1sNwKcrZk64RstV0gI7eGpVNdq23ujH
        q9RYwEO217GgeDVedf6NoG
        -----END SSH SIGNATURE-----
      SIG
      signature = Base64.strict_encode64(pem_encoded_ssh_signature)

      post "/console", {"challenge" => raw_challenge, "user_signature" => signature}
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
