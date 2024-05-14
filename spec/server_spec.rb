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

    it "should succeed with a good signature from known key" do
      key = SSHData::PrivateKey::ED25519.generate
      iam_client = Kekse::Aws.iam_stub_client
      sts_client = Kekse::Aws.sts_stub_client

      app.settings.known_keys << key.public_key.fingerprint
      roles = [
        Aws::IAM::Types::Role.new(path: "/", role_name: "Admin"),
        Aws::IAM::Types::Role.new(path: "/", role_name: "ReadOnly")
      ]
      stubbed_list_roles = Aws::IAM::Types::ListRolesResponse.new(roles: roles)
      iam_client.stub_responses(:list_roles, stubbed_list_roles)
      app.settings.iam = iam_client

      dummy_account = "001122334455"
      stubbed_caller_identity =
        Aws::STS::Types::GetCallerIdentityResponse.new(account: dummy_account)
      sts_client.stub_responses(:get_caller_identity, stubbed_caller_identity)
      app.settings.sts = sts_client

      challenge = Kekse::Challenge.new
      signature = Kekse::Utils.openssh_signature(key, challenge.to_s)

      params = {
        "challenge"      => challenge.to_s,
        "user_signature" => Base64.strict_encode64(signature.to_pem)
      }

      post "/console", params
      expect(last_response).to        be_ok
      expect(last_response.status).to eq(200)
      expect(last_response.body).to   match(/Roles/)
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

    it "should fail when dependencies are not available" do
      key = SSHData::PrivateKey::ED25519.generate
      iam_client = Kekse::Aws.iam_stub_client
      sts_client = Kekse::Aws.sts_stub_client

      app.settings.known_keys << key.public_key.fingerprint

      access_denied_error = Aws::IAM::Errors::AccessDenied.new(nil, "foo")
      network_error = Seahorse::Client::NetworkingError.new(Net::ReadTimeout.new)
      errors = [access_denied_error, network_error]
      iam_client.stub_responses(:list_roles, errors.sample)

      app.settings.iam = iam_client

      dummy_account = "001122334455"
      stubbed_caller_identity =
        Aws::STS::Types::GetCallerIdentityResponse.new(account: dummy_account)
      sts_client.stub_responses(:get_caller_identity, stubbed_caller_identity)
      app.settings.sts = sts_client

      challenge = Kekse::Challenge.new
      signature = Kekse::Utils.openssh_signature(key, challenge.to_s)

      params = {
        "challenge"      => challenge.to_s,
        "user_signature" => Base64.strict_encode64(signature.to_pem)
      }

      post "/console", params
      expect(last_response).to_not    be_ok
      expect(last_response.status).to eq(500)
      expect(last_response.body).to   match(/Internal Server Error/)
    end
  end

  context "requesting role data for federated console access" do
    it "should fail when no signature is given" do
      get "/console/role/foobar", {}
      expect(last_response).to_not    be_ok
      expect(last_response.status).to eq(400)
      expect(last_response.body).to   match(/Bad Request/)
    end

    it "should fail when signature is not found" do
      signature = Digest::SHA512.hexdigest("whatever")
      get "/console/role/foobar", {"signature" => signature}
      expect(last_response).to_not    be_ok
      expect(last_response.status).to eq(400)
      expect(last_response.body).to   match(/Bad Request/)
    end

    it "should fail if no signature but an invalid parameter is given" do
      get "/console/role/app", {"invalid" => "42"}
      expect(last_response).to_not    be_ok
      expect(last_response.status).to eq(400)
      expect(last_response.body).to   match(/Bad Request/)
    end

    it "should fail if extraneous parameter is given" do
      signature = Digest::SHA512.hexdigest("whatever")
      get "/console/role/admin", {"signature" => signature, "invalid" => "42"}
      expect(last_response).to_not    be_ok
      expect(last_response.status).to eq(400)
      expect(last_response.body).to   match(/Bad Request/)
    end

    it "should fail if bad signature is given" do
      bad_signature = "crap"
      get "/console/role/admin", {"signature" => bad_signature}
      expect(last_response).to_not    be_ok
      expect(last_response.status).to eq(400)
      expect(last_response.body).to   match(/Bad Request/)
    end

    # iam error => error 500
    # iam role not found => error 400
    # valid signature and found role => 200 (role data and button for post form)
    # #<struct Aws::IAM::Types::Role path=\"/\", role_name=\"AdminRole-AdminRole-19H8ZDODHGVK4\", role_id=\"AROATE7TPVQLIJNBB7O7S\", arn=\"arn:aws:iam::216869612566:role/AdminRole-AdminRole-19H8ZDODHGVK4\", create_date=2020-07-13 17:39:35 UTC, assume_role_policy_document=\"%7B%22Version%22%3A%222012-10-17%22%2C%22Statement%22%3A%5B%7B%22Effect%22%3A%22Allow%22%2C%22Principal%22%3A%7B%22AWS%22%3A%22arn%3Aaws%3Aiam%3A%3A216869612566%3Aroot%22%7D%2C%22Action%22%3A%22sts%3AAssumeRole%22%7D%5D%7D\", description=\"\", max_session_duration=3600, permissions_boundary=nil, tags=[], role_last_used=#<struct Aws::IAM::Types::RoleLastUsed last_used_date=2024-05-11 23:13:18 UTC, region=\"eu-west-1\">>"
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
