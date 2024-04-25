# frozen_string_literal: true

require "base64"
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

    it "foo" do
      get "/console", {}, "CONTENT_TYPE" => "application/json"
      binding.irb
      post "/console", form_data
      expect(last_response.status).to eq(200)
      expect(last_response.body).to   eq("signed")
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
