# frozen_string_literal: true

RSpec.describe "Kekse service" do
  include Rack::Test::Methods

  it "should succeed on /hello GET request" do
    get "/hello"
    expect(last_response).to be_ok
    expect(last_response.body).to eq("hello")
  end

  it "should fail on /not-found GET request" do
    get "/not-found"
    expect(last_response).to_not be_ok
    expect(last_response.status).to eq(404)
    expect(last_response.body).to match(/not-found/)
  end
end
