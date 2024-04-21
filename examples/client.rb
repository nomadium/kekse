require "net/http"
require "time"
require "base64"
require "linzer"

debug = true

headers = {"x-foo" => "bar",
           "date" => Time.now.to_s,
           "user-agent" => "Ruby",
           "host" => "localhost:9292"}

request = Linzer.new_request(:get, "/role", {}, headers)
message = Linzer::Message.new(request)
fields = %w[x-foo date user-agent @method]

key_material = "9JUDPGznyXtu5boxSosE//gIwt9oGozFA5f7lgjMU6Q="
key = Linzer.new_ed25519_key(Base64.strict_decode64(key_material))

signature = Linzer.sign(key, message, fields)

http = Net::HTTP.new(request.host, request.port)
http.set_debug_output($stderr) if debug
response = http.get(request.path_info, headers.merge(signature.to_h))
p response.inspect
