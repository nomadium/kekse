require "net/http"
require "time"
require "base64"
require "linzer"

headers = {"x-foo" => "bar", "date" => Time.now.to_s, "user-agent" => "Ruby"}
metadata = {"method" => "GET", "host" => "localhost:9292", "path" => "/test"}

message = Linzer::Message.new(headers: headers, http: metadata)
fields = %w[x-foo date user-agent @method]

key_material = "9JUDPGznyXtu5boxSosE//gIwt9oGozFA5f7lgjMU6Q="
key = Linzer.new_ed25519_key(Base64.strict_decode64(key_material))

signature = Linzer.sign(key, message, fields)

http = Net::HTTP.new("localhost", 9292)
http.set_debug_output($stderr)
response = http.get("/test2", headers.merge(signature.to_h))
p response.inspect
