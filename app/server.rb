# frozen_string_literal: true

require "sinatra"
require "aws-sdk-sts"
require "cgi"
require "open-uri"

require_relative "helpers"

# set :known_keys, %w[ZDtwx65wb2PwVnZfHjIIS9TbtmDw+yg+YJ+Kqzfwf2w]
set :known_keys, %w[]

before do
  reject if unauthorized?
end

get "/hello" do
  erb :hello
end

get "/role" do
  "protected"
end

get "/console" do
  # binding.irb
  erb :console, locals: {challenge: console_challenge.to_s}
end

post "/console" do
  challenge     = request.params["challenge"]
  raw_signature = request.params["user_signature"]
  ssh_signature = console_access_signature(challenge, raw_signature)
  public_key    = ssh_signature.public_key

  reject_with :bad_request if ssh_signature.invalid? || unknown?(public_key)
  "signed"
  # sts = Aws::STS::Client.new
  # sts.get_caller_identity
  # sts.config.region # => "eu-west-1"

# https://rb.gy/es157n
#   access = federated_access_aws_console
#   if access.successful? # redirect and send
#     notify access.login_url # redirect and send
#   else
#     # reject_with :bad_request if access.something?
#     # reject_with :something if access.something?
#     "error"
#   end
#   
#   # "signed"
#   ENV.to_h.to_s
#   # sts = Aws::STS::Client.new
#   # response = sts.get_caller_identity
#   # response.to_s
# 
#   issuer_url = "http://localhost:9292/console"
#   console_url = "https://console.aws.amazon.com/ec2"
#   signin_url = "https://signin.aws.amazon.com/federation"
# 
#   session_json = {
#     :sessionId => ENV["AWS_ACCESS_KEY_ID"],
#     :sessionKey => ENV["AWS_SECRET_ACCESS_KEY"],
#     :sessionToken => ENV["AWS_SESSION_TOKEN"],
#   }.to_json
# 
#   get_signin_token_url = signin_url + 
#                        "?Action=getSigninToken" + 
#                        "&SessionType=json&Session=" + 
#                        CGI.escape(session_json)
# 
#   returned_content = URI.parse(get_signin_token_url).read
#   puts returned_content
# 
#   signin_token = JSON.parse(returned_content)['SigninToken']
#   signin_token_param = "&SigninToken=" + CGI.escape(signin_token)
# 
#   issuer_param = "&Issuer=" + CGI.escape(issuer_url)
#   destination_param = "&Destination=" + CGI.escape(console_url)
#   login_url = signin_url + "?Action=login" + signin_token_param + issuer_param + destination_param
# 
#   puts login_url
#   # redirect login_url
#   "redirect"

# {"SigninToken":"mgabuTQqCQi9oeMcdW3gP7AojgUJCETxSStLvlMu88Rx3YXmkFUL4nIe-tdAq142117plJUkeMJ8aQRBH64TAE1b5nPAyL7p0yEPKUL3QZeDYCpFndigZgh_B4wvIOih0Pu4htDd_uSyRQvjVeSsPGTqg3-PRgAjnAVnXylF1b1zEcE_FFUerQYLCQIP3uID2b8EVW1DCFF9zvbFI3qTDnleUZjmnuX7fLtlAe-TULlxlqFaPKb8bZ9GTpme6bFjiK2KXVWIECMJQrm3Izc3E9kgq8FkBgx6DmjVvZT8_Golv3GMBDDqTSvpCD5kV7X06XFQtqeO5j5SoLtkRzAiVZnb-UKh1xkYC8s6hZJfkRWF5V71fqGSCnE7kbcN6LSaaqvUMT_j1FaAoD9URlmgWSi9FiWx_KI0vFfUuRvGo5laX1FMCwZZDp_GeGMi6Lfgs24RcT5WYube8oMl45QPFMBxdtqip6PIciF0I1f-JwmjWaZX52XZnK7ZXnLkQdxNsxJVLaf9WmrYfKl0Dvei5AF8zWRMuX6emcHJm8FsI4rUeD_i577d-1StgMfJj0CbPko8iNxp0XsAnrOu73ElSsM0rzgoefhNQRCvhkUo-mhz1JYLx_UfFlpaHr-rmjbD7fH14xCL-vmMbBeaNQej1w2y-DydKQa4w9ohWXB59UN4Hoi1dotOrJmGNmhOY8sZ-shvkP3sG5wp1jVmPMPWybzt-_5ZpNeTlx1WQUIhFbyv9Shtlyw_KLdbNqK9nEtcsURUnI0G4gtXll4me3lM4c5Qt94dcSWYM671laivM6dWJcsepCZby5HkOM7tjPSmQt7OpIeMSnwO6kaP9YyLrywQIO42KJkCAwNi0feFpd7BSD0sdNg_NsGgRVNs6Lo3PTjTF6qQTpd_kXudy4hvsM4q-0CxTng4TetoJ7f8j6pVi5WnSVS1QZQSZB1OY2Y5ZypPNY9vPmvBJa-qOLXVJGOHOuGm8wF_GPD1KT5d0XICB-4xQZKejw5pbOiciu9X9e_-2oarC9-7hrOBWd9F_OvP6PprRpEpLIbUsb7A257F8AAKKuJFq5am3-pp5Gly-xQnmUAy098hJu48qrsDKNjsuWh4v7fJrY7P1Bx8C0Ougmqq26FfVRcwhCrYXMFXI5cK_BtEyo3w_aPE5M9XRL-mv_metK0_52Qyy_7NJyC9Yrtx0KffrQTnUNKMVUWWpuQUsyI3CoRkXf4TIe_gf-Uxa_vggG-Y4VG-777uFVHrZRlk3ztfazkzfwy1hyIStgO9Z8rfoLtupiDoom0e9fwoydPwGvplXhiI3cP67MPwNy65z29Shbt-WtLfosC-3Qeb51qNBsufJ9HGHz_ZCWuaRnQJph02I4_LnRuCIgXh6sFQRnH385FkfTBVGmDQ5dYfx8h-yQQc5_hS_OXJSjuVWNRxlzDTaOwOGgvgZIBvN8b4QuMGWbTJfQwU4YMALx_E8JGQjslAvNf1KflVT0_vvSTcJ--lGrSTN9VQ87z9mGNNSS1nJq7vhfd8xe0KXQ"}

# https://signin.aws.amazon.com/federation?Action=login&SigninToken=mgabuTQqCQi9oeMcdW3gP7AojgUJCETxSStLvlMu88Rx3YXmkFUL4nIe-tdAq142117plJUkeMJ8aQRBH64TAE1b5nPAyL7p0yEPKUL3QZeDYCpFndigZgh_B4wvIOih0Pu4htDd_uSyRQvjVeSsPGTqg3-PRgAjnAVnXylF1b1zEcE_FFUerQYLCQIP3uID2b8EVW1DCFF9zvbFI3qTDnleUZjmnuX7fLtlAe-TULlxlqFaPKb8bZ9GTpme6bFjiK2KXVWIECMJQrm3Izc3E9kgq8FkBgx6DmjVvZT8_Golv3GMBDDqTSvpCD5kV7X06XFQtqeO5j5SoLtkRzAiVZnb-UKh1xkYC8s6hZJfkRWF5V71fqGSCnE7kbcN6LSaaqvUMT_j1FaAoD9URlmgWSi9FiWx_KI0vFfUuRvGo5laX1FMCwZZDp_GeGMi6Lfgs24RcT5WYube8oMl45QPFMBxdtqip6PIciF0I1f-JwmjWaZX52XZnK7ZXnLkQdxNsxJVLaf9WmrYfKl0Dvei5AF8zWRMuX6emcHJm8FsI4rUeD_i577d-1StgMfJj0CbPko8iNxp0XsAnrOu73ElSsM0rzgoefhNQRCvhkUo-mhz1JYLx_UfFlpaHr-rmjbD7fH14xCL-vmMbBeaNQej1w2y-DydKQa4w9ohWXB59UN4Hoi1dotOrJmGNmhOY8sZ-shvkP3sG5wp1jVmPMPWybzt-_5ZpNeTlx1WQUIhFbyv9Shtlyw_KLdbNqK9nEtcsURUnI0G4gtXll4me3lM4c5Qt94dcSWYM671laivM6dWJcsepCZby5HkOM7tjPSmQt7OpIeMSnwO6kaP9YyLrywQIO42KJkCAwNi0feFpd7BSD0sdNg_NsGgRVNs6Lo3PTjTF6qQTpd_kXudy4hvsM4q-0CxTng4TetoJ7f8j6pVi5WnSVS1QZQSZB1OY2Y5ZypPNY9vPmvBJa-qOLXVJGOHOuGm8wF_GPD1KT5d0XICB-4xQZKejw5pbOiciu9X9e_-2oarC9-7hrOBWd9F_OvP6PprRpEpLIbUsb7A257F8AAKKuJFq5am3-pp5Gly-xQnmUAy098hJu48qrsDKNjsuWh4v7fJrY7P1Bx8C0Ougmqq26FfVRcwhCrYXMFXI5cK_BtEyo3w_aPE5M9XRL-mv_metK0_52Qyy_7NJyC9Yrtx0KffrQTnUNKMVUWWpuQUsyI3CoRkXf4TIe_gf-Uxa_vggG-Y4VG-777uFVHrZRlk3ztfazkzfwy1hyIStgO9Z8rfoLtupiDoom0e9fwoydPwGvplXhiI3cP67MPwNy65z29Shbt-WtLfosC-3Qeb51qNBsufJ9HGHz_ZCWuaRnQJph02I4_LnRuCIgXh6sFQRnH385FkfTBVGmDQ5dYfx8h-yQQc5_hS_OXJSjuVWNRxlzDTaOwOGgvgZIBvN8b4QuMGWbTJfQwU4YMALx_E8JGQjslAvNf1KflVT0_vvSTcJ--lGrSTN9VQ87z9mGNNSS1nJq7vhfd8xe0KXQ&Issuer=http%3A%2F%2Flocalhost%3A9292%2Fconsole&Destination=https%3A%2F%2Fconsole.aws.amazon.com%2Fsns

  # result = federate
  # reject_with :bad_request if !result.ok?
  # redirect federate.url
  #   "signed"
  #   # once we know the message is signed:
  #   # generate a random 256 bits value (or 512)
  #   # fetch credentials and store them in a key with the random value
  #   # send url with the random value to a sns topic
  #   # if link clicked, redirect to console
end
