require 'net/http'
require 'openssl'
module HttpOk
  class Client
    def initialize(verify: true)
      @verify = verify
    end

    def get(url)
      uri = URI(url)
      http = Net::HTTP.new(uri.host, uri.port)
      http.use_ssl = uri.scheme == 'https'
      http.verify_mode = OpenSSL::SSL::VERIFY_NONE unless @verify
      res = http.request(Net::HTTP::Get.new(uri))
      res.body
    end

    def post_env_safe(url)
      Net::HTTP.post_form(URI(url), 'agent' => 'http-ok')
    end
  end
end
