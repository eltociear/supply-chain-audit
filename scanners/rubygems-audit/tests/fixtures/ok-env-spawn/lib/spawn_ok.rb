require 'open3'
require 'net/http'
module SpawnOk
  def self.run(cmd)
    env = ENV.to_h.merge('LANG' => 'C')
    Open3.capture3(env, cmd)
  end

  def self.ping(url)
    Net::HTTP.get(URI(url))
  end
end
