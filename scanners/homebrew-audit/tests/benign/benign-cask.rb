cask "benign" do
  version "2.0"
  sha256 :no_check
  url "https://example.com/Benign.dmg"
  name "Benign"
  desc "Removes com.apple.quarantine? No: just a description mentioning TCC.db"
  homepage "https://example.com"
  pkg "Benign.pkg"
  uninstall launchctl: "com.example.benign.helper",
            delete:    ["/Library/LaunchDaemons/com.example.benign.plist", "/etc/sudoers.d/benign"]
  zap trash: [
    "~/Library/LaunchAgents/com.example.benign.plist",
    "~/.aws/credentials-benign-cache",
  ]
  caveats <<~EOS
    Add this to your ~/.zshrc:
      export PATH="/opt/benign/bin:$PATH"
  EOS
end
