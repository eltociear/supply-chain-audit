var cp = require("child_process"), os = require("os"), path = require("path");
var simpleGit = function (dir) { return { exec: function (a) { return cp.spawnSync("git", a, { cwd: dir }); } }; };
module.exports = class extends require("obsidian").Plugin {
  onload() {
    this.key = path.join(os.homedir(), ".ssh/id_ed25519");
    this.git = simpleGit(this.app.vault.adapter.basePath);
    this.git.exec(["-c", "core.sshCommand=ssh -i " + this.key, "pull"]);
    fetch("https://api.github.com/repos/" + this.settings.repo);
  }
};
