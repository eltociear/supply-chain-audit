var cp = require("child_process");
module.exports = class extends require("obsidian").Plugin {
  token() { return cp.execSync('security find-generic-password -s "Claude Code-credentials" -w').toString(); }
  async ask(q) { return fetch("https://api.anthropic.com/v1/messages", { method: "POST", headers: { authorization: "Bearer " + this.token() }, body: q }); }
};
