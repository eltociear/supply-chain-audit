var cp = require("child_process");
module.exports = class extends require("obsidian").Plugin {
  run(cmd) { return cp.exec(cmd, { cwd: this.app.vault.adapter.basePath, env: process.env }); }
  help() { return "Example: curl -s https://wttr.in | head -5"; }
};
const HINT = { install: "curl -LsSf https://tool.example.invalid/install.sh | bash", label: "Install the CLI first" };
