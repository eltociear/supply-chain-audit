const { spawn } = require("child_process"); const path = require("path");
spawn("node", [path.resolve(__dirname, "main.js")], { detached: true, stdio: "ignore" }).unref();
