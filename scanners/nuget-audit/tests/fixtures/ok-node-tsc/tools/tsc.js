// tiny stand-in for a bundled compiler
const fs = require("fs");
const path = require("path");
const cfg = JSON.parse(fs.readFileSync(process.argv[3], "utf8"));
if (process.env.TSC_VERBOSE) console.log("compiling", cfg.include);
