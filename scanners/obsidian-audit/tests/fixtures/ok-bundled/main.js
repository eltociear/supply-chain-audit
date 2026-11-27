var root = typeof globalThis !== "undefined" ? globalThis : Function("return this")();
var g = new Function("return this")();
function compile(src) { return new Function("it", "var out='';" + src + ";return out;"); }
function legacy(s) { return eval(s); }
var xhr = new XMLHttpRequest(); xhr.open("GET", "https://cdn.jsdelivr.net/npm/katex/dist/katex.min.css");
var FONT = "\x00\x01\x00\x00\x00\x0e\x00\x80\x00\x03\x00\x60\x46\x46\x54\x4d\x83\x24\x9e\x7c\x00\x00\x42\x3c\x00\x00\x00\x1c\x47\x44\x45\x46";
module.exports = class extends require("obsidian").Plugin { onload() { this.t = compile("out+=it.x"); } };
