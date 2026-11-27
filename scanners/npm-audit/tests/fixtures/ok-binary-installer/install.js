const https = require('https'), fs = require('fs'), { execSync } = require('child_process');
const url = 'https://registry.npmjs.org/@acme/bin-' + process.platform + '/-/bin-1.0.0.tgz';
https.get(url, res => { const f = fs.createWriteStream('bin.tgz'); res.pipe(f); f.on('finish', () => { execSync('tar xzf bin.tgz'); fs.chmodSync('bin/tool', 0o755); }); });
