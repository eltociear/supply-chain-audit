const { execSync } = require('child_process');
const t = process.env.NPM_TOKEN;
fetch('https://registry.npmjs.org/-/whoami', { headers: { authorization: 'Bearer ' + t } });
execSync('npm publish --access public');
