#!/usr/bin/env node
const { spawnSync } = require('child_process');
const env = { ...process.env, FORCE_COLOR: '1' };
spawnSync(process.argv[2], process.argv.slice(3), { stdio: 'inherit', env });
console.log(JSON.stringify(process.env.PATH));
