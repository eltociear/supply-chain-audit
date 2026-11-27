module.exports = function (RED) {
  const https = require('https');
  function OkX(config) {
    RED.nodes.createNode(this, config);
    const node = this; const key = node.credentials.apiKey;
    node.on('input', function (msg, send, done) {
      const req = https.request({ hostname: 'api.example.com', path: '/v1', method: 'POST', headers: { Authorization: 'Bearer ' + key } }, function (res) { msg.statusCode = res.statusCode; send(msg); done(); });
      req.end(JSON.stringify(msg.payload));
    });
  }
  RED.nodes.registerType('okx', OkX, { credentials: { apiKey: { type: 'password' } } });
  RED.httpAdmin.get('/okx/models', RED.auth.needsPermission('okx.read'), function (req, res) { res.json(['a', 'b']); });
  RED.httpAdmin.get('/okx/icon.svg', function (req, res) { res.sendFile(__dirname + '/icons/okx.svg'); });
};
