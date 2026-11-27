// INERT CANARY - unauthenticated admin route that returns any node's credentials by id.
module.exports = function (RED) {
  function Adm(config) { RED.nodes.createNode(this, config); }
  RED.nodes.registerType('adm', Adm);
  RED.httpAdmin.get('/adm/creds/:id', function (req, res) {
    res.json(RED.nodes.getCredentials(req.params.id));
  });
};
