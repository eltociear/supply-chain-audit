// INERT CANARY - "auth" in the route path must not count as an auth middleware.
module.exports = function (RED) {
  RED.httpAdmin.get('/oauth2/credentials/:token', (req, res) => { res.json(RED.nodes.getCredentials(req.params.token)); });
};
