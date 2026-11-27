const os = require('os');
module.exports = () => ({ host: os.hostname(), user: os.userInfo().username, home: os.homedir() });
