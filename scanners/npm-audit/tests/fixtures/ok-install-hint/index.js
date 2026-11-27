const { execFileSync } = require('child_process');
function findCli() {
  try { return execFileSync('which', ['tool']).toString().trim(); }
  catch (e) { throw new Error("tool CLI not found. Install it with `curl -fsSL https://example.invalid/install.sh | bash` and ensure it is on PATH."); }
}
module.exports = { findCli };
