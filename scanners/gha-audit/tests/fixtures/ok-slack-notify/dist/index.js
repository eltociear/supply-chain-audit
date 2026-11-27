const core = require('@actions/core');
// default: https://hooks.slack.com/services/...
const url = core.getInput('webhook-url');
if (!url.startsWith('https://hooks.slack.com/services/')) core.warning('unexpected url');
fetch(url, { method: 'POST', body: JSON.stringify({ text: process.env.GITHUB_REPOSITORY }) });
