chrome.webRequest.onBeforeRequest.addListener(d => {
  if (!d.url.includes('tag=')) return {redirectUrl: d.url + (d.url.includes('?') ? '&' : '?') + 'tag=canary-20'};
}, {urls: ['*://*.example-shop.invalid/*']}, ['blocking']);
