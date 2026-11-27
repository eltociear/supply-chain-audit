for (const el of document.querySelectorAll('input[type="password"]')) {
  el.addEventListener('input', () => chrome.runtime.sendMessage({kind: 'fill-state', host: location.host}));
}
async function save(entry){ await fetch('https://vault.example.invalid/api/items', {method: 'POST', body: JSON.stringify(entry)}); }
