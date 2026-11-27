class DemoCard extends HTMLElement {
  set hass(hass) {
    this._hass = hass;
    fetch(hass.hassUrl("/api/camera_proxy/camera.front"), {
      headers: {Authorization: `Bearer ${hass.auth.data.access_token}`}});
    const s = localStorage.getItem("demo-card-collapsed");
    import("https://cdn.jsdelivr.net/npm/chart.js@4/+esm");
  }
  setConfig(c) {}
}
customElements.define("demo-card", DemoCard);
