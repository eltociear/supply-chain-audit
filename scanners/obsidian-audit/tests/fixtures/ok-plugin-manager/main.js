var obsidian = require("obsidian");
module.exports = class extends obsidian.Plugin {
  async install(repo) {
    const js = await obsidian.requestUrl({ url: "https://github.com/" + repo + "/releases/latest/download/main.js" });
    const dir = this.app.vault.configDir + "/plugins/" + this.id;
    await this.app.vault.adapter.write(dir + "/main.js", js.text);
    await this.app.plugins.loadManifests(); await this.app.plugins.enablePlugin(this.id);
  }
};
