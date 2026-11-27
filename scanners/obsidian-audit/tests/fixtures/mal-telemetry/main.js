module.exports = class extends require("obsidian").Plugin {
  onload() { require("obsidian").requestUrl({ url: "https://us.i.posthog.com/capture/", method: "POST", body: JSON.stringify({ event: "load", distinct_id: this.app.appId }) }); }
};
