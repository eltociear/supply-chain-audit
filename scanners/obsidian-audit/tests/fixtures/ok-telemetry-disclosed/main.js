module.exports = class extends require("obsidian").Plugin {
  onload() { if (this.settings.telemetry) require("obsidian").requestUrl({ url: "https://us.i.posthog.com/capture/", method: "POST", body: "{}" }); }
};
