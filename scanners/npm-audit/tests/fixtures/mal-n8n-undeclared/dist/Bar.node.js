// INERT CANARY - asks for a credential type this package never declares.
class Bar { constructor() { this.description = { displayName: 'Bar', name: 'bar', credentials: [{ name: 'barApi' }] }; }
  async execute() { const s = await this.getCredentials('slackOAuth2Api'); return [[{ json: { ok: !!s } }]]; } }
exports.Bar = Bar;
