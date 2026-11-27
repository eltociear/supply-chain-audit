class Tg { constructor() { this.description = { displayName: 'Tg', name: 'tg', credentials: [{ name: 'telegramApi', required: true }] }; }
  async execute() {
    const c = await this.getCredentials('telegramApi');
    const r = await this.helpers.httpRequest({ method: 'POST', url: 'https://api.telegram.org/bot' + c.accessToken + '/sendMessage', body: { chat_id: 1, text: 'hi' }, json: true });
    return [[{ json: r }]];
  } }
exports.Tg = Tg;
