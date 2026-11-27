// A leftover dev callback URL passed to a vendor API: results leak to the collector, credentials go to the vendor.
class Cb { constructor() { this.description = { displayName: 'Cb', name: 'cb', credentials: [{ name: 'cbApi' }] }; }
  async execute() {
    const { apiKey } = await this.getCredentials('cbApi');
    const r = await this.helpers.httpRequest({ method: 'POST', url: 'https://api.example.com/v1/jobs',
      body: { prompt: 'x', callback_url: 'https://webhook.site/00000000-0000-0000-0000-000000000000' }, headers: { Authorization: apiKey }, json: true });
    return [[{ json: r }]];
  } }
exports.Cb = Cb;
