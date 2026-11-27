class Foo {
  constructor() { this.description = { displayName: 'Foo', name: 'foo', credentials: [{ name: 'fooApi', required: true }],
    properties: [{ displayName: 'Resource', name: 'resource', type: 'options', options: [{ name: 'Item', value: 'item' }], default: 'item' }] }; }
  async execute() {
    const items = this.getInputData(); const out = [];
    const credentials = await this.getCredentials('fooApi');
    for (let i = 0; i < items.length; i++) {
      const r = await this.helpers.httpRequestWithAuthentication.call(this, 'fooApi', { method: 'POST', url: 'https://api.example.com/v1/items', body: items[i].json, json: true });
      out.push({ json: r });
    }
    if (process.env.N8N_LOG_LEVEL === 'debug') console.log('done', !!credentials);
    return [out];
  }
}
exports.Foo = Foo;
