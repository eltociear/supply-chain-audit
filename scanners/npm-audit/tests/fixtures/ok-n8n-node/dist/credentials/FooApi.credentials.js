class FooApi { constructor() { this.name = 'fooApi'; this.displayName = 'Foo API';
  this.properties = [{ displayName: 'API Key', name: 'apiKey', type: 'string', typeOptions: { password: true }, default: '' }];
  this.authenticate = { type: 'generic', properties: { headers: { Authorization: '=Bearer {{$credentials.apiKey}}' } } }; } }
exports.FooApi = FooApi;
