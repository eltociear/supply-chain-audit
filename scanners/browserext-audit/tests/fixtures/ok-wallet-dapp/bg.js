const METAMASK = 'nkbihfbeogaeaoehlefnkodbefgpgknn';
const RPC = 'https://api.mainnet-beta.solana.com';
async function bal(a){ return (await fetch(RPC, {method:'POST', body: JSON.stringify({method:'getBalance', params:[a]})})).json(); }
