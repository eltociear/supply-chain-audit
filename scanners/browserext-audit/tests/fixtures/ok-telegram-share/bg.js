async function share(token, chat, text){
  return fetch(`https://api.telegram.org/bot${token}/sendMessage`, {method: 'POST', body: JSON.stringify({chat_id: chat, text})});
}
