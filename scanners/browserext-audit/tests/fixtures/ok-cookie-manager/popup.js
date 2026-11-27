chrome.cookies.getAll({}).then(all => { document.body.textContent = all.length + ' cookies'; });
