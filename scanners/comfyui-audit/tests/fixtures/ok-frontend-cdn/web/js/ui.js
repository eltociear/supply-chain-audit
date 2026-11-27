import { app } from '../../scripts/app.js';
const s = document.createElement('script');
s.src = 'https://cdn.jsdelivr.net/npm/marked/marked.min.js';
document.head.appendChild(s);
const key = localStorage.getItem('my.node.setting');
fetch('/my_node/config', {method: 'POST', body: key});
