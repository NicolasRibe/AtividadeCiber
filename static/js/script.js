document.addEventListener('DOMContentLoaded', () => {
  const btn = document.getElementById('btnFetchItems');
  if (btn) {
    btn.addEventListener('click', async () => {
      try {
        const resp = await fetch('/api/items', {
          headers: { 'Accept': 'application/json', 'X-CSRF-Token': window.CSRF_TOKEN }
        });
        if (!resp.ok) throw new Error('Erro na requisição: ' + resp.status);
        const data = await resp.json();
        document.getElementById('apiResult').textContent = JSON.stringify(data, null, 2);
      } catch (err) {
        document.getElementById('apiResult').textContent = 'Erro: ' + err.message;
      }
    });
  }
});
