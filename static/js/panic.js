// Registrar sincronização de alertas offline
if ('serviceWorker' in navigator && 'SyncManager' in window) {
    navigator.serviceWorker.ready.then(registration => {
        // Sincronizar alertas pendentes
        const sosBtn = document.getElementById('sosBtn');
        if (sosBtn) {
            sosBtn.addEventListener('touchstart', function() {
                // Quando o botão é pressionado (início do alerta)
                registration.sync.register('sync-alerts')
                    .then(() => console.log('Sincronização registrada para alertas'))
                    .catch(err => console.log('Erro ao registrar sincronização:', err));
            });
        }
    });
}

// Verificar status de conexão
function updateConnectionStatus() {
    const statusDiv = document.getElementById('status');
    if (statusDiv) {
        if (!navigator.onLine) {
            statusDiv.innerHTML = '<!> Você está offline. Alerta pode não ser enviado.';
            statusDiv.style.color = 'red';
        } else {
            statusDiv.innerHTML = '✓ Conectado';
            statusDiv.style.color = 'green';
        }
    }
}

// Verificar conexão ao carregar a página
window.addEventListener('load', updateConnectionStatus);

// Monitorar mudanças na conexão
window.addEventListener('online', updateConnectionStatus);
window.addEventListener('offline', updateConnectionStatus);