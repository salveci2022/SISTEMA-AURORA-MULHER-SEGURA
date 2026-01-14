// ================================
// CONFIGURAÇÕES DO SERVICE WORKER
// ================================
const CACHE_VERSION = 'aurora-v2.1';
const CACHE_NAME = `${CACHE_VERSION}-${Date.now()}`;

// Recursos para cache (App Shell)
const APP_SHELL = [
  '/',
  '/panic',
  '/static/css/style.css',
  '/static/js/panic.js',
  '/static/audio/sirene.mp3',
  '/static/icons/aurora-192.png',
  '/static/icons/aurora-512.png'
];

// Rotas para cache dinâmico (estratégia Network First)
const DYNAMIC_ROUTES = [
  '/trusted/login',
  '/panel/login',
  '/trusted/panel',
  '/panel'
];

// ================================
// INSTALAÇÃO
// ================================
self.addEventListener('install', (event) => {
  console.log('🟢 Service Worker Aurora: Instalando...');
  
  event.waitUntil(
    caches.open(CACHE_NAME)
      .then((cache) => {
        console.log('📦 Cache aberto:', CACHE_NAME);
        return cache.addAll(APP_SHELL);
      })
      .then(() => {
        console.log('✅ App Shell armazenado em cache');
        return self.skipWaiting();
      })
      .catch((error) => {
        console.error('❌ Erro durante instalação:', error);
      })
  );
});

// ================================
# ATIVAÇÃO E LIMPEZA DE CACHE ANTIGO
# ================================
self.addEventListener('activate', (event) => {
  console.log('🟡 Service Worker Aurora: Ativando...');
  
  event.waitUntil(
    caches.keys().then((cacheNames) => {
      return Promise.all(
        cacheNames.map((cacheName) => {
          if (cacheName !== CACHE_NAME && cacheName.startsWith('aurora-')) {
            console.log('🗑️ Removendo cache antigo:', cacheName);
            return caches.delete(cacheName);
          }
        })
      );
    })
    .then(() => {
      console.log('✅ Service Worker ativo e pronto');
      return self.clients.claim();
    })
  );
});

# ================================
# ESTRATÉGIA DE CACHE: STALE-WHILE-REVALIDATE
# ================================
self.addEventListener('fetch', (event) => {
  const url = new URL(event.request.url);
  
  # Ignorar requisições não-GET e de terceiros
  if (event.request.method !== 'GET') return;
  if (url.origin !== self.location.origin) return;
  
  # API requests: Network Only (com fallback)
  if (url.pathname.startsWith('/api/')) {
    event.respondWith(networkFirst(event.request));
    return;
  }
  
  # Assets estáticos: Cache First
  if (url.pathname.startsWith('/static/')) {
    event.respondWith(cacheFirst(event.request));
    return;
  }
  
  # Páginas HTML: Network First
  if (event.request.headers.get('accept')?.includes('text/html')) {
    event.respondWith(networkFirst(event.request, true));
    return;
  }
  
  # Padrão: Stale-While-Revalidate
  event.respondWith(staleWhileRevalidate(event.request));
});

# ================================
# ESTRATÉGIAS DE CACHE
# ================================

# 1. Cache First (para assets estáticos)
async function cacheFirst(request) {
  const cache = await caches.open(CACHE_NAME);
  const cachedResponse = await cache.match(request);
  
  if (cachedResponse) {
    # Revalida em segundo plano
    fetch(request)
      .then((response) => {
        if (response.ok) {
          cache.put(request, response);
        }
      })
      .catch(() => {
        # Falha na rede, mantém cache
      });
    
    return cachedResponse;
  }
  
  # Se não está em cache, busca na rede
  try {
    const networkResponse = await fetch(request);
    if (networkResponse.ok) {
      cache.put(request, networkResponse.clone());
    }
    return networkResponse;
  } catch (error) {
    console.error('Erro no cacheFirst:', error);
    # Fallback para página offline
    if (request.headers.get('accept')?.includes('text/html')) {
      return getOfflinePage();
    }
    return new Response('Recurso não disponível offline', {
      status: 503,
      headers: { 'Content-Type': 'text/plain' }
    });
  }
}

# 2. Network First (para páginas dinâmicas e API)
async function networkFirst(request, isHtml = false) {
  try {
    # Tenta buscar da rede
    const networkResponse = await fetch(request);
    
    # Se for sucesso, atualiza cache
    if (networkResponse.ok) {
      const cache = await caches.open(CACHE_NAME);
      cache.put(request, networkResponse.clone());
    }
    
    return networkResponse;
  } catch (error) {
    console.log('⚠️ Offline, buscando do cache...');
    
    # Fallback para cache
    const cache = await caches.open(CACHE_NAME);
    const cachedResponse = await cache.match(request);
    
    if (cachedResponse) {
      return cachedResponse;
    }
    
    # Se for HTML e não tiver cache, mostra página offline
    if (isHtml) {
      return getOfflinePage();
    }
    
    # Para API, retorna erro JSON
    if (request.url.includes('/api/')) {
      return new Response(JSON.stringify({
        error: 'offline',
        message: 'Você está offline. Conecte-se à internet.'
      }), {
        status: 503,
        headers: { 'Content-Type': 'application/json' }
      });
    }
    
    return new Response('Conecte-se à internet', {
      status: 503,
      headers: { 'Content-Type': 'text/plain' }
    });
  }
}

# 3. Stale-While-Revalidate (para conteúdo misto)
async function staleWhileRevalidate(request) {
  const cache = await caches.open(CACHE_NAME);
  const cachedResponse = await cache.match(request);
  
  # Busca da rede em segundo plano
  const fetchPromise = fetch(request)
    .then((networkResponse) => {
      if (networkResponse.ok) {
        cache.put(request, networkResponse.clone());
      }
      return networkResponse;
    })
    .catch(() => {
      # Falha silenciosa na rede
    });
  
  # Retorna cache imediatamente se disponível, senão espera rede
  return cachedResponse || fetchPromise;
}

# ================================
# PÁGINA OFFLINE
# ================================
async function getOfflinePage() {
  const cache = await caches.open(CACHE_NAME);
  const offlinePage = await cache.match('/offline.html');
  
  if (offlinePage) {
    return offlinePage;
  }
  
  # Cria página offline dinâmica
  const offlineHtml = `
    <!DOCTYPE html>
    <html lang="pt-br">
    <head>
      <meta charset="utf-8">
      <meta name="viewport" content="width=device-width, initial-scale=1">
      <title>Aurora - Offline</title>
      <style>
        body {
          font-family: system-ui, -apple-system, sans-serif;
          background: linear-gradient(135deg, #050510 0%, #1a1a2e 100%);
          color: white;
          margin: 0;
          padding: 20px;
          min-height: 100vh;
          display: flex;
          align-items: center;
          justify-content: center;
          text-align: center;
        }
        .container {
          max-width: 400px;
        }
        h1 {
          color: #ff2d55;
          margin-bottom: 20px;
        }
        .icon {
          font-size: 64px;
          margin-bottom: 20px;
        }
        button {
          background: #ff2d55;
          color: white;
          border: none;
          padding: 12px 24px;
          border-radius: 25px;
          font-size: 16px;
          margin-top: 20px;
          cursor: pointer;
        }
      </style>
    </head>
    <body>
      <div class="container">
        <div class="icon">📶</div>
        <h1>Você está offline</h1>
        <p>O Aurora Mulher Segura requer conexão com a internet.</p>
        <p>Algumas funcionalidades podem não estar disponíveis.</p>
        <button onclick="location.reload()">Tentar Novamente</button>
      </div>
    </body>
    </html>
  `;
  
  return new Response(offlineHtml, {
    status: 200,
    headers: { 'Content-Type': 'text/html' }
  });
}

# ================================
# BACKGROUND SYNC (para alertas offline)
# ================================
self.addEventListener('sync', (event) => {
  if (event.tag === 'sync-alerts') {
    console.log('🔄 Sincronizando alertas pendentes...');
    event.waitUntil(syncAlerts());
  }
});

async function syncAlerts() {
  try {
    const cache = await caches.open('pending-alerts');
    const keys = await cache.keys();
    
    for (const request of keys) {
      const response = await cache.match(request);
      if (response) {
        const alertData = await response.json();
        
        # Tenta enviar para o servidor
        const result = await fetch('/api/send_alert', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(alertData)
        });
        
        if (result.ok) {
          # Remove do cache se enviado com sucesso
          await cache.delete(request);
          console.log('✅ Alerta sincronizado:', alertData.id);
        }
      }
    }
  } catch (error) {
    console.error('Erro na sincronização:', error);
  }
}

# ================================
# PUSH NOTIFICATIONS (futuro)
# ================================
self.addEventListener('push', (event) => {
  if (!event.data) return;
  
  const data = event.data.json();
  
  const options = {
    body: data.body || 'Novo alerta recebido',
    icon: '/static/icons/aurora-192.png',
    badge: '/static/icons/badge.png',
    vibrate: [200, 100, 200],
    data: {
      url: data.url || '/trusted/panel',
      id: data.id
    },
    actions: [
      {
        action: 'open',
        title: 'Abrir Painel'
      },
      {
        action: 'dismiss',
        title: 'Fechar'
      }
    ]
  };
  
  event.waitUntil(
    self.registration.showNotification(data.title || 'Aurora Mulher Segura', options)
  );
});

self.addEventListener('notificationclick', (event) => {
  event.notification.close();
  
  if (event.action === 'open') {
    event.waitUntil(
      clients.openWindow(event.notification.data.url)
    );
  }
});

# ================================
# MENSAGENS DO CLIENT
# ================================
self.addEventListener('message', (event) => {
  if (event.data && event.data.type === 'SKIP_WAITING') {
    self.skipWaiting();
  }
  
  if (event.data && event.data.type === 'CACHE_ASSETS') {
    const assets = event.data.assets;
    event.waitUntil(cacheAdditionalAssets(assets));
  }
});

async function cacheAdditionalAssets(assets) {
  const cache = await caches.open(CACHE_NAME);
  return cache.addAll(assets);
}