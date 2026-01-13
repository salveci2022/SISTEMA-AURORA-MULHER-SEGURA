import multiprocessing
import os

# Número de workers (processos)
workers = 2

# Threads por worker
threads = 4

# Timeout (Render recomenda 30 segundos)
timeout = 30

# Endereço e porta (Render define a porta)
bind = f"0.0.0.0:{os.getenv('PORT', '10000')}"

# Logs
accesslog = "-"
errorlog = "-"

# Configurações para produção
worker_class = "sync"
worker_connections = 1000
max_requests = 1000
max_requests_jitter = 50
keepalive = 2

# Reiniciar workers periodicamente para evitar memory leaks
max_requests = 1200
max_requests_jitter = 200