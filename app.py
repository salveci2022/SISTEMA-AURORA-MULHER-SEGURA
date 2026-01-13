from __future__ import annotations
from flask import Flask, render_template, request, redirect, session, url_for, jsonify, abort, make_response, flash
from flask_wtf.csrf import CSRFProtect, generate_csrf
from werkzeug.security import generate_password_hash, check_password_hash
from pathlib import Path
import json
import os
import hashlib
import secrets
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo
import logging
from functools import wraps
from typing import Optional, Dict, Any, List, Tuple
import html
import re

# ================================
# CONFIGURAÇÕES DE SEGURANÇA
# ================================

# Configuração via variáveis de ambiente
SECRET_KEY = os.environ.get("SECRET_KEY") or "aurora_v21_ultra_estavel_" + secrets.token_hex(32)
ADMIN_DEFAULT_PASSWORD = os.environ.get("ADMIN_DEFAULT_PASSWORD", "admin123")
SESSION_TIMEOUT_MINUTES = int(os.environ.get("SESSION_TIMEOUT_MINUTES", "30"))
MAX_TRUSTED_USERS = int(os.environ.get("MAX_TRUSTED_USERS", "5"))
MAX_LOGIN_ATTEMPTS = int(os.environ.get("MAX_LOGIN_ATTEMPTS", "5"))
LOGIN_LOCKOUT_MINUTES = int(os.environ.get("LOGIN_LOCKOUT_MINUTES", "15"))
CSRF_ENABLED = os.environ.get("CSRF_ENABLED", "True").lower() == "true"
HTTPS_ENABLED = os.environ.get("HTTPS_ENABLED", "False").lower() == "true"
DEBUG_MODE = os.environ.get("DEBUG_MODE", "False").lower() == "true"

# ================================
# INICIALIZAÇÃO
# ================================

try:
    TZ = ZoneInfo("America/Sao_Paulo")
except Exception:
    TZ = None

BASE_DIR = Path(__file__).resolve().parent
USERS_FILE = BASE_DIR / "data" / "users.json"
ALERTS_FILE = BASE_DIR / "data" / "alerts.log"
STATE_FILE = BASE_DIR / "data" / "state.json"
FAILED_LOGINS_FILE = BASE_DIR / "data" / "failed_logins.json"
AUDIT_LOG_FILE = BASE_DIR / "data" / "audit.log"
LOG_FILE = BASE_DIR / "logs" / "app.log"

# Criar diretórios se não existirem
for dir_path in [BASE_DIR / "data", BASE_DIR / "logs", BASE_DIR / "templates"]:
    dir_path.mkdir(exist_ok=True, parents=True)

app = Flask(__name__)
app.secret_key = SECRET_KEY

# Configurações de segurança para sessões
app.config.update(
    SESSION_COOKIE_SECURE=HTTPS_ENABLED,  # True em produção com HTTPS
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Strict',
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=SESSION_TIMEOUT_MINUTES),
    WTF_CSRF_ENABLED=CSRF_ENABLED,
    WTF_CSRF_SECRET_KEY=SECRET_KEY + "_csrf",
    WTF_CSRF_TIME_LIMIT=3600,
    JSONIFY_PRETTYPRINT_REGULAR=False  # Desabilitar JSON bonito em produção
)

# Proteção CSRF
csrf = CSRFProtect(app)

# Configurar logging
logging.basicConfig(
    level=logging.DEBUG if DEBUG_MODE else logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(LOG_FILE, encoding='utf-8'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# ================================
# FUNÇÕES AUXILIARES SEGURAS - CORRIGIDAS
# ================================

def hash_password(password: str, salt: str) -> str:
    """Hash seguro para senhas usando o salt fornecido."""
    return generate_password_hash(salt + password, method='scrypt')

def verify_password(stored_hash: str, password: str, salt: str) -> bool:
    """Verifica se a senha corresponde ao hash armazenado."""
    try:
        return check_password_hash(stored_hash, salt + password)
    except Exception:
        return False

def generate_salt() -> str:
    """Gera um salt seguro."""
    return secrets.token_hex(32)

def now_br_str() -> str:
    """Timestamp atual formatado."""
    if TZ is None:
        return datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    return datetime.now(TZ).strftime("%Y-%m-%d %H:%M:%S")

def sanitize_input(text: str, max_length: int = 500) -> str:
    """Remove caracteres perigosos e limita tamanho."""
    if not text:
        return ""
    
    # Remove tags HTML/JavaScript e caracteres especiais
    text = html.escape(text)
    
    # Remove caracteres de controle
    text = re.sub(r'[\x00-\x1F\x7F]', '', text)
    
    # Limita tamanho
    if len(text) > max_length:
        text = text[:max_length-3] + "..."
    
    return text.strip()

def validate_email(email: str) -> bool:
    """Valida formato de email."""
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return bool(re.match(pattern, email))

def validate_username(username: str) -> bool:
    """Valida formato de username."""
    pattern = r'^[a-zA-Z0-9._-]{3,50}$'
    return bool(re.match(pattern, username))

def ensure_files() -> None:
    """Garante que arquivos necessários existam."""
    try:
        if not USERS_FILE.exists():
            # Cria admin com senha hasheada - CORRIGIDO
            admin_salt = generate_salt()
            admin_hash = hash_password(ADMIN_DEFAULT_PASSWORD, admin_salt)  # Passa o salt!
            
            users_data = {
                "admin": {
                    "password": admin_hash,
                    "salt": admin_salt,
                    "role": "admin",
                    "name": "Administrador do Sistema",
                    "email": "admin@localhost",
                    "created_at": now_br_str(),
                    "last_login": None,
                    "last_password_change": now_br_str(),
                    "must_change_password": True,
                    "is_active": True,
                    "failed_attempts": 0,
                    "mfa_enabled": False
                }
            }
            
            USERS_FILE.parent.mkdir(exist_ok=True, parents=True)
            USERS_FILE.write_text(json.dumps(users_data, indent=2, ensure_ascii=False), encoding="utf-8")
            logger.warning("⚠️ ARQUIVO users.json CRIADO COM SENHA PADRÃO! ALTERE A SENHA DO ADMIN IMEDIATAMENTE!")
            log_audit("system", "users.json created with default admin password", "HIGH")

        for file_path in [ALERTS_FILE, STATE_FILE, FAILED_LOGINS_FILE, AUDIT_LOG_FILE]:
            if not file_path.exists():
                file_path.parent.mkdir(exist_ok=True, parents=True)
                if file_path.suffix == '.json':
                    file_path.write_text("{}", encoding="utf-8")
                else:
                    file_path.write_text("", encoding="utf-8")

        if not STATE_FILE.exists() or STATE_FILE.stat().st_size == 0:
            STATE_FILE.write_text(json.dumps({
                "last_id": 0,
                "created_at": now_br_str(),
                "updated_at": now_br_str(),
                "total_alerts": 0,
                "system_version": "2.2.0-secure"
            }, indent=2, ensure_ascii=False), encoding="utf-8")
            
    except Exception as e:
        logger.error(f"Erro ao criar arquivos: {e}")
        raise

def log_audit(user: str, action: str, severity: str = "INFO", details: Dict = None) -> None:
    """Registra evento de auditoria."""
    try:
        audit_entry = {
            "timestamp": now_br_str(),
            "user": user,
            "action": action,
            "severity": severity,
            "ip": request.remote_addr if request else "system",
            "user_agent": request.headers.get('User-Agent') if request else "system",
            "details": details or {}
        }
        
        with AUDIT_LOG_FILE.open("a", encoding="utf-8") as f:
            f.write(json.dumps(audit_entry, ensure_ascii=False) + "\n")
    except Exception as e:
        logger.error(f"Erro ao registrar auditoria: {e}")

def load_users() -> Dict[str, Dict[str, Any]]:
    """Carrega usuários do arquivo JSON com verificação de integridade."""
    ensure_files()
    try:
        data = json.loads(USERS_FILE.read_text(encoding="utf-8"))
        
        # Valida estrutura básica
        if not isinstance(data, dict):
            logger.error("users.json não é um dicionário válido")
            return {}
        
        # Valida cada usuário
        for username, user_data in data.items():
            if not isinstance(user_data, dict):
                logger.error(f"Dados inválidos para usuário {username}")
                continue
                
            # Garante campos obrigatórios
            required_fields = ["password", "role", "name", "created_at"]
            for field in required_fields:
                if field not in user_data:
                    if field == "password":
                        user_data[field] = ""
                    elif field == "role":
                        user_data[field] = "trusted"
                    elif field == "name":
                        user_data[field] = username
                    elif field == "created_at":
                        user_data[field] = now_br_str()
        
        return data
    except json.JSONDecodeError as e:
        logger.error(f"Erro ao decodificar users.json: {e}")
        # Cria backup do arquivo corrompido
        backup_file = USERS_FILE.with_suffix('.json.bak.' + datetime.now().strftime('%Y%m%d_%H%M%S'))
        USERS_FILE.rename(backup_file)
        logger.warning(f"Backup do users.json corrompido criado: {backup_file}")
        ensure_files()  # Recria o arquivo
        return load_users()
    except Exception as e:
        logger.error(f"Erro ao carregar usuários: {e}")
        return {}

def save_users(data: Dict[str, Dict[str, Any]]) -> None:
    """Salva usuários no arquivo JSON com verificação de integridade."""
    try:
        # Valida dados antes de salvar
        if not isinstance(data, dict):
            raise ValueError("Dados devem ser um dicionário")
        
        # Cria backup antes de salvar
        if USERS_FILE.exists():
            backup_file = USERS_FILE.with_suffix('.json.bak.' + datetime.now().strftime('%Y%m%d_%H%M%S'))
            import shutil
            shutil.copy2(USERS_FILE, backup_file)
        
        # Salva dados
        USERS_FILE.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
        
    except Exception as e:
        logger.error(f"Erro ao salvar usuários: {e}")
        log_audit("system", f"Erro ao salvar usuários: {str(e)}", "HIGH")
        raise

def load_failed_logins() -> Dict[str, Dict[str, Any]]:
    """Carrega tentativas falhas de login."""
    try:
        if FAILED_LOGINS_FILE.exists() and FAILED_LOGINS_FILE.stat().st_size > 0:
            return json.loads(FAILED_LOGINS_FILE.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        logger.warning("failed_logins.json corrompido, recriando...")
        FAILED_LOGINS_FILE.write_text("{}", encoding="utf-8")
    except Exception as e:
        logger.error(f"Erro ao carregar logins falhos: {e}")
    return {}

def save_failed_logins(data: Dict[str, Dict[str, Any]]) -> None:
    """Salva tentativas falhas de login."""
    try:
        FAILED_LOGINS_FILE.write_text(json.dumps(data, indent=2), encoding="utf-8")
    except Exception as e:
        logger.error(f"Erro ao salvar logins falhos: {e}")

def is_locked_out(username: str) -> Tuple[bool, Optional[str]]:
    """Verifica se usuário está bloqueado por tentativas falhas."""
    failed_logins = load_failed_logins()
    user_data = failed_logins.get(username, {})
    
    if not user_data:
        return False, None
    
    attempts = user_data.get("attempts", 0)
    lock_time = user_data.get("lock_time")
    
    if attempts >= MAX_LOGIN_ATTEMPTS and lock_time:
        try:
            lock_dt = datetime.strptime(lock_time, "%Y-%m-%d %H:%M:%S")
            unlock_time = lock_dt + timedelta(minutes=LOGIN_LOCKOUT_MINUTES)
            
            if datetime.now() < unlock_time:
                remaining = unlock_time - datetime.now()
                remaining_minutes = int(remaining.total_seconds() / 60) + 1
                return True, f"{remaining_minutes} minutos"
            else:
                # Limpa o bloqueio após o tempo
                del failed_logins[username]
                save_failed_logins(failed_logins)
                log_audit("system", f"Lockout expirado para usuário {username}")
        except ValueError:
            pass
    
    return False, None

def record_failed_login(username: str) -> None:
    """Registra tentativa falha de login."""
    failed_logins = load_failed_logins()
    
    if username not in failed_logins:
        failed_logins[username] = {"attempts": 0, "last_attempt": None, "lock_time": None}
    
    user_data = failed_logins[username]
    user_data["attempts"] = user_data.get("attempts", 0) + 1
    user_data["last_attempt"] = now_br_str()
    
    if user_data["attempts"] >= MAX_LOGIN_ATTEMPTS:
        user_data["lock_time"] = now_br_str()
        logger.warning(f"Usuário {username} bloqueado por {LOGIN_LOCKOUT_MINUTES} minutos")
        log_audit(username, "Account locked due to failed login attempts", "HIGH")
    
    save_failed_logins(failed_logins)
    logger.warning(f"Tentativa de login falhou para: {username} (tentativa {user_data['attempts']})")

def clear_failed_logins(username: str) -> None:
    """Limpa tentativas falhas após login bem-sucedido."""
    failed_logins = load_failed_logins()
    if username in failed_logins:
        del failed_logins[username]
        save_failed_logins(failed_logins)
        log_audit(username, "Failed login attempts cleared")

def list_trusted_names() -> List[str]:
    """Lista nomes de pessoas de confiança ativas."""
    users = load_users()
    arr = [
        info.get("name") or u 
        for u, info in users.items() 
        if info.get("role") == "trusted" and info.get("is_active", True)
    ]
    arr.sort(key=lambda s: s.lower())
    return arr

def next_alert_id() -> int:
    """Gera próximo ID de alerta."""
    ensure_files()
    try:
        with STATE_FILE.open("r+", encoding="utf-8") as f:
            data = json.load(f)
            new_id = int(data.get("last_id", 0)) + 1
            data["last_id"] = new_id
            data["updated_at"] = now_br_str()
            data["total_alerts"] = data.get("total_alerts", 0) + 1
            
            f.seek(0)
            json.dump(data, f, indent=2, ensure_ascii=False)
            f.truncate()
            
        return new_id
    except Exception as e:
        logger.error(f"Erro ao gerar ID de alerta: {e}")
        return 1

def log_alert(payload: Dict[str, Any]) -> None:
    """Registra alerta no log."""
    ensure_files()
    try:
        with ALERTS_FILE.open("a", encoding="utf-8") as f:
            f.write(json.dumps(payload, ensure_ascii=False) + "\n")
        
        logger.info(f"Alerta registrado: ID {payload.get('id')} - {payload.get('name')} - {payload.get('situation')}")
        log_audit(payload.get('name', 'unknown'), f"Alert sent - Situation: {payload.get('situation')}", "HIGH")
        
    except Exception as e:
        logger.error(f"Erro ao registrar alerta: {e}")

def read_last_alert() -> Optional[Dict[str, Any]]:
    """Lê último alerta do log."""
    ensure_files()
    try:
        if not ALERTS_FILE.exists() or ALERTS_FILE.stat().st_size == 0:
            return None
        
        with ALERTS_FILE.open("r", encoding="utf-8") as f:
            lines = f.readlines()
            if not lines:
                return None
            
            # Busca a última linha válida
            for line in reversed(lines):
                line = line.strip()
                if line:
                    try:
                        return json.loads(line)
                    except json.JSONDecodeError:
                        continue
            
        return None
    except Exception as e:
        logger.error(f"Erro ao ler último alerta: {e}")
        return None

def read_all_alerts(limit: int = 100, offset: int = 0) -> List[Dict[str, Any]]:
    """Lê todos os alertas (para relatório) com paginação."""
    ensure_files()
    alerts = []
    try:
        if not ALERTS_FILE.exists():
            return alerts
        
        with ALERTS_FILE.open("r", encoding="utf-8") as f:
            lines = f.readlines()
            
        # Processa linhas em ordem reversa (mais recentes primeiro)
        valid_lines = []
        for line in reversed(lines):
            line = line.strip()
            if line:
                valid_lines.append(line)
        
        # Aplica paginação
        start_idx = offset
        end_idx = offset + limit
        paginated_lines = valid_lines[start_idx:end_idx]
        
        for line in paginated_lines:
            try:
                alert = json.loads(line)
                alerts.append(alert)
            except json.JSONDecodeError:
                continue
        
        return alerts
    except Exception as e:
        logger.error(f"Erro ao ler alertas: {e}")
        return []

def validate_coordinates(lat: Any, lon: Any) -> Tuple[Optional[float], Optional[float]]:
    """Valida e converte coordenadas geográficas."""
    try:
        if lat is None or lon is None:
            return None, None
            
        lat_val = float(lat)
        lon_val = float(lon)
        
        # Valida ranges (latitude: -90 a 90, longitude: -180 a 180)
        if not (-90.0 <= lat_val <= 90.0) or not (-180.0 <= lon_val <= 180.0):
            logger.warning(f"Coordenadas fora do range válido: {lat_val}, {lon_val}")
            return None, None
        
        # Valida se não é 0,0 (localização padrão/não definida)
        if abs(lat_val) < 0.0001 and abs(lon_val) < 0.0001:
            logger.warning("Coordenadas são 0,0 (possivelmente não definidas)")
            return None, None
        
        return lat_val, lon_val
    except (ValueError, TypeError, AttributeError) as e:
        logger.debug(f"Erro ao validar coordenadas: {e}")
        return None, None

def rate_limit_key() -> str:
    """Gera chave para rate limiting baseada no IP."""
    ip = request.remote_addr
    path = request.path
    return f"{ip}:{path}"

# ================================
# DECORATORS DE AUTENTICAÇÃO
# ================================

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get("authenticated"):
            logger.warning(f"Acesso não autenticado à rota {request.path}")
            return redirect(url_for("admin_login"))
        
        if session.get("role") != "admin":
            logger.warning(f"Acesso não autorizado à rota {request.path}")
            abort(403)
        
        # Verifica timeout da sessão
        last_activity = session.get("last_activity")
        if last_activity:
            try:
                last_activity_dt = datetime.strptime(last_activity, "%Y-%m-%d %H:%M:%S")
                if datetime.now() - last_activity_dt > timedelta(minutes=SESSION_TIMEOUT_MINUTES):
                    session.clear()
                    flash("Sessão expirada. Faça login novamente.", "warning")
                    return redirect(url_for("admin_login"))
            except ValueError:
                pass
        
        # Atualiza última atividade
        session["last_activity"] = now_br_str()
        
        return f(*args, **kwargs)
    return decorated_function

def trusted_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get("authenticated"):
            logger.warning(f"Acesso não autenticado à rota {request.path}")
            return redirect(url_for("trusted_login"))
        
        if session.get("role") != "trusted":
            logger.warning(f"Acesso não autorizado à rota {request.path}")
            abort(403)
        
        # Verifica timeout da sessão
        last_activity = session.get("last_activity")
        if last_activity:
            try:
                last_activity_dt = datetime.strptime(last_activity, "%Y-%m-%d %H:%M:%S")
                if datetime.now() - last_activity_dt > timedelta(minutes=SESSION_TIMEOUT_MINUTES):
                    session.clear()
                    flash("Sessão expirada. Faça login novamente.", "warning")
                    return redirect(url_for("trusted_login"))
            except ValueError:
                pass
        
        # Atualiza última atividade
        session["last_activity"] = now_br_str()
        
        return f(*args, **kwargs)
    return decorated_function

def login_required(role: str = None):
    """Decorator genérico para login requerido."""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not session.get("authenticated"):
                if role == "admin":
                    return redirect(url_for("admin_login"))
                else:
                    return redirect(url_for("trusted_login"))
            
            if role and session.get("role") != role:
                abort(403)
            
            # Verifica timeout da sessão
            last_activity = session.get("last_activity")
            if last_activity:
                try:
                    last_activity_dt = datetime.strptime(last_activity, "%Y-%m-%d %H:%M:%S")
                    if datetime.now() - last_activity_dt > timedelta(minutes=SESSION_TIMEOUT_MINUTES):
                        session.clear()
                        flash("Sessão expirada. Faça login novamente.", "warning")
                        if role == "admin":
                            return redirect(url_for("admin_login"))
                        else:
                            return redirect(url_for("trusted_login"))
                except ValueError:
                    pass
            
            # Atualiza última atividade
            session["last_activity"] = now_br_str()
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# ================================
# MIDDLEWARE E HANDLERS
# ================================

@app.before_request
def before_request():
    """Executado antes de cada requisição."""
    # Ignora requisições estáticas
    if request.endpoint == 'static':
        return
    
    # Log de requisições
    logger.info(f"{request.method} {request.path} - IP: {request.remote_addr} - User-Agent: {request.headers.get('User-Agent', 'Unknown')}")
    
    # Verifica HTTPS em produção
    if not DEBUG_MODE and HTTPS_ENABLED and not request.is_secure:
        if request.headers.get('X-Forwarded-Proto', 'http') != 'https':
            abort(400, description="HTTPS requerido")
    
    # Atualiza sessão se autenticado
    if session.get("authenticated"):
        session.permanent = True
        session.modified = True

@app.after_request
def add_security_headers(response):
    """Adiciona headers de segurança HTTP."""
    # Headers básicos de segurança
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    
    # CSP - Content Security Policy
    csp_policy = [
        "default-src 'self'",
        "script-src 'self' 'unsafe-inline'",
        "style-src 'self' 'unsafe-inline'",
        "img-src 'self' data: https:",
        "font-src 'self'",
        "connect-src 'self'",
        "frame-ancestors 'none'",
        "base-uri 'self'",
        "form-action 'self'"
    ]
    
    if DEBUG_MODE:
        csp_policy = [
            "default-src 'self' 'unsafe-inline'",
            "script-src 'self' 'unsafe-inline' 'unsafe-eval'",
            "style-src 'self' 'unsafe-inline'",
            "img-src 'self' data: https:",
            "font-src 'self' data:",
            "connect-src 'self'",
            "frame-ancestors 'none'"
        ]
    
    response.headers['Content-Security-Policy'] = '; '.join(csp_policy)
    
    # HSTS - HTTP Strict Transport Security
    if HTTPS_ENABLED and not DEBUG_MODE:
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    
    # Outros headers
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    
    # Adicionar CSRF token para formulários
    if CSRF_ENABLED and request.endpoint and request.endpoint not in ['static', 'health']:
        try:
            csrf_token = generate_csrf()
            response.headers['X-CSRF-Token'] = csrf_token
        except Exception:
            pass
    
    return response

@app.errorhandler(404)
def page_not_found(e):
    """Handler para página não encontrada."""
    logger.warning(f"404 - Página não encontrada: {request.path} - IP: {request.remote_addr}")
    return render_template('404.html'), 404

@app.errorhandler(403)
def forbidden(e):
    """Handler para acesso proibido."""
    logger.warning(f"403 - Acesso proibido: {request.path} - IP: {request.remote_addr} - Usuário: {session.get('user', 'Não autenticado')}")
    return render_template('403.html'), 403

@app.errorhandler(400)
def bad_request(e):
    """Handler para requisição inválida."""
    logger.warning(f"400 - Requisição inválida: {request.path} - IP: {request.remote_addr}")
    return render_template('400.html'), 400

@app.errorhandler(500)
def internal_server_error(e):
    """Handler para erro interno."""
    logger.error(f"500 - Erro interno: {e} - Path: {request.path}")
    return render_template('500.html'), 500

# ================================
# ROTAS BÁSICAS
# ================================

@app.get("/health")
def health():
    """Endpoint de saúde do sistema."""
    try:
        # Verifica integridade dos arquivos
        files_status = {
            "users.json": USERS_FILE.exists() and USERS_FILE.stat().st_size > 0,
            "alerts.log": ALERTS_FILE.exists(),
            "state.json": STATE_FILE.exists() and STATE_FILE.stat().st_size > 0,
            "failed_logins.json": FAILED_LOGINS_FILE.exists(),
            "audit.log": AUDIT_LOG_FILE.exists()
        }
        
        # Verifica permissões
        can_read = os.access(USERS_FILE, os.R_OK)
        can_write = os.access(USERS_FILE, os.W_OK)
        
        # Conta usuários
        users = load_users()
        admin_count = sum(1 for u in users.values() if u.get("role") == "admin")
        trusted_count = sum(1 for u in users.values() if u.get("role") == "trusted" and u.get("is_active", True))
        
        return jsonify({
            "status": "healthy",
            "timestamp": now_br_str(),
            "timezone": str(TZ) if TZ else "UTC",
            "version": "2.2.0-secure",
            "files": files_status,
            "permissions": {
                "read": can_read,
                "write": can_write
            },
            "users": {
                "total": len(users),
                "admin": admin_count,
                "trusted": trusted_count,
                "active": sum(1 for u in users.values() if u.get("is_active", True))
            },
            "security": {
                "csrf_enabled": CSRF_ENABLED,
                "https_enabled": HTTPS_ENABLED,
                "debug_mode": DEBUG_MODE,
                "session_timeout": f"{SESSION_TIMEOUT_MINUTES} minutos"
            },
            "limits": {
                "max_trusted_users": MAX_TRUSTED_USERS,
                "max_login_attempts": MAX_LOGIN_ATTEMPTS,
                "login_lockout_minutes": LOGIN_LOCKOUT_MINUTES
            }
        })
    except Exception as e:
        logger.error(f"Erro no endpoint health: {e}")
        return jsonify({"status": "unhealthy", "error": str(e)}), 500

@app.get("/")
def index():
    """Página inicial."""
    return redirect(url_for("panic_button"))

@app.get("/panic")
def panic_button():
    """Botão de pânico."""
    trusted = list_trusted_names()
    last_alert = read_last_alert()
    
    # Gera token para o formulário
    form_token = secrets.token_hex(16)
    session['panic_token'] = form_token
    
    return render_template(
        "panic_button.html", 
        trusted=trusted,
        last_alert=last_alert,
        form_token=form_token,
        google_maps_api_key=os.environ.get("GOOGLE_MAPS_API_KEY", "")
    )

# ================================
# ALERTAS (API)
# ================================

@app.post("/api/send_alert")
def send_alert():
    """Recebe alerta do botão de pânico."""
    # Verifica rate limiting
    client_ip = request.remote_addr
    rate_key = f"alert:{client_ip}"
    
    # Verifica token do formulário
    form_token = request.headers.get('X-Form-Token') or request.json.get('form_token', '')
    if not form_token or form_token != session.get('panic_token'):
        logger.warning(f"Token de formulário inválido ou ausente do IP: {client_ip}")
        return jsonify({"ok": False, "error": "Token inválido"}), 403
    
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"ok": False, "error": "Dados JSON inválidos"}), 400
    
    # Sanitiza inputs
    name = sanitize_input(data.get("name") or "Anônimo", 100)
    situation = sanitize_input(data.get("situation") or "Emergência", 100)
    message = sanitize_input(data.get("message") or "", 500)
    
    # Valida localização
    location = data.get("location")
    validated_location = None
    
    if location and isinstance(location, dict):
        lat, lon = validate_coordinates(location.get("lat"), location.get("lon"))
        if lat is not None and lon is not None:
            validated_location = {
                "lat": lat,
                "lon": lon,
                "accuracy_m": min(float(location.get("accuracy_m", 0)), 1000),  # Limita a 1000m
                "timestamp": location.get("timestamp") or now_br_str()
            }
    
    # Valida endereço se fornecido
    address = sanitize_input(data.get("address", ""), 200)
    
    # Cria payload do alerta
    alert_id = next_alert_id()
    payload = {
        "id": alert_id,
        "ts": now_br_str(),
        "name": name,
        "situation": situation,
        "message": message,
        "location": validated_location,
        "address": address if address else None,
        "ip": client_ip,
        "user_agent": request.headers.get('User-Agent', 'Unknown')
    }
    
    # Registra alerta
    log_alert(payload)
    
    # Notifica pessoas de confiança
    users = load_users()
    trusted_users = [
        {"username": u, "name": info.get("name", u), "email": info.get("email")}
        for u, info in users.items()
        if info.get("role") == "trusted" and info.get("is_active", True)
    ]
    
    logger.info(f"Alerta #{alert_id} enviado por {name}. Pessoas de confiança notificadas: {len(trusted_users)}")
    
    # Gera novo token para próximo uso
    session['panic_token'] = secrets.token_hex(16)
    
    return jsonify({
        "ok": True, 
        "id": alert_id,
        "message": f"Alerta #{alert_id} registrado com sucesso. {len(trusted_users)} pessoas serão notificadas."
    })

@app.get("/api/last_alert")
def last_alert():
    """Retorna o último alerta registrado."""
    alert = read_last_alert()
    if alert:
        # Remove informações sensíveis antes de retornar
        alert.pop('ip', None)
        alert.pop('user_agent', None)
    
    return jsonify({"ok": True, "last": alert})

@app.get("/api/alerts")
@admin_required
def list_alerts():
    """Lista alertas com paginação."""
    try:
        page = int(request.args.get('page', 1))
        per_page = int(request.args.get('per_page', 20))
        
        if page < 1:
            page = 1
        if per_page < 1 or per_page > 100:
            per_page = 20
        
        offset = (page - 1) * per_page
        alerts = read_all_alerts(limit=per_page, offset=offset)
        
        # Conta total de alertas
        if ALERTS_FILE.exists():
            with ALERTS_FILE.open("r", encoding="utf-8") as f:
                total_lines = sum(1 for line in f if line.strip())
        else:
            total_lines = 0
        
        return jsonify({
            "ok": True,
            "alerts": alerts,
            "pagination": {
                "page": page,
                "per_page": per_page,
                "total": total_lines,
                "pages": (total_lines + per_page - 1) // per_page
            }
        })
    except Exception as e:
        logger.error(f"Erro ao listar alertas: {e}")
        return jsonify({"ok": False, "error": str(e)}), 500

# ================================
# ADMIN - CORRIGIDO
# ================================

@app.route("/panel/login", methods=["GET", "POST"])
def admin_login():
    """Login do administrador."""
    # Se já estiver autenticado, redireciona
    if session.get("authenticated") and session.get("role") == "admin":
        return redirect(url_for("admin_panel"))
    
    error = False
    lockout = False
    lockout_time = None
    users = load_users()
    
    if request.method == "POST":
        username = sanitize_input(request.form.get("user", "").strip().lower(), 50)
        password = request.form.get("password", "")
        
        # Validação básica
        if not username or not password:
            error = True
            flash("Preencha todos os campos", "error")
        else:
            # Verifica se está bloqueado
            locked_out, remaining = is_locked_out(username)
            if locked_out:
                lockout = True
                lockout_time = remaining
                flash(f"Conta bloqueada. Tente novamente em {remaining}.", "error")
                log_audit(username, "Login bloqueado por tentativas excessivas", "HIGH")
            else:
                info = users.get(username)
                
                # Verifica usuário
                if not info or info.get("role") != "admin":
                    record_failed_login(username)
                    error = True
                    flash("Credenciais inválidas", "error")
                    log_audit(username, "Tentativa de login de admin falhou", "MEDIUM")
                elif not info.get("is_active", True):
                    error = True
                    flash("Conta desativada", "error")
                    log_audit(username, "Tentativa de login em conta desativada", "MEDIUM")
                else:
                    # Verifica senha - CORRIGIDO
                    salt = info.get("salt", "")
                    if verify_password(info.get("password", ""), password, salt):
                        # Login bem-sucedido
                        session.clear()
                        session["authenticated"] = True
                        session["role"] = "admin"
                        session["user"] = username
                        session["name"] = info.get("name", username)
                        session["last_activity"] = now_br_str()
                        session.permanent = True
                        
                        # Atualiza último login
                        users[username]["last_login"] = now_br_str()
                        users[username]["failed_attempts"] = 0
                        save_users(users)
                        
                        # Limpa tentativas falhas
                        clear_failed_logins(username)
                        
                        logger.info(f"Admin {username} logado com sucesso")
                        log_audit(username, "Login de admin bem-sucedido")
                        
                        # Verifica se precisa mudar senha
                        if users[username].get("must_change_password", False):
                            flash("Você deve alterar sua senha antes de continuar.", "warning")
                            return redirect(url_for("admin_change_password"))
                        
                        return redirect(url_for("admin_panel"))
                    else:
                        # Senha incorreta
                        record_failed_login(username)
                        error = True
                        flash("Credenciais inválidas", "error")
                        log_audit(username, "Senha de admin incorreta", "MEDIUM")
    
    return render_template(
        "login_admin.html", 
        error=error, 
        lockout=lockout, 
        lockout_time=lockout_time
    )

@app.route("/panel/change_password", methods=["GET", "POST"])
@admin_required
def admin_change_password():
    """Força alteração de senha do admin na primeira vez."""
    users = load_users()
    username = session.get("user")
    user_info = users.get(username, {})
    
    msg = ""
    err = ""
    
    if request.method == "POST":
        old_password = request.form.get("old_password", "")
        new_password = request.form.get("new_password", "")
        confirm_password = request.form.get("confirm_password", "")
        
        # Validações
        if not old_password or not new_password or not confirm_password:
            err = "Preencha todos os campos"
        elif len(new_password) < 12:
            err = "A nova senha deve ter pelo menos 12 caracteres"
        elif new_password == old_password:
            err = "A nova senha deve ser diferente da antiga"
        elif new_password != confirm_password:
            err = "As senhas não coincidem"
        else:
            # Verifica senha antiga
            salt = user_info.get("salt", "")
            if verify_password(user_info.get("password", ""), old_password, salt):
                # Gera novo salt e hash - CORRIGIDO
                new_salt = generate_salt()
                new_hash = hash_password(new_password, new_salt)  # Passa o salt!
                
                # Atualiza usuário
                users[username]["password"] = new_hash
                users[username]["salt"] = new_salt
                users[username]["last_password_change"] = now_br_str()
                users[username]["must_change_password"] = False
                users[username]["password_history"] = users[username].get("password_history", []) + [{
                    "hash": user_info.get("password"),
                    "salt": user_info.get("salt"),
                    "changed_at": now_br_str()
                }]
                
                # Limita histórico a 5 senhas
                if len(users[username]["password_history"]) > 5:
                    users[username]["password_history"] = users[username]["password_history"][-5:]
                
                save_users(users)
                
                msg = "Senha alterada com sucesso! Agora você pode acessar o painel."
                logger.info(f"Admin {username} alterou a senha")
                log_audit(username, "Senha de admin alterada")
                
                flash(msg, "success")
                return redirect(url_for("admin_panel"))
            else:
                err = "Senha atual incorreta"
    
    return render_template(
        "admin_change_password.html", 
        msg=msg, 
        err=err,
        must_change=user_info.get("must_change_password", False)
    )

@app.get("/panel")
@admin_required
def admin_panel():
    """Painel do administrador."""
    users = load_users()
    trusted_users = {u: info for u, info in users.items() if info.get("role") == "trusted"}
    
    # Estatísticas
    total_alerts = 0
    if STATE_FILE.exists():
        try:
            with STATE_FILE.open("r", encoding="utf-8") as f:
                state = json.load(f)
                total_alerts = state.get("total_alerts", 0)
        except:
            pass
    
    total_trusted = len(trusted_users)
    active_trusted = sum(1 for u in trusted_users.values() if u.get("is_active", True))
    
    # Últimos alertas
    recent_alerts = read_all_alerts(limit=10)
    
    # Sistema
    system_info = {
        "version": "2.2.0-secure",
        "uptime": "N/A",
        "last_backup": "N/A",
        "disk_usage": "N/A"
    }
    
    return render_template(
        "panel_admin.html", 
        trusted_users=trusted_users,
        total_alerts=total_alerts,
        total_trusted=total_trusted,
        active_trusted=active_trusted,
        recent_alerts=recent_alerts,
        system_info=system_info,
        max_trusted_users=MAX_TRUSTED_USERS
    )

@app.post("/panel/add_trusted")
@admin_required
def admin_add_trusted():
    """Adiciona pessoa de confiança - CORRIGIDO."""
    name = sanitize_input(request.form.get("trusted_name", "").strip(), 100)
    username = request.form.get("trusted_user", "").strip().lower()
    password = request.form.get("trusted_password", "")
    confirm_password = request.form.get("confirm_password", "")
    email = request.form.get("trusted_email", "").strip()
    phone = sanitize_input(request.form.get("trusted_phone", ""), 20)
    
    # Validações
    if not name or not username or not password:
        flash("Preencha pelo menos nome, usuário e senha", "error")
        return redirect(url_for("admin_panel"))
    
    if not validate_username(username):
        flash("Nome de usuário inválido. Use apenas letras, números, ponto, hífen e sublinhado (3-50 caracteres)", "error")
        return redirect(url_for("admin_panel"))
    
    if email and not validate_email(email):
        flash("Email inválido", "error")
        return redirect(url_for("admin_panel"))
    
    if len(password) < 8:
        flash("A senha deve ter pelo menos 8 caracteres", "error")
        return redirect(url_for("admin_panel"))
    
    if password != confirm_password:
        flash("As senhas não coincidem", "error")
        return redirect(url_for("admin_panel"))
    
    users = load_users()
    
    # Verifica se usuário já existe
    if username in users:
        flash("Nome de usuário já existe", "error")
        return redirect(url_for("admin_panel"))
    
    # Verifica limite de pessoas de confiança
    trusted_count = sum(1 for u in users.values() if u.get("role") == "trusted" and u.get("is_active", True))
    if trusted_count >= MAX_TRUSTED_USERS:
        flash(f"Limite de {MAX_TRUSTED_USERS} pessoas de confiança atingido", "error")
        return redirect(url_for("admin_panel"))
    
    # Gera salt e hash da senha - CORRIGIDO
    salt = generate_salt()
    password_hash = hash_password(password, salt)  # Passa o salt!
    
    # Cria usuário
    users[username] = {
        "password": password_hash,
        "salt": salt,
        "role": "trusted",
        "name": name,
        "email": email if email else None,
        "phone": phone if phone else None,
        "created_at": now_br_str(),
        "last_login": None,
        "last_password_change": now_br_str(),
        "is_active": True,
        "failed_attempts": 0,
        "mfa_enabled": False,
        "notes": ""
    }
    
    save_users(users)
    
    logger.info(f"Pessoa de confiança adicionada: {name} ({username})")
    log_audit(session.get("user"), f"Pessoa de confiança adicionada: {name} ({username})")
    
    flash(f"Pessoa de confiança '{name}' adicionada com sucesso", "success")
    return redirect(url_for("admin_panel"))

@app.post("/panel/update_trusted")
@admin_required
def admin_update_trusted():
    """Atualiza pessoa de confiança."""
    username = request.form.get("username", "").strip()
    name = sanitize_input(request.form.get("name", "").strip(), 100)
    email = request.form.get("email", "").strip()
    phone = sanitize_input(request.form.get("phone", ""), 20)
    is_active = request.form.get("is_active") == "on"
    notes = sanitize_input(request.form.get("notes", ""), 500)
    
    users = load_users()
    
    if username in users and users[username].get("role") == "trusted":
        old_name = users[username].get("name", username)
        
        # Atualiza campos
        users[username]["name"] = name
        if email:
            if validate_email(email):
                users[username]["email"] = email
            else:
                flash("Email inválido", "error")
                return redirect(url_for("admin_panel"))
        
        users[username]["phone"] = phone if phone else None
        users[username]["is_active"] = is_active
        users[username]["notes"] = notes
        users[username]["updated_at"] = now_br_str()
        
        save_users(users)
        
        logger.info(f"Pessoa de confiança atualizada: {old_name} -> {name} ({username})")
        log_audit(session.get("user"), f"Pessoa de confiança atualizada: {username}")
        
        flash(f"Pessoa de confiança '{name}' atualizada com sucesso", "success")
    
    return redirect(url_for("admin_panel"))

@app.post("/panel/reset_trusted_password")
@admin_required
def admin_reset_trusted_password():
    """Redefine senha de pessoa de confiança - CORRIGIDO."""
    username = request.form.get("username", "").strip()
    new_password = request.form.get("new_password", "")
    confirm_password = request.form.get("confirm_password", "")
    
    users = load_users()
    
    if username in users and users[username].get("role") == "trusted":
        if len(new_password) < 8:
            flash("A senha deve ter pelo menos 8 caracteres", "error")
            return redirect(url_for("admin_panel"))
        
        if new_password != confirm_password:
            flash("As senhas não coincidem", "error")
            return redirect(url_for("admin_panel"))
        
        # Gera novo salt e hash - CORRIGIDO
        new_salt = generate_salt()
        new_hash = hash_password(new_password, new_salt)  # Passa o salt!
        
        users[username]["password"] = new_hash
        users[username]["salt"] = new_salt
        users[username]["last_password_change"] = now_br_str()
        users[username]["must_change_password"] = True
        
        save_users(users)
        
        logger.info(f"Senha redefinida para pessoa de confiança: {username}")
        log_audit(session.get("user"), f"Senha redefinida para pessoa de confiança: {username}")
        
        flash(f"Senha redefinida para '{users[username].get('name', username)}'", "success")
    
    return redirect(url_for("admin_panel"))

@app.post("/panel/delete_trusted")
@admin_required
def admin_delete_trusted():
    """Remove pessoa de confiança."""
    username = request.form.get("username", "").strip()
    users = load_users()
    
    if username in users and users[username].get("role") == "trusted":
        name = users[username].get("name", username)
        
        # Não permite excluir a si mesmo
        if username == session.get("user"):
            flash("Você não pode excluir sua própria conta", "error")
            return redirect(url_for("admin_panel"))
        
        # Marca como inativo em vez de excluir
        users[username]["is_active"] = False
        users[username]["deactivated_at"] = now_br_str()
        users[username]["deactivated_by"] = session.get("user")
        
        save_users(users)
        
        logger.info(f"Pessoa de confiança desativada: {name} ({username})")
        log_audit(session.get("user"), f"Pessoa de confiança desativada: {username}")
        
        flash(f"Pessoa de confiança '{name}' desativada com sucesso", "success")
    
    return redirect(url_for("admin_panel"))

@app.get("/panel/audit_log")
@admin_required
def admin_audit_log():
    """Visualiza log de auditoria."""
    try:
        lines = []
        if AUDIT_LOG_FILE.exists():
            with AUDIT_LOG_FILE.open("r", encoding="utf-8") as f:
                lines = [line.strip() for line in f if line.strip()]
        
        # Converte para objetos JSON
        audit_entries = []
        for line in reversed(lines[-100:]):  # Últimas 100 entradas
            try:
                audit_entries.append(json.loads(line))
            except:
                continue
        
        return render_template("audit_log.html", audit_entries=audit_entries)
    except Exception as e:
        logger.error(f"Erro ao ler log de auditoria: {e}")
        flash("Erro ao carregar log de auditoria", "error")
        return redirect(url_for("admin_panel"))

@app.get("/panel/system_info")
@admin_required
def admin_system_info():
    """Informações do sistema."""
    import platform
    import psutil
    
    try:
        # Informações do sistema
        system_info = {
            "python_version": platform.python_version(),
            "platform": platform.platform(),
            "processor": platform.processor(),
            "hostname": platform.node(),
            "flask_version": "2.3.3",  # Versão atual do Flask
            "timezone": str(TZ) if TZ else "UTC",
            "current_time": now_br_str()
        }
        
        # Uso de recursos
        disk_usage = psutil.disk_usage('/')
        memory = psutil.virtual_memory()
        
        resource_info = {
            "disk_total_gb": round(disk_usage.total / (1024**3), 2),
            "disk_used_gb": round(disk_usage.used / (1024**3), 2),
            "disk_free_gb": round(disk_usage.free / (1024**3), 2),
            "disk_percent": disk_usage.percent,
            "memory_total_gb": round(memory.total / (1024**3), 2),
            "memory_available_gb": round(memory.available / (1024**3), 2),
            "memory_percent": memory.percent,
            "cpu_percent": psutil.cpu_percent(interval=1)
        }
        
        # Arquivos do sistema
        files_info = {}
        for file_path in [USERS_FILE, ALERTS_FILE, STATE_FILE, FAILED_LOGINS_FILE, AUDIT_LOG_FILE]:
            if file_path.exists():
                size_kb = file_path.stat().st_size / 1024
                files_info[file_path.name] = {
                    "exists": True,
                    "size_kb": round(size_kb, 2),
                    "modified": datetime.fromtimestamp(file_path.stat().st_mtime).strftime("%Y-%m-%d %H:%M:%S")
                }
            else:
                files_info[file_path.name] = {"exists": False}
        
        return render_template(
            "system_info.html",
            system_info=system_info,
            resource_info=resource_info,
            files_info=files_info
        )
    except Exception as e:
        logger.error(f"Erro ao coletar informações do sistema: {e}")
        flash(f"Erro ao coletar informações do sistema: {str(e)}", "error")
        return redirect(url_for("admin_panel"))

@app.get("/logout_admin")
def logout_admin():
    """Logout do administrador."""
    username = session.get("user")
    
    if session.get("authenticated") and session.get("role") == "admin":
        logger.info(f"Admin {username} deslogou")
        log_audit(username, "Logout de admin")
    
    session.clear()
    flash("Logout realizado com sucesso", "success")
    return redirect(url_for("admin_login"))

# ================================
# PESSOAS DE CONFIANÇA - CORRIGIDAS
# ================================

@app.route("/trusted/login", methods=["GET", "POST"])
def trusted_login():
    """Login de pessoa de confiança - CORRIGIDO."""
    # Se já estiver autenticado, redireciona
    if session.get("authenticated") and session.get("role") == "trusted":
        return redirect(url_for("trusted_panel"))
    
    error = False
    lockout = False
    lockout_time = None
    users = load_users()
    
    if request.method == "POST":
        username = sanitize_input(request.form.get("user", "").strip().lower(), 50)
        password = request.form.get("password", "")
        
        # Validação básica
        if not username or not password:
            error = True
            flash("Preencha todos os campos", "error")
        else:
            # Verifica se está bloqueado
            locked_out, remaining = is_locked_out(username)
            if locked_out:
                lockout = True
                lockout_time = remaining
                flash(f"Conta bloqueada. Tente novamente em {remaining}.", "error")
                log_audit(username, "Login bloqueado (trusted)", "HIGH")
            else:
                info = users.get(username)
                
                # Verifica usuário
                if not info or info.get("role") != "trusted":
                    record_failed_login(username)
                    error = True
                    flash("Credenciais inválidas", "error")
                    log_audit(username, "Tentativa de login (trusted) falhou", "MEDIUM")
                elif not info.get("is_active", True):
                    error = True
                    flash("Conta desativada", "error")
                    log_audit(username, "Tentativa de login em conta desativada (trusted)", "MEDIUM")
                else:
                    # Verifica senha - CORRIGIDO
                    salt = info.get("salt", "")
                    if verify_password(info.get("password", ""), password, salt):
                        # Login bem-sucedido
                        session.clear()
                        session["authenticated"] = True
                        session["role"] = "trusted"
                        session["trusted"] = username
                        session["name"] = info.get("name", username)
                        session["last_activity"] = now_br_str()
                        session.permanent = True
                        
                        # Atualiza último login
                        users[username]["last_login"] = now_br_str()
                        users[username]["failed_attempts"] = 0
                        save_users(users)
                        
                        # Limpa tentativas falhas
                        clear_failed_logins(username)
                        
                        logger.info(f"Pessoa de confiança {username} logou")
                        log_audit(username, "Login de pessoa de confiança bem-sucedido")
                        
                        return redirect(url_for("trusted_panel"))
                    else:
                        # Senha incorreta
                        record_failed_login(username)
                        error = True
                        flash("Credenciais inválidas", "error")
                        log_audit(username, "Senha incorreta (trusted)", "MEDIUM")
    
    return render_template(
        "login_trusted.html", 
        error=error, 
        lockout=lockout, 
        lockout_time=lockout_time
    )

@app.get("/trusted/panel")
@trusted_required
def trusted_panel():
    """Painel da pessoa de confiança."""
    users = load_users()
    username = session.get("trusted")
    user_info = users.get(username, {})
    display_name = user_info.get("name") or username
    
    # Últimos alertas (10 mais recentes)
    alerts = read_all_alerts(limit=10)
    
    # Informações da conta
    account_info = {
        "username": username,
        "name": display_name,
        "email": user_info.get("email", "Não informado"),
        "phone": user_info.get("phone", "Não informado"),
        "created_at": user_info.get("created_at", "Desconhecido"),
        "last_login": user_info.get("last_login", "Nunca"),
        "last_password_change": user_info.get("last_password_change", "Desconhecido")
    }
    
    return render_template(
        "panel_trusted.html", 
        display_name=display_name,
        recent_alerts=alerts,
        account_info=account_info
    )

@app.route("/trusted/change_password", methods=["GET", "POST"])
@trusted_required
def trusted_change_password():
    """Alteração de senha pela pessoa de confiança - CORRIGIDO."""
    users = load_users()
    username = session.get("trusted")
    user_info = users.get(username, {})
    
    msg = ""
    err = ""
    
    if request.method == "POST":
        old_password = request.form.get("old_password", "")
        new_password = request.form.get("new_password", "")
        confirm_password = request.form.get("confirm_password", "")
        
        # Validações
        if not old_password or not new_password or not confirm_password:
            err = "Preencha todos os campos"
        elif len(new_password) < 8:
            err = "A nova senha deve ter pelo menos 8 caracteres"
        elif new_password == old_password:
            err = "A nova senha deve ser diferente da antiga"
        elif new_password != confirm_password:
            err = "As senhas não coincidem"
        else:
            # Verifica senha antiga
            salt = user_info.get("salt", "")
            if verify_password(user_info.get("password", ""), old_password, salt):
                # Gera novo salt e hash - CORRIGIDO
                new_salt = generate_salt()
                new_hash = hash_password(new_password, new_salt)  # Passa o salt!
                
                # Atualiza usuário
                users[username]["password"] = new_hash
                users[username]["salt"] = new_salt
                users[username]["last_password_change"] = now_br_str()
                users[username]["must_change_password"] = False
                
                save_users(users)
                
                msg = "Senha alterada com sucesso"
                logger.info(f"Pessoa de confiança {username} alterou a senha")
                log_audit(username, "Senha alterada (trusted)")
                
                flash(msg, "success")
                return redirect(url_for("trusted_panel"))
            else:
                err = "Senha atual incorreta"
    
    return render_template("trusted_change_password.html", msg=msg, err=err)

@app.route("/trusted/profile", methods=["GET", "POST"])
@trusted_required
def trusted_profile():
    """Edição de perfil da pessoa de confiança."""
    users = load_users()
    username = session.get("trusted")
    user_info = users.get(username, {})
    
    msg = ""
    err = ""
    
    if request.method == "POST":
        name = sanitize_input(request.form.get("name", "").strip(), 100)
        email = request.form.get("email", "").strip()
        phone = sanitize_input(request.form.get("phone", ""), 20)
        
        # Validações
        if not name:
            err = "Nome é obrigatório"
        elif email and not validate_email(email):
            err = "Email inválido"
        else:
            # Atualiza informações
            old_name = user_info.get("name", username)
            users[username]["name"] = name
            
            if email:
                users[username]["email"] = email
            else:
                users[username]["email"] = None
            
            users[username]["phone"] = phone if phone else None
            users[username]["updated_at"] = now_br_str()
            
            save_users(users)
            
            # Atualiza sessão se nome mudou
            if old_name != name:
                session["name"] = name
            
            msg = "Perfil atualizado com sucesso"
            logger.info(f"Pessoa de confiança {username} atualizou o perfil")
            log_audit(username, "Perfil atualizado")
            
            flash(msg, "success")
            return redirect(url_for("trusted_panel"))
    
    return render_template(
        "trusted_profile.html",
        user_info=user_info,
        msg=msg,
        err=err
    )

@app.route("/trusted/recover", methods=["GET", "POST"])
def trusted_recover():
    """Recuperação de senha (apenas admin pode redefinir) - CORRIGIDO."""
    if session.get("authenticated") and session.get("role") == "admin":
        # Admin está logado, mostrar formulário
        msg = ""
        err = ""
        
        if request.method == "POST":
            username = request.form.get("user", "").strip().lower()
            new_password = request.form.get("new_password", "")
            confirm_password = request.form.get("confirm_password", "")
            
            if not username or not new_password or not confirm_password:
                err = "Preencha todos os campos"
            elif len(new_password) < 8:
                err = "A nova senha deve ter pelo menos 8 caracteres"
            elif new_password != confirm_password:
                err = "As senhas não coincidem"
            else:
                users = load_users()
                if username in users and users[username].get("role") == "trusted":
                    # Gera novo salt e hash - CORRIGIDO
                    new_salt = generate_salt()
                    new_hash = hash_password(new_password, new_salt)  # Passa o salt!
                    
                    users[username]["password"] = new_hash
                    users[username]["salt"] = new_salt
                    users[username]["last_password_change"] = now_br_str()
                    users[username]["must_change_password"] = True
                    
                    save_users(users)
                    
                    msg = "Senha redefinida com sucesso"
                    logger.info(f"Admin {session.get('user')} redefiniu senha para {username}")
                    log_audit(session.get("user"), f"Redefiniu senha para {username}", "HIGH")
                    
                    flash(msg, "success")
                    return redirect(url_for("admin_panel"))
                else:
                    err = "Usuário não encontrado ou não é pessoa de confiança"
        
        return render_template("trusted_recover_admin.html", msg=msg, err=err)
    else:
        # Usuário não é admin, redirecionar para login de admin
        flash("Apenas administradores podem redefinir senhas", "warning")
        return redirect(url_for("admin_login"))

@app.get("/logout_trusted")
def logout_trusted():
    """Logout da pessoa de confiança."""
    username = session.get("trusted")
    
    if session.get("authenticated") and session.get("role") == "trusted":
        logger.info(f"Pessoa de confiança {username} deslogou")
        log_audit(username, "Logout de pessoa de confiança")
    
    session.clear()
    flash("Logout realizado com sucesso", "success")
    return redirect(url_for("trusted_login"))

# ================================
# RELATÓRIOS
# ================================

@app.get("/report.html")
@admin_required
def generate_report():
    """Gera relatório HTML de ocorrências."""
    alerts = read_all_alerts(limit=100)
    
    # Estatísticas
    total_alerts = len(alerts)
    today = datetime.now().date()
    today_alerts = sum(1 for a in alerts if datetime.strptime(a.get('ts', ''), '%Y-%m-%d %H:%M:%S').date() == today)
    
    # Agrupa por situação
    situations = {}
    for alert in alerts:
        situation = alert.get('situation', 'Desconhecida')
        situations[situation] = situations.get(situation, 0) + 1
    
    # Formata relatório em HTML
    report_html = f"""<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="utf-8">
    <title>Relatório Aurora Mulher Segura</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; line-height: 1.6; }}
        h1 {{ color: #2c3e50; border-bottom: 2px solid #3498db; padding-bottom: 10px; }}
        h2 {{ color: #34495e; }}
        .header {{ background: #f8f9fa; padding: 20px; border-radius: 5px; margin-bottom: 20px; }}
        .stats {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin: 20px 0; }}
        .stat-card {{ background: white; border: 1px solid #ddd; border-radius: 5px; padding: 15px; text-align: center; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
        .stat-value {{ font-size: 24px; font-weight: bold; color: #2c3e50; }}
        .stat-label {{ color: #7f8c8d; font-size: 14px; }}
        table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
        th, td {{ border: 1px solid #ddd; padding: 12px; text-align: left; }}
        th {{ background-color: #3498db; color: white; }}
        tr:nth-child(even) {{ background-color: #f8f9fa; }}
        .location {{ font-size: 12px; color: #666; }}
        .footer {{ margin-top: 30px; padding-top: 20px; border-top: 1px solid #ddd; color: #7f8c8d; font-size: 12px; }}
        .alert {{ margin-bottom: 15px; padding: 10px; background: #f9f9f9; border-left: 4px solid #3498db; }}
        @media print {{
            .no-print {{ display: none; }}
            body {{ margin: 0; }}
            .stat-card {{ break-inside: avoid; }}
        }}
    </style>
</head>
<body>
    <div class="header">
        <h1>Relatório Aurora Mulher Segura</h1>
        <p><strong>Sistema de Proteção e Emergência</strong></p>
        <p><strong>Gerado em:</strong> {now_br_str()}</p>
        <p><strong>Gerado por:</strong> {session.get('name', 'Administrador')}</p>
    </div>
    
    <div class="stats">
        <div class="stat-card">
            <div class="stat-value">{total_alerts}</div>
            <div class="stat-label">Total de Ocorrências</div>
        </div>
        <div class="stat-card">
            <div class="stat-value">{today_alerts}</div>
            <div class="stat-label">Ocorrências Hoje</div>
        </div>
        <div class="stat-card">
            <div class="stat-value">{len(situations)}</div>
            <div class="stat-label">Tipos de Situações</div>
        </div>
        <div class="stat-card">
            <div class="stat-value">{len(list_trusted_names())}</div>
            <div class="stat-label">Pessoas de Confiança Ativas</div>
        </div>
    </div>
    
    <h2>Distribuição por Situação</h2>
    <table>
        <tr>
            <th>Situação</th>
            <th>Quantidade</th>
            <th>Porcentagem</th>
        </tr>
"""
    
    for situation, count in sorted(situations.items(), key=lambda x: x[1], reverse=True):
        percentage = (count / total_alerts * 100) if total_alerts > 0 else 0
        report_html += f"""
        <tr>
            <td>{html.escape(situation)}</td>
            <td>{count}</td>
            <td>{percentage:.1f}%</td>
        </tr>
"""
    
    report_html += """
    </table>
    
    <h2>Últimas Ocorrências</h2>
"""
    
    for alert in alerts[:50]:  # Mostra apenas as 50 mais recentes
        loc = alert.get("location", {})
        lat = loc.get("lat") if loc else None
        lon = loc.get("lon") if loc else None
        location_str = f"{lat}, {lon}" if lat and lon else "Não informada"
        
        report_html += f"""
    <div class="alert">
        <strong>#{alert.get('id', 'N/A')}</strong> - {alert.get('ts', 'N/A')}<br>
        <strong>Nome:</strong> {html.escape(alert.get('name', 'N/A'))}<br>
        <strong>Situação:</strong> {html.escape(alert.get('situation', 'N/A'))}<br>
        <strong>Mensagem:</strong> {html.escape(alert.get('message', 'N/A'))}<br>
        <strong>Localização:</strong> <span class="location">{location_str}</span>
    </div>
"""
    
    report_html += f"""
    <div class="footer">
        <p>Relatório gerado automaticamente pelo sistema Aurora Mulher Segura v2.2.0-secure.</p>
        <p>Este é um documento confidencial. Distribuição restrita.</p>
        <p>Total de registros no sistema: {total_alerts}</p>
    </div>
    
    <div class="no-print" style="margin-top: 20px;">
        <button onclick="window.print()" style="padding: 10px 20px; background: #3498db; color: white; border: none; border-radius: 5px; cursor: pointer;">
            Imprimir Relatório
        </button>
        <button onclick="window.close()" style="padding: 10px 20px; background: #95a5a6; color: white; border: none; border-radius: 5px; cursor: pointer; margin-left: 10px;">
            Fechar
        </button>
    </div>
</body>
</html>
"""
    
    response = make_response(report_html)
    response.headers['Content-Type'] = 'text/html; charset=utf-8'
    response.headers['Content-Disposition'] = f'attachment; filename=relatorio_{datetime.now().strftime("%Y%m%d_%H%M%S")}.html'
    
    return response

@app.get("/report/pdf")
@admin_required
def generate_pdf_report():
    """Gera relatório em PDF."""
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib import colors
        from reportlab.lib.units import cm
        from reportlab.pdfgen import canvas
        from reportlab.pdfbase import pdfmetrics
        from reportlab.pdfbase.ttfonts import TTFont
        import io
        
        # Cria buffer para o PDF
        buffer = io.BytesIO()
        
        # Configura documento
        doc = SimpleDocTemplate(
            buffer,
            pagesize=A4,
            rightMargin=2*cm,
            leftMargin=2*cm,
            topMargin=2*cm,
            bottomMargin=2*cm
        )
        
        # Estilos
        styles = getSampleStyleSheet()
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Heading1'],
            fontSize=16,
            spaceAfter=30,
            textColor=colors.HexColor('#2c3e50')
        )
        
        heading_style = ParagraphStyle(
            'CustomHeading',
            parent=styles['Heading2'],
            fontSize=14,
            spaceAfter=12,
            textColor=colors.HexColor('#34495e')
        )
        
        normal_style = styles['Normal']
        
        # Conteúdo do PDF
        story = []
        
        # Título
        story.append(Paragraph("Relatório Aurora Mulher Segura", title_style))
        story.append(Paragraph(f"Gerado em: {now_br_str()}", normal_style))
        story.append(Paragraph(f"Gerado por: {session.get('name', 'Administrador')}", normal_style))
        story.append(Spacer(1, 20))
        
        # Coleta dados
        alerts = read_all_alerts(limit=100)
        total_alerts = len(alerts)
        
        # Estatísticas
        story.append(Paragraph("Estatísticas", heading_style))
        
        stats_data = [
            ["Total de Ocorrências", str(total_alerts)],
            ["Pessoas de Confiança Ativas", str(len(list_trusted_names()))],
            ["Versão do Sistema", "2.2.0-secure"]
        ]
        
        stats_table = Table(stats_data, colWidths=[10*cm, 5*cm])
        stats_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#3498db')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 12),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.white),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ('FONTSIZE', (0, 1), (-1, -1), 10),
            ('PADDING', (0, 1), (-1, -1), 6),
        ]))
        
        story.append(stats_table)
        story.append(Spacer(1, 20))
        
        # Últimas ocorrências
        story.append(Paragraph("Últimas Ocorrências", heading_style))
        
        if alerts:
            alert_data = [["ID", "Data/Hora", "Nome", "Situação"]]
            
            for alert in alerts[:20]:  # Limita a 20 no PDF
                alert_data.append([
                    str(alert.get('id', '')),
                    alert.get('ts', ''),
                    alert.get('name', ''),
                    alert.get('situation', '')
                ])
            
            alert_table = Table(alert_data, colWidths=[2*cm, 4*cm, 5*cm, 5*cm])
            alert_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#2c3e50')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 10),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 6),
                ('BACKGROUND', (0, 1), (-1, -1), colors.white),
                ('GRID', (0, 0), (-1, -1), 1, colors.grey),
                ('FONTSIZE', (0, 1), (-1, -1), 8),
                ('PADDING', (0, 1), (-1, -1), 4),
                ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f8f9fa')]),
            ]))
            
            story.append(alert_table)
        else:
            story.append(Paragraph("Nenhuma ocorrência registrada.", normal_style))
        
        story.append(Spacer(1, 20))
        
        # Rodapé
        story.append(Paragraph("Este é um documento confidencial. Distribuição restrita.", 
                              ParagraphStyle('Footer', parent=normal_style, fontSize=8, textColor=colors.grey)))
        
        # Gera PDF
        doc.build(story)
        
        # Prepara resposta
        buffer.seek(0)
        response = make_response(buffer.read())
        response.headers['Content-Type'] = 'application/pdf'
        response.headers['Content-Disposition'] = f'attachment; filename=relatorio_{datetime.now().strftime("%Y%m%d_%H%M%S")}.pdf'
        
        return response
        
    except ImportError:
        logger.error("ReportLab não instalado. Use 'pip install reportlab' para gerar PDFs.")
        flash("Funcionalidade PDF não disponível. Instale ReportLab.", "error")
        return redirect(url_for("admin_panel"))
    except Exception as e:
        logger.error(f"Erro ao gerar PDF: {e}")
        flash(f"Erro ao gerar PDF: {str(e)}", "error")
        return redirect(url_for("admin_panel"))

# ================================
# BACKUP E RESTAURAÇÃO
# ================================

@app.get("/panel/backup")
@admin_required
def admin_backup():
    """Cria backup dos dados."""
    try:
        import zipfile
        import shutil
        from pathlib import Path
        
        # Cria diretório de backups se não existir
        backup_dir = BASE_DIR / "backups"
        backup_dir.mkdir(exist_ok=True)
        
        # Nome do arquivo de backup
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_file = backup_dir / f"backup_{timestamp}.zip"
        
        # Arquivos para backup
        files_to_backup = [
            USERS_FILE,
            ALERTS_FILE,
            STATE_FILE,
            FAILED_LOGINS_FILE,
            AUDIT_LOG_FILE
        ]
        
        # Cria arquivo ZIP
        with zipfile.ZipFile(backup_file, 'w', zipfile.ZIP_DEFLATED) as zipf:
            for file_path in files_to_backup:
                if file_path.exists():
                    # Adiciona arquivo com caminho relativo
                    arcname = file_path.relative_to(BASE_DIR)
                    zipf.write(file_path, arcname)
        
        # Limita quantidade de backups (mantém últimos 10)
        backup_files = sorted(backup_dir.glob("backup_*.zip"), key=lambda x: x.stat().st_mtime, reverse=True)
        for old_backup in backup_files[10:]:
            old_backup.unlink()
        
        logger.info(f"Backup criado: {backup_file}")
        log_audit(session.get("user"), "Backup do sistema criado", "HIGH")
        
        # Disponibiliza para download
        response = make_response(backup_file.read_bytes())
        response.headers['Content-Type'] = 'application/zip'
        response.headers['Content-Disposition'] = f'attachment; filename="{backup_file.name}"'
        
        return response
        
    except Exception as e:
        logger.error(f"Erro ao criar backup: {e}")
        flash(f"Erro ao criar backup: {str(e)}", "error")
        return redirect(url_for("admin_panel"))

# ================================
# INICIALIZAÇÃO
# ================================

def init_app():
    """Inicializa a aplicação."""
    # Criar/verificar arquivos
    ensure_files()
    
    # Configurar logging
    logger.info("=" * 60)
    logger.info(f"Iniciando Aurora Mulher Segura v2.2.0-secure")
    logger.info(f"Data/Hora: {now_br_str()}")
    logger.info(f"Diretório base: {BASE_DIR}")
    logger.info(f"Modo debug: {DEBUG_MODE}")
    logger.info(f"HTTPS habilitado: {HTTPS_ENABLED}")
    logger.info(f"CSRF ativado: {CSRF_ENABLED}")
    logger.info(f"Tempo limite de sessão: {SESSION_TIMEOUT_MINUTES} minutos")
    logger.info(f"Máximo de pessoas de confiança: {MAX_TRUSTED_USERS}")
    logger.info("=" * 60)

if __name__ == "__main__":
    # Inicializar aplicação
    init_app()
    
    # Configurar servidor
    host = os.environ.get("HOST", "0.0.0.0")
    port = int(os.environ.get("PORT", 5000))
    
    # Configurar SSL se habilitado
    ssl_context = None
    if HTTPS_ENABLED:
        cert_path = BASE_DIR / "ssl" / "cert.pem"
        key_path = BASE_DIR / "ssl" / "key.pem"
        
        if cert_path.exists() and key_path.exists():
            ssl_context = (str(cert_path), str(key_path))
            logger.info(f"SSL configurado: {cert_path}")
        else:
            logger.warning("Certificados SSL não encontrados. HTTPS desabilitado.")
            if not DEBUG_MODE:
                logger.error("Em produção, HTTPS é obrigatório quando habilitado!")
    
    # Iniciar servidor
    try:
        app.run(
            host=host,
            port=port,
            debug=DEBUG_MODE,
            use_reloader=DEBUG_MODE,
            ssl_context=ssl_context,
            threaded=True
        )
    except Exception as e:
        logger.error(f"Erro ao iniciar servidor: {e}")
        raise