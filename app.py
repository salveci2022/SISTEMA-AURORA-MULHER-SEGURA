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
import pytz  # Substitui zoneinfo por pytz (compatível com Python 3.8)
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
    # Usando pytz em vez de zoneinfo (compatível com Python 3.8 do Render)
    TZ = pytz.timezone("America/Sao_Paulo")
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
    SESSION_COOKIE_SECURE=HTTPS_ENABLED,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Strict',
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=SESSION_TIMEOUT_MINUTES),
    WTF_CSRF_ENABLED=CSRF_ENABLED,
    WTF_CSRF_SECRET_KEY=SECRET_KEY + "_csrf",
    WTF_CSRF_TIME_LIMIT=3600,
    JSONIFY_PRETTYPRINT_REGULAR=False
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
# FUNÇÕES AUXILIARES SEGURAS
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
    try:
        if TZ is None:
            return datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        # Correção para pytz
        return datetime.now(TZ).strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def sanitize_input(text: str, max_length: int = 500) -> str:
    """Remove caracteres perigosos e limita tamanho."""
    if not text:
        return ""
    
    text = html.escape(text)
    text = re.sub(r'[\x00-\x1F\x7F]', '', text)
    
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

def ensure_files() -> bool:
    """Garante que arquivos necessários existam. Retorna True se sucesso."""
    try:
        if not USERS_FILE.exists():
            admin_salt = generate_salt()
            admin_hash = hash_password(ADMIN_DEFAULT_PASSWORD, admin_salt)
            
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
        
        return True
    except Exception as e:
        logger.error(f"Erro ao criar arquivos: {e}")
        return False

def log_audit(user: str, action: str, severity: str = "INFO", details: Dict = None) -> None:
    """Registra evento de auditoria."""
    try:
        audit_entry = {
            "timestamp": now_br_str(),
            "user": user,
            "action": action,
            "severity": severity,
            "ip": request.remote_addr if request else "system",
            "details": details or {}
        }
        
        with AUDIT_LOG_FILE.open("a", encoding="utf-8") as f:
            f.write(json.dumps(audit_entry, ensure_ascii=False) + "\n")
    except Exception as e:
        logger.error(f"Erro ao registrar auditoria: {e}")

def load_users() -> Dict[str, Dict[str, Any]]:
    """Carrega usuários do arquivo JSON."""
    if not ensure_files():
        return {}
    
    try:
        if not USERS_FILE.exists():
            return {}
            
        data = json.loads(USERS_FILE.read_text(encoding="utf-8"))
        
        if not isinstance(data, dict):
            logger.error("users.json não é um dicionário válido")
            return {}
        
        return data
    except json.JSONDecodeError as e:
        logger.error(f"Erro ao decodificar users.json: {e}")
        # Tenta recriar o arquivo
        ensure_files()
        return load_users()
    except Exception as e:
        logger.error(f"Erro ao carregar usuários: {e}")
        return {}

def save_users(data: Dict[str, Dict[str, Any]]) -> bool:
    """Salva usuários no arquivo JSON."""
    try:
        if not isinstance(data, dict):
            raise ValueError("Dados devem ser um dicionário")
        
        USERS_FILE.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
        return True
    except Exception as e:
        logger.error(f"Erro ao salvar usuários: {e}")
        return False

def load_failed_logins() -> Dict[str, Dict[str, Any]]:
    """Carrega tentativas falhas de login."""
    try:
        if FAILED_LOGINS_FILE.exists() and FAILED_LOGINS_FILE.stat().st_size > 0:
            return json.loads(FAILED_LOGINS_FILE.read_text(encoding="utf-8"))
    except:
        pass
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
                del failed_logins[username]
                save_failed_logins(failed_logins)
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
    
    save_failed_logins(failed_logins)

def clear_failed_logins(username: str) -> None:
    """Limpa tentativas falhas após login bem-sucedido."""
    failed_logins = load_failed_logins()
    if username in failed_logins:
        del failed_logins[username]
        save_failed_logins(failed_logins)

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
    try:
        ensure_files()
        
        if not STATE_FILE.exists():
            return 1
            
        with STATE_FILE.open("r+", encoding="utf-8") as f:
            try:
                data = json.load(f)
            except json.JSONDecodeError:
                data = {}
                
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
    try:
        ensure_files()
        
        with ALERTS_FILE.open("a", encoding="utf-8") as f:
            f.write(json.dumps(payload, ensure_ascii=False) + "\n")
        
        logger.info(f"Alerta registrado: ID {payload.get('id')}")
        
    except Exception as e:
        logger.error(f"Erro ao registrar alerta: {e}")

def read_last_alert() -> Optional[Dict[str, Any]]:
    """Lê último alerta do log."""
    try:
        if not ALERTS_FILE.exists() or ALERTS_FILE.stat().st_size == 0:
            return None
        
        with ALERTS_FILE.open("r", encoding="utf-8") as f:
            lines = f.readlines()
            if not lines:
                return None
            
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
    """Lê todos os alertas com paginação."""
    alerts = []
    try:
        if not ALERTS_FILE.exists():
            return alerts
        
        with ALERTS_FILE.open("r", encoding="utf-8") as f:
            lines = f.readlines()
        
        valid_lines = []
        for line in reversed(lines):
            line = line.strip()
            if line:
                valid_lines.append(line)
        
        start_idx = offset
        end_idx = offset + limit
        paginated_lines = valid_lines[start_idx:end_idx]
        
        for line in paginated_lines:
            try:
                alerts.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        
        return alerts
    except Exception as e:
        logger.error(f"Erro ao ler alertas: {e}")
        return []

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

# ================================
# MIDDLEWARE E HANDLERS
# ================================

@app.before_request
def before_request():
    """Executado antes de cada requisição."""
    if request.endpoint == 'static':
        return
    
    logger.info(f"{request.method} {request.path} - IP: {request.remote_addr}")
    
    if session.get("authenticated"):
        session.permanent = True
        session.modified = True

@app.after_request
def add_security_headers(response):
    """Adiciona headers de segurança HTTP."""
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    
    # CSP simplificado
    csp_policy = [
        "default-src 'self'",
        "script-src 'self'",
        "style-src 'self'",
        "img-src 'self' data: https:",
        "font-src 'self'"
    ]
    
    response.headers['Content-Security-Policy'] = '; '.join(csp_policy)
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    
    return response

@app.errorhandler(404)
def page_not_found(e):
    """Handler para página não encontrada."""
    logger.warning(f"404 - Página não encontrada: {request.path}")
    return render_template('404.html'), 404

@app.errorhandler(403)
def forbidden(e):
    """Handler para acesso proibido."""
    logger.warning(f"403 - Acesso proibido: {request.path}")
    return render_template('403.html'), 403

@app.errorhandler(400)
def bad_request(e):
    """Handler para requisição inválida."""
    logger.warning(f"400 - Requisição inválida: {request.path}")
    return render_template('400.html'), 400

@app.errorhandler(500)
def internal_server_error(e):
    """Handler para erro interno."""
    logger.error(f"500 - Erro interno: {str(e)[:200]}")
    return render_template('500.html'), 500

# ================================
# ROTAS BÁSICAS
# ================================

@app.get("/health")
def health():
    """Endpoint de saúde do sistema CORRIGIDO."""
    try:
        # Verifica arquivos
        files_status = {
            "users.json": USERS_FILE.exists(),
            "alerts.log": ALERTS_FILE.exists(),
            "state.json": STATE_FILE.exists(),
            "failed_logins.json": FAILED_LOGINS_FILE.exists(),
            "audit.log": AUDIT_LOG_FILE.exists()
        }
        
        # Conta usuários
        users = load_users()
        
        return jsonify({
            "status": "healthy",
            "timestamp": now_br_str(),
            "version": "2.2.0-secure",
            "files": files_status,
            "users": {
                "total": len(users),
                "admin": sum(1 for u in users.values() if u.get("role") == "admin"),
                "trusted": sum(1 for u in users.values() if u.get("role") == "trusted"),
                "active": sum(1 for u in users.values() if u.get("is_active", True))
            }
        })
    except Exception as e:
        logger.error(f"Erro no endpoint health: {e}")
        return jsonify({"status": "unhealthy", "error": str(e)[:100]}), 500

@app.get("/")
def index():
    """Página inicial."""
    return redirect(url_for("panic_button"))

@app.get("/panic")
def panic_button():
    """Botão de pânico."""
    trusted = list_trusted_names()
    last_alert = read_last_alert()
    
    form_token = secrets.token_hex(16)
    session['panic_token'] = form_token
    
    return render_template(
        "panic_button.html", 
        trusted=trusted,
        last_alert=last_alert,
        form_token=form_token
    )

# ================================
# ALERTAS (API)
# ================================

@app.post("/api/send_alert")
def send_alert():
    """Recebe alerta do botão de pânico."""
    try:
        data = request.get_json(silent=True)
        if not data:
            return jsonify({"ok": False, "error": "Dados JSON inválidos"}), 400
        
        # Verifica token do formulário
        form_token = request.headers.get('X-Form-Token') or data.get('form_token', '')
        if not form_token or form_token != session.get('panic_token'):
            return jsonify({"ok": False, "error": "Token inválido"}), 403
        
        # Sanitiza inputs
        name = sanitize_input(data.get("name") or "Anônimo", 100)
        situation = sanitize_input(data.get("situation") or "Emergência", 100)
        message = sanitize_input(data.get("message") or "", 500)
        
        # Cria payload do alerta
        alert_id = next_alert_id()
        payload = {
            "id": alert_id,
            "ts": now_br_str(),
            "name": name,
            "situation": situation,
            "message": message,
            "ip": request.remote_addr
        }
        
        # Registra alerta
        log_alert(payload)
        
        # Gera novo token
        session['panic_token'] = secrets.token_hex(16)
        
        return jsonify({
            "ok": True, 
            "id": alert_id,
            "message": f"Alerta #{alert_id} registrado com sucesso."
        })
    except Exception as e:
        logger.error(f"Erro em send_alert: {e}")
        return jsonify({"ok": False, "error": "Erro interno"}), 500

@app.get("/api/last_alert")
def last_alert():
    """Retorna o último alerta registrado."""
    alert = read_last_alert()
    return jsonify({"ok": True, "last": alert})

# ================================
# ADMIN - CORRIGIDO
# ================================

@app.route("/panel/login", methods=["GET", "POST"])
def admin_login():
    """Login do administrador - CORRIGIDO."""
    try:
        # Se já estiver autenticado, redireciona
        if session.get("authenticated") and session.get("role") == "admin":
            return redirect(url_for("admin_panel"))
        
        if request.method == "GET":
            return render_template("login_admin.html")
        
        # Processa POST
        username = request.form.get("user", "").strip().lower()
        password = request.form.get("password", "")
        
        if not username or not password:
            flash("Preencha todos os campos", "error")
            return render_template("login_admin.html")
        
        # Verifica bloqueio
        locked_out, remaining = is_locked_out(username)
        if locked_out:
            flash(f"Conta bloqueada. Tente novamente em {remaining}.", "error")
            return render_template("login_admin.html")
        
        users = load_users()
        info = users.get(username)
        
        # Verifica usuário
        if not info or info.get("role") != "admin":
            record_failed_login(username)
            flash("Credenciais inválidas", "error")
            return render_template("login_admin.html")
        
        if not info.get("is_active", True):
            flash("Conta desativada", "error")
            return render_template("login_admin.html")
        
        # Verifica senha
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
            
            # Verifica se precisa mudar senha
            if users[username].get("must_change_password", False):
                flash("Você deve alterar sua senha antes de continuar.", "warning")
                return redirect(url_for("admin_change_password"))
            
            return redirect(url_for("admin_panel"))
        else:
            # Senha incorreta
            record_failed_login(username)
            flash("Credenciais inválidas", "error")
            return render_template("login_admin.html")
            
    except Exception as e:
        logger.error(f"Erro no admin_login: {e}")
        flash("Erro interno no servidor", "error")
        return render_template("login_admin.html")

@app.route("/panel/change_password", methods=["GET", "POST"])
@admin_required
def admin_change_password():
    """Força alteração de senha do admin."""
    users = load_users()
    username = session.get("user")
    user_info = users.get(username, {})
    
    if request.method == "GET":
        return render_template("admin_change_password.html")
    
    # Processa POST
    old_password = request.form.get("old_password", "")
    new_password = request.form.get("new_password", "")
    confirm_password = request.form.get("confirm_password", "")
    
    # Validações
    if not old_password or not new_password or not confirm_password:
        flash("Preencha todos os campos", "error")
        return render_template("admin_change_password.html")
    
    if len(new_password) < 12:
        flash("A nova senha deve ter pelo menos 12 caracteres", "error")
        return render_template("admin_change_password.html")
    
    if new_password == old_password:
        flash("A nova senha deve ser diferente da antiga", "error")
        return render_template("admin_change_password.html")
    
    if new_password != confirm_password:
        flash("As senhas não coincidem", "error")
        return render_template("admin_change_password.html")
    
    # Verifica senha antiga
    salt = user_info.get("salt", "")
    if verify_password(user_info.get("password", ""), old_password, salt):
        # Gera novo salt e hash
        new_salt = generate_salt()
        new_hash = hash_password(new_password, new_salt)
        
        # Atualiza usuário
        users[username]["password"] = new_hash
        users[username]["salt"] = new_salt
        users[username]["last_password_change"] = now_br_str()
        users[username]["must_change_password"] = False
        
        save_users(users)
        
        flash("Senha alterada com sucesso!", "success")
        return redirect(url_for("admin_panel"))
    else:
        flash("Senha atual incorreta", "error")
        return render_template("admin_change_password.html")

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
    
    return render_template(
        "panel_admin.html", 
        trusted_users=trusted_users,
        total_alerts=total_alerts,
        total_trusted=total_trusted,
        active_trusted=active_trusted,
        max_trusted_users=MAX_TRUSTED_USERS
    )

@app.post("/panel/add_trusted")
@admin_required
def admin_add_trusted():
    """Adiciona pessoa de confiança."""
    name = request.form.get("trusted_name", "").strip()
    username = request.form.get("trusted_user", "").strip().lower()
    password = request.form.get("trusted_password", "")
    confirm_password = request.form.get("confirm_password", "")
    
    # Validações
    if not name or not username or not password:
        flash("Preencha pelo menos nome, usuário e senha", "error")
        return redirect(url_for("admin_panel"))
    
    if not validate_username(username):
        flash("Nome de usuário inválido", "error")
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
    
    # Verifica limite
    trusted_count = sum(1 for u in users.values() if u.get("role") == "trusted" and u.get("is_active", True))
    if trusted_count >= MAX_TRUSTED_USERS:
        flash(f"Limite de {MAX_TRUSTED_USERS} pessoas de confiança atingido", "error")
        return redirect(url_for("admin_panel"))
    
    # Gera salt e hash
    salt = generate_salt()
    password_hash = hash_password(password, salt)
    
    # Cria usuário
    users[username] = {
        "password": password_hash,
        "salt": salt,
        "role": "trusted",
        "name": name,
        "created_at": now_br_str(),
        "last_login": None,
        "last_password_change": now_br_str(),
        "is_active": True,
        "failed_attempts": 0
    }
    
    save_users(users)
    
    flash(f"Pessoa de confiança '{name}' adicionada com sucesso", "success")
    return redirect(url_for("admin_panel"))

@app.post("/panel/update_trusted")
@admin_required
def admin_update_trusted():
    """Atualiza pessoa de confiança."""
    username = request.form.get("username", "").strip()
    name = request.form.get("name", "").strip()
    is_active = request.form.get("is_active") == "on"
    
    users = load_users()
    
    if username in users and users[username].get("role") == "trusted":
        users[username]["name"] = name
        users[username]["is_active"] = is_active
        users[username]["updated_at"] = now_br_str()
        
        save_users(users)
        flash(f"Pessoa de confiança '{name}' atualizada", "success")
    
    return redirect(url_for("admin_panel"))

@app.post("/panel/reset_trusted_password")
@admin_required
def admin_reset_trusted_password():
    """Redefine senha de pessoa de confiança."""
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
        
        # Gera novo salt e hash
        new_salt = generate_salt()
        new_hash = hash_password(new_password, new_salt)
        
        users[username]["password"] = new_hash
        users[username]["salt"] = new_salt
        users[username]["last_password_change"] = now_br_str()
        users[username]["must_change_password"] = True
        
        save_users(users)
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
        
        if username == session.get("user"):
            flash("Você não pode excluir sua própria conta", "error")
            return redirect(url_for("admin_panel"))
        
        # Marca como inativo
        users[username]["is_active"] = False
        users[username]["deactivated_at"] = now_br_str()
        
        save_users(users)
        flash(f"Pessoa de confiança '{name}' desativada", "success")
    
    return redirect(url_for("admin_panel"))

@app.get("/logout_admin")
def logout_admin():
    """Logout do administrador."""
    username = session.get("user")
    
    if session.get("authenticated") and session.get("role") == "admin":
        logger.info(f"Admin {username} deslogou")
    
    session.clear()
    flash("Logout realizado com sucesso", "success")
    return redirect(url_for("admin_login"))

# ================================
# PESSOAS DE CONFIANÇA
# ================================

@app.route("/trusted/login", methods=["GET", "POST"])
def trusted_login():
    """Login de pessoa de confiança."""
    try:
        # Se já estiver autenticado, redireciona
        if session.get("authenticated") and session.get("role") == "trusted":
            return redirect(url_for("trusted_panel"))
        
        if request.method == "GET":
            return render_template("login_trusted.html")
        
        # Processa POST
        username = request.form.get("user", "").strip().lower()
        password = request.form.get("password", "")
        
        if not username or not password:
            flash("Preencha todos os campos", "error")
            return render_template("login_trusted.html")
        
        # Verifica bloqueio
        locked_out, remaining = is_locked_out(username)
        if locked_out:
            flash(f"Conta bloqueada. Tente novamente em {remaining}.", "error")
            return render_template("login_trusted.html")
        
        users = load_users()
        info = users.get(username)
        
        # Verifica usuário
        if not info or info.get("role") != "trusted":
            record_failed_login(username)
            flash("Credenciais inválidas", "error")
            return render_template("login_trusted.html")
        
        if not info.get("is_active", True):
            flash("Conta desativada", "error")
            return render_template("login_trusted.html")
        
        # Verifica senha
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
            return redirect(url_for("trusted_panel"))
        else:
            # Senha incorreta
            record_failed_login(username)
            flash("Credenciais inválidas", "error")
            return render_template("login_trusted.html")
            
    except Exception as e:
        logger.error(f"Erro no trusted_login: {e}")
        flash("Erro interno no servidor", "error")
        return render_template("login_trusted.html")

@app.get("/trusted/panel")
@trusted_required
def trusted_panel():
    """Painel da pessoa de confiança."""
    users = load_users()
    username = session.get("trusted")
    user_info = users.get(username, {})
    display_name = user_info.get("name") or username
    
    # Últimos alertas
    alerts = read_all_alerts(limit=10)
    
    return render_template(
        "panel_trusted.html", 
        display_name=display_name,
        recent_alerts=alerts
    )

@app.route("/trusted/change_password", methods=["GET", "POST"])
@trusted_required
def trusted_change_password():
    """Alteração de senha pela pessoa de confiança."""
    users = load_users()
    username = session.get("trusted")
    user_info = users.get(username, {})
    
    if request.method == "GET":
        return render_template("trusted_change_password.html")
    
    # Processa POST
    old_password = request.form.get("old_password", "")
    new_password = request.form.get("new_password", "")
    confirm_password = request.form.get("confirm_password", "")
    
    # Validações
    if not old_password or not new_password or not confirm_password:
        flash("Preencha todos os campos", "error")
        return render_template("trusted_change_password.html")
    
    if len(new_password) < 8:
        flash("A nova senha deve ter pelo menos 8 caracteres", "error")
        return render_template("trusted_change_password.html")
    
    if new_password == old_password:
        flash("A nova senha deve ser diferente da antiga", "error")
        return render_template("trusted_change_password.html")
    
    if new_password != confirm_password:
        flash("As senhas não coincidem", "error")
        return render_template("trusted_change_password.html")
    
    # Verifica senha antiga
    salt = user_info.get("salt", "")
    if verify_password(user_info.get("password", ""), old_password, salt):
        # Gera novo salt e hash
        new_salt = generate_salt()
        new_hash = hash_password(new_password, new_salt)
        
        # Atualiza usuário
        users[username]["password"] = new_hash
        users[username]["salt"] = new_salt
        users[username]["last_password_change"] = now_br_str()
        
        save_users(users)
        
        flash("Senha alterada com sucesso", "success")
        return redirect(url_for("trusted_panel"))
    else:
        flash("Senha atual incorreta", "error")
        return render_template("trusted_change_password.html")

@app.get("/logout_trusted")
def logout_trusted():
    """Logout da pessoa de confiança."""
    username = session.get("trusted")
    
    if session.get("authenticated") and session.get("role") == "trusted":
        logger.info(f"Pessoa de confiança {username} deslogou")
    
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
    
    # Formata relatório
    report_html = f"""<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="utf-8">
    <title>Relatório Aurora Mulher Segura</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        h1 {{ color: #2c3e50; }}
        table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
        th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
        th {{ background-color: #3498db; color: white; }}
        .footer {{ margin-top: 30px; padding-top: 20px; border-top: 1px solid #ddd; }}
    </style>
</head>
<body>
    <h1>Relatório Aurora Mulher Segura</h1>
    <p><strong>Gerado em:</strong> {now_br_str()}</p>
    <p><strong>Total de Ocorrências:</strong> {total_alerts}</p>
    
    <table>
        <tr>
            <th>ID</th>
            <th>Data/Hora</th>
            <th>Nome</th>
            <th>Situação</th>
            <th>Mensagem</th>
        </tr>
"""
    
    for alert in alerts:
        report_html += f"""
        <tr>
            <td>{alert.get('id', '')}</td>
            <td>{alert.get('ts', '')}</td>
            <td>{html.escape(alert.get('name', ''))}</td>
            <td>{html.escape(alert.get('situation', ''))}</td>
            <td>{html.escape(alert.get('message', ''))}</td>
        </tr>
"""
    
    report_html += """
    </table>
    
    <div class="footer">
        <p>Relatório gerado automaticamente pelo sistema Aurora Mulher Segura.</p>
    </div>
</body>
</html>
"""
    
    response = make_response(report_html)
    response.headers['Content-Type'] = 'text/html; charset=utf-8'
    
    return response

# ================================
# INICIALIZAÇÃO
# ================================

def init_app():
    """Inicializa a aplicação."""
    logger.info("=" * 60)
    logger.info(f"Iniciando Aurora Mulher Segura")
    logger.info(f"Data/Hora: {now_br_str()}")
    logger.info(f"Diretório base: {BASE_DIR}")
    logger.info(f"Modo debug: {DEBUG_MODE}")
    logger.info("=" * 60)
    
    # Criar arquivos necessários
    ensure_files()

# ================================
# MAIN
# ================================

if __name__ == "__main__":
    init_app()
    
    host = os.environ.get("HOST", "0.0.0.0")
    port = int(os.environ.get("PORT", 5000))
    
    app.run(host=host, port=port, debug=DEBUG_MODE)


# ==========================
# Aliases de rotas (compatibilidade de links)
# ==========================

@app.get("/login")
def login_alias():
    # Alias para login do Admin
    return redirect(url_for("admin_login"))

@app.get("/admin")
def admin_alias():
    # Alias para painel Admin
    return redirect(url_for("admin_panel"))

@app.get("/history")
def history_alias():
    # Alias para histórico/relatório
    return redirect(url_for("generate_report"))

@app.get("/diagnostic")
def diagnostic_page():
    # Página simples de diagnóstico (links principais)
    return render_template("diagnostic.html", now=now_br_str())

@app.get("/diagnostico")
def diagnostico_alias():
    return redirect(url_for("diagnostic_page"))

